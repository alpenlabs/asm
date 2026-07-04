//! Admin subprotocol test utilities
//!
//! Provides ergonomic helpers for testing admin subprotocol transactions.
//!
//! # Example
//!
//! ```ignore
//! use harness::admin::{admin_harness, sequencer_update, AdminExt, DEFAULT_CONFIRMATION_DEPTH};
//!
//! let (harness, mut ctx) = admin_harness(DEFAULT_CONFIRMATION_DEPTH).await;
//! harness.submit_admin_action(&mut ctx, sequencer_update([1u8; 32])).await?;
//! let state = harness.admin_state()?;
//! ```

use std::{collections::HashMap, future::Future, num::NonZero};

use bitcoin::{
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    BlockHash, Transaction,
};
use ssz::Encode;
use strata_asm_common::{AnchorState, Subprotocol};
use strata_asm_params::{AdministrationInitConfig, ConfirmationDepths, Role};
use strata_asm_proto_admin::{AdministrationSubprotoState, AdministrationSubprotocol};
use strata_asm_proto_admin_txs::{
    actions::{
        updates::{
            AlpenAdminMultisigUpdate, AsmStfVkUpdate, Defcon1Update, Defcon3Update, EeStfVkUpdate,
            OlStfVkUpdate, OperatorSetUpdate, SafeHarbourAddressUpdate, SequencerUpdate,
            StrataAdminMultisigUpdate, StrataSecurityCouncilMultisigUpdate,
            StrataSeqManagerMultisigUpdate,
        },
        CancelAction, MultisigAction, UpdateAction,
    },
    parser::SignedPayload,
    test_utils::create_signature_set,
};
use strata_asm_proto_bridge_v1_types::SafeHarbourAddress;
use strata_crypto::{
    keys::compressed::CompressedPublicKey,
    threshold_signature::{ThresholdConfig, ThresholdConfigUpdate},
    EvenPublicKey,
};
use strata_identifiers::Buf32;
use strata_predicate::PredicateKey;

use super::test_harness::AsmTestHarness;

/// The default allowed seqno gap for admin subprotocol.
const DEFAULT_MAX_SEQNO_GAP: NonZero<u8> = NonZero::new(10).expect("10 is non-zero");

/// Default non-zero confirmation depth for admin updates in tests: large enough that updates
/// queue rather than apply immediately, small enough to activate within a couple of blocks.
pub const DEFAULT_CONFIRMATION_DEPTH: u16 = 2;

/// Extension trait for admin subprotocol operations on the test harness.
///
/// This trait provides admin-specific convenience methods while keeping
/// the core harness infrastructure-focused.
pub trait AdminExt {
    /// Get admin subprotocol state.
    fn admin_state(&self) -> anyhow::Result<AdministrationSubprotoState>;

    /// Submit an admin action: sign with the action's required role, build tx, submit, mine.
    fn submit_admin_action(
        &self,
        ctx: &mut AdminContext,
        action: MultisigAction,
    ) -> impl Future<Output = anyhow::Result<BlockHash>>;

    /// Submit an admin action with a specific sequence number (for replay testing).
    fn submit_admin_action_with_seqno(
        &self,
        ctx: &AdminContext,
        action: MultisigAction,
        seqno: u64,
    ) -> impl Future<Output = anyhow::Result<BlockHash>>;

    /// Submit an admin action signed with `signing_role`'s keys.
    ///
    /// Used to exercise role-segregation rejection: the handler resolves the required
    /// role from the action itself, so passing a `signing_role` that doesn't match
    /// produces a signature that fails verification against the required role's config.
    fn submit_admin_action_as_role(
        &self,
        ctx: &mut AdminContext,
        action: MultisigAction,
        signing_role: Role,
    ) -> impl Future<Output = anyhow::Result<BlockHash>>;

    /// Submit an admin action with `signing_role`'s keys and an explicit seqno.
    ///
    /// Needed when a role-mismatch test has to set the seqno above the action's
    /// *required* role's `last_seqno` (e.g. cancelling a queued alpen update where
    /// alpen's seqno already advanced) so that signature verification is the
    /// unambiguous failure path rather than replay protection.
    fn submit_admin_action_as_role_with_seqno(
        &self,
        ctx: &AdminContext,
        action: MultisigAction,
        signing_role: Role,
        seqno: u64,
    ) -> impl Future<Output = anyhow::Result<BlockHash>>;

    /// Build (but do not submit or mine) an admin action transaction, signed with the
    /// action's required role.
    ///
    /// Used to place an admin action in the same block as another transaction (e.g. a
    /// checkpoint) via [`AsmTestHarness::mine_block_with_ordered_txs`].
    fn build_admin_action_tx(
        &self,
        ctx: &mut AdminContext,
        action: MultisigAction,
    ) -> impl Future<Output = anyhow::Result<Transaction>>;
}

/// Signing material for a single role.
#[derive(Debug, Clone)]
struct RoleKeys {
    privkeys: Vec<SecretKey>,
    signer_indices: Vec<u8>,
}

/// Context for signing admin transactions.
///
/// Holds distinct signing material per role and tracks sequence numbers per role. By
/// default, signing routes to the action's required role and uses that role's keys;
/// tests can also sign with a *different* role's keys via [`AdminContext::sign_as_role`]
/// to exercise role-segregation rejection paths.
#[derive(Debug)]
pub struct AdminContext {
    keys: HashMap<Role, RoleKeys>,
    seqnos: HashMap<Role, u64>,
}

impl AdminContext {
    /// Create a context from per-role signing material.
    ///
    /// The map must contain an entry for every [`Role`]; callers that omit a role will
    /// panic the first time signing under that role is requested.
    pub fn new(role_keys: HashMap<Role, (Vec<SecretKey>, Vec<u8>)>) -> Self {
        let keys = role_keys
            .into_iter()
            .map(|(role, (privkeys, signer_indices))| {
                (
                    role,
                    RoleKeys {
                        privkeys,
                        signer_indices,
                    },
                )
            })
            .collect();
        Self {
            keys,
            seqnos: HashMap::new(),
        }
    }

    /// Sign an action using its required role's keys; auto-increments that role's seqno.
    pub fn sign(&mut self, action: &MultisigAction) -> Vec<u8> {
        self.sign_as_role(action, action.required_role())
    }

    /// Sign an action using `signing_role`'s keys; auto-increments that role's seqno.
    ///
    /// When `signing_role` differs from `action.required_role()`, the produced signature
    /// will fail verification against the action's required role — use this to exercise
    /// role-segregation rejection paths.
    pub fn sign_as_role(&mut self, action: &MultisigAction, signing_role: Role) -> Vec<u8> {
        let seqno = *self.seqnos.entry(signing_role).or_insert(1);
        let result = self.sign_impl(action, signing_role, seqno);
        *self.seqnos.get_mut(&signing_role).unwrap() += 1;
        result
    }

    /// Sign with an explicit seqno using the action's required role's keys.
    ///
    /// Does NOT auto-increment the internal sequence number.
    pub fn sign_with_seqno(&self, action: &MultisigAction, seqno: u64) -> Vec<u8> {
        self.sign_as_role_with_seqno(action, action.required_role(), seqno)
    }

    /// Sign with an explicit seqno using `signing_role`'s keys.
    pub fn sign_as_role_with_seqno(
        &self,
        action: &MultisigAction,
        signing_role: Role,
        seqno: u64,
    ) -> Vec<u8> {
        self.sign_impl(action, signing_role, seqno)
    }

    /// Get the private keys associated with `role` (for manual signature construction).
    pub fn privkeys(&self, role: Role) -> &[SecretKey] {
        &self.role_keys(role).privkeys
    }

    /// Get the signer indices associated with `role`.
    pub fn signer_indices(&self, role: Role) -> &[u8] {
        &self.role_keys(role).signer_indices
    }

    fn role_keys(&self, role: Role) -> &RoleKeys {
        self.keys
            .get(&role)
            .unwrap_or_else(|| panic!("AdminContext has no keys for {role:?}"))
    }

    fn sign_impl(&self, action: &MultisigAction, signing_role: Role, seqno: u64) -> Vec<u8> {
        let keys = self.role_keys(signing_role);
        let sig_set = create_signature_set(&keys.privkeys, &keys.signer_indices, action, seqno);
        SignedPayload::new(seqno, action.clone(), sig_set).as_ssz_bytes()
    }
}

// ============================================================================
// Action Builders
// ============================================================================

/// Create a sequencer update action.
pub fn sequencer_update(key: [u8; 32]) -> MultisigAction {
    MultisigAction::Update(UpdateAction::Sequencer(SequencerUpdate::new(Buf32::from(
        key,
    ))))
}

/// Create an operator set update action.
pub fn operator_set_update(add: Vec<EvenPublicKey>, remove: Vec<u32>) -> MultisigAction {
    MultisigAction::Update(UpdateAction::OperatorSet(OperatorSetUpdate::new(
        add, remove,
    )))
}

/// Create a cancel action for a queued update.
///
/// Looks up the queued action at `id` so the cancel embeds the correct `UpdateAction`
/// payload (required for role resolution and the handler's equality check).
pub fn cancel_update(id: u32, state: &AdministrationSubprotoState) -> MultisigAction {
    let update = state
        .find_queued(&id)
        .expect("queued update must exist for cancel")
        .action()
        .clone();
    MultisigAction::Cancel(CancelAction::new(id, update))
}

/// Create a multisig config update action.
///
/// This updates the threshold configuration for a specific role (admin or sequencer manager).
pub fn multisig_config_update(
    role: Role,
    add_members: Vec<CompressedPublicKey>,
    remove_members: Vec<CompressedPublicKey>,
    new_threshold: u8,
) -> MultisigAction {
    let config = ThresholdConfigUpdate::try_new(
        add_members,
        remove_members,
        NonZero::new(new_threshold).expect("threshold must be non-zero"),
    )
    .expect("valid threshold config");
    let update = match role {
        Role::StrataAdministrator => {
            UpdateAction::StrataAdminMultisig(StrataAdminMultisigUpdate::new(config))
        }
        Role::StrataSequencerManager => {
            UpdateAction::StrataSeqManagerMultisig(StrataSeqManagerMultisigUpdate::new(config))
        }
        Role::AlpenAdministrator => {
            UpdateAction::AlpenAdminMultisig(AlpenAdminMultisigUpdate::new(config))
        }
        Role::StrataSecurityCouncil => UpdateAction::StrataSecurityCouncilMultisig(
            StrataSecurityCouncilMultisigUpdate::new(config),
        ),
    };
    MultisigAction::Update(update)
}

/// Create an ASM STF verifying key update action.
pub fn asm_stf_vk_update(key: PredicateKey) -> MultisigAction {
    MultisigAction::Update(UpdateAction::AsmStfVk(AsmStfVkUpdate::new(key)))
}

/// Create an OL STF (rollup) verifying key update action.
pub fn ol_stf_vk_update(key: PredicateKey) -> MultisigAction {
    MultisigAction::Update(UpdateAction::OlStfVk(OlStfVkUpdate::new(key)))
}

/// Create an EE STF verifying key update action.
pub fn ee_stf_vk_update(key: PredicateKey) -> MultisigAction {
    MultisigAction::Update(UpdateAction::EeStfVk(EeStfVkUpdate::new(key)))
}

/// Create a Defcon 1 immediate sweep action.
pub fn defcon1_update() -> MultisigAction {
    MultisigAction::Update(UpdateAction::Defcon1(Defcon1Update))
}

/// Create a Defcon 3 delayed sweep action.
pub fn defcon3_update() -> MultisigAction {
    MultisigAction::Update(UpdateAction::Defcon3(Defcon3Update))
}

/// Create a safe harbour address update action.
pub fn safe_harbour_address_update(address: SafeHarbourAddress) -> MultisigAction {
    MultisigAction::Update(UpdateAction::SafeHarbourAddress(
        SafeHarbourAddressUpdate::new(address),
    ))
}

// ============================================================================
// Test Setup
// ============================================================================

/// Creates matching admin subprotocol params and signing context.
///
/// Generates a distinct 1-of-1 [`ThresholdConfig`] keypair for each of the four roles
/// ([`Role::StrataAdministrator`], [`Role::StrataSequencerManager`],
/// [`Role::AlpenAdministrator`], [`Role::StrataSecurityCouncil`]). The returned
/// [`AdminContext`] holds the matching signing material per role, so by default
/// `submit_admin_action(ctx, action)` signs with the action's required role's keys.
/// Combine with [`AdminExt::submit_admin_action_as_role`] to exercise role-segregation
/// rejection paths (e.g. signing an OL STF VK update with the AlpenAdministrator's keys).
pub fn create_test_admin_setup(
    confirmation_depth: u16,
) -> (AdministrationInitConfig, AdminContext) {
    let secp = Secp256k1::new();
    let make_role = || {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let pk = CompressedPublicKey::from(PublicKey::from_secret_key(&secp, &sk));
        let config =
            ThresholdConfig::try_new(vec![pk], NonZero::new(1).unwrap()).expect("valid config");
        (config, sk)
    };

    let (strata_administrator, sk_admin) = make_role();
    let (strata_sequencer_manager, sk_seq) = make_role();
    let (alpen_administrator, sk_alpen) = make_role();
    let (strata_security_council, sk_council) = make_role();

    let params = AdministrationInitConfig {
        strata_administrator,
        strata_sequencer_manager,
        alpen_administrator,
        strata_security_council,
        confirmation_depths: ConfirmationDepths {
            strata_admin_multisig_update: confirmation_depth,
            strata_seq_manager_multisig_update: confirmation_depth,
            alpen_admin_multisig_update: confirmation_depth,
            strata_security_council_multisig_update: confirmation_depth,
            operator_update: confirmation_depth,
            sequencer_update: confirmation_depth,
            ol_stf_vk_update: confirmation_depth,
            asm_stf_vk_update: confirmation_depth,
            ee_stf_vk_update: confirmation_depth,
            defcon3: confirmation_depth,
            safe_harbour_address_update: confirmation_depth,
        },
        max_seqno_gap: DEFAULT_MAX_SEQNO_GAP,
    };

    let role_keys = HashMap::from([
        (Role::StrataAdministrator, (vec![sk_admin], vec![0u8])),
        (Role::StrataSequencerManager, (vec![sk_seq], vec![0u8])),
        (Role::AlpenAdministrator, (vec![sk_alpen], vec![0u8])),
        (Role::StrataSecurityCouncil, (vec![sk_council], vec![0u8])),
    ]);
    let ctx = AdminContext::new(role_keys);

    (params, ctx)
}

// ============================================================================
// Action helpers
// ============================================================================

/// The number of blocks to mine after submitting `action` for it to take effect: the
/// confirmation depth configured for the action's update type, read from the live admin state.
///
/// Mirrors the production handler's `confirmation_depths.get(update.update_tx_type())` — a depth
/// of zero (an immediate-apply update) surfaces as `None`, and cancels apply immediately too, so
/// both return `0` (nothing to wait for).
fn activation_depth(harness: &AsmTestHarness, action: &MultisigAction) -> u16 {
    match action {
        MultisigAction::Update(update) => harness
            .admin_state()
            .expect("admin state should be available")
            .confirmation_depth(update.update_tx_type())
            .unwrap_or(0),
        MultisigAction::Cancel(_) => 0,
    }
}

/// Submits an admin action and mines until it activates: the confirmation depth configured for
/// that action's update type (see `activation_depth`). Immediate-apply updates and cancels
/// mine no extra blocks.
pub async fn submit_and_activate(
    harness: &AsmTestHarness,
    ctx: &mut AdminContext,
    action: MultisigAction,
) {
    let depth = activation_depth(harness, &action);
    harness.submit_admin_action(ctx, action).await.unwrap();
    harness.mine_blocks(depth as usize).await.unwrap();
}

/// Asserts that `action` can only be authorized by its required role.
///
/// Submits `action` once per *other* role (signing with that role's keys) and verifies the
/// handler rejects every one: nothing new is queued, the update-id counter does not advance,
/// and the required role's seqno does not advance — both immediately and after mining through
/// `confirmation_depth` blocks (to confirm nothing latent activates later).
///
/// Baselines are captured from the live admin state, so this tolerates a harness that already
/// has unrelated admin history. Subprotocol-specific "the effect did not happen" assertions
/// (e.g. a checkpoint predicate or bridge safe harbour left unchanged) are left to the caller,
/// which already holds the harness.
///
/// The activation window mined through is the action's own configured confirmation depth (see
/// `activation_depth`), so it can't drift out of sync with how the admin config was built.
pub async fn assert_only_required_role_can_send(
    harness: &AsmTestHarness,
    ctx: &mut AdminContext,
    action: MultisigAction,
) {
    let confirmation_depth = activation_depth(harness, &action);
    let required_role = action.required_role();

    let before = harness.admin_state().unwrap();
    let baseline_queued = before.queued().len();
    let baseline_next_id = before.next_update_id();
    let baseline_seqno = before.authority(required_role).unwrap().last_seqno();

    let assert_unchanged = |stage: &str| {
        let state = harness.admin_state().unwrap();
        assert_eq!(
            state.queued().len(),
            baseline_queued,
            "no update should be queued when signed by the wrong role ({stage})",
        );
        assert_eq!(
            state.next_update_id(),
            baseline_next_id,
            "next_update_id must not advance for rejected txs ({stage})",
        );
        assert_eq!(
            state.authority(required_role).unwrap().last_seqno(),
            baseline_seqno,
            "{required_role:?} seqno must not advance for rejected txs ({stage})",
        );
    };

    for signing_role in [
        Role::StrataAdministrator,
        Role::StrataSequencerManager,
        Role::AlpenAdministrator,
        Role::StrataSecurityCouncil,
    ] {
        if signing_role == required_role {
            continue;
        }
        harness
            .submit_admin_action_as_role(ctx, action.clone(), signing_role)
            .await
            .unwrap();
    }

    assert_unchanged("after wrong-role submissions");

    // Mine through the activation window to confirm nothing latent applies later.
    harness
        .mine_blocks(confirmation_depth as usize)
        .await
        .unwrap();
    assert_unchanged("after mining the activation window");
}

/// Extract admin subprotocol state from AnchorState.
pub fn extract_admin_state(
    anchor_state: &AnchorState,
) -> anyhow::Result<AdministrationSubprotoState> {
    let section = anchor_state
        .find_section(AdministrationSubprotocol::ID)
        .ok_or_else(|| anyhow::anyhow!("Admin section not found"))?;
    let admin_state = section.try_to_state::<AdministrationSubprotocol>()?;
    Ok(admin_state)
}

impl AdminExt for AsmTestHarness {
    fn admin_state(&self) -> anyhow::Result<AdministrationSubprotoState> {
        let (_, asm_state) = self
            .get_latest_asm_state()?
            .ok_or_else(|| anyhow::anyhow!("No ASM state available"))?;
        extract_admin_state(&asm_state)
    }

    async fn submit_admin_action(
        &self,
        ctx: &mut AdminContext,
        action: MultisigAction,
    ) -> anyhow::Result<BlockHash> {
        let payload = ctx.sign(&action);
        let tx = self.build_envelope_tx(action.tag(), payload).await?;
        self.submit_and_mine_tx(&tx).await
    }

    async fn submit_admin_action_with_seqno(
        &self,
        ctx: &AdminContext,
        action: MultisigAction,
        seqno: u64,
    ) -> anyhow::Result<BlockHash> {
        let tag = action.tag();
        let payload = ctx.sign_with_seqno(&action, seqno);
        let tx = self.build_envelope_tx(tag, payload).await?;
        self.submit_and_mine_tx(&tx).await
    }

    async fn submit_admin_action_as_role(
        &self,
        ctx: &mut AdminContext,
        action: MultisigAction,
        signing_role: Role,
    ) -> anyhow::Result<BlockHash> {
        let payload = ctx.sign_as_role(&action, signing_role);
        let tx = self.build_envelope_tx(action.tag(), payload).await?;
        self.submit_and_mine_tx(&tx).await
    }

    async fn submit_admin_action_as_role_with_seqno(
        &self,
        ctx: &AdminContext,
        action: MultisigAction,
        signing_role: Role,
        seqno: u64,
    ) -> anyhow::Result<BlockHash> {
        let tag = action.tag();
        let payload = ctx.sign_as_role_with_seqno(&action, signing_role, seqno);
        let tx = self.build_envelope_tx(tag, payload).await?;
        self.submit_and_mine_tx(&tx).await
    }

    async fn build_admin_action_tx(
        &self,
        ctx: &mut AdminContext,
        action: MultisigAction,
    ) -> anyhow::Result<Transaction> {
        let payload = ctx.sign(&action);
        self.build_envelope_tx(action.tag(), payload).await
    }
}
