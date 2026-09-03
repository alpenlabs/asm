use std::sync::Arc;

use anyhow::Result;
use bitcoin::Network;
use bitcoind_async_client::{Auth, Client};
use strata_asm_moho_worker::MohoWorkerBuilder;
use strata_asm_params::StrataGenesisConfig;
use strata_asm_prover_types::MohoProofJobIdentity;
use strata_asm_prover_worker::{InputBuilder, ProofBackend, ProverWorkerBuilder};
use strata_asm_spec::{StrataAsmTarget, StrataAsmTargets, qualified_release_targets};
use strata_asm_worker::AsmWorkerBuilder;
use strata_predicate::PredicateKey;
use strata_tasks::TaskExecutor;
use tokio::{runtime::Handle, task};
use tracing::warn;

use crate::{
    bitcoin_client::RetryingBitcoinClient,
    block_watcher::drive_asm_from_bitcoin,
    config::{AsmRpcConfig, BitcoinConfig},
    moho_context::MohoWorkerContextImpl,
    prover_context::AsmProverContext,
    rpc_server::{AsmProofRpcDeps, run_rpc_server},
    storage::{
        AsmStorage, MohoStorage, create_asm_storage, create_moho_storage, create_proof_storage,
    },
    worker_context::AsmWorkerContext,
};
pub(crate) async fn bootstrap(
    config: AsmRpcConfig,
    params: StrataGenesisConfig,
    executor: TaskExecutor,
) -> Result<()> {
    // 1. Create storage. The ASM and Moho stores live in two separate sled DBs; the proof DB is
    //    opened with the orchestrator that owns it (step 3).
    let AsmStorage {
        state_db,
        aux_db,
        handover_db,
        manifest_db,
        mmr_db,
    } = create_asm_storage(&config.database.asm_path)?;
    let MohoStorage {
        state_db: moho_state_db,
        export_entries_db,
    } = create_moho_storage(&config.database.moho_path)?;

    // 2. Connect to Bitcoin node
    let bitcoin_client = Arc::new(RetryingBitcoinClient::new(
        connect_bitcoin(&config.bitcoin).await?,
        &config.bitcoin.retry_config,
    ));

    // 3. If the orchestrator is configured, open proof storage and build the proof backend up front
    //    so the Moho worker and orchestrator can receive the asm predicate.
    let runtime_handle = Handle::current();
    let orch_prep = if let Some(orch_config) = config.orchestrator {
        if orch_config.backend.is_unqualified_development()
            && params.anchor.network != Network::Regtest
        {
            anyhow::bail!(
                "the native-development proof backend is unqualified and may run only on regtest"
            );
        }
        let proof_db = create_proof_storage(&orch_config.proof_db_path)?;
        let backend = ProofBackend::new(&orch_config.backend).await?;
        Some((orch_config, proof_db, backend))
    } else {
        None
    };

    // 4. Create the ASM worker context. Moho state and the export-entries index are no longer
    //    materialized here; a dedicated Moho worker derives both from each ASM commit (step 7).
    //
    // The worker aligns the DB-side ASM manifest MMR with L1 heights during
    // startup (`ManifestMmrStore::prefill_manifest_mmr`), so no prefill is
    // needed here.
    let worker_context = AsmWorkerContext::new(
        runtime_handle.clone(),
        bitcoin_client.clone(),
        state_db.clone(),
        aux_db.clone(),
        handover_db.clone(),
        manifest_db.clone(),
        mmr_db.clone(),
    );

    // 5. Launch ASM worker.
    //
    // `launch` builds the worker state synchronously, and that now includes validating the
    // anchor against L1 — which drives blocking `WorkerContext` RPC calls (`block_on`). We are
    // on a runtime worker thread here, so wrap the build in `block_in_place` to allow blocking;
    // the worker's own loop runs on a dedicated sync thread where blocking is already fine.
    // Genesis is built and validated here, where the params live; the worker
    // receives a validated bootstrap and never sees params.
    //
    // The predicate the chain starts under. Every later predicate is carried or
    // enacted by the blocks themselves, so this is the only one a node has to be
    // told — or, where it is unambiguous, to work out.
    let backend = orch_prep.as_ref().map(|(_, _, backend)| backend);
    let genesis = resolve_genesis_predicate(
        params.genesis_asm_predicate.as_ref(),
        backend,
        params.anchor.network == Network::Regtest,
    )?;

    let targets = build_targets(backend, &genesis)?;
    let genesis_predicate = genesis.predicate;

    // Which rules the chain *launched* under is not a separate fact to configure:
    // it is whatever the genesis predicate selects. Getting this wrong would
    // matter only for a node syncing from genesis with an empty database — and it
    // would matter completely, because the genesis state it built would not be
    // the state the chain committed to.
    let bootstrap = Arc::new(build_genesis_bootstrap(
        &targets,
        &genesis_predicate,
        &params,
    )?);

    let asm_worker = task::block_in_place(|| {
        AsmWorkerBuilder::new()
            .with_context(worker_context)
            .with_targets(targets)
            .with_genesis_predicate(genesis_predicate.clone())
            .with_bootstrap(bootstrap)
            .launch(&executor)
    })?;

    let asm_worker = Arc::new(asm_worker);

    // 6. Finish orchestrator wiring if it was configured.
    let proof_rpc_deps = if let Some((orch_config, proof_db, backend)) = orch_prep {
        let ProofBackend {
            asm,
            moho_host,
            moho_predicate,
            moho_artifact_id,
        } = backend;
        let moho_identity = MohoProofJobIdentity {
            predicate: moho_predicate.clone(),
            artifact_id: moho_artifact_id,
        };

        // Spin the Moho worker off onto its own service task, driven by the ASM
        // worker's per-block commit stream. It derives each block's MohoState
        // (and the export-entry leaves its ExportState MMR commits to) from the
        // anchor state the ASM worker committed, and persists both to the same
        // stores the orchestrator and RPC read. Subscribe before the block
        // watcher is spawned (step 7): the subscription has no replay, so a later
        // subscriber would miss already-committed blocks. The genesis Moho state
        // is seeded from the ASM genesis anchor during launch.
        let moho_context = MohoWorkerContextImpl::new(
            runtime_handle.clone(),
            bitcoin_client.clone(),
            state_db.clone(),
            manifest_db.clone(),
            moho_state_db.clone(),
            export_entries_db.clone(),
        );
        let moho_worker = MohoWorkerBuilder::new()
            .with_context(moho_context)
            .with_subscription(asm_worker.subscribe_blocks())
            .with_genesis_block(params.anchor.block)
            // The same value the ASM worker was seeded with, so the two cannot
            // start the chain on different rules.
            .with_asm_predicate(genesis_predicate.clone())
            .launch(&executor)
            .await?;

        // The prover context wires the proof store, moho-state store, ASM
        // anchor-state store, aux-data store, and Bitcoin client into the
        // worker's traits. Clone the two stores the RPC handlers also read from
        // before the context takes ownership.
        let rpc_proof_db = proof_db.clone();
        let rpc_moho_state_db = moho_state_db.clone();
        let prover_ctx = AsmProverContext::new(
            proof_db,
            moho_state_db,
            state_db.clone(),
            aux_db.clone(),
            bitcoin_client.clone(),
        );
        let input_builder = InputBuilder::new(params.anchor.block, moho_predicate);

        // Drive the prover from the *Moho* worker's commit stream, not the ASM
        // worker's: the Moho worker emits a block only after it has persisted
        // that block's MohoState, so any block the prover sees here already has
        // its MohoState available for proof-input assembly. This serializes the
        // ASM → Moho → prover chain and removes the race that existed when the
        // prover and the Moho worker subscribed to the ASM stream independently.
        //
        // Subscribe before the block watcher (spawned below) starts feeding the
        // ASM worker. The stream has no replay buffer, but commits only flow once
        // the watcher hands the ASM worker blocks, so subscribing here misses
        // nothing.
        let block_subscription = moho_worker.subscribe_blocks();

        let prover_handle = ProverWorkerBuilder::new()
            .with_context(prover_ctx)
            .with_hosts(asm, moho_host, moho_identity)
            .with_config(orch_config)
            .with_input_builder(input_builder)
            .with_block_subscription(block_subscription)
            .launch(&executor)
            .await?;

        Some(AsmProofRpcDeps {
            proof_db: rpc_proof_db,
            prover_handle: Arc::new(prover_handle),
            moho_state_db: rpc_moho_state_db,
            export_entries_db,
        })
    } else {
        None
    };

    // 7. Spawn block watcher as a critical task.
    let asm_worker_for_driver = asm_worker.clone();
    let bitcoin_config = config.bitcoin.clone();
    let bitcoin_client_for_driver = bitcoin_client.clone();
    executor.spawn_critical_async_with_shutdown("block_watcher", move |shutdown| {
        drive_asm_from_bitcoin(
            bitcoin_config,
            bitcoin_client_for_driver,
            asm_worker_for_driver,
            shutdown,
        )
    });

    // 8. Spawn RPC server as a critical task
    let rpc_host = config.rpc.host.clone();
    let rpc_port = config.rpc.port;
    executor.spawn_critical_async_with_shutdown("rpc_server", move |shutdown| {
        run_rpc_server(
            state_db,
            manifest_db,
            asm_worker,
            bitcoin_client,
            params,
            proof_rpc_deps,
            rpc_host,
            rpc_port,
            shutdown,
        )
    });

    Ok(())
}

/// Builds the genesis state for the specification the chain launched under.
///
/// The launch specification is read off the genesis predicate rather than
/// configured separately: a predicate selects rules, and the genesis predicate
/// selects the rules block one ran under. Two facts kept in agreement would be
/// one fact too many.
///
/// This only takes effect on a node whose database is empty — a node that resumes
/// adopts its stored anchor instead. That makes it easy to get away with being
/// wrong here for a long time, and then wrong in the worst place: a fresh node
/// syncing a chain that launched under the released rules would build a genesis
/// state the chain never committed to, and diverge from block one.
fn build_genesis_bootstrap(
    targets: &StrataAsmTargets,
    genesis_predicate: &PredicateKey,
    params: &StrataGenesisConfig,
) -> Result<strata_asm_common::AsmBootstrap> {
    let target = targets.resolve(genesis_predicate).ok_or_else(|| {
        anyhow::anyhow!(
            "this build binds no rules to the chain's genesis predicate \
             ({genesis_predicate:?}), so it cannot construct the chain's genesis state"
        )
    })?;

    Ok(match target {
        StrataAsmTarget::V0 => strata_asm_spec::build_v0_bootstrap(params)?,
        StrataAsmTarget::V1 => strata_asm_spec::build_v1_bootstrap(params)?,
    })
}

/// Resolves the predicate the chain started under.
///
/// Params pin it where it matters. Where they do not, a node with exactly one ASM
/// artifact can only have started under that artifact's predicate, so it is
/// derived — which is what keeps a plain single-specification deployment from
/// having to restate a verifying key by hand.
///
/// Ambiguity is refused rather than guessed: a node carrying artifacts for both
/// sides of an upgrade boundary has two candidates and no way to tell which the
/// chain launched under. Guessing there would put the node on the wrong rules
/// from block one. A runner with neither fact may use `AlwaysAccept` only on
/// regtest, where it is explicitly an unproven development chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenesisPredicateOrigin {
    /// The chain configuration pins this historical fact explicitly.
    Configured,
    /// A single proving artifact makes the predicate unambiguous.
    Artifact,
    /// No chain predicate or artifact exists; use the unproven development sentinel.
    DevelopmentDefault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedGenesisPredicate {
    predicate: PredicateKey,
    origin: GenesisPredicateOrigin,
}

fn resolve_genesis_predicate(
    configured: Option<&PredicateKey>,
    backend: Option<&ProofBackend>,
    allow_unproven_development: bool,
) -> Result<ResolvedGenesisPredicate> {
    if let Some(pinned) = configured {
        return Ok(ResolvedGenesisPredicate {
            predicate: pinned.clone(),
            origin: GenesisPredicateOrigin::Configured,
        });
    }

    let Some(backend) = backend else {
        if !allow_unproven_development {
            anyhow::bail!(
                "params omit `genesis_asm_predicate` and no prover is configured; the \
                 always-accept development fallback is allowed only on regtest"
            );
        }
        warn!(
            "params omit `genesis_asm_predicate` and no prover is configured; falling back to the \
             always-accept predicate. This is the unproven development default, not a production \
             binding."
        );
        return Ok(ResolvedGenesisPredicate {
            predicate: PredicateKey::always_accept(),
            origin: GenesisPredicateOrigin::DevelopmentDefault,
        });
    };

    let mut bindings = backend.asm.bindings();
    let (predicate, _) = bindings
        .next()
        .expect("an artifact set is non-empty by construction");

    if bindings.next().is_some() {
        anyhow::bail!(
            "params omit `genesis_asm_predicate` and this node loads more than one ASM guest \
             artifact, so which rules the chain started under is ambiguous; pin it in params"
        );
    }

    Ok(ResolvedGenesisPredicate {
        predicate: predicate.clone(),
        origin: GenesisPredicateOrigin::Artifact,
    })
}

/// Builds the predicate-to-specification table this node executes with.
///
/// # Where the bindings come from
///
/// A proving node derives them from the artifacts it actually loaded. The
/// backend config names only an immutable artifact id and local ELF/VK paths;
/// the release manifest supplies the artifact's predicate and semantic
/// specification. Startup hashes both files, decodes the VK, derives the ELF's
/// predicate, and refuses any disagreement before these bindings reach the
/// worker.
///
/// It then checks the one thing derivation cannot establish: that the chain's
/// genesis predicate resolves. A prover whose artifacts do not include the rules
/// the chain started under cannot prove the chain's own history, and refusing to
/// start says so at the point where it is cheap to fix.
///
/// A node that does not prove has no artifacts and therefore nothing to derive
/// from; the ASM worker deliberately carries no proving stack. For a configured
/// chain predicate it uses the release-qualified table compiled into
/// `strata-asm-spec`. That table currently binds the published baseline artifact,
/// so a non-proving node replays existing L1 history under baseline rules and
/// halts on an unqualified successor instead of guessing. Release qualification
/// appends the successor binding before this release may follow the boundary.
///
/// Omitting the genesis predicate and the prover remains an explicit unproven
/// development mode. Its `AlwaysAccept` sentinel maps to current rules so the
/// local single-specification environment remains usable; no configured
/// production predicate ever takes that fallback.
fn build_targets(
    backend: Option<&ProofBackend>,
    genesis: &ResolvedGenesisPredicate,
) -> Result<StrataAsmTargets> {
    let Some(backend) = backend else {
        return match genesis.origin {
            GenesisPredicateOrigin::DevelopmentDefault => {
                warn!(
                    "no prover or configured genesis predicate; running the unproven development \
                     target under successor rules"
                );
                Ok(StrataAsmTargets::new(vec![(
                    genesis.predicate.clone(),
                    StrataAsmTarget::V1,
                )])?)
            }
            GenesisPredicateOrigin::Configured => {
                let targets = qualified_release_targets()?;
                if targets.resolve(&genesis.predicate).is_none() {
                    anyhow::bail!(
                        "configured genesis ASM predicate ({:?}) is not bound by this release; \
                         refusing to guess which rules execute the chain's history",
                        genesis.predicate,
                    );
                }
                warn!(
                    "no prover configured; using the release-qualified execution table and \
                     halting on any enacted predicate this release does not bind"
                );
                Ok(targets)
            }
            GenesisPredicateOrigin::Artifact => anyhow::bail!(
                "internal error: an artifact-derived genesis predicate has no proof backend"
            ),
        };
    };

    let bindings = backend
        .asm
        .bindings()
        .map(|(predicate, spec_id)| (predicate.clone(), StrataAsmTarget::for_spec_id(spec_id)))
        .collect::<Vec<_>>();

    let targets = StrataAsmTargets::new(bindings)?;

    if targets.resolve(&genesis.predicate).is_none() {
        anyhow::bail!(
            "no ASM guest artifact implements the rules this chain started under \
             (genesis predicate {:?}); the configured artifacts cannot prove the chain's own \
             history",
            genesis.predicate,
        );
    }

    Ok(targets)
}

/// Connect to Bitcoin node.
///
/// All three `Option` parameters are passed as `None` so
/// `bitcoind-async-client` applies its own defaults for `max_retries`,
/// `retry_interval`, and `timeout`. See [`BitcoinConfig::retry_config`]
/// for how this inner layer composes with the outer retry wrapper.
async fn connect_bitcoin(config: &BitcoinConfig) -> Result<Client> {
    let client = Client::new(
        config.rpc_url.clone(),
        Auth::UserPass(config.rpc_user.clone(), config.rpc_password.clone()),
        None,
        None,
        None,
    )?;

    Ok(client)
}

#[cfg(test)]
mod tests {
    use strata_asm_common::AsmSpecId;
    use strata_predicate::PredicateTypeId;

    use super::*;

    #[test]
    fn non_proving_release_maps_the_published_genesis_predicate_to_baseline_rules() {
        let release = qualified_release_targets().expect("release table is valid");
        let baseline_predicate = release.entries()[0].0.clone();
        let genesis = ResolvedGenesisPredicate {
            predicate: baseline_predicate.clone(),
            origin: GenesisPredicateOrigin::Configured,
        };

        let targets = build_targets(None, &genesis).expect("baseline release is executable");
        assert_eq!(
            targets.resolve(&baseline_predicate),
            Some(StrataAsmTarget::V0),
        );
        assert_eq!(
            targets
                .resolve(&baseline_predicate)
                .map(|target| target.spec_id()),
            Some(AsmSpecId::V0),
        );
    }

    #[test]
    fn non_proving_release_rejects_an_unbound_configured_genesis_predicate() {
        let unknown = PredicateKey::try_new(PredicateTypeId::Sp1Groth16, vec![0xff; 32])
            .expect("valid test predicate");
        let genesis = ResolvedGenesisPredicate {
            predicate: unknown,
            origin: GenesisPredicateOrigin::Configured,
        };

        let error = build_targets(None, &genesis)
            .expect_err("an unknown production predicate must not select fallback rules");
        assert!(
            error.to_string().contains("refusing to guess"),
            "unexpected error: {error:#}",
        );
    }

    #[test]
    fn omitted_unproven_genesis_keeps_the_explicit_development_default() {
        let genesis =
            resolve_genesis_predicate(None, None, true).expect("development default resolves");
        assert_eq!(genesis.origin, GenesisPredicateOrigin::DevelopmentDefault);
        assert_eq!(genesis.predicate, PredicateKey::always_accept());

        let targets = build_targets(None, &genesis).expect("development target is executable");
        assert_eq!(
            targets.resolve(&genesis.predicate),
            Some(StrataAsmTarget::V1),
        );
    }

    #[test]
    fn omitted_unproven_genesis_is_rejected_outside_development() {
        let error = resolve_genesis_predicate(None, None, false)
            .expect_err("a production chain must pin its genesis predicate");
        assert!(
            error.to_string().contains("allowed only on regtest"),
            "unexpected error: {error:#}",
        );
    }
}
