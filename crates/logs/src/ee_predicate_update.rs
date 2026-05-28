use strata_asm_common::AsmLog;
use strata_codec::Codec;
use strata_codec_utils::CodecSsz;
use strata_identifiers::AccountSerial;
use strata_msg_fmt::TypeId;
use strata_predicate::PredicateKey;

use crate::constants::AsmLogTypeId;

/// Records an update to a snark account's `update_vk` (predicate key) used to
/// verify future updates to that account.
///
/// The target account is identified by its [`AccountSerial`]; the OL STF
/// resolves the serial and applies the new predicate key during manifest
/// processing.
#[derive(Debug, Clone, Codec)]
pub struct EePredicateKeyUpdate {
    /// Serial of the snark account whose predicate key is being updated.
    account: AccountSerial,

    /// New predicate key to install on the target account.
    new_predicate: CodecSsz<PredicateKey>,
}

impl EePredicateKeyUpdate {
    /// Creates a new [`EePredicateKeyUpdate`] for the given account serial and
    /// predicate key.
    pub fn new(account: AccountSerial, new_predicate: PredicateKey) -> Self {
        Self {
            account,
            new_predicate: CodecSsz::new(new_predicate),
        }
    }

    /// Returns the target account serial.
    pub fn account(&self) -> AccountSerial {
        self.account
    }

    /// Returns a reference to the new predicate key.
    pub fn new_predicate(&self) -> &PredicateKey {
        self.new_predicate.inner()
    }

    /// Consumes this log and returns the owned predicate key.
    pub fn into_new_predicate(self) -> PredicateKey {
        self.new_predicate.into_inner()
    }
}

impl AsmLog for EePredicateKeyUpdate {
    const TY: TypeId = AsmLogTypeId::EePredicateKeyUpdate as TypeId;
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use strata_asm_common::AsmLogEntry;
    use strata_codec::{decode_buf_exact, encode_to_vec};
    use strata_identifiers::{test_utils::account_serial_strategy, AccountSerial};
    use strata_predicate::{PredicateKey, PredicateTypeId, MAX_CONDITION_LEN};

    use super::*;

    // Local `PredicateKey` strategy — `strata_predicate::test_utils::predicate_key_strategy`
    // is `pub(crate)` upstream. Mirrors the one in `asm_stf.rs`.
    fn predicate_key_strategy() -> impl Strategy<Value = PredicateKey> {
        prop::collection::vec(any::<u8>(), 0..=MAX_CONDITION_LEN as usize)
            .prop_map(|c| PredicateKey::new(PredicateTypeId::AlwaysAccept, c))
    }

    fn ee_predicate_key_update_strategy() -> impl Strategy<Value = EePredicateKeyUpdate> {
        (account_serial_strategy(), predicate_key_strategy())
            .prop_map(|(account, key)| EePredicateKeyUpdate::new(account, key))
    }

    proptest! {
        #[test]
        fn from_log_is_infallible(log in ee_predicate_key_update_strategy()) {
            prop_assert!(AsmLogEntry::from_log(&log).is_ok());
        }
    }

    #[test]
    fn from_log_boundary_cases() {
        let cases = [
            EePredicateKeyUpdate::new(
                AccountSerial::new(0),
                PredicateKey::new(PredicateTypeId::AlwaysAccept, vec![]),
            ),
            EePredicateKeyUpdate::new(
                AccountSerial::new(u32::MAX),
                PredicateKey::new(
                    PredicateTypeId::AlwaysAccept,
                    vec![0u8; MAX_CONDITION_LEN as usize],
                ),
            ),
        ];
        for log in cases {
            assert!(AsmLogEntry::from_log(&log).is_ok());
        }
    }

    #[test]
    fn ee_predicate_key_update_roundtrip() {
        let account = AccountSerial::new(42);
        let new_predicate = PredicateKey::always_accept();
        let update = EePredicateKeyUpdate::new(account, new_predicate.clone());

        let encoded = encode_to_vec(&update).expect("encoding should not fail");
        let decoded: EePredicateKeyUpdate =
            decode_buf_exact(&encoded).expect("decoding should not fail");

        assert_eq!(decoded.account(), account);
        assert_eq!(decoded.new_predicate(), &new_predicate);
    }
}
