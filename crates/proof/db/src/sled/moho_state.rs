//! [`MohoStateDb`] implementation for [`SledProofDb`].

use moho_types::MohoState;
use ssz::{Decode, Encode};
use strata_identifiers::L1BlockCommitment;

use super::{SledProofDb, encode_moho_key};
use crate::MohoStateDb;

impl MohoStateDb for SledProofDb {
    type Error = sled::Error;

    async fn store_moho_state(
        &self,
        l1ref: L1BlockCommitment,
        state: MohoState,
    ) -> Result<(), Self::Error> {
        self.moho_states
            .insert(encode_moho_key(&l1ref), state.as_ssz_bytes())?;
        Ok(())
    }

    async fn get_moho_state(
        &self,
        l1ref: L1BlockCommitment,
    ) -> Result<Option<MohoState>, Self::Error> {
        Ok(self
            .moho_states
            .get(encode_moho_key(&l1ref))?
            .map(|v| MohoState::from_ssz_bytes(&v).expect("stored state should be valid SSZ")))
    }
}

#[cfg(test)]
mod tests {
    use moho_types::{ExportState, InnerStateCommitment, MohoState};
    use proptest::prelude::*;
    use strata_predicate::PredicateKey;
    use tokio::runtime::Runtime;

    use super::*;
    use crate::sled::test_util::*;

    /// Generates an arbitrary [`MohoState`].
    fn arb_moho_state() -> impl Strategy<Value = MohoState> {
        any::<[u8; 32]>().prop_map(|inner| {
            MohoState::new(
                InnerStateCommitment::from(inner),
                PredicateKey::always_accept(),
                ExportState::new(vec![]).unwrap(),
            )
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]

        /// Property: a stored Moho state can be retrieved with the same commitment key.
        #[test]
        fn moho_state_roundtrip(
            commitment in arb_l1_block_commitment(),
            state in arb_moho_state(),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                db.store_moho_state(commitment, state.clone()).await.unwrap();

                let retrieved = db.get_moho_state(commitment).await.unwrap();

                prop_assert_eq!(Some(state), retrieved);

                Ok(())
            })?;
        }

        /// Property: querying a commitment that was never stored returns `None`.
        #[test]
        fn get_missing_moho_state_returns_none(
            commitment in arb_l1_block_commitment(),
        ) {
            let (db, _dir) = temp_db();

            Runtime::new().unwrap().block_on(async {
                let result = db.get_moho_state(commitment).await.unwrap();

                prop_assert_eq!(result, None);

                Ok(())
            })?;
        }
    }
}
