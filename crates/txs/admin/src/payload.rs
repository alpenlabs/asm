use ssz_derive::{Decode as DeriveDecode, Encode as DeriveEncode};
use strata_crypto::{keys::compressed::CompressedPublicKey, threshold_signature::SignatureSet};
use strata_identifiers::Buf32;
use strata_predicate::PredicateKey;

use crate::actions::UpdateId;

/// Wire payload for [`crate::constants::AdminTxType::Cancel`].
#[derive(Clone, Debug, Eq, PartialEq, DeriveEncode, DeriveDecode)]
pub(crate) struct CancelPayload {
    pub(crate) seqno: u64,
    pub(crate) target_id: UpdateId,
    pub(crate) signatures: SignatureSet,
}

/// Wire payload for [`crate::constants::AdminTxType::StrataAdminMultisigUpdate`] and
/// [`crate::constants::AdminTxType::StrataSeqManagerMultisigUpdate`].
#[derive(Clone, Debug, Eq, PartialEq, DeriveEncode, DeriveDecode)]
pub(crate) struct MultisigUpdatePayload {
    pub(crate) seqno: u64,
    pub(crate) add_members: Vec<CompressedPublicKey>,
    pub(crate) remove_members: Vec<CompressedPublicKey>,
    pub(crate) new_threshold: u8,
    pub(crate) signatures: SignatureSet,
}

/// Wire payload for [`crate::constants::AdminTxType::OperatorUpdate`].
#[derive(Clone, Debug, Eq, PartialEq, DeriveEncode, DeriveDecode)]
pub(crate) struct OperatorUpdatePayload {
    pub(crate) seqno: u64,
    pub(crate) add_members: Vec<Buf32>,
    pub(crate) remove_members: Vec<Buf32>,
    pub(crate) signatures: SignatureSet,
}

/// Wire payload for [`crate::constants::AdminTxType::SequencerUpdate`].
#[derive(Clone, Debug, Eq, PartialEq, DeriveEncode, DeriveDecode)]
pub(crate) struct SequencerUpdatePayload {
    pub(crate) seqno: u64,
    pub(crate) pub_key: Buf32,
    pub(crate) signatures: SignatureSet,
}

/// Wire payload for [`crate::constants::AdminTxType::OlStfVkUpdate`] and
/// [`crate::constants::AdminTxType::AsmStfVkUpdate`].
#[derive(Clone, Debug, Eq, PartialEq, DeriveEncode, DeriveDecode)]
pub(crate) struct PredicateUpdatePayload {
    pub(crate) seqno: u64,
    pub(crate) key: PredicateKey,
    pub(crate) signatures: SignatureSet,
}
