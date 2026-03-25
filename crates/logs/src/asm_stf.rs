use strata_asm_common::AsmLog;
use strata_codec::{Codec, CodecError, Decoder, Encoder};
use strata_codec_utils::CodecSsz;
use strata_msg_fmt::TypeId;
use strata_predicate::PredicateKey;

use crate::constants::ASM_STF_UPDATE_LOG_TYPE;

/// Details for an execution environment verification key update.
#[derive(Debug, Clone)]
pub struct AsmStfUpdate {
    /// New execution environment state transition function verification key.
    new_predicate: PredicateKey,
}

impl AsmStfUpdate {
    /// Create a new AsmStfUpdate instance.
    pub fn new(new_predicate: PredicateKey) -> Self {
        Self { new_predicate }
    }

    pub fn new_predicate(&self) -> &PredicateKey {
        &self.new_predicate
    }

    pub fn into_new_predicate(self) -> PredicateKey {
        self.new_predicate
    }
}

impl Codec for AsmStfUpdate {
    fn decode(dec: &mut impl Decoder) -> Result<Self, CodecError> {
        let new_predicate = CodecSsz::<PredicateKey>::decode(dec)?.into_inner();
        Ok(Self { new_predicate })
    }

    fn encode(&self, enc: &mut impl Encoder) -> Result<(), CodecError> {
        CodecSsz::new(self.new_predicate.clone()).encode(enc)
    }
}

impl AsmLog for AsmStfUpdate {
    const TY: TypeId = ASM_STF_UPDATE_LOG_TYPE;
}
