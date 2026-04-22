use strata_asm_common::AsmLog;
use strata_asm_proto_checkpoint_types::CheckpointTip;
use strata_codec::Codec;
use strata_codec_utils::CodecSsz;
use strata_msg_fmt::TypeId;

use crate::constants::CHECKPOINT_TIP_UPDATE_LOG_TYPE;

/// Records a verified [`CheckpointTip`] update from the checkpoint subprotocol.
#[derive(Debug, Clone, Codec)]
pub struct CheckpointTipUpdate {
    /// The new verified checkpoint tip.
    tip: CodecSsz<CheckpointTip>,
}

impl CheckpointTipUpdate {
    /// Creates a new [`CheckpointTipUpdate`] from a [`CheckpointTip`].
    pub fn new(tip: CheckpointTip) -> Self {
        Self {
            tip: CodecSsz::new(tip),
        }
    }

    /// Returns a reference to the checkpoint tip.
    pub fn tip(&self) -> &CheckpointTip {
        self.tip.inner()
    }
}

impl AsmLog for CheckpointTipUpdate {
    const TY: TypeId = CHECKPOINT_TIP_UPDATE_LOG_TYPE;
}

#[cfg(test)]
mod tests {
    use strata_asm_proto_checkpoint_types::CheckpointTip;
    use strata_codec::{decode_buf_exact, encode_to_vec};
    use strata_identifiers::{Buf32, OLBlockCommitment, OLBlockId};

    use super::*;

    #[test]
    fn checkpoint_tip_update_roundtrip() {
        let l2_commitment = OLBlockCommitment::new(42, OLBlockId::from(Buf32::from([0xAB; 32])));
        let tip = CheckpointTip::new(7, 100, l2_commitment);
        let update = CheckpointTipUpdate::new(tip);

        let encoded = encode_to_vec(&update).expect("encoding should not fail");
        let decoded: CheckpointTipUpdate =
            decode_buf_exact(&encoded).expect("decoding should not fail");

        assert_eq!(decoded.tip().epoch, 7);
        assert_eq!(decoded.tip().l1_height, 100);
        assert_eq!(decoded.tip().l2_commitment(), update.tip().l2_commitment());
    }

    #[test]
    fn checkpoint_tip_update_type_id() {
        assert_eq!(
            CheckpointTipUpdate::TY,
            CHECKPOINT_TIP_UPDATE_LOG_TYPE,
            "type ID must match the constant"
        );
    }
}
