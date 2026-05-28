use core::{fmt, mem::size_of};
use std::error::Error;

use strata_msg_fmt::TypeId;

/// ASM log type IDs (SPS-52 wire tags).
///
/// This enum represents all valid log type tags emitted by ASM subprotocols.
/// Each variant corresponds to a specific log entry with its associated u16 value.
///
/// ## Tag ranges
/// - `1-10`: logs consumed by the OL.
/// - `11-20`: logs consumed by Moho.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AsmLogTypeId {
    /// Bridge mint instruction for the OL to credit the destination
    Deposit = 1,
    /// Forced inclusion - reserved wire tag;
    ForcedInclusion = 2,
    /// Verified checkpoint tip advance from the checkpoint subprotocol
    CheckpointTipUpdate = 3,
    /// Admin-driven rotation of a snark account's `update_vk`
    EePredicateKeyUpdate = 4,
    /// Admin-driven rotation of the ASM STF verification predicate
    AsmStfUpdate = 11,
    /// Subprotocol-published entry into the MohoState export MMR
    NewExportEntry = 12,
}

// Pin the enum's `#[repr(u16)]` width to `TypeId`. If they ever drift
// (e.g., `TypeId` becomes `u8` or `u32`), the `as TypeId` cast at every
// `AsmLog::TY` site would silently truncate or zero-extend — fail the
// build so the `#[repr(...)]` gets updated alongside it.
const _: () = assert!(size_of::<TypeId>() == size_of::<AsmLogTypeId>());

impl From<AsmLogTypeId> for TypeId {
    fn from(id: AsmLogTypeId) -> Self {
        // Lossless: the `size_of::<TypeId>() == size_of::<AsmLogTypeId>()`
        // assertion above guarantees the cast neither truncates nor extends.
        id as TypeId
    }
}

impl TryFrom<TypeId> for AsmLogTypeId {
    type Error = UnknownLogTypeId;

    fn try_from(value: TypeId) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Deposit),
            2 => Ok(Self::ForcedInclusion),
            3 => Ok(Self::CheckpointTipUpdate),
            4 => Ok(Self::EePredicateKeyUpdate),
            11 => Ok(Self::AsmStfUpdate),
            12 => Ok(Self::NewExportEntry),
            other => Err(UnknownLogTypeId(other)),
        }
    }
}

/// Returned by `TryFrom<TypeId> for AsmLogTypeId` when the value doesn't match
/// any known variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownLogTypeId(pub TypeId);

impl fmt::Display for UnknownLogTypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown ASM log type id: {}", self.0)
    }
}

impl Error for UnknownLogTypeId {}

#[cfg(test)]
mod tests {
    use super::*;

    // Guards against drift between the discriminants and the `TryFrom` match arms.
    #[test]
    fn type_id_roundtrip() {
        let all = [
            AsmLogTypeId::Deposit,
            AsmLogTypeId::ForcedInclusion,
            AsmLogTypeId::CheckpointTipUpdate,
            AsmLogTypeId::EePredicateKeyUpdate,
            AsmLogTypeId::AsmStfUpdate,
            AsmLogTypeId::NewExportEntry,
        ];
        for variant in all {
            let raw: TypeId = variant.into();
            assert_eq!(AsmLogTypeId::try_from(raw).unwrap(), variant);
        }
    }

    #[test]
    fn unknown_type_id_is_rejected() {
        // Gaps inside the OL range (5..=10), inside the Moho range (13..=20),
        // and outside both ranges should all reject.
        for raw in [0u16, 5, 9, 10, 13, 20, 999] {
            assert_eq!(AsmLogTypeId::try_from(raw), Err(UnknownLogTypeId(raw)));
        }
    }
}
