use core::{fmt, mem::size_of};
use std::error::Error;

use strata_msg_fmt::TypeId;

/// Wire-format type IDs for ASM log entries (SPS-52).
///
/// `#[repr(u16)]` makes each discriminant a [`TypeId`]; convert with the
/// [`From`] impl or `as TypeId` in const context. The compiler rejects
/// duplicate discriminants, so uniqueness is enforced at build time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AsmLogTypeId {
    /// Tag for [`DepositLog`](crate::DepositLog).
    Deposit = 1,
    /// Tag for [`AsmStfUpdate`](crate::AsmStfUpdate).
    AsmStfUpdate = 5,
    /// Tag for [`NewExportEntry`](crate::NewExportEntry).
    NewExportEntry = 6,
    /// Tag for [`CheckpointTipUpdate`](crate::CheckpointTipUpdate).
    CheckpointTipUpdate = 7,
    /// Tag for [`EePredicateKeyUpdate`](crate::EePredicateKeyUpdate).
    EePredicateKeyUpdate = 8,
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
            5 => Ok(Self::AsmStfUpdate),
            6 => Ok(Self::NewExportEntry),
            7 => Ok(Self::CheckpointTipUpdate),
            8 => Ok(Self::EePredicateKeyUpdate),
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
            AsmLogTypeId::AsmStfUpdate,
            AsmLogTypeId::NewExportEntry,
            AsmLogTypeId::CheckpointTipUpdate,
            AsmLogTypeId::EePredicateKeyUpdate,
        ];
        for variant in all {
            let raw: TypeId = variant.into();
            assert_eq!(AsmLogTypeId::try_from(raw).unwrap(), variant);
        }
    }

    #[test]
    fn unknown_type_id_is_rejected() {
        for raw in [0u16, 2, 3, 4, 9, 999] {
            assert_eq!(AsmLogTypeId::try_from(raw), Err(UnknownLogTypeId(raw)));
        }
    }
}
