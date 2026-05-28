use core::mem::size_of;

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
