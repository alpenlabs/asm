//! Semantic identity of an ASM specification.
//!
//! [`AsmSpecId`] names a set of consensus rules. It is deliberately *not* a
//! selector: nothing in the state transition consults it to decide what to do.
//! Each executable target — a guest ELF, or a natively compiled spec — is fixed
//! to exactly one specification at compile time, and the authenticated
//! predicate handover is what selects which target executes a block. The id
//! exists so that choice can be recorded, ordered, and reported.

use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Stable identifier of one ASM specification.
///
/// Variants are appended in upgrade order and never removed or renumbered: a
/// node replaying history resolves every specification the chain has ever run
/// under, so an old variant stays meaningful forever.
///
/// The discriminant is the stable identity used on the wire and in storage.
/// Do not derive it from a state codec version or from a predicate — those
/// version bytes and authorize proofs respectively, and neither tracks this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u16)]
#[serde(try_from = "u16", into = "u16")]
pub enum AsmSpecId {
    /// The rules of the initial release.
    V0 = 0,

    /// The first successor specification.
    V1 = 1,
}

impl AsmSpecId {
    /// Returns the stable numeric representation.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl From<AsmSpecId> for u16 {
    fn from(value: AsmSpecId) -> Self {
        value.as_u16()
    }
}

impl TryFrom<u16> for AsmSpecId {
    type Error = UnknownAsmSpecId;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            other => Err(UnknownAsmSpecId(other)),
        }
    }
}

impl BorshSerialize for AsmSpecId {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        BorshSerialize::serialize(&self.as_u16(), writer)
    }
}

impl BorshDeserialize for AsmSpecId {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        let raw = u16::deserialize_reader(reader)?;
        Self::try_from(raw).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

impl fmt::Display for AsmSpecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V0 => f.write_str("v0"),
            Self::V1 => f.write_str("v1"),
        }
    }
}

/// A numeric spec id this build has no variant for.
///
/// Reaching this means the software predates a specification the chain has
/// already run under, so it cannot execute those blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownAsmSpecId(pub u16);

impl fmt::Display for UnknownAsmSpecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown ASM spec id {}", self.0)
    }
}

impl Error for UnknownAsmSpecId {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The numeric discriminant is the stable identity; pinning it here catches
    /// an accidental reorder or renumber of existing variants.
    #[test]
    fn discriminants_are_stable() {
        assert_eq!(AsmSpecId::V0.as_u16(), 0);
        assert_eq!(AsmSpecId::V1.as_u16(), 1);
    }

    /// An id past the known set surfaces as an error carrying the raw value,
    /// so a caller can report exactly which specification it lacks.
    #[test]
    fn unknown_ids_carry_the_raw_value() {
        assert_eq!(AsmSpecId::try_from(0u16), Ok(AsmSpecId::V0));
        assert_eq!(AsmSpecId::try_from(2u16), Err(UnknownAsmSpecId(2)));
        assert_eq!(
            AsmSpecId::try_from(u16::MAX),
            Err(UnknownAsmSpecId(u16::MAX))
        );
    }

    /// The id travels over the status RPC, so its serialized form is the numeric
    /// discriminant — and an id this build has no variant for must fail to
    /// deserialize rather than decode to something plausible.
    #[test]
    fn serde_round_trips_as_the_numeric_id() {
        assert_eq!(serde_json::to_string(&AsmSpecId::V1).unwrap(), "1");
        assert_eq!(
            serde_json::from_str::<AsmSpecId>("0").unwrap(),
            AsmSpecId::V0
        );
        assert!(serde_json::from_str::<AsmSpecId>("2").is_err());
    }

    /// Durable proof-job records use the same stable u16 representation, not
    /// Borsh's default one-byte enum ordinal.
    #[test]
    fn borsh_round_trips_the_stable_u16_id() {
        assert_eq!(borsh::to_vec(&AsmSpecId::V1).unwrap(), [1, 0]);
        assert_eq!(
            borsh::from_slice::<AsmSpecId>(&[0, 0]).unwrap(),
            AsmSpecId::V0
        );
        assert!(borsh::from_slice::<AsmSpecId>(&[2, 0]).is_err());
    }
}
