//! Identities carried by committed ASM state.

/// Identifies the ruleset that initialized or produced an anchor state.
///
/// Each ID fixes the anchor encoding and commitment contract for that ruleset.
/// Multiple IDs may share a representation. IDs are opaque: their numeric order
/// does not imply migration compatibility or authorize the next block's ruleset.
/// Adding this field changes SSZ bytes and roots; ID zero does not identify the
/// former unversioned encoding.
pub type SpecId = u16;

/// Identifies a payload schema within a particular subprotocol ID.
pub type SectionStateVersion = u16;
