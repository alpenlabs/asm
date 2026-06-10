use strata_asm_common::AsmLog;
use strata_codec::Codec;
use strata_codec_utils::CodecSsz;
use strata_msg_fmt::TypeId;

use crate::constants::AsmLogTypeId;

/// Details for an export state update event.
#[derive(Debug, Clone, Codec)]
pub struct NewExportEntry {
    /// Export container ID.
    container_id: u8,

    /// Export entry data.
    entry_data: CodecSsz<[u8; 32]>,
}

impl NewExportEntry {
    /// Create a new NewExportEntry instance.
    pub fn new(container_id: u8, entry_data: [u8; 32]) -> Self {
        Self {
            container_id,
            entry_data: CodecSsz::new(entry_data),
        }
    }

    pub fn container_id(&self) -> u8 {
        self.container_id
    }

    pub fn entry_data(&self) -> &[u8; 32] {
        self.entry_data.inner()
    }
}

impl AsmLog for NewExportEntry {
    const TY: TypeId = AsmLogTypeId::NewExportEntry as TypeId;
}

/// Update to an export container's `extra_data` field.
///
/// Unlike [`NewExportEntry`], which appends to a container's MMR, this overwrites the 32-byte
/// `extra_data` slot of the container identified by `container_id`.
#[derive(Debug, Clone, Codec)]
pub struct ExportExtraDataUpdate {
    /// Export container ID.
    container_id: u8,

    /// New value for the container's `extra_data` field.
    extra_data: CodecSsz<[u8; 32]>,
}

impl ExportExtraDataUpdate {
    /// Create a new ExportExtraDataUpdate instance.
    pub fn new(container_id: u8, extra_data: [u8; 32]) -> Self {
        Self {
            container_id,
            extra_data: CodecSsz::new(extra_data),
        }
    }

    pub fn container_id(&self) -> u8 {
        self.container_id
    }

    pub fn extra_data(&self) -> &[u8; 32] {
        self.extra_data.inner()
    }
}

impl AsmLog for ExportExtraDataUpdate {
    const TY: TypeId = AsmLogTypeId::ExportExtraDataUpdate as TypeId;
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use strata_asm_common::AsmLogEntry;

    use super::*;

    fn new_export_entry_strategy() -> impl Strategy<Value = NewExportEntry> {
        (any::<u8>(), any::<[u8; 32]>()).prop_map(|(id, data)| NewExportEntry::new(id, data))
    }

    fn extra_data_update_strategy() -> impl Strategy<Value = ExportExtraDataUpdate> {
        (any::<u8>(), any::<[u8; 32]>()).prop_map(|(id, data)| ExportExtraDataUpdate::new(id, data))
    }

    proptest! {
        #[test]
        fn from_log_is_infallible(log in new_export_entry_strategy()) {
            prop_assert!(AsmLogEntry::from_log(&log).is_ok());
        }

        #[test]
        fn extra_data_from_log_is_infallible(log in extra_data_update_strategy()) {
            prop_assert!(AsmLogEntry::from_log(&log).is_ok());
        }
    }

    #[test]
    fn from_log_boundary_cases() {
        let cases = [
            NewExportEntry::new(0, [0u8; 32]),
            NewExportEntry::new(u8::MAX, [0xFFu8; 32]),
        ];
        for log in cases {
            assert!(AsmLogEntry::from_log(&log).is_ok());
        }
    }
}
