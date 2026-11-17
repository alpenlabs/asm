use crate::errors::UpdateValidationError;

/// Checks an update's contents beyond what decoding enforces.
///
/// Implemented by every update type. Most have nothing to check and keep the default.
pub(crate) trait ValidateUpdate {
    /// Returns an error if the update could never take effect as intended.
    fn validate(&self) -> Result<(), UpdateValidationError> {
        Ok(())
    }
}
