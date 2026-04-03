use arbitrary::Arbitrary;
use bitvec::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use ssz::{Decode as SszDecode, DecodeError, Encode as SszEncode};
use ssz_derive::{Decode, Encode};
use thiserror::Error;

/// The ID of an operator.
///
/// We define it as a type alias over [`u32`] instead of a newtype because we perform a bunch of
/// mathematical operations on it while managing the operator table.
pub type OperatorIdx = u32;

/// Sentinel value representing "no specific operator selected."
const NO_SELECTION_SENTINEL: u32 = u32::MAX;

/// Encapsulates the user's operator selection for a withdrawal assignment.
///
/// Wraps a [`u32`] where [`u32::MAX`] means "any operator" (random assignment)
/// and any other value is a specific [`OperatorIdx`].
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
    Arbitrary,
    Encode,
    Decode,
)]
pub struct OperatorSelection(u32);

impl OperatorSelection {
    /// Creates a selection meaning "assign to any eligible operator."
    pub fn any() -> Self {
        Self(NO_SELECTION_SENTINEL)
    }

    /// Creates a selection for a specific operator index.
    ///
    /// # Panics
    ///
    /// Panics if `idx` equals [`u32::MAX`], which is reserved as the "any" sentinel.
    pub fn specific(idx: OperatorIdx) -> Self {
        assert_ne!(
            idx, NO_SELECTION_SENTINEL,
            "u32::MAX is reserved for the 'any' sentinel"
        );
        Self(idx)
    }

    /// Returns the specific operator index, or [`None`] if this is an "any" selection.
    pub fn as_specific(&self) -> Option<OperatorIdx> {
        (self.0 != NO_SELECTION_SENTINEL).then_some(self.0)
    }

    /// Returns the raw [`u32`] representation.
    pub fn raw(self) -> u32 {
        self.0
    }

    /// Constructs from a raw [`u32`], as decoded from the wire.
    pub fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
}

/// Error type for OperatorBitmap operations.
#[derive(Debug, Error, PartialEq)]
pub enum OperatorBitmapError {
    /// Attempted to set a bit at an index that would create a gap in the bitmap.
    /// Only sequential indices are allowed.
    #[error(
        "Index {index} is out of bounds for sequential bitmap (valid range: 0..={max_valid_index})"
    )]
    IndexOutOfBounds {
        index: OperatorIdx,
        max_valid_index: OperatorIdx,
    },

    /// Notary operators and previous assignees bitmaps have mismatched lengths.
    #[error(
        "Notary operators length ({notary_len}) does not match previous assignees length ({previous_len})"
    )]
    MismatchedBitmapLengths {
        notary_len: usize,
        previous_len: usize,
    },

    /// Current active operators bitmap is shorter than notary operators bitmap.
    /// This indicates a system inconsistency since operator indices are only appended.
    #[error(
        "Current active operators bitmap length ({active_len}) is shorter than notary operators length ({notary_len}). This should never happen as operator bitmaps only grow."
    )]
    InsufficientActiveBitmapLength {
        active_len: usize,
        notary_len: usize,
    },
}

/// Memory-efficient bitmap for tracking active operators in a multisig set.
///
/// This structure provides a compact representation of which operators are active
/// in a specific context (e.g., current multisig, deposit notary set). Uses a
/// dynamic `BitVec` to efficiently handle arbitrary operator index ranges while
/// minimizing memory usage compared to storing operator indices in a `Vec`.
///
/// # Use Cases
///
/// - **Operator Table**: Track which operators are in the current N/N multisig
/// - **Deposit Entries**: Store historical notary operators for each deposit
/// - **Assignment Creation**: Efficiently select operators for new tasks
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperatorBitmap {
    /// Bitmap where bit `i` is set if operator index `i` is active.
    /// Uses `BitVec<u8>` for dynamic sizing and memory efficiency.
    bits: BitVec<u8>,
}

#[derive(Debug, Encode, Decode)]
struct OperatorBitmapSsz {
    bit_len: u32,
    bytes: Vec<u8>,
}

impl From<&OperatorBitmap> for OperatorBitmapSsz {
    fn from(value: &OperatorBitmap) -> Self {
        Self {
            bit_len: value.bits.len() as u32,
            bytes: value.bits.as_raw_slice().to_vec(),
        }
    }
}

impl TryFrom<OperatorBitmapSsz> for OperatorBitmap {
    type Error = DecodeError;

    fn try_from(value: OperatorBitmapSsz) -> Result<Self, Self::Error> {
        let mut bits = BitVec::from_vec(value.bytes);
        if value.bit_len as usize > bits.len() {
            return Err(DecodeError::BytesInvalid(
                "operator bitmap bit length exceeds byte payload".into(),
            ));
        }
        bits.truncate(value.bit_len as usize);
        Ok(Self { bits })
    }
}

impl SszEncode for OperatorBitmap {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        OperatorBitmapSsz::from(self).ssz_append(buf);
    }

    fn ssz_bytes_len(&self) -> usize {
        OperatorBitmapSsz::from(self).ssz_bytes_len()
    }
}

impl SszDecode for OperatorBitmap {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        OperatorBitmapSsz::from_ssz_bytes(bytes)?.try_into()
    }
}

impl OperatorBitmap {
    /// Creates a new empty operator bitmap.
    pub fn new_empty() -> Self {
        Self {
            bits: BitVec::new(),
        }
    }

    /// Creates a new operator bitmap with specified size and initial state.
    ///
    /// This is optimized for creating bitmaps with all bits set to the same initial value.
    /// Common use cases include creating cleared bitmaps for tracking previous assignees
    /// or active bitmaps for sequential operators.
    ///
    /// # Parameters
    ///
    /// - `size` - Number of bits in the bitmap
    /// - `initial_state` - Initial state for all bits (true = active, false = inactive)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Create a bitmap with 5 operators all inactive (for tracking previous assignees)
    /// let cleared = OperatorBitmap::new_with_size(5, false);
    ///
    /// // Create a bitmap with 3 operators all active (for sequential operators 0, 1, 2)
    /// let active = OperatorBitmap::new_with_size(3, true);
    /// ```
    pub fn new_with_size(size: usize, initial_state: bool) -> Self {
        Self {
            bits: BitVec::repeat(initial_state, size),
        }
    }

    /// Returns whether the operator at the given index is active.
    ///
    /// # Parameters
    ///
    /// - `idx` - Operator index to check
    ///
    /// # Returns
    ///
    /// `true` if the operator is active, `false` if not active or index out of bounds
    pub fn is_active(&self, idx: OperatorIdx) -> bool {
        self.bits.get(idx as usize).map(|b| *b).unwrap_or(false)
    }

    /// Attempts to set the active state of an operator.
    ///
    /// The bitmap maintains sequential indices and only allows extending its size by exactly 1
    /// position at a time. If the index equals the current length, the bitmap is extended by 1.
    /// Indices that would skip positions (greater than current length) are rejected.
    ///
    /// # Parameters
    ///
    /// - `idx` - Operator index to update
    /// - `active` - Whether the operator should be active
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, `Err(BitmapError)` if index would create a gap in the bitmap
    ///
    /// # Index Overflow
    ///
    /// **WARNING**: Since `OperatorIdx` is `u32`, this method cannot handle indices beyond
    /// `u32::MAX` (4,294,967,295). This limits the total number of unique operators that can
    /// ever be registered over the bridge's lifetime.
    pub fn try_set(&mut self, idx: OperatorIdx, active: bool) -> Result<(), OperatorBitmapError> {
        let idx_usize = idx as usize;
        // Only allow increasing bitmap size by 1 at a time to maintain sequential indices
        if idx_usize > self.bits.len() {
            return Err(OperatorBitmapError::IndexOutOfBounds {
                index: idx,
                max_valid_index: self.bits.len() as OperatorIdx,
            });
        }
        if idx_usize == self.bits.len() {
            self.bits.resize(idx_usize + 1, false);
        }
        self.bits.set(idx_usize, active);
        Ok(())
    }

    /// Returns an iterator over all active operator indices.
    ///
    /// # Index Overflow
    ///
    /// **WARNING**: This method casts internal bit positions (`usize`) to `OperatorIdx` (`u32`).
    /// If the bitmap contains indices beyond `u32::MAX`, this cast will truncate/wrap the values,
    /// producing incorrect results. In practice, this is constrained by the system's operator
    /// registration limit of `u32::MAX` unique operators.
    pub fn active_indices(&self) -> impl Iterator<Item = OperatorIdx> + '_ {
        self.bits.iter_ones().map(|i| i as OperatorIdx)
    }

    /// Returns the number of active operators.
    pub fn active_count(&self) -> usize {
        self.bits.count_ones()
    }

    /// Returns the number of inactive operators.
    pub fn inactive_count(&self) -> usize {
        self.bits.count_zeros()
    }

    /// Returns the number of bits in the bitmap.
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Returns `true` if the bitmap contains no bits.
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }
}

impl From<BitVec<u8>> for OperatorBitmap {
    fn from(bits: BitVec<u8>) -> Self {
        Self { bits }
    }
}

impl<'a> Arbitrary<'a> for OperatorBitmap {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate a random number of operators between 2 and 20
        let num_operators = u.int_in_range(2..=20)?;

        // Create a random bitmap by generating random bits for each operator
        let mut bits = BitVec::with_capacity(num_operators);
        for _ in 0..num_operators {
            let bit = u.int_in_range(0..=1)? == 1;
            bits.push(bit);
        }

        Ok(OperatorBitmap::from(bits))
    }
}

/// Filters and returns eligible operators for assignment or reassignment.
///
/// Returns a bitmap of operators who meet all eligibility criteria:
/// - Must be part of the deposit's notary operator set
/// - Must not have previously been assigned to this withdrawal (prevents reassignment to failed
///   operators)
/// - Must be currently active in the network
///
/// # Parameters
///
/// - `notary_operators` - Bitmap of notary operators authorized for this deposit
/// - `previous_assignees` - Bitmap of operators who have previously been assigned but failed
/// - `current_active_operators` - Bitmap of operators currently active in the network
///
/// # Returns
///
/// `Result<OperatorBitmap, WithdrawalAssignmentError>` - Either the filtered bitmap of eligible
/// operators, or an error if the input bitmaps have incompatible lengths.
///
/// # Errors
///
/// - [`WithdrawalAssignmentError::MismatchedBitmapLengths`] - If notary_operators and
///   previous_assignees have different lengths
/// - [`WithdrawalAssignmentError::InsufficientActiveBitmapLength`] - If current_active_operators is
///   shorter than notary_operators
pub fn filter_eligible_operators(
    notary_operators: &OperatorBitmap,
    previous_assignees: &OperatorBitmap,
    current_active_operators: &OperatorBitmap,
) -> Result<OperatorBitmap, OperatorBitmapError> {
    // Notary operators and previous assignees must have the same length to ensure
    // bitwise operations don't panic
    if notary_operators.len() != previous_assignees.len() {
        return Err(OperatorBitmapError::MismatchedBitmapLengths {
            notary_len: notary_operators.len(),
            previous_len: previous_assignees.len(),
        });
    }

    // If current_active_operators is shorter, this indicates a system inconsistency
    // since we only append operator indices to bitmaps, never remove them.
    // We also need to ensure sufficient length to avoid panics during bitwise operations.
    if current_active_operators.len() < notary_operators.len() {
        return Err(OperatorBitmapError::InsufficientActiveBitmapLength {
            active_len: current_active_operators.len(),
            notary_len: notary_operators.len(),
        });
    }

    let notary_len = notary_operators.len();

    // Clone and truncate current_active_operators to match notary length
    let mut active_truncated = current_active_operators.bits.clone();
    active_truncated.truncate(notary_len);

    // In-place operations: active = (notary & !previous) & active
    active_truncated &= &notary_operators.bits;
    active_truncated &= &!previous_assignees.bits.clone();

    Ok(active_truncated.into())
}

#[cfg(test)]
mod tests {
    use ssz::{Decode, Encode};
    use strata_test_utils_arb::ArbitraryGenerator;

    use super::*;

    #[test]
    fn test_operator_bitmap_new_empty() {
        let bitmap = OperatorBitmap::new_empty();
        assert!(bitmap.is_empty());
        assert_eq!(bitmap.active_count(), 0);
        assert_eq!(bitmap.active_indices().count(), 0);
    }

    #[test]
    fn test_operator_bitmap_new_with_size() {
        // Test creating cleared bitmap
        let cleared_bitmap = OperatorBitmap::new_with_size(5, false);
        assert!(!cleared_bitmap.is_empty());
        assert_eq!(cleared_bitmap.len(), 5);
        assert_eq!(cleared_bitmap.active_count(), 0);
        assert_eq!(cleared_bitmap.active_indices().count(), 0);

        // Check individual bits are all false
        for i in 0..5 {
            assert!(!cleared_bitmap.is_active(i));
        }
        assert!(!cleared_bitmap.is_active(5)); // Out of bounds should be false

        // Test creating active bitmap
        let active_bitmap = OperatorBitmap::new_with_size(3, true);
        assert!(!active_bitmap.is_empty());
        assert_eq!(active_bitmap.len(), 3);
        assert_eq!(active_bitmap.active_count(), 3);
        assert_eq!(
            active_bitmap.active_indices().collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        // Check individual bits are all true
        for i in 0..3 {
            assert!(active_bitmap.is_active(i));
        }
        assert!(!active_bitmap.is_active(3)); // Out of bounds should be false
    }

    #[test]
    fn test_operator_bitmap_try_set() {
        let mut bitmap = OperatorBitmap::new_empty();

        // Setting bit 0 should work
        assert!(bitmap.try_set(0, true).is_ok());
        assert!(bitmap.is_active(0));
        assert_eq!(bitmap.active_count(), 1);

        // Setting bit 1 should work (sequential)
        assert!(bitmap.try_set(1, true).is_ok());
        assert!(bitmap.is_active(1));
        assert_eq!(bitmap.active_count(), 2);

        // Setting bit 0 to false should work
        assert!(bitmap.try_set(0, false).is_ok());
        assert!(!bitmap.is_active(0));
        assert_eq!(bitmap.active_count(), 1);

        // Trying to set bit 3 (skipping 2) should fail
        assert_eq!(
            bitmap.try_set(3, true),
            Err(OperatorBitmapError::IndexOutOfBounds {
                index: 3,
                max_valid_index: 2
            })
        );
        assert_eq!(bitmap.active_count(), 1);

        // Use a large initial bitmap
        let mut bitmap = OperatorBitmap::new_with_size(500, true);

        // Setting bit active doesn't change the active count
        assert!(bitmap.try_set(0, true).is_ok());
        assert_eq!(bitmap.active_count(), 500);

        // Setting bit inactive changes change the active count
        assert!(bitmap.try_set(0, false).is_ok());
        assert_eq!(bitmap.active_count(), 499);

        // Setting bit 500 should work (sequential)
        assert!(bitmap.try_set(500, true).is_ok());
        assert!(bitmap.is_active(500));
        assert_eq!(bitmap.active_count(), 500);

        // Trying to unset bit 1000 (skipping 501..) should fail
        assert_eq!(
            bitmap.try_set(1000, false),
            Err(OperatorBitmapError::IndexOutOfBounds {
                index: 1000,
                max_valid_index: 501
            })
        );
        assert_eq!(bitmap.active_count(), 500);
    }

    #[test]
    fn test_operator_bitmap_serialization_roundtrip() {
        let mut arb = ArbitraryGenerator::new();
        let bitmap: OperatorBitmap = arb.generate();
        let serialized_bytes = bitmap.as_ssz_bytes();
        let deserialized_bitmap = OperatorBitmap::from_ssz_bytes(&serialized_bytes).unwrap();
        assert_eq!(bitmap, deserialized_bitmap);
    }
}
