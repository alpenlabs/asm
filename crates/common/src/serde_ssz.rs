use serde::{Serialize, de::DeserializeOwned};
use ssz::{Decode, DecodeError, Encode};

pub fn ssz_append_via_serde_json<T: Serialize>(value: &T, buf: &mut Vec<u8>, context: &str) {
    serde_json::to_vec(value)
        .unwrap_or_else(|err| panic!("{context} serialization should not fail: {err}"))
        .ssz_append(buf);
}

pub fn ssz_bytes_len_via_serde_json<T: Serialize>(value: &T, context: &str) -> usize {
    serde_json::to_vec(value)
        .unwrap_or_else(|err| panic!("{context} serialization should not fail: {err}"))
        .ssz_bytes_len()
}

pub fn from_ssz_bytes_via_serde_json<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, DecodeError> {
    let payload = Vec::<u8>::from_ssz_bytes(bytes)?;
    serde_json::from_slice(&payload).map_err(|err| DecodeError::BytesInvalid(err.to_string()))
}
