//! [`AsmSpecActivationDb`] implementation backed by sled.

use anyhow::{Context, Result};
use strata_identifiers::L1Height;
use strata_predicate::PredicateKey;

use crate::spec_activation::{AsmSpecActivationDb, RawSpecActivation};

/// Size of an encoded activation key: 4-byte BE enacting height + 2-byte BE
/// spec version.
const ENCODED_KEY_SIZE: usize = 4 + 2;

/// Sled-backed [`AsmSpecActivationDb`] keyed by `(enacting_height, version)`,
/// with the enacted predicate as the value.
///
/// The composite key allows several spec activations at one enacting height;
/// the big-endian height prefix keeps sled's lexicographic ordering aligned
/// with height ordering so `prune_after` can range-scan.
#[derive(Debug, Clone)]
pub struct SledSpecActivationDb {
    activations: sled::Tree,
}

impl SledSpecActivationDb {
    /// Opens or creates the spec-activation tree in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            activations: db.open_tree("asm_spec_activations")?,
        })
    }

    /// Synchronous variant of [`AsmSpecActivationDb::put`]. The ASM worker
    /// runs on a sync thread (via `ServiceBuilder::launch_sync`), where
    /// awaiting is not possible; calling this directly avoids that.
    pub fn put(
        &self,
        enacting_height: L1Height,
        version: u16,
        new_predicate: &PredicateKey,
    ) -> Result<()> {
        let key = encode_key(enacting_height, version);
        let value = borsh::to_vec(new_predicate)?;
        self.activations.insert(key, value)?;
        Ok(())
    }

    /// Synchronous variant of [`AsmSpecActivationDb::list`]. See [`Self::put`].
    pub fn list(&self) -> Result<Vec<RawSpecActivation>> {
        self.activations
            .iter()
            .map(|entry| {
                let (key, value) = entry?;
                decode_entry(&key, &value)
            })
            .collect()
    }

    /// Synchronous variant of [`AsmSpecActivationDb::prune_after`]. See
    /// [`Self::put`].
    pub fn prune_after(&self, after_height: L1Height) -> Result<()> {
        let Some(first_removed) = after_height.checked_add(1) else {
            return Ok(());
        };
        let lower: &[u8] = &first_removed.to_be_bytes();
        for entry in self.activations.range(lower..) {
            let (key, _) = entry?;
            self.activations.remove(&key)?;
        }
        Ok(())
    }
}

impl AsmSpecActivationDb for SledSpecActivationDb {
    type Error = anyhow::Error;

    async fn put(
        &self,
        enacting_height: L1Height,
        version: u16,
        new_predicate: &PredicateKey,
    ) -> Result<()> {
        self.put(enacting_height, version, new_predicate)
    }

    async fn list(&self) -> Result<Vec<RawSpecActivation>> {
        self.list()
    }

    async fn prune_after(&self, after_height: L1Height) -> Result<()> {
        self.prune_after(after_height)
    }
}

/// Encodes an activation key as `[enacting_height_be(4)][version_be(2)]`.
fn encode_key(enacting_height: L1Height, version: u16) -> [u8; ENCODED_KEY_SIZE] {
    let mut buf = [0u8; ENCODED_KEY_SIZE];
    buf[0..4].copy_from_slice(&enacting_height.to_be_bytes());
    buf[4..6].copy_from_slice(&version.to_be_bytes());
    buf
}

/// Decodes a tree entry back into a [`RawSpecActivation`].
fn decode_entry(key: &[u8], value: &[u8]) -> Result<RawSpecActivation> {
    let enacting_height = L1Height::from_be_bytes(
        key[0..4]
            .try_into()
            .context("spec activation key shorter than 4 bytes")?,
    );
    let version = u16::from_be_bytes(
        key[4..6]
            .try_into()
            .context("spec activation key shorter than 6 bytes")?,
    );
    let new_predicate = borsh::from_slice::<PredicateKey>(value)
        .context("malformed predicate in spec activation store")?;
    Ok((enacting_height, version, new_predicate))
}

#[cfg(test)]
mod tests {
    use strata_predicate::PredicateTypeId;

    use super::*;
    use crate::sled::test_util::test_db;

    const VERSION: u16 = 1;

    /// A per-height predicate, so roundtrip failures can't hide behind a
    /// shared constant.
    fn predicate(enacting_height: L1Height) -> PredicateKey {
        PredicateKey::new(PredicateTypeId::AlwaysAccept, vec![enacting_height as u8])
    }

    fn activation(enacting_height: L1Height) -> RawSpecActivation {
        (enacting_height, VERSION, predicate(enacting_height))
    }

    fn put(store: &SledSpecActivationDb, enacting_height: L1Height) {
        store
            .put(enacting_height, VERSION, &predicate(enacting_height))
            .unwrap();
    }

    #[test]
    fn put_list_roundtrip() {
        let (db, _dir) = test_db();
        let store = SledSpecActivationDb::open(&db).unwrap();

        put(&store, 7);
        put(&store, 3);

        // Ascending by enacting height regardless of insertion order.
        assert_eq!(store.list().unwrap(), vec![activation(3), activation(7)]);
    }

    #[test]
    fn put_is_idempotent() {
        let (db, _dir) = test_db();
        let store = SledSpecActivationDb::open(&db).unwrap();

        put(&store, 5);
        put(&store, 5);
        assert_eq!(store.list().unwrap(), vec![activation(5)]);
    }

    #[test]
    fn prune_after_drops_only_higher_entries() {
        let (db, _dir) = test_db();
        let store = SledSpecActivationDb::open(&db).unwrap();

        put(&store, 3);
        put(&store, 5);
        put(&store, 6);

        store.prune_after(5).unwrap();
        assert_eq!(store.list().unwrap(), vec![activation(3), activation(5)]);
    }
}
