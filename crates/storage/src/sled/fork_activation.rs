//! [`AsmForkActivationDb`] implementation backed by sled.

use anyhow::{Context, Result, anyhow};
use strata_asm_common::{ForkActivation, ForkId};
use strata_predicate::PredicateKey;

use crate::fork_activation::AsmForkActivationDb;

/// Size of an encoded activation key: 4-byte BE enacting height + 1-byte fork id.
const ENCODED_KEY_SIZE: usize = 4 + 1;

/// Sled-backed [`AsmForkActivationDb`] keyed by `(enacting_height, fork)`,
/// with the enacted predicate as the value.
///
/// The composite key allows several fork activations at one enacting height;
/// the big-endian height prefix keeps sled's lexicographic ordering aligned
/// with height ordering so `prune_after` can range-scan.
#[derive(Debug, Clone)]
pub struct SledForkActivationDb {
    activations: sled::Tree,
}

impl SledForkActivationDb {
    /// Opens or creates the fork-activation tree in the given sled instance.
    pub fn open(db: &sled::Db) -> Result<Self> {
        Ok(Self {
            activations: db.open_tree("asm_fork_activations")?,
        })
    }

    /// Synchronous variant of [`AsmForkActivationDb::put`]. The ASM worker runs
    /// on a sync thread (via `ServiceBuilder::launch_sync`), where awaiting is
    /// not possible; calling this directly avoids that.
    pub fn put(&self, activation: ForkActivation) -> Result<()> {
        let key = encode_key(activation.enacting_height, activation.fork);
        let value = borsh::to_vec(&activation.new_predicate)?;
        self.activations.insert(key, value)?;
        Ok(())
    }

    /// Synchronous variant of [`AsmForkActivationDb::list`]. See [`Self::put`].
    pub fn list(&self) -> Result<Vec<ForkActivation>> {
        self.activations
            .iter()
            .map(|entry| {
                let (key, value) = entry?;
                decode_entry(&key, &value)
            })
            .collect()
    }

    /// Synchronous variant of [`AsmForkActivationDb::prune_after`]. See [`Self::put`].
    pub fn prune_after(&self, after_height: u32) -> Result<()> {
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

impl AsmForkActivationDb for SledForkActivationDb {
    type Error = anyhow::Error;

    async fn put(&self, activation: ForkActivation) -> Result<()> {
        self.put(activation)
    }

    async fn list(&self) -> Result<Vec<ForkActivation>> {
        self.list()
    }

    async fn prune_after(&self, after_height: u32) -> Result<()> {
        self.prune_after(after_height)
    }
}

/// Encodes an activation key as `[enacting_height_be(4)][fork_id(1)]`.
fn encode_key(enacting_height: u32, fork: ForkId) -> [u8; ENCODED_KEY_SIZE] {
    let mut buf = [0u8; ENCODED_KEY_SIZE];
    buf[0..4].copy_from_slice(&enacting_height.to_be_bytes());
    buf[4] = fork.into();
    buf
}

/// Decodes a tree entry back into a [`ForkActivation`].
fn decode_entry(key: &[u8], value: &[u8]) -> Result<ForkActivation> {
    let enacting_height = u32::from_be_bytes(
        key[0..4]
            .try_into()
            .context("fork activation key shorter than 4 bytes")?,
    );
    let fork = ForkId::try_from(key[4])
        .map_err(|id| anyhow!("unknown fork id {id} in fork activation store"))?;
    let new_predicate = borsh::from_slice::<PredicateKey>(value)
        .context("malformed predicate in fork activation store")?;
    Ok(ForkActivation {
        enacting_height,
        fork,
        new_predicate,
    })
}

#[cfg(test)]
mod tests {
    use strata_predicate::PredicateTypeId;

    use super::*;
    use crate::sled::test_util::test_db;

    /// A per-height predicate, so roundtrip failures can't hide behind a
    /// shared constant.
    fn predicate(enacting_height: u32) -> PredicateKey {
        PredicateKey::new(PredicateTypeId::AlwaysAccept, vec![enacting_height as u8])
    }

    fn activation(enacting_height: u32) -> ForkActivation {
        ForkActivation {
            enacting_height,
            fork: ForkId::Fork1,
            new_predicate: predicate(enacting_height),
        }
    }

    #[test]
    fn put_list_roundtrip() {
        let (db, _dir) = test_db();
        let store = SledForkActivationDb::open(&db).unwrap();

        store.put(activation(7)).unwrap();
        store.put(activation(3)).unwrap();

        // Ascending by enacting height regardless of insertion order.
        assert_eq!(store.list().unwrap(), vec![activation(3), activation(7)]);
    }

    #[test]
    fn put_is_idempotent() {
        let (db, _dir) = test_db();
        let store = SledForkActivationDb::open(&db).unwrap();

        store.put(activation(5)).unwrap();
        store.put(activation(5)).unwrap();
        assert_eq!(store.list().unwrap(), vec![activation(5)]);
    }

    #[test]
    fn prune_after_drops_only_higher_entries() {
        let (db, _dir) = test_db();
        let store = SledForkActivationDb::open(&db).unwrap();

        store.put(activation(3)).unwrap();
        store.put(activation(5)).unwrap();
        store.put(activation(6)).unwrap();

        store.prune_after(5).unwrap();
        assert_eq!(store.list().unwrap(), vec![activation(3), activation(5)]);
    }
}
