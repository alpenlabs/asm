//! Predicate-based artifact lookup and bounded caching of loaded ASM hosts.

use std::{collections::VecDeque, future::Future, num::NonZeroUsize};

use strata_asm_common::SpecId;
use strata_predicate::PredicateKey;
use zkaleido::ZkVmRemoteHost;

use super::AsmProofHost;
use crate::{AsmArtifactConfig, ProverError, ProverResult};

/// Constructs hosts for the specs compiled into the node.
///
/// Implementations bind each host to its concrete spec. The registry checks the
/// resulting descriptor against the configured identity before caching it.
pub trait AsmHostLoader: Send + Sync + 'static {
    /// Backend shared by ASM and Moho proving on this node.
    type Host: ZkVmRemoteHost;

    /// Rejects unsupported specs during registration, without loading artifacts.
    fn validate_spec(&self, spec_id: SpecId) -> ProverResult<()>;

    /// Loads the artifact and derives the host's program descriptor.
    fn load(
        &self,
        artifact: &AsmArtifactConfig,
    ) -> impl Future<Output = ProverResult<AsmProofHost<Self::Host>>> + Send;
}

#[derive(Debug)]
struct CachedHost<H> {
    artifact_index: usize,
    host: AsmProofHost<H>,
}

/// Looks up configured artifacts and caches at most `capacity` loaded hosts.
///
/// The worker serializes access. Borrowed hosts remain valid until the next
/// mutable registry access; backend clones held by active operations can outlive
/// cache eviction, so capacity is not a total process-memory limit.
#[derive(Debug)]
pub struct AsmHostRegistry<L: AsmHostLoader> {
    artifacts: Vec<AsmArtifactConfig>,
    loaded: VecDeque<CachedHost<L::Host>>,
    capacity: NonZeroUsize,
    loader: L,
}

impl<L: AsmHostLoader> AsmHostRegistry<L> {
    /// Creates an empty registry with a cache limit and a concrete host loader.
    pub fn new(capacity: NonZeroUsize, loader: L) -> Self {
        Self {
            artifacts: Vec::new(),
            loaded: VecDeque::new(),
            capacity,
            loader,
        }
    }

    /// Registers artifact data without loading its host.
    /// Each spec and predicate must be unique, matching native execution recovery.
    pub fn register(&mut self, artifact: AsmArtifactConfig) -> ProverResult<()> {
        self.loader.validate_spec(artifact.spec_id)?;
        if self
            .artifacts
            .iter()
            .any(|entry| entry.spec_id == artifact.spec_id || entry.predicate == artifact.predicate)
        {
            return Err(ProverError::DuplicateArtifact);
        }
        self.artifacts.push(artifact);
        Ok(())
    }

    /// Resolves a configured program without loading its ELF.
    pub fn spec_id(&self, predicate: &PredicateKey) -> ProverResult<SpecId> {
        self.artifacts
            .iter()
            .find(|entry| &entry.predicate == predicate)
            .map(|entry| entry.spec_id)
            .ok_or_else(|| ProverError::UnknownArtifact(predicate.clone()))
    }

    /// Loads and validates the requested program, or borrows its cached host.
    pub async fn load(&mut self, predicate: &PredicateKey) -> ProverResult<&AsmProofHost<L::Host>> {
        let index = self
            .artifacts
            .iter()
            .position(|entry| &entry.predicate == predicate)
            .ok_or_else(|| ProverError::UnknownArtifact(predicate.clone()))?;
        if let Some(position) = self
            .loaded
            .iter()
            .position(|entry| entry.artifact_index == index)
        {
            let cached = self
                .loaded
                .remove(position)
                .expect("located cache entry exists");
            self.loaded.push_back(cached);
        } else {
            // Drop the least recently used cached host before initializing another.
            if self.loaded.len() == self.capacity.get() {
                self.loaded.pop_front();
            }
            let artifact = &self.artifacts[index];
            let host = self.loader.load(artifact).await?;
            if host.descriptor().spec_id() != artifact.spec_id
                || host.descriptor().predicate() != &artifact.predicate
            {
                return Err(ProverError::AsmArtifactMismatch {
                    spec_id: artifact.spec_id,
                });
            }
            self.loaded.push_back(CachedHost {
                artifact_index: index,
                host,
            });
        }
        Ok(&self.loaded.back().expect("requested host was cached").host)
    }
}
