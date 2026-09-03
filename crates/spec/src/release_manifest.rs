//! Qualified, immutable guest-artifact manifests.
//!
//! A predicate authenticates program bytes, but it does not say which native
//! [`AsmSpecId`] implements the same rules. Release manifests are the reviewed
//! authority for that binding. Operators select a qualified artifact by its
//! content identity and provide local files; they do not label an ELF with a
//! specification.

#[cfg(test)]
use std::env;
use std::{
    collections::BTreeSet,
    fmt, fs, io,
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};
use strata_asm_common::{AsmArtifactId, AsmSpecId, GuestArtifactId};
use strata_predicate::PredicateKey;

const MANIFEST_FORMAT: u16 = 1;
const ARTIFACT_ID_DOMAIN: &[u8] = b"strata-asm-qualified-guest-artifact-v1";
const BASELINE_MANIFEST_JSON: &str = include_str!("../release/v0.3.0-rc.2/guest-artifacts.json");

// `legacy_published` is a narrow compatibility exception, not a second path
// for qualifying new programs. These are the only historical statements whose
// published bytes predate the reproducible-build policy.
const LEGACY_BASELINE_RELEASE: &str = "v0.3.0-rc.2";
const LEGACY_BASELINE_REPOSITORY: &str = "https://github.com/alpenlabs/asm";
const LEGACY_BASELINE_REVISION: &str = "45a1fa2f52289b483dd9767b4ec9c80545d5789b";
const LEGACY_BASELINE_ARTIFACT_IDS: [&str; 2] = [
    // Updated only when the canonical statement schema changes before this
    // registry is released. Published artifact bytes themselves never change.
    "sha256:30b4111c71ddd5ba449e7c813cb049cf97544b10bfd4e079464b0acefcaf20b3",
    "sha256:7bab67c7574b5222a5019e586b5040ca767c099142f6e1fd0f9d62a28fddabcd",
];

/// The immutable manifests compiled into this release.
const EMBEDDED_MANIFESTS: &[&str] = &[BASELINE_MANIFEST_JSON];

/// SHA-256 digest encoded as 64 lowercase hexadecimal characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Constructs a digest from raw bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Sha256Digest {
    type Err = ParseSha256DigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.strip_prefix("sha256:").unwrap_or(value);
        let decoded = hex::decode(value).map_err(ParseSha256DigestError::InvalidHex)?;
        let bytes = decoded
            .try_into()
            .map_err(|bytes: Vec<u8>| ParseSha256DigestError::InvalidLength(bytes.len()))?;
        Ok(Self(bytes))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <String as Deserialize>::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

/// A SHA-256 digest string was malformed.
#[derive(Debug, thiserror::Error)]
pub enum ParseSha256DigestError {
    /// The value was not hexadecimal.
    #[error("digest is not valid hexadecimal")]
    InvalidHex(#[source] hex::FromHexError),

    /// The value was not a 32-byte digest.
    #[error("digest contains {0} bytes; expected 32")]
    InvalidLength(usize),
}

/// Whether the build provenance meets the current release policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseQualification {
    /// Published before builder images were digest-pinned. The exact published
    /// bytes remain usable for historical replay, but cannot claim reproducible
    /// builder provenance retroactively.
    LegacyPublished,
    /// Built and checked with the current digest-pinned release process.
    Qualified,
}

impl ReleaseQualification {
    fn canonical_name(self) -> &'static str {
        match self {
            Self::LegacyPublished => "legacy_published",
            Self::Qualified => "qualified",
        }
    }
}

/// The guest program represented by one manifest entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestProgram {
    /// An ASM state-transition guest.
    Asm,
    /// The recursive Moho guest.
    Moho,
}

impl GuestProgram {
    fn canonical_name(self) -> &'static str {
        match self {
            Self::Asm => "asm",
            Self::Moho => "moho",
        }
    }
}

/// Source revision from which a release's guests were built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceProvenance {
    /// Canonical source repository URL.
    pub repository: String,
    /// Full 40-character Git commit SHA.
    pub revision: String,
}

/// Exact host, SP1, guest, and builder identities used for a release build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainProvenance {
    /// Host Rust toolchain channel.
    pub host_rust: Option<String>,
    /// Resolved host-side `sp1-build` version.
    pub sp1_build: Option<String>,
    /// Resolved host-side `sp1-sdk` version.
    pub sp1_sdk: Option<String>,
    /// Resolved host-side `sp1-verifier` version.
    pub sp1_verifier: Option<String>,
    /// Resolved `sp1-zkvm` version inside each standalone guest lockfile.
    pub guest_zkvm: Option<String>,
    /// Docker builder image. Qualified releases require an `@sha256:` digest;
    /// legacy releases may leave this absent when the historical image cannot
    /// be established.
    pub builder_image: Option<String>,
}

/// One file and its release-qualified digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFile {
    /// Filename used in the GitHub release.
    pub file: String,
    /// SHA-256 of the exact published bytes.
    pub sha256: Sha256Digest,
}

/// One guest program and every fact needed to load it safely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestArtifact {
    /// Canonical digest of this artifact statement.
    pub artifact_id: GuestArtifactId,
    /// Stable release asset stem (for example `asm-v0`).
    pub name: String,
    /// Semantic role of the guest.
    pub program: GuestProgram,
    /// Native ASM rules implemented by an ASM guest. Must be absent for Moho.
    pub asm_spec_id: Option<AsmSpecId>,
    /// ASM artifacts this guest may recursively verify.
    ///
    /// This is empty for an ASM program. A Moho entry lists every exact ASM
    /// artifact identity it is qualified to recurse over, including historical
    /// artifacts needed across an upgrade boundary.
    pub compatible_asm_artifact_ids: Vec<AsmArtifactId>,
    /// Predicate derived from the guest verifying key.
    pub predicate: PredicateKey,
    /// Exact ELF bytes.
    pub elf: ArtifactFile,
    /// Exact JSON-encoded predicate asset.
    pub verifying_key: ArtifactFile,
}

/// Exact local bytes after manifest verification.
///
/// Callers initialize a proving host from `elf` directly instead of reopening
/// the path after verification, which avoids a verify-then-swap race.
#[derive(Debug, Clone)]
pub struct VerifiedArtifactFiles {
    /// ELF bytes whose SHA-256 matched the manifest.
    pub elf: Vec<u8>,
    /// Predicate decoded from the byte-exact VK JSON asset.
    pub predicate: PredicateKey,
}

/// One immutable release artifact manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    /// Manifest schema version.
    pub format_version: u16,
    /// Release tag whose assets this manifest describes.
    pub release: String,
    /// Whether the build meets the current provenance policy.
    pub qualification: ReleaseQualification,
    /// Source repository and revision.
    pub source: SourceProvenance,
    /// Exact build toolchain and builder identities.
    pub toolchain: ToolchainProvenance,
    /// Every guest asset published by the release.
    pub artifacts: Vec<GuestArtifact>,
}

impl ReleaseManifest {
    /// Parses and validates a machine-readable release manifest.
    pub fn parse(json: &str) -> Result<Self, ReleaseManifestError> {
        let manifest: Self = serde_json::from_str(json)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates schema, provenance, role, uniqueness, and content identities.
    pub fn validate(&self) -> Result<(), ReleaseManifestError> {
        if self.format_version != MANIFEST_FORMAT {
            return Err(ReleaseManifestError::UnsupportedFormat(self.format_version));
        }
        if self.release.is_empty() {
            return Err(ReleaseManifestError::InvalidField(
                "release must not be empty",
            ));
        }
        if self.source.repository.is_empty() {
            return Err(ReleaseManifestError::InvalidField(
                "source.repository must not be empty",
            ));
        }
        if !is_full_git_revision(&self.source.revision) {
            return Err(ReleaseManifestError::InvalidField(
                "source.revision must be a full 40-character Git SHA",
            ));
        }
        for (field, value) in [
            ("toolchain.host_rust", self.toolchain.host_rust.as_deref()),
            ("toolchain.sp1_build", self.toolchain.sp1_build.as_deref()),
            ("toolchain.sp1_sdk", self.toolchain.sp1_sdk.as_deref()),
            (
                "toolchain.sp1_verifier",
                self.toolchain.sp1_verifier.as_deref(),
            ),
            ("toolchain.guest_zkvm", self.toolchain.guest_zkvm.as_deref()),
            (
                "toolchain.builder_image",
                self.toolchain.builder_image.as_deref(),
            ),
        ] {
            if value.is_some_and(|value| value.trim().is_empty()) {
                return Err(ReleaseManifestError::InvalidOptionalToolchainField(field));
            }
        }
        if self.qualification == ReleaseQualification::Qualified {
            for (field, value) in [
                ("toolchain.host_rust", self.toolchain.host_rust.as_deref()),
                ("toolchain.sp1_build", self.toolchain.sp1_build.as_deref()),
                ("toolchain.sp1_sdk", self.toolchain.sp1_sdk.as_deref()),
                (
                    "toolchain.sp1_verifier",
                    self.toolchain.sp1_verifier.as_deref(),
                ),
                ("toolchain.guest_zkvm", self.toolchain.guest_zkvm.as_deref()),
                (
                    "toolchain.builder_image",
                    self.toolchain.builder_image.as_deref(),
                ),
            ] {
                if value.is_none_or(str::is_empty) {
                    return Err(ReleaseManifestError::MissingQualifiedToolchainField(field));
                }
            }
            let builder_image = self
                .toolchain
                .builder_image
                .as_deref()
                .expect("qualified field presence was checked");
            if !has_sha256_image_digest(builder_image) {
                return Err(ReleaseManifestError::UnpinnedBuilderImage(
                    builder_image.to_owned(),
                ));
            }
        }
        if self.artifacts.is_empty() {
            return Err(ReleaseManifestError::NoArtifacts);
        }

        let asm_count = self
            .artifacts
            .iter()
            .filter(|artifact| artifact.program == GuestProgram::Asm)
            .count();
        let moho_count = self
            .artifacts
            .iter()
            .filter(|artifact| artifact.program == GuestProgram::Moho)
            .count();
        if self.qualification == ReleaseQualification::Qualified {
            if asm_count == 0 {
                return Err(ReleaseManifestError::MissingAsmArtifact);
            }
            match moho_count {
                0 => return Err(ReleaseManifestError::MissingMohoArtifact),
                1 => {}
                count => return Err(ReleaseManifestError::MultipleMohoArtifacts(count)),
            }
        }

        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut filenames = BTreeSet::new();
        let mut asm_predicates = BTreeSet::new();
        for artifact in &self.artifacts {
            validate_artifact_name(&artifact.name)?;
            validate_asset_filename(&artifact.elf.file, ".elf")?;
            validate_asset_filename(&artifact.verifying_key.file, "-vk.json")?;
            match (artifact.program, artifact.asm_spec_id) {
                (GuestProgram::Asm, Some(_)) => {
                    if !artifact.compatible_asm_artifact_ids.is_empty() {
                        return Err(ReleaseManifestError::UnexpectedAsmCompatibility(
                            artifact.name.clone(),
                        ));
                    }
                }
                (GuestProgram::Moho, None) => {
                    if artifact.compatible_asm_artifact_ids.is_empty() {
                        return Err(ReleaseManifestError::MissingMohoCompatibility(
                            artifact.name.clone(),
                        ));
                    }
                    if artifact
                        .compatible_asm_artifact_ids
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
                    {
                        return Err(ReleaseManifestError::NonCanonicalMohoCompatibility(
                            artifact.name.clone(),
                        ));
                    }
                }
                (GuestProgram::Asm, None) => {
                    return Err(ReleaseManifestError::MissingAsmSpec(artifact.name.clone()));
                }
                (GuestProgram::Moho, Some(_)) => {
                    return Err(ReleaseManifestError::UnexpectedMohoSpec(
                        artifact.name.clone(),
                    ));
                }
            }

            let expected = self.compute_artifact_id(artifact);
            if artifact.artifact_id != expected {
                return Err(ReleaseManifestError::ArtifactIdMismatch {
                    name: artifact.name.clone(),
                    declared: artifact.artifact_id,
                    expected,
                });
            }
            if !ids.insert(artifact.artifact_id) {
                return Err(ReleaseManifestError::DuplicateArtifactId(
                    artifact.artifact_id,
                ));
            }
            if !names.insert(artifact.name.as_str()) {
                return Err(ReleaseManifestError::DuplicateArtifactName(
                    artifact.name.clone(),
                ));
            }
            for filename in [&artifact.elf.file, &artifact.verifying_key.file] {
                if !filenames.insert(filename.as_str()) {
                    return Err(ReleaseManifestError::DuplicateArtifactFilename(
                        filename.clone(),
                    ));
                }
            }
            if artifact.program == GuestProgram::Asm
                && !asm_predicates.insert((
                    artifact.predicate.id(),
                    artifact.predicate.condition().to_vec(),
                ))
            {
                return Err(ReleaseManifestError::DuplicateAsmPredicate(format!(
                    "{:?}",
                    artifact.predicate
                )));
            }
        }

        let local_asm_ids = self
            .artifacts
            .iter()
            .filter(|artifact| artifact.program == GuestProgram::Asm)
            .map(|artifact| artifact.artifact_id)
            .collect::<BTreeSet<_>>();
        for moho in self
            .artifacts
            .iter()
            .filter(|artifact| artifact.program == GuestProgram::Moho)
        {
            for asm_id in &local_asm_ids {
                if !moho.compatible_asm_artifact_ids.contains(asm_id) {
                    return Err(ReleaseManifestError::MohoOmitsBundledAsm {
                        moho: moho.name.clone(),
                        asm_artifact_id: *asm_id,
                    });
                }
            }
        }

        if self.qualification == ReleaseQualification::LegacyPublished {
            self.validate_legacy_allowlist()?;
        }

        Ok(())
    }

    fn validate_legacy_allowlist(&self) -> Result<(), ReleaseManifestError> {
        if self.artifacts.iter().any(|artifact| {
            artifact.program == GuestProgram::Asm && artifact.asm_spec_id != Some(AsmSpecId::V0)
        }) {
            return Err(ReleaseManifestError::LegacySuccessorArtifact);
        }

        let actual_ids = self
            .artifacts
            .iter()
            .map(|artifact| artifact.artifact_id.to_string())
            .collect::<BTreeSet<_>>();
        let expected_ids = LEGACY_BASELINE_ARTIFACT_IDS
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if self.release != LEGACY_BASELINE_RELEASE
            || self.source.repository != LEGACY_BASELINE_REPOSITORY
            || self.source.revision != LEGACY_BASELINE_REVISION
            || actual_ids != expected_ids
        {
            return Err(ReleaseManifestError::UnapprovedLegacyManifest);
        }

        Ok(())
    }

    /// Computes the canonical identity of one artifact statement.
    pub fn compute_artifact_id(&self, artifact: &GuestArtifact) -> GuestArtifactId {
        let mut hasher = Sha256::new();
        hasher.update(ARTIFACT_ID_DOMAIN);
        hash_string(&mut hasher, &self.release);
        hash_string(&mut hasher, self.qualification.canonical_name());
        hash_string(&mut hasher, &self.source.repository);
        hash_string(&mut hasher, &self.source.revision);
        hash_optional_string(&mut hasher, self.toolchain.host_rust.as_deref());
        hash_optional_string(&mut hasher, self.toolchain.sp1_build.as_deref());
        hash_optional_string(&mut hasher, self.toolchain.sp1_sdk.as_deref());
        hash_optional_string(&mut hasher, self.toolchain.sp1_verifier.as_deref());
        hash_optional_string(&mut hasher, self.toolchain.guest_zkvm.as_deref());
        hash_optional_string(&mut hasher, self.toolchain.builder_image.as_deref());
        hash_string(&mut hasher, &artifact.name);
        hash_string(&mut hasher, artifact.program.canonical_name());
        match artifact.asm_spec_id {
            Some(spec_id) => {
                hasher.update([1]);
                hasher.update(spec_id.as_u16().to_le_bytes());
            }
            None => hasher.update([0]),
        }
        let compatibility_len = u64::try_from(artifact.compatible_asm_artifact_ids.len())
            .expect("artifact compatibility list fits in u64");
        hasher.update(compatibility_len.to_le_bytes());
        for artifact_id in &artifact.compatible_asm_artifact_ids {
            hasher.update(artifact_id.as_bytes());
        }
        hasher.update([artifact.predicate.id()]);
        hash_bytes(&mut hasher, artifact.predicate.condition());
        hash_string(&mut hasher, &artifact.elf.file);
        hasher.update(artifact.elf.sha256.as_bytes());
        hash_string(&mut hasher, &artifact.verifying_key.file);
        hasher.update(artifact.verifying_key.sha256.as_bytes());
        GuestArtifactId::new(hasher.finalize().into())
    }

    /// Verifies local ELF and VK files against one manifest entry.
    ///
    /// The predicate JSON is parsed and compared with the manifest in addition
    /// to its byte checksum. SP1 startup separately derives the predicate from
    /// the loaded ELF, closing the final ELF-to-VK link.
    pub fn verify_artifact_files(
        &self,
        artifact: &GuestArtifact,
        elf_path: &Path,
        vk_path: &Path,
    ) -> Result<VerifiedArtifactFiles, ReleaseManifestError> {
        if !self.artifacts.iter().any(|entry| entry == artifact) {
            return Err(ReleaseManifestError::ForeignArtifact(artifact.artifact_id));
        }
        let elf = verify_file_digest(elf_path, artifact.elf.sha256, "ELF")?;
        let vk_bytes =
            verify_file_digest(vk_path, artifact.verifying_key.sha256, "verifying-key JSON")?;
        let predicate: PredicateKey = serde_json::from_slice(&vk_bytes).map_err(|source| {
            ReleaseManifestError::InvalidPredicateFile {
                path: vk_path.to_path_buf(),
                source,
            }
        })?;
        if predicate != artifact.predicate {
            return Err(ReleaseManifestError::PredicateFileMismatch {
                path: vk_path.to_path_buf(),
                expected: format!("{:?}", artifact.predicate),
                actual: format!("{predicate:?}"),
            });
        }
        Ok(VerifiedArtifactFiles { elf, predicate })
    }
}

/// All release-qualified artifacts compiled into this binary.
#[derive(Debug, Clone)]
pub struct QualifiedGuestArtifacts {
    manifests: Vec<ReleaseManifest>,
}

impl QualifiedGuestArtifacts {
    /// Resolves an artifact identity to its manifest and entry.
    pub fn resolve(
        &self,
        artifact_id: &GuestArtifactId,
    ) -> Option<(&ReleaseManifest, &GuestArtifact)> {
        self.manifests.iter().find_map(|manifest| {
            manifest
                .artifacts
                .iter()
                .find(|artifact| &artifact.artifact_id == artifact_id)
                .map(|artifact| (manifest, artifact))
        })
    }

    /// Iterates through every compiled manifest.
    pub fn manifests(&self) -> impl Iterator<Item = &ReleaseManifest> {
        self.manifests.iter()
    }

    /// Iterates through every compiled ASM artifact.
    pub fn asm_artifacts(&self) -> impl Iterator<Item = &GuestArtifact> {
        self.manifests
            .iter()
            .flat_map(|manifest| manifest.artifacts.iter())
            .filter(|artifact| artifact.program == GuestProgram::Asm)
    }
}

/// Loads and cross-validates every manifest compiled into this release.
pub fn qualified_guest_artifacts() -> Result<QualifiedGuestArtifacts, ReleaseManifestError> {
    let manifests = EMBEDDED_MANIFESTS
        .iter()
        .map(|json| ReleaseManifest::parse(json))
        .collect::<Result<Vec<_>, _>>()?;

    let mut ids = BTreeSet::new();
    let mut asm_predicates = BTreeSet::new();
    for manifest in &manifests {
        for artifact in &manifest.artifacts {
            if !ids.insert(artifact.artifact_id) {
                return Err(ReleaseManifestError::DuplicateArtifactId(
                    artifact.artifact_id,
                ));
            }
            if artifact.program == GuestProgram::Asm
                && !asm_predicates.insert(format!("{:?}", artifact.predicate))
            {
                return Err(ReleaseManifestError::DuplicateAsmPredicate(format!(
                    "{:?}",
                    artifact.predicate
                )));
            }
        }
    }

    Ok(QualifiedGuestArtifacts { manifests })
}

/// Manifest or artifact validation failed.
#[derive(Debug, thiserror::Error)]
pub enum ReleaseManifestError {
    /// JSON decoding failed.
    #[error("invalid release artifact manifest JSON")]
    Json(#[from] serde_json::Error),

    /// A manifest used an unsupported schema.
    #[error("unsupported release artifact manifest format {0}")]
    UnsupportedFormat(u16),

    /// A required field was malformed.
    #[error("invalid release artifact manifest: {0}")]
    InvalidField(&'static str),

    /// A qualified release omitted an exact toolchain identity.
    #[error("qualified release artifact manifest requires non-empty field {0}")]
    MissingQualifiedToolchainField(&'static str),

    /// An optional toolchain identity was present but malformed.
    #[error("release artifact manifest contains malformed field {0}")]
    InvalidOptionalToolchainField(&'static str),

    /// A qualified release named a mutable builder image.
    #[error("qualified release builder image is not digest-pinned: {0}")]
    UnpinnedBuilderImage(String),

    /// The manifest contained no artifacts.
    #[error("release artifact manifest contains no artifacts")]
    NoArtifacts,

    /// An ASM artifact omitted its semantic spec.
    #[error("ASM artifact {0} has no asm_spec_id")]
    MissingAsmSpec(String),

    /// A Moho artifact incorrectly declared an ASM semantic spec.
    #[error("Moho artifact {0} must not declare asm_spec_id")]
    UnexpectedMohoSpec(String),

    /// An artifact filename was not a safe release basename.
    #[error("artifact filename is not a plain basename: {0}")]
    InvalidFilename(String),

    /// A qualified release published no ASM artifact.
    ///
    /// Qualification means the release can prove the chain; without an ASM
    /// program it cannot.
    #[error("qualified release artifact manifest contains no ASM artifact")]
    MissingAsmArtifact,

    /// A qualified release published no Moho artifact.
    #[error("qualified release artifact manifest contains no Moho artifact")]
    MissingMohoArtifact,

    /// A qualified release published more than one Moho artifact.
    ///
    /// The recursive verifier is one program; several would leave which one
    /// authorizes a step undecided.
    #[error("qualified release artifact manifest contains {0} Moho artifacts, expected one")]
    MultipleMohoArtifacts(usize),

    /// An ASM artifact declared Moho compatibility.
    ///
    /// Compatibility runs one way: a Moho artifact names the ASM artifacts it
    /// verifies. An ASM entry claiming the reverse would let the bundle assert
    /// its own acceptance.
    #[error("ASM artifact {0} must not declare compatible_asm_artifact_ids")]
    UnexpectedAsmCompatibility(String),

    /// A Moho artifact named no compatible ASM artifact.
    #[error("Moho artifact {0} declares no compatible ASM artifacts")]
    MissingMohoCompatibility(String),

    /// A Moho artifact's compatibility list was unordered or repeated an id.
    ///
    /// The list is part of the statement the artifact id commits to, so it has
    /// one canonical form: strictly ascending.
    #[error("Moho artifact {0} lists compatible ASM artifacts out of canonical order")]
    NonCanonicalMohoCompatibility(String),

    /// A bundled ASM artifact was absent from the Moho artifact's list.
    ///
    /// Shipping an ASM program the bundled verifier does not accept would give
    /// a node an artifact it can run but never prove.
    #[error("Moho artifact {moho} omits bundled ASM artifact {asm_artifact_id}")]
    MohoOmitsBundledAsm {
        /// Name of the Moho artifact.
        moho: String,
        /// Bundled ASM artifact missing from its compatibility list.
        asm_artifact_id: GuestArtifactId,
    },

    /// A legacy-published manifest carried a successor ASM artifact.
    ///
    /// Legacy publication exists only for the baseline, whose historical build
    /// cannot be reproduced. A successor artifact must be qualified properly
    /// rather than inheriting that exemption.
    #[error("legacy-published manifest declares a non-baseline ASM artifact")]
    LegacySuccessorArtifact,

    /// A legacy-published manifest declared artifacts outside the allowlist.
    ///
    /// The exemption is pinned to specific reviewed artifact ids, so it cannot
    /// be widened by editing the manifest.
    #[error("legacy-published manifest declares artifacts outside the reviewed allowlist")]
    UnapprovedLegacyManifest,

    /// An artifact ID did not authenticate its full statement.
    #[error("artifact {name} declares id {declared}, but its canonical id is {expected}")]
    ArtifactIdMismatch {
        /// Artifact name.
        name: String,
        /// ID in the manifest.
        declared: GuestArtifactId,
        /// ID derived from the statement.
        expected: GuestArtifactId,
    },

    /// An artifact ID was reused.
    #[error("artifact id {0} appears more than once")]
    DuplicateArtifactId(GuestArtifactId),

    /// An artifact name was reused in one manifest.
    #[error("artifact name {0} appears more than once")]
    DuplicateArtifactName(String),

    /// Two assets reused one release filename.
    #[error("artifact filename {0} appears more than once")]
    DuplicateArtifactFilename(String),

    /// Two ASM entries claimed the same predicate.
    #[error("ASM predicate {0} appears more than once")]
    DuplicateAsmPredicate(String),

    /// A file could not be read.
    #[error("failed to read {kind} artifact {path}: {source}")]
    ReadArtifact {
        /// Artifact kind.
        kind: &'static str,
        /// Local path.
        path: PathBuf,
        /// I/O failure.
        #[source]
        source: io::Error,
    },

    /// Local bytes did not match the qualified digest.
    #[error("{kind} artifact {path} has SHA-256 {actual}, expected {expected}")]
    FileDigestMismatch {
        /// Artifact kind.
        kind: &'static str,
        /// Local path.
        path: PathBuf,
        /// Qualified digest.
        expected: Sha256Digest,
        /// Actual digest.
        actual: Sha256Digest,
    },

    /// The VK asset was not a predicate JSON value.
    #[error("failed to decode predicate JSON {path}: {source}")]
    InvalidPredicateFile {
        /// Local path.
        path: PathBuf,
        /// JSON failure.
        #[source]
        source: serde_json::Error,
    },

    /// The VK asset decoded to a different predicate.
    #[error("predicate JSON {path} contains {actual}, expected {expected}")]
    PredicateFileMismatch {
        /// Local path.
        path: PathBuf,
        /// Qualified predicate.
        expected: String,
        /// Actual predicate.
        actual: String,
    },

    /// Verification was requested with an entry from another manifest.
    #[error("artifact {0} does not belong to this release manifest")]
    ForeignArtifact(GuestArtifactId),

    /// A qualified ASM identity was expected but a general guest ID was supplied.
    #[error("artifact {0} is not an ASM artifact")]
    NotAsmArtifact(AsmArtifactId),
}

fn has_sha256_image_digest(image: &str) -> bool {
    let Some((_, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_full_git_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Checks an artifact name is a plain, non-empty identifier.
///
/// The name is part of the statement the artifact id commits to and is used in
/// error messages and lookups, so it may not be empty or carry surrounding
/// whitespace that would make two entries look distinct while reading alike.
fn validate_artifact_name(name: &str) -> Result<(), ReleaseManifestError> {
    if name.is_empty() || name.trim() != name {
        return Err(ReleaseManifestError::InvalidField("artifact.name"));
    }
    Ok(())
}

/// Checks a release asset filename is a plain basename with the expected suffix.
///
/// The suffix is what stops an ELF and its verifying key being swapped in a
/// manifest that is otherwise well-formed.
fn validate_asset_filename(filename: &str, suffix: &str) -> Result<(), ReleaseManifestError> {
    validate_filename(filename)?;
    if !filename.ends_with(suffix) {
        return Err(ReleaseManifestError::InvalidFilename(filename.to_owned()));
    }
    Ok(())
}

fn validate_filename(filename: &str) -> Result<(), ReleaseManifestError> {
    let path = Path::new(filename);
    if filename.is_empty()
        || path.file_name().and_then(|name| name.to_str()) != Some(filename)
        || path.components().count() != 1
    {
        return Err(ReleaseManifestError::InvalidFilename(filename.to_owned()));
    }
    Ok(())
}

fn hash_string(hasher: &mut Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_optional_string(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            hash_string(hasher, value);
        }
        None => hasher.update([0]),
    }
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    let len = u64::try_from(value.len()).expect("artifact manifest fields fit in u64");
    hasher.update(len.to_le_bytes());
    hasher.update(value);
}

fn verify_file_digest(
    path: &Path,
    expected: Sha256Digest,
    kind: &'static str,
) -> Result<Vec<u8>, ReleaseManifestError> {
    let bytes = fs::read(path).map_err(|source| ReleaseManifestError::ReadArtifact {
        kind,
        path: path.to_path_buf(),
        source,
    })?;
    let actual = Sha256Digest::of(&bytes);
    if actual != expected {
        return Err(ReleaseManifestError::FileDigestMismatch {
            kind,
            path: path.to_path_buf(),
            expected,
            actual,
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_release_manifests_are_self_authenticating() {
        let releases = qualified_guest_artifacts().expect("embedded manifests are valid");
        let artifacts = releases
            .manifests()
            .flat_map(|manifest| manifest.artifacts.iter())
            .collect::<Vec<_>>();

        assert_eq!(artifacts.len(), 2);
        assert_eq!(
            releases.asm_artifacts().next().unwrap().asm_spec_id,
            Some(AsmSpecId::V0)
        );
    }

    #[test]
    fn qualified_manifests_require_a_digest_pinned_builder() {
        let mut manifest = ReleaseManifest::parse(BASELINE_MANIFEST_JSON).unwrap();
        manifest.qualification = ReleaseQualification::Qualified;
        // Satisfy every other qualified-release requirement so the assertion
        // below is about the builder image and nothing else.
        manifest.toolchain.host_rust = Some("nightly-2026-01-01".to_owned());
        manifest.toolchain.sp1_build = Some("6.3.0".to_owned());
        manifest.toolchain.sp1_sdk = Some("6.3.0".to_owned());
        manifest.toolchain.sp1_verifier = Some("6.3.0".to_owned());
        manifest.toolchain.guest_zkvm = Some("6.3.0".to_owned());
        // A tag rather than an @sha256: digest, which is the point of the test.
        manifest.toolchain.builder_image = Some("ghcr.io/succinctlabs/sp1:v6.3.0".to_owned());

        assert!(matches!(
            manifest.validate(),
            Err(ReleaseManifestError::UnpinnedBuilderImage(_))
        ));
    }

    #[test]
    fn tampering_with_the_semantic_spec_invalidates_the_artifact_id() {
        let mut manifest = ReleaseManifest::parse(BASELINE_MANIFEST_JSON).unwrap();
        let artifact = manifest
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.program == GuestProgram::Asm)
            .unwrap();
        artifact.asm_spec_id = Some(AsmSpecId::V1);

        assert!(matches!(
            manifest.validate(),
            Err(ReleaseManifestError::ArtifactIdMismatch { .. })
        ));
    }

    #[test]
    fn malformed_and_traversing_filenames_are_rejected() {
        let mut manifest = ReleaseManifest::parse(BASELINE_MANIFEST_JSON).unwrap();
        manifest.artifacts[0].elf.file = "../asm.elf".to_owned();

        assert!(matches!(
            manifest.validate(),
            Err(ReleaseManifestError::InvalidFilename(_))
        ));
    }

    /// The release workflow sets both environment variables and runs this exact
    /// test after building guests. Local unit-test runs skip the external-file
    /// portion while still exercising all embedded manifests above.
    #[test]
    fn requested_release_files_match_an_embedded_manifest() {
        let (Ok(manifest_path), Ok(artifacts_dir)) = (
            env::var("RELEASE_MANIFEST_PATH"),
            env::var("RELEASE_ARTIFACT_DIR"),
        ) else {
            return;
        };
        let json = fs::read_to_string(&manifest_path).expect("read requested release manifest");
        let requested = ReleaseManifest::parse(&json).expect("requested manifest is valid");
        let embedded = qualified_guest_artifacts().expect("embedded manifests are valid");
        assert!(
            embedded.manifests().any(|manifest| manifest == &requested),
            "the requested release manifest is not compiled into this release"
        );

        let artifacts_dir = Path::new(&artifacts_dir);
        for artifact in &requested.artifacts {
            requested
                .verify_artifact_files(
                    artifact,
                    &artifacts_dir.join(&artifact.elf.file),
                    &artifacts_dir.join(&artifact.verifying_key.file),
                )
                .unwrap_or_else(|error| panic!("artifact {}: {error}", artifact.name));
        }
    }
}
