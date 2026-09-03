//! Build script for SP1 guest artifacts (`guest-asm-v0`, `guest-asm`, `guest-moho`) used by ASM
//! proof workflows.
//!
//! There is one ASM guest per specification, not one in total. A guest bakes in the rules it
//! executes, so proving a block requires the artifact for the rules that block ran under — and
//! since the recursive chain re-verifies every step from genesis, every specification the chain has
//! ever run under stays buildable.
//!
//! Compiled ELFs are emitted to `<crate>/elfs/{asm-v0,asm,moho}.elf` regardless of the
//! `docker-build`
//! feature, so consumers can reference a stable path that survives `cargo clean`. Alongside each
//! ELF, the SP1 Groth16 [`PredicateKey`] is derived and written to `<crate>/elfs/<name>-vk.json`
//! as a JSON-encoded `"Sp1Groth16:<hex>"` string — the form the bridge consumes as a trust
//! anchor.
//!
//! # Environment
//!
//! Both steps are off by default and opt-in, because both are slow and most builds of this
//! workspace only need the crate to compile. The ELFs in `<crate>/elfs/` survive `cargo clean`,
//! so a build that skips these steps still leaves whatever was built earlier in place.
//!
//! - **`BUILD_ELF`** — set to `1`/`true` to compile the guest programs. Ignored under `cargo
//!   clippy`, which only needs the crate to typecheck.
//! - **`BUILD_VKEY`** — set to `1`/`true` to derive each guest's vk and write the `*-vk.json`
//!   files. Requires the ELFs to exist, so it implies `BUILD_ELF`.
//! - **`SP1_DOCKER_IMAGE`** — when `docker-build` is enabled, release automation sets this to the
//!   digest-pinned SP1 v6.3.0 builder recorded in the release manifest. A tag-only local build is
//!   useful for development but is not release-qualified.
//!
//! # Features
//!
//! - **`docker-build`** — when enabled, guest programs are compiled inside Docker via
//!   `build_program_with_args` instead of locally. The output location is unchanged.

use std::{fs, path::Path};

use sp1_build::{build_program_with_args, BuildArgs};
use sp1_sdk::{
    blocking::{Prover, ProverClient},
    HashableKey, ProvingKey,
};
use sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES};
use strata_predicate::{PredicateKey, PredicateTypeId};
use zkaleido_sp1_groth16_verifier::SP1Groth16Verifier;

const ELFS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/elfs");
const SP1_BUILD_TAG: &str = "v6.3.0";

/// `(guest_crate_dir, elf_name, vk_json_name)` for every guest this builder produces.
///
/// Entries are added, never edited or removed: an ASM specification the chain has already run under
/// must stay provable forever, so its artifact keeps its place and its name.
const GUESTS: &[(&str, &str, &str)] = &[
    ("guest-asm-v0", "asm-v0.elf", "asm-v0-vk.json"),
    ("guest-asm", "asm.elf", "asm-vk.json"),
    ("guest-moho", "moho.elf", "moho-vk.json"),
];

fn main() {
    println!("cargo:rerun-if-env-changed=BUILD_ELF");
    println!("cargo:rerun-if-env-changed=BUILD_VKEY");
    println!("cargo:rerun-if-env-changed=SP1_DOCKER_IMAGE");

    // clippy only needs the crate to typecheck, so it never builds guests whatever is set.
    if is_clippy() {
        return;
    }

    // Deriving a vk reads the ELF back off disk, so asking for the vk implies building the ELF.
    let build_vkey = is_enabled("BUILD_VKEY");
    if !is_enabled("BUILD_ELF") && !build_vkey {
        println!("cargo:warning=BUILD_ELF/BUILD_VKEY unset; skipping SP1 guest build");
        return;
    }

    println!("cargo:warning=exporting SP1 guest ELFs to {ELFS_DIR}");

    // macOS-only: point cc-rs (used by secp256k1-sys etc.) at the SP1 toolchain's llvm-ar,
    // which knows how to package archives for the riscv32im-succinct-zkvm-elf target. macOS's
    // BSD `ar` produces archives that fail to link in the guest; Linux's GNU `ar` is fine, and
    // docker-build runs entirely inside a pinned image so the host's `ar` is irrelevant there.
    #[cfg(target_os = "macos")]
    export_sp1_ar();

    for (guest_dir, elf_name, _) in GUESTS {
        build_guest(guest_dir, elf_name);
    }

    if !build_vkey {
        return;
    }

    for (_, elf_name, vk_json_name) in GUESTS {
        emit_predicate(elf_name, vk_json_name);
    }
}

fn build_guest(guest_dir: &str, elf_name: &str) {
    let build_args = BuildArgs {
        output_directory: Some(ELFS_DIR.to_owned()),
        elf_name: Some(elf_name.to_owned()),
        tag: SP1_BUILD_TAG.to_owned(),
        locked: true,
        #[cfg(feature = "docker-build")]
        docker: true,
        #[cfg(feature = "docker-build")]
        workspace_directory: Some("../../".to_owned()),
        ..BuildArgs::default()
    };
    build_program_with_args(guest_dir, build_args);
}

/// Derives the `Sp1Groth16:<hex>` predicate from the freshly built ELF and writes it as a
/// JSON-encoded string to `<ELFS_DIR>/<vk_json_name>`.
fn emit_predicate(elf_name: &str, vk_json_name: &str) {
    let elf_path = Path::new(ELFS_DIR).join(elf_name);
    let elf = fs::read(&elf_path)
        .unwrap_or_else(|e| panic!("read built ELF {}: {e}", elf_path.display()));

    let vkey_hash = program_vkey_hash(&elf);
    let predicate_key = sp1_groth16_predicate_key(vkey_hash);
    let json = serde_json::to_string(&predicate_key)
        .unwrap_or_else(|e| panic!("serialize predicate key for {elf_name}: {e}"));

    let out_path = Path::new(ELFS_DIR).join(vk_json_name);
    fs::write(&out_path, json).unwrap_or_else(|e| panic!("write {}: {e}", out_path.display()));
    println!("cargo:warning=wrote {}", out_path.display());
}

fn program_vkey_hash(elf: &[u8]) -> [u8; 32] {
    let prover = ProverClient::builder().cpu().build();
    let pk = prover
        .setup(elf.to_vec().into())
        .unwrap_or_else(|e| panic!("sp1 key setup: {e}"));
    pk.verifying_key().bytes32_raw()
}

fn sp1_groth16_predicate_key(vkey_hash: [u8; 32]) -> PredicateKey {
    let verifier = SP1Groth16Verifier::load(&GROTH16_VK_BYTES, vkey_hash, *VK_ROOT_BYTES, true)
        .unwrap_or_else(|e| panic!("load SP1 Groth16 verifier: {e}"));
    let condition_bytes = verifier.to_uncompressed_bytes();
    PredicateKey::try_new(PredicateTypeId::Sp1Groth16, condition_bytes)
        .expect("SP1 verifier key must be within the predicate condition limit")
}

#[cfg(target_os = "macos")]
fn export_sp1_ar() {
    let sysroot = rustc_succinct(&["--print", "sysroot"]);
    let host = rustc_succinct(&["-vV"])
        .lines()
        .find_map(|l| l.strip_prefix("host: ").map(str::to_owned))
        .expect("rustc +succinct -vV must report a `host:` line");

    let sp1_ar = format!("{sysroot}/lib/rustlib/{host}/bin/llvm-ar");
    std::env::set_var("SP1_AR", &sp1_ar);
    std::env::set_var("AR", &sp1_ar);
    std::env::set_var("AR_riscv64im_unknown_none_elf", &sp1_ar);
}

#[cfg(target_os = "macos")]
fn rustc_succinct(args: &[&str]) -> String {
    let output = std::process::Command::new("rustc")
        .arg("+succinct")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("invoke `rustc +succinct {}`: {e}", args.join(" ")));
    assert!(
        output.status.success(),
        "`rustc +succinct {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("rustc stdout is utf-8")
        .trim()
        .to_owned()
}

fn is_clippy() -> bool {
    std::env::var("RUSTC_WORKSPACE_WRAPPER")
        .map(|v| v.contains("clippy-driver"))
        .unwrap_or(false)
}

/// Reads an opt-in flag: set and equal to `1` or `true` (any case) enables it.
fn is_enabled(var: &str) -> bool {
    std::env::var(var)
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}
