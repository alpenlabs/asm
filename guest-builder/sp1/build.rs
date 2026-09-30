//! Build script for the SP1 ASM guest (`guest-asm`) used by ASM proof workflows.
//!
//! The compiled ELF is emitted to `<crate>/elfs/asm.elf` regardless of the `docker-build`
//! feature, so consumers can reference a stable path that survives `cargo clean`. Alongside the
//! ELF, two plain-text files are derived from the guest's vk:
//!
//! - `<crate>/elfs/asm-predicate.txt` holds the SP1 Groth16 [`PredicateKey`] in its `Display` form,
//!   `Sp1Groth16:<hex>`. The bridge uses it as the trust anchor for ASM proofs.
//! - `<crate>/elfs/asm-vkey-hash.txt` holds SP1's program vkey hash as `0x<hex>`. It is the same
//!   value `cargo prove vkey` prints, so anyone can check it against the ELF.
//!
//! The Moho recursive proof guest is built and released by the moho repo. Fetch its ELF
//! into the same directory with `contrib/fetch_moho_artifacts.sh`.
//!
//! # Environment
//!
//! Both steps are off by default and opt-in, because both are slow and most builds of this
//! workspace only need the crate to compile. The files in `<crate>/elfs/` survive `cargo clean`,
//! so a build that skips these steps still leaves whatever was built earlier in place.
//!
//! - **`BUILD_ELF`** — set to `1`/`true` to compile the guest program. Ignored under `cargo
//!   clippy`, which only needs the crate to typecheck.
//! - **`BUILD_VKEY`** — set to `1`/`true` to derive the guest's vk and write the predicate and vkey
//!   hash files. Requires the ELF to exist, so it implies `BUILD_ELF`.
//!
//! # Features
//!
//! - **`docker-build`** — when enabled, the guest program is compiled inside Docker via
//!   `build_program_with_args` instead of locally. The output location is unchanged.

use std::{fs, path::Path};

use sp1_build::{build_program_with_args, BuildArgs};
use sp1_sdk::{
    blocking::{Prover, ProverClient},
    HashableKey, ProvingKey, SP1VerifyingKey,
};
use sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES};
use strata_predicate::{PredicateKey, PredicateTypeId};
use zkaleido_sp1_groth16_verifier::SP1Groth16Verifier;

const ELFS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/elfs");

const GUEST_DIR: &str = "guest-asm";
const ELF_NAME: &str = "asm.elf";
const PREDICATE_NAME: &str = "asm-predicate.txt";
const VKEY_HASH_NAME: &str = "asm-vkey-hash.txt";

fn main() {
    println!("cargo:rerun-if-env-changed=BUILD_ELF");
    println!("cargo:rerun-if-env-changed=BUILD_VKEY");

    // clippy only needs the crate to typecheck, so it never builds the guest whatever is set.
    if is_clippy() {
        return;
    }

    // Deriving the vk reads the ELF back off disk, so asking for the vk implies building the ELF.
    let build_vkey = is_enabled("BUILD_VKEY");
    if !is_enabled("BUILD_ELF") && !build_vkey {
        println!("cargo:warning=BUILD_ELF/BUILD_VKEY unset; skipping SP1 guest build");
        return;
    }

    println!("cargo:warning=exporting SP1 guest ELF to {ELFS_DIR}");

    // macOS-only: point cc-rs (used by secp256k1-sys etc.) at the SP1 toolchain's llvm-ar,
    // which knows how to package archives for the riscv32im-succinct-zkvm-elf target. macOS's
    // BSD `ar` produces archives that fail to link in the guest; Linux's GNU `ar` is fine, and
    // docker-build runs entirely inside a pinned image so the host's `ar` is irrelevant there.
    #[cfg(target_os = "macos")]
    export_sp1_ar();

    build_guest(GUEST_DIR, ELF_NAME);

    if build_vkey {
        emit_vkey(ELF_NAME, PREDICATE_NAME, VKEY_HASH_NAME);
    }
}

fn build_guest(guest_dir: &str, elf_name: &str) {
    let build_args = BuildArgs {
        output_directory: Some(ELFS_DIR.to_owned()),
        elf_name: Some(elf_name.to_owned()),
        #[cfg(feature = "docker-build")]
        docker: true,
        #[cfg(feature = "docker-build")]
        workspace_directory: Some("../../".to_owned()),
        ..BuildArgs::default()
    };
    build_program_with_args(guest_dir, build_args);
}

/// Derives the guest's vk from the freshly built ELF and writes the `Sp1Groth16:<hex>` predicate
/// and the `0x<hex>` program vkey hash to `<ELFS_DIR>`.
fn emit_vkey(elf_name: &str, predicate_name: &str, vkey_hash_name: &str) {
    let elf_path = Path::new(ELFS_DIR).join(elf_name);
    let elf = fs::read(&elf_path)
        .unwrap_or_else(|e| panic!("read built ELF {}: {e}", elf_path.display()));

    let vk = program_vkey(&elf);
    let predicate_key = sp1_groth16_predicate_key(vk.bytes32_raw());

    write_elfs_file(predicate_name, &predicate_key.to_string());
    write_elfs_file(vkey_hash_name, &vk.bytes32());
}

fn program_vkey(elf: &[u8]) -> SP1VerifyingKey {
    let prover = ProverClient::builder().cpu().build();
    let pk = prover
        .setup(elf.to_vec().into())
        .unwrap_or_else(|e| panic!("sp1 key setup: {e}"));
    pk.verifying_key().clone()
}

/// Writes `contents` to `<ELFS_DIR>/<name>`.
fn write_elfs_file(name: &str, contents: &str) {
    let path = Path::new(ELFS_DIR).join(name);
    fs::write(&path, contents).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    println!("cargo:warning=wrote {}", path.display());
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
