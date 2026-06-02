//! Build script for SP1 guest artifacts (`guest-asm`, `guest-moho`) used by ASM proof workflows.
//!
//! Compiled ELFs are emitted to `<crate>/elfs/{asm,moho}.elf` regardless of the `docker-build`
//! feature, so consumers can reference a stable path that survives `cargo clean`. Alongside each
//! ELF, the SP1 Groth16 [`PredicateKey`] is derived and written to `<crate>/elfs/<name>-vk.json`
//! as a JSON-encoded `"Sp1Groth16:<hex>"` string — the form the bridge consumes as a trust
//! anchor.
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

/// `(guest_crate_dir, elf_name, vk_json_name)` for every guest this builder produces.
const GUESTS: &[(&str, &str, &str)] = &[
    ("guest-asm", "asm.elf", "asm-vk.json"),
    ("guest-moho", "moho.elf", "moho-vk.json"),
];

fn main() {
    println!("cargo:rerun-if-env-changed=SP1_SKIP_PROGRAM_BUILD");
    println!("cargo:rerun-if-env-changed=SKIP_VKEY_BUILD");
    println!("cargo:warning=exporting SP1 guest ELFs to {ELFS_DIR}");

    if skip_elf_build() {
        println!(
            "cargo:warning=SP1_SKIP_PROGRAM_BUILD set or clippy detected; skipping guest build"
        );
        return;
    }

    // macOS-only: point cc-rs (used by secp256k1-sys etc.) at the SP1 toolchain's llvm-ar,
    // which knows how to package archives for the riscv32im-succinct-zkvm-elf target. macOS's
    // BSD `ar` produces archives that fail to link in the guest; Linux's GNU `ar` is fine, and
    // docker-build runs entirely inside a pinned image so the host's `ar` is irrelevant there.
    #[cfg(target_os = "macos")]
    export_sp1_ar();

    for (guest_dir, elf_name, _) in GUESTS {
        build_guest(guest_dir, elf_name);
    }

    if skip_vkey_build() {
        println!("cargo:warning=SKIP_VKEY_BUILD set; skipping vk JSON emission");
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
    let condition =
        borsh::to_vec(&verifier).expect("borsh-encoding SP1 Groth16 verifier is infallible");
    PredicateKey::new(PredicateTypeId::Sp1Groth16, condition)
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

/// Returns `true` when `SKIP_VKEY_BUILD` is set, suppressing vk emission.
fn skip_vkey_build() -> bool {
    std::env::var("SKIP_VKEY_BUILD")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}

/// Returns `true` when sp1-build itself would skip the build — under
/// `SP1_SKIP_PROGRAM_BUILD=true` or `cargo clippy`.
fn skip_elf_build() -> bool {
    let skip_env = std::env::var("SP1_SKIP_PROGRAM_BUILD")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let is_clippy = std::env::var("RUSTC_WORKSPACE_WRAPPER")
        .map(|v| v.contains("clippy-driver"))
        .unwrap_or(false);
    skip_env || is_clippy
}
