use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let staticlib_path = out_dir.join("xorany_obf_rt_opacity.rs");
    fs::write(&staticlib_path, OPACITY_STATICLIB).expect("write opacity staticlib source");

    let target = env::var("TARGET").expect("TARGET env var not set by cargo");
    let host = env::var("HOST").expect("HOST env var not set by cargo");
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    let is_release = profile == "release";
    let crate_name = "xorany_obf_rt";

    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let mut cmd = Command::new(&rustc);
    cmd.arg("--crate-type=staticlib")
        .arg("--crate-name")
        .arg(crate_name)
        .arg("--edition=2021")
        .arg("-C").arg("opt-level=1")
        .arg("-C").arg("codegen-units=1")
        .arg("--out-dir").arg(&out_dir);

    if is_release {
        cmd.arg("-C").arg("debuginfo=0");
    }
    if target != host {
        cmd.arg("--target").arg(&target);
    }
    if let Ok(flags) = env::var("CARGO_ENCODED_RUSTFLAGS") {
        for f in flags.split('\x1f').filter(|s| !s.is_empty()) {
            cmd.arg(f);
        }
    }
    cmd.arg(&staticlib_path);

    let status = cmd.status().expect("xorany: failed to invoke rustc");
    assert!(status.success(), "xorany: opacity staticlib build failed");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static={crate_name}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
}

const OPACITY_STATICLIB: &str = r#"
#![allow(dead_code, unused_imports)]

use core::hint::black_box;

#[inline(always)]
fn make_opaque(mut v: usize) -> usize {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"))]
    unsafe {
        core::arch::asm!("/* {0} */", inout(reg) v, options(nostack, preserves_flags));
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    { v = black_box(v); }
    v
}

#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __xorany_seed() {}

#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __xorany_x() -> usize { make_opaque(0) }

#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn __xorany_y() -> usize { make_opaque(0) }
"#;
