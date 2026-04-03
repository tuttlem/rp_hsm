//! Set up linker scripts for the rp235x-hal examples

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    if let Err(err) = run() {
        eprintln!("build script failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    // Put the linker script somewhere the linker can find it
    let out_dir =
        std::env::var_os("OUT_DIR").ok_or_else(|| "OUT_DIR environment variable missing".to_string())?;
    let out = PathBuf::from(out_dir);
    println!("cargo:rustc-link-search={}", out.display());

    // The file `memory.x` is loaded by cortex-m-rt's `link.x` script, which
    // is what we specify in `.cargo/config.toml` for Arm builds
    let memory_x = include_bytes!("memory.x");
    let mut f = File::create(out.join("memory.x"))
        .map_err(|err| format!("failed to create memory.x: {err}"))?;
    f.write_all(memory_x)
        .map_err(|err| format!("failed to write memory.x: {err}"))?;
    println!("cargo:rerun-if-changed=memory.x");

    // The file `rp235x_riscv.x` is what we specify in `.cargo/config.toml` for
    // RISC-V builds
    let rp235x_riscv_x = include_bytes!("rp235x_riscv.x");
    let mut f = File::create(out.join("rp235x_riscv.x"))
        .map_err(|err| format!("failed to create rp235x_riscv.x: {err}"))?;
    f.write_all(rp235x_riscv_x)
        .map_err(|err| format!("failed to write rp235x_riscv.x: {err}"))?;
    println!("cargo:rerun-if-changed=rp235x_riscv.x");

    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
