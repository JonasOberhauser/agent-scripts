use std::path::PathBuf;

fn main() {
    let sysroot = rustc_sysroot();
    // Link against this toolchain's rustc_private libraries...
    println!("cargo:rustc-link-search=native={}/lib", sysroot.display());
    // ...and embed the directory as a runtime loader path (rpath), so the
    // binary works as RUSTC_WRAPPER without any LD_LIBRARY_PATH setup.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}/lib", sysroot.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=USCOPE_SYSROOT");
}

/// Sysroot of the toolchain compiling THIS binary (not the wrapped one).
fn rustc_sysroot() -> PathBuf {
    std::env::var_os("USCOPE_SYSROOT")
        .map(PathBuf::from)
        .or_else(|| {
            let out = std::process::Command::new("rustc")
                .args(["--print", "sysroot"])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            Some(PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string()))
        })
        .expect("failed to determine rustc sysroot")
}
