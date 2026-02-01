use std::env;
use std::path;

#[cfg(target_arch = "aarch64")]
const CFLAGS: &str = "-fPIC -pie";

#[cfg(not(target_arch = "aarch64"))]
const CFLAGS: &str = "";

fn main() {
    let src_dir = path::PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let xdptools_dir = src_dir.join("xdp-tools");
    let libxdp_dir = xdptools_dir.join("lib/libxdp");
    let xdp_headers_dir = xdptools_dir.join("headers/xdp");

    let libbpf_dir = xdptools_dir.join("lib/libbpf/src");
    let bpf_headers_dir = libbpf_dir.join("root/include");

    let sh = xshell::Shell::new().unwrap();
    {
        let _guard = sh.push_dir(&xdptools_dir);
        let _ = xshell::cmd!(sh, "make clean").run();
    }
    {
        let _guard = sh.push_dir(&xdptools_dir);
        let _guard = sh.push_env("CFLAGS", CFLAGS);
        xshell::cmd!(sh, "make libxdp").run().expect("make libxdp");
    }
    {
        let _guard = sh.push_dir(&libbpf_dir);
        xshell::cmd!(sh, "make").run().expect("make libbpf");
    }

    // Tell Cargo to rerun if any of these files change
    println!("cargo:rerun-if-changed={}", xdptools_dir.display());
    println!("cargo:rerun-if-changed=build.rs");

    println!("cargo:rustc-link-search={}", libxdp_dir.display());
    println!("cargo:rustc-link-search={}", libbpf_dir.display());
    println!("cargo:rustc-link-lib=static=xdp");
    println!("cargo:rustc-link-lib=static=bpf");
    emit_pkg_config_include("libelf");
    println!("cargo:rustc-link-lib=elf");
    emit_pkg_config_include("zlib");
    println!("cargo:rustc-link-lib=z");

    bindgen::Builder::default()
        .header("bindings.h")
        .generate_inline_functions(true)
        .clang_arg(format!("-I{}", bpf_headers_dir.display()))
        .clang_arg(format!("-I{}", xdp_headers_dir.display()))
        .allowlist_var("BPF_.*")
        .allowlist_var("LIBBPF.*")
        .allowlist_var("XDP_.*")
        .allowlist_var("MAX_DISPATCHER_ACTIONS")
        .allowlist_var("XSK_.*")
        .allowlist_var("BTF_.*")
        .allowlist_function("xdp_.*")
        .allowlist_function("libxdp_.*")
        .allowlist_function("xsk_.*")
        .allowlist_function("btf_.*")
        .allowlist_function("bpf_.*")
        .allowlist_type("xsk_.*")
        .allowlist_type("xdp_.*")
        .allowlist_type("bpf_.*")
        .allowlist_type("btf_.*")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(src_dir.join("src/bindings.rs"))
        .expect("Couldn't write bindings");
}

/// from https://github.com/rust-lang/libz-sys/blob/main/build.rs#L42-L65
fn emit_pkg_config_include(lib_name: &str) {
    // Don't print system lib dirs to cargo since this interferes with other
    // packages adding non-system search paths to link against libraries
    // that are also found in a system-wide lib dir.
    let zlib = pkg_config::Config::new()
        .cargo_metadata(true)
        .print_system_libs(false)
        .probe(lib_name);
    match zlib {
        Ok(zlib) => {
            if !zlib.include_paths.is_empty() {
                let paths = zlib
                    .include_paths
                    .iter()
                    .map(|s| s.display().to_string())
                    .collect::<Vec<_>>();
                println!("cargo:include={}", paths.join(","));
            }
        }
        Err(e) => {
            let e = format!("Could not find {lib_name} include paths via pkg-config: {e}");
            for line in e.lines() {
                println!("cargo:warning={line}");
            }
        }
    }
}
