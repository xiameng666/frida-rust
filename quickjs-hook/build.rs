use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let src_path = PathBuf::from(&manifest_dir).join("src");
    let target = env::var("TARGET").unwrap_or_default();

    // For Android cross-compilation, derive sysroot from CC env var
    let android_clang_args: Vec<String> = if target.contains("android") {
        let cc_key = format!("CC_{}", target.replace('-', "_"));
        env::var(&cc_key)
            .ok()
            .and_then(|cc| {
                let cc_path = PathBuf::from(&cc);
                let toolchain = cc_path.parent()?.parent()?;
                let sysroot = toolchain.join("sysroot");
                if sysroot.exists() {
                    let mut args = vec![
                        format!("--sysroot={}", sysroot.display()),
                        "-target".to_string(),
                        target.clone(),
                        // Explicit include paths for Windows libclang cross-compilation
                        format!("-isystem{}", sysroot.join("usr").join("include").display()),
                        format!("-isystem{}", sysroot.join("usr").join("include").join("aarch64-linux-android").display()),
                    ];
                    // Also add LLVM's own resource dir include
                    let llvm_include = toolchain.join("lib").join("clang");
                    if llvm_include.exists() {
                        // Find the version directory (e.g. lib/clang/18/include)
                        if let Ok(entries) = std::fs::read_dir(&llvm_include) {
                            for entry in entries.flatten() {
                                let inc = entry.path().join("include");
                                if inc.exists() {
                                    args.push(format!("-isystem{}", inc.display()));
                                    break;
                                }
                            }
                        }
                    }
                    Some(args)
                } else {
                    None
                }
            })
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Compile hook_engine.c + so_hide.c
    cc::Build::new()
        .file(src_path.join("hook_engine.c"))
        .file(src_path.join("arm64_writer.c"))
        .file(src_path.join("arm64_relocator.c"))
        .file(src_path.join("so_hide.c"))
        .include(&src_path)
        .opt_level(2)
        .flag("-fPIC")
        .flag("-fno-exceptions")
        .warnings(false)
        .compile("hook_engine");

    // Compile QuickJS sources
    let quickjs_src = PathBuf::from(&manifest_dir).join("quickjs-src");
    if quickjs_src.exists() {
        let mut build = cc::Build::new();
        build
            .file(quickjs_src.join("quickjs.c"))
            .file(quickjs_src.join("libregexp.c"))
            .file(quickjs_src.join("libunicode.c"))
            .file(quickjs_src.join("cutils.c"))
            .file(quickjs_src.join("libbf.c"))
            .file(src_path.join("quickjs_wrapper.c"))
            .include(&quickjs_src)
            .include(&src_path)
            .opt_level(2)
            .flag("-fPIC")
            .flag("-fno-exceptions")
            .flag("-DCONFIG_VERSION=\"2024-01-13\"")
            .flag("-DCONFIG_BIGNUM")
            .flag("-D_GNU_SOURCE")
            .warnings(false);

        // Android-specific flags
        if env::var("TARGET").unwrap_or_default().contains("android") {
            build.flag("-DANDROID");
        }

        build.compile("quickjs");

        // Generate bindings for QuickJS + wrapper
        let mut qjs_builder = bindgen::Builder::default()
            .header(quickjs_src.join("quickjs.h").to_string_lossy().to_string())
            .header(src_path.join("quickjs_wrapper.h").to_string_lossy().to_string())
            .clang_arg(format!("-I{}", quickjs_src.display()))
            .clang_arg(format!("-I{}", src_path.display()))
            .clang_arg("-xc");
        for arg in &android_clang_args {
            qjs_builder = qjs_builder.clang_arg(arg);
        }
        let bindings = qjs_builder
            .generate_comments(true)
            .derive_debug(true)
            .derive_default(true)
            .layout_tests(false)
            .allowlist_function("JS_.*")
            .allowlist_function("js_.*")
            .allowlist_function("__JS_.*")
            .allowlist_function("qjs_.*")
            .allowlist_type("JS.*")
            .allowlist_var("JS_.*")
            .use_core()
            .generate()
            .expect("Unable to generate QuickJS bindings");

        bindings
            .write_to_file(out_path.join("quickjs_bindings.rs"))
            .expect("Couldn't write QuickJS bindings!");

        println!("cargo:rustc-link-lib=static=quickjs");
    } else {
        // QuickJS source not found - generate empty bindings
        std::fs::write(
            out_path.join("quickjs_bindings.rs"),
            "// QuickJS source not found - run setup script to download\n"
        ).expect("Failed to write placeholder bindings");

        println!("cargo:warning=QuickJS source not found at {:?}", quickjs_src);
        println!("cargo:warning=Run: cd quickjs-hook && ./setup_quickjs.sh");
    }

    // Generate bindings for hook_engine + so_hide (includes arm64_writer and arm64_relocator)
    let mut hook_builder = bindgen::Builder::default()
        .header(src_path.join("hook_engine.h").to_string_lossy().to_string())
        .header(src_path.join("arm64_writer.h").to_string_lossy().to_string())
        .header(src_path.join("arm64_relocator.h").to_string_lossy().to_string())
        .header(src_path.join("so_hide.h").to_string_lossy().to_string())
        .clang_arg(format!("-I{}", src_path.display()))
        .clang_arg("-xc");
    for arg in &android_clang_args {
        hook_builder = hook_builder.clang_arg(arg);
    }
    let hook_bindings = hook_builder
        .generate_comments(true)
        .derive_debug(true)
        .derive_default(true)
        .layout_tests(false)
        .allowlist_function("hook_.*")
        .allowlist_function("arm64_writer_.*")
        .allowlist_function("arm64_relocator_.*")
        .allowlist_function("so_hide_.*")
        .allowlist_type("Hook.*")
        .allowlist_type("Arm64.*")
        .allowlist_var("ARM64_.*")
        .allowlist_var("SO_HIDE_.*")
        .use_core()
        .generate()
        .expect("Unable to generate hook_engine bindings");

    hook_bindings
        .write_to_file(out_path.join("hook_bindings.rs"))
        .expect("Couldn't write hook_engine bindings!");

    println!("cargo:rustc-link-lib=static=hook_engine");
    if target.contains("android") {
        println!("cargo:rustc-link-lib=log"); // for __android_log_print in hook_engine.c
    }
    println!("cargo:rerun-if-changed=src/hook_engine.c");
    println!("cargo:rerun-if-changed=src/hook_engine.h");
    println!("cargo:rerun-if-changed=src/so_hide.c");
    println!("cargo:rerun-if-changed=src/so_hide.h");
    println!("cargo:rerun-if-changed=src/arm64_writer.c");
    println!("cargo:rerun-if-changed=src/arm64_writer.h");
    println!("cargo:rerun-if-changed=src/arm64_relocator.c");
    println!("cargo:rerun-if-changed=src/arm64_relocator.h");
    println!("cargo:rerun-if-changed=quickjs-src/quickjs.c");
    println!("cargo:rerun-if-changed=quickjs-src/quickjs.h");
    println!("cargo:rerun-if-changed=build.rs");
}
