// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(clippy::pedantic)]

#[cfg(feature = "nss")]
mod nss {
    use std::{
        collections::HashMap,
        env, fs,
        path::{Path, PathBuf},
        process::Command,
    };

    use bindgen::Builder;
    use serde_derive::Deserialize;

    const BINDINGS_DIR: &str = "bindings";
    const BINDINGS_CONFIG: &str = "bindings.toml";

    // This is the format of a single section of the configuration file.
    #[derive(Deserialize)]
    struct Bindings {
        /// types that are explicitly included
        #[serde(default)]
        types: Vec<String>,
        /// functions that are explicitly included
        #[serde(default)]
        functions: Vec<String>,
        /// variables (and `#define`s) that are explicitly included
        #[serde(default)]
        variables: Vec<String>,
        /// types that should be explicitly marked as opaque
        #[serde(default)]
        opaque: Vec<String>,
        /// enumerations that are turned into a module (without this, the enum is
        /// mapped using the default, which means that the individual values are
        /// formed with an underscore as `<enum_type>_<enum_value_name>`).
        #[serde(default)]
        enums: Vec<String>,

        /// Any item that is specifically excluded; if none of the types, functions,
        /// or variables fields are specified, everything defined will be mapped,
        /// so this can be used to limit that.
        #[serde(default)]
        exclude: Vec<String>,

        /// Whether the file is to be interpreted as C++
        #[serde(default)]
        cplusplus: bool,
    }

    fn is_debug() -> bool {
        env::var("DEBUG")
            .map(|d| d.parse::<bool>().unwrap_or(false))
            .unwrap_or(false)
    }

    // bindgen needs access to libclang.
    // On windows, this doesn't just work, you have to set LIBCLANG_PATH.
    // Rather than download the 400Mb+ files, like gecko does, let's just reuse their work.
    fn setup_clang() {
        if env::consts::OS != "windows" {
            return;
        }
        println!("rerun-if-env-changed=LIBCLANG_PATH");
        println!("rerun-if-env-changed=MOZBUILD_STATE_PATH");
        if env::var("LIBCLANG_PATH").is_ok() {
            return;
        }
        let mozbuild_root = if let Ok(dir) = env::var("MOZBUILD_STATE_PATH") {
            PathBuf::from(dir.trim())
        } else {
            eprintln!("warning: Building without a gecko setup is not likely to work.");
            eprintln!("         A working libclang is needed to build neqo.");
            eprintln!("         Either LIBCLANG_PATH or MOZBUILD_STATE_PATH needs to be set.");
            eprintln!();
            eprintln!("    We recommend checking out https://github.com/mozilla/gecko-dev");
            eprintln!("    Then run `./mach bootstrap` which will retrieve clang.");
            eprintln!("    Make sure to export MOZBUILD_STATE_PATH when building.");
            return;
        };
        let libclang_dir = mozbuild_root.join("clang").join("lib");
        if libclang_dir.is_dir() {
            env::set_var("LIBCLANG_PATH", libclang_dir.to_str().unwrap());
            println!("rustc-env:LIBCLANG_PATH={}", libclang_dir.to_str().unwrap());
        } else {
            println!("warning: LIBCLANG_PATH isn't set; maybe run ./mach bootstrap with gecko");
        }
    }

    fn nss_dir() -> Option<PathBuf> {
        // Note that this returns a relative path because UNC
        // paths on windows cause certain tools to explode.
        env::var("NSS_DIR").ok().map(|dir| {
            let dir = PathBuf::from(dir.trim());
            assert!(dir.is_dir());
            dir
        })
    }

    fn get_bash() -> PathBuf {
        // When running under MOZILLABUILD, we need to make sure not to invoke
        // another instance of bash that might be sitting around (like WSL).
        match env::var("MOZILLABUILD") {
            Ok(d) => PathBuf::from(d).join("msys").join("bin").join("bash.exe"),
            Err(_) => PathBuf::from("bash"),
        }
    }

    fn run_build_script(dir: &Path) {
        let mut build_nss = vec![
            String::from("./build.sh"),
            String::from("-Ddisable_tests=1"),
        ];
        if is_debug() {
            build_nss.push(String::from("--static"));
        } else {
            build_nss.push(String::from("-o"));
        }
        if let Ok(d) = env::var("NSS_JOBS") {
            build_nss.push(String::from("-j"));
            build_nss.push(d);
        }
        let status = Command::new(get_bash())
            .args(build_nss)
            .current_dir(dir)
            .status()
            .expect("couldn't start NSS build");
        assert!(status.success(), "NSS build failed");
    }

    fn nspr_libs() -> Vec<&'static str> {
        if env::consts::OS == "windows" {
            vec!["libplds4", "libplc4", "libnspr4"]
        } else {
            vec!["plds4", "plc4", "nspr4"]
        }
    }

    fn dynamic_link() {
        let mut libs = if env::consts::OS == "windows" {
            vec!["nssutil3.dll", "nss3.dll"]
        } else {
            vec!["nssutil3", "nss3"]
        };

        libs.append(&mut nspr_libs());

        for lib in &libs {
            println!("cargo:rustc-link-lib=dylib={lib}");
        }
    }

    fn static_softoken_libs(nsslibdir: &Path) -> Vec<&'static str> {
        let mut static_libs = vec!["pk11wrap_static", "softokn_static", "freebl_static"];

        // NSS optionally builds platform-specific acceleration libraries as
        // separate static libraries.
        let accel_libs = &[
            "gcm-aes-x86_c_lib",
            "sha-x86_c_lib",
            "hw-acc-crypto-avx",
            "hw-acc-crypto-avx2",
            "armv8_c_lib",
            "gcm-aes-arm32-neon_c_lib",
            "gcm-aes-aarch64_c_lib",
            // NOTE: The intel-gcm-* libraries are already automatically
            //       included in freebl_static as source files.
        ];

        // Build rules are complex, so simply check the lib directory to see if
        // any of the accelerator libraries were built to decide what to
        // include. Check different variations of the filename to handle
        // platform differences.
        for libname in accel_libs {
            let filename = if env::consts::OS == "windows" {
                format!("{libname}.lib")
            } else {
                format!("lib{libname}.a")
            };
            if nsslibdir.join(filename).is_file() {
                static_libs.push(libname);
            }
        }

        static_libs
    }

    fn static_link(nsslibdir: &Path, use_static_softoken: bool, use_static_nspr: bool) {
        // The ordering of these libraries is critical for the linker.
        let mut static_libs = vec!["cryptohi", "nss_static"];
        let mut dynamic_libs = vec![];

        if use_static_softoken {
            // Statically link pk11/softokn/freebl
            static_libs.append(&mut static_softoken_libs(nsslibdir));
        } else {
            // Use dlopen to get softokn3.so
            static_libs.push("pk11wrap");
        }

        static_libs.extend_from_slice(&["nsspki", "nssdev", "nssb", "certhi", "certdb", "nssutil"]);

        if use_static_nspr {
            static_libs.append(&mut nspr_libs());
        } else {
            dynamic_libs.append(&mut nspr_libs());
        }

        if cfg!(not(feature = "external-sqlite")) && env::consts::OS != "macos" {
            static_libs.push("sqlite");
        }

        // Dynamic libs that aren't transitively included by NSS libs.
        if env::consts::OS != "windows" {
            dynamic_libs.extend_from_slice(&["pthread", "dl", "c", "z"]);
        }
        if cfg!(not(feature = "external-sqlite")) && env::consts::OS == "macos" {
            dynamic_libs.push("sqlite3");
        }

        for lib in &static_libs {
            println!("cargo:rustc-link-lib=static={lib}");
        }
        for lib in &dynamic_libs {
            println!("cargo:rustc-link-lib=dylib={lib}");
        }
    }

    fn get_includes(nsstarget: &Path, nssdist: &Path) -> Vec<PathBuf> {
        let nsprinclude = nsstarget.join("include").join("nspr");
        let nssinclude = nssdist.join("public").join("nss");
        let includes = vec![nsprinclude, nssinclude];
        for i in &includes {
            println!("cargo:include={}", i.to_str().unwrap());
        }
        includes
    }

    fn build_bindings(base: &str, bindings: &Bindings, flags: &[String]) {
        let suffix = if bindings.cplusplus { ".hpp" } else { ".h" };
        let header_path = PathBuf::from(BINDINGS_DIR).join(String::from(base) + suffix);
        let header = header_path.to_str().unwrap();
        let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join(String::from(base) + ".rs");

        println!("cargo:rerun-if-changed={header}");

        let mut builder = Builder::default().header(header);
        builder = builder.generate_comments(false);
        builder = builder.size_t_is_usize(true);

        builder = builder.clang_arg("-v");

        builder = builder.clang_arg("-DNO_NSPR_10_SUPPORT");
        if env::consts::OS == "windows" {
            builder = builder.clang_arg("-DWIN");
        } else if env::consts::OS == "macos" {
            builder = builder.clang_arg("-DDARWIN");
        } else if env::consts::OS == "linux" {
            builder = builder.clang_arg("-DLINUX");
        } else if env::consts::OS == "android" {
            builder = builder.clang_arg("-DLINUX");
            builder = builder.clang_arg("-DANDROID");
        }
        if bindings.cplusplus {
            builder = builder.clang_args(&["-x", "c++", "-std=c++11"]);
        }

        builder = builder.clang_args(flags);

        // Apply the configuration.
        for v in &bindings.types {
            builder = builder.allowlist_type(v);
        }
        for v in &bindings.functions {
            builder = builder.allowlist_function(v);
        }
        for v in &bindings.variables {
            builder = builder.allowlist_var(v);
        }
        for v in &bindings.exclude {
            builder = builder.blocklist_item(v);
        }
        for v in &bindings.opaque {
            builder = builder.opaque_type(v);
        }
        for v in &bindings.enums {
            builder = builder.constified_enum_module(v);
        }

        let bindings = builder.generate().expect("unable to generate bindings");
        bindings
            .write_to_file(out)
            .expect("couldn't write bindings");
    }

    fn build_nss(nss: &Path) -> Vec<String> {
        setup_clang();

        run_build_script(nss);

        // $NSS_DIR/../dist/
        let nssdist = nss.parent().unwrap().join("dist");
        println!("cargo:rerun-if-env-changed=NSS_TARGET");
        let nsstarget = env::var("NSS_TARGET")
            .unwrap_or_else(|_| fs::read_to_string(nssdist.join("latest")).unwrap());
        let nsstarget = nssdist.join(nsstarget.trim());

        let includes = get_includes(&nsstarget, &nssdist);

        let nsslibdir = nsstarget.join("lib");
        println!(
            "cargo:rustc-link-search=native={}",
            nsslibdir.to_str().unwrap()
        );
        if is_debug() {
            let use_static_softoken = true;
            let use_static_nspr = true;
            static_link(&nsslibdir, use_static_softoken, use_static_nspr);
        } else {
            dynamic_link();
        }

        let mut flags: Vec<String> = Vec::new();
        for i in includes {
            flags.push(String::from("-I") + i.to_str().unwrap());
        }

        flags
    }

    fn pkg_config() -> Vec<String> {
        let modversion = Command::new("pkg-config")
            .args(["--modversion", "nss"])
            .output()
            .expect("pkg-config reports NSS as absent")
            .stdout;
        let modversion_str = String::from_utf8(modversion).expect("non-UTF8 from pkg-config");
        let mut v = modversion_str.split('.');
        assert_eq!(
            v.next(),
            Some("3"),
            "NSS version 3.62 or higher is needed (or set $NSS_DIR)"
        );
        if let Some(minor) = v.next() {
            let minor = minor
                .trim_end()
                .parse::<u32>()
                .expect("NSS minor version is not a number");
            assert!(
                minor >= 62,
                "NSS version 3.62 or higher is needed (or set $NSS_DIR)",
            );
        }

        let cfg = Command::new("pkg-config")
            .args(["--cflags", "--libs", "nss"])
            .output()
            .expect("NSS flags not returned by pkg-config")
            .stdout;
        let cfg_str = String::from_utf8(cfg).expect("non-UTF8 from pkg-config");

        let mut flags: Vec<String> = Vec::new();
        for f in cfg_str.split(' ') {
            if let Some(include) = f.strip_prefix("-I") {
                flags.push(String::from(f));
                println!("cargo:include={include}");
            } else if let Some(path) = f.strip_prefix("-L") {
                println!("cargo:rustc-link-search=native={path}");
            } else if let Some(lib) = f.strip_prefix("-l") {
                println!("cargo:rustc-link-lib=dylib={lib}");
            } else {
                println!("Warning: Unknown flag from pkg-config: {f}");
            }
        }

        flags
    }

    #[cfg(feature = "gecko")]
    fn setup_for_gecko() -> Vec<String> {
        use mozbuild::{
            config::{BINDGEN_SYSTEM_FLAGS, NSPR_CFLAGS, NSS_CFLAGS},
            TOPOBJDIR,
        };

        let mut flags: Vec<String> = Vec::new();

        let fold_libs = mozbuild::config::MOZ_FOLD_LIBS;
        let libs = if fold_libs {
            vec!["nss3"]
        } else {
            vec!["nssutil3", "nss3", "ssl3", "plds4", "plc4", "nspr4"]
        };

        for lib in &libs {
            println!("cargo:rustc-link-lib=dylib={}", lib);
        }

        if fold_libs {
            println!(
                "cargo:rustc-link-search=native={}",
                TOPOBJDIR.join("security").to_str().unwrap()
            );
        } else {
            println!(
                "cargo:rustc-link-search=native={}",
                TOPOBJDIR.join("dist").join("bin").to_str().unwrap()
            );
            let nsslib_path = TOPOBJDIR.join("security").join("nss").join("lib");
            println!(
                "cargo:rustc-link-search=native={}",
                nsslib_path.join("nss").join("nss_nss3").to_str().unwrap()
            );
            println!(
                "cargo:rustc-link-search=native={}",
                nsslib_path.join("ssl").join("ssl_ssl3").to_str().unwrap()
            );
            println!(
                "cargo:rustc-link-search=native={}",
                TOPOBJDIR
                    .join("config")
                    .join("external")
                    .join("nspr")
                    .join("pr")
                    .to_str()
                    .unwrap()
            );
        }

        flags = BINDGEN_SYSTEM_FLAGS
            .iter()
            .chain(&NSPR_CFLAGS)
            .chain(&NSS_CFLAGS)
            .map(|s| s.to_string())
            .collect();

        flags.push(String::from("-include"));
        flags.push(
            TOPOBJDIR
                .join("dist")
                .join("include")
                .join("mozilla-config.h")
                .to_str()
                .unwrap()
                .to_string(),
        );
        flags
    }

    #[cfg(not(feature = "gecko"))]
    fn setup_for_gecko() -> Vec<String> {
        unreachable!()
    }

    #[cfg(feature = "app-svc")]
    fn setup_for_app_svc() -> Vec<String> {
        // Locate the NSS libraries that application_services is using.
        // NOTE: This directory has a slightly different layout than then normal
        //       'dist' directory that NSS builds output.
        let nss_dir = nss_dir().expect("NSS_DIR env must be set for app_svc builds");
        if !nss_dir.exists() {
            eprintln!(
                "NSS_DIR path (obtained via `env`) does not exist: {}",
                nss_dir.display()
            );
            panic!("It looks like NSS is not built. Please run `libs/verify-[platform]-environment.sh` in application-services first!");
        }

        let lib_dir = nss_dir.join("lib");
        println!(
            "cargo:rustc-link-search=native={}",
            lib_dir.to_string_lossy()
        );

        // For app_svc builds, we use static linking of NSS.
        let use_static_softoken = true;
        let use_static_nspr = true;
        static_link(&lib_dir, use_static_softoken, use_static_nspr);

        let include_dir = nss_dir.join("include");
        println!("cargo:include={}", include_dir.to_string_lossy());

        vec![String::from("-I") + &include_dir.join("nss").to_string_lossy()]
    }

    #[cfg(not(feature = "app-svc"))]
    fn setup_for_app_svc() -> Vec<String> {
        unreachable!()
    }

    pub fn build() {
        println!("cargo:rerun-if-env-changed=NSS_DIR");
        let flags = if cfg!(feature = "gecko") {
            setup_for_gecko()
        } else if cfg!(feature = "app-svc") {
            setup_for_app_svc()
        } else {
            nss_dir().map_or_else(pkg_config, |nss| build_nss(&nss))
        };

        let config_file = PathBuf::from(BINDINGS_DIR).join(BINDINGS_CONFIG);
        println!("cargo:rerun-if-changed={}", config_file.to_str().unwrap());
        let config = fs::read_to_string(config_file).expect("unable to read binding configuration");
        let config: HashMap<String, Bindings> = ::toml::from_str(&config).unwrap();

        for (k, v) in &config {
            build_bindings(k, v, &flags[..]);
        }
    }
}

fn main() {
    #[cfg(feature = "nss")]
    nss::build();
}
