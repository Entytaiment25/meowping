#[cfg(windows)]
extern crate windres;

fn main() {
    #[cfg(windows)]
    windows::compile_resources_file();
}

#[cfg(windows)]
mod windows {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use windres::Build;

    pub fn compile_resources_file() {
        println!("cargo:rerun-if-changed=resources.rc");

        let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
        let resource_header = out_dir.join("versions.h");
        let major = env!("CARGO_PKG_VERSION_MAJOR");
        let minor = env!("CARGO_PKG_VERSION_MINOR");
        let patch = env!("CARGO_PKG_VERSION_PATCH");
        let full = env!("CARGO_PKG_VERSION");
        let description = env!("CARGO_PKG_DESCRIPTION");
        let author = env!("CARGO_PKG_AUTHORS");
        let name = env!("CARGO_PKG_NAME");

        fs::write(
            resource_header,
            format!(
                "
    #define VERSION_MAJOR {major}
    #define VERSION_MINOR {minor}
    #define VERSION_PATCH {patch}
    #define VERSION_FULL \"{full}\"
    #define VERSION_DESCRIPTION  \"{description}\"
    #define VERSION_AUTHOR  \"{author}\"
    #define VERSION_NAME \"{name}\"
    "
            ),
        )
        .unwrap();

        if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu") {
            compile_gnu_resources(&out_dir);
        } else {
            Build::new()
                .include(&out_dir)
                .compile("resources.rc")
                .unwrap();
        }
    }

    fn compile_gnu_resources(out_dir: &Path) {
        let resource_object = out_dir.join("resources.o");
        let windres = env::var_os("WINDRES").unwrap_or_else(|| "x86_64-w64-mingw32-windres".into());

        let status = Command::new(&windres)
            .arg("-I")
            .arg(out_dir)
            .arg("-i")
            .arg("resources.rc")
            .arg("-o")
            .arg(&resource_object)
            .arg("-O")
            .arg("coff")
            .status()
            .unwrap_or_else(|error| panic!("failed to run {:?}: {error}", windres));

        assert!(status.success(), "windres exited with {status}");

        println!("cargo:rustc-link-arg={}", resource_object.display());
    }
}
