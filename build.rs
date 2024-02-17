#[cfg(windows)]
extern crate windres;

use std::env;
use std::fs;
use std::path::Path;

#[cfg(windows)]
use windres::Build;

#[cfg(windows)]
fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let resource_header = Path::new(&out_dir).join("versions.h");

    // Write include file for resource parameters based on cargo settings
    let major = env!("CARGO_PKG_VERSION_MAJOR");
    let minor = env!("CARGO_PKG_VERSION_MINOR");
    let patch = env!("CARGO_PKG_VERSION_PATCH");
    let full = env!("CARGO_PKG_VERSION");
    let description = env!("CARGO_PKG_DESCRIPTION");
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
#define VERSION_NAME \"{name}\"
"
        ),
    )
    .unwrap();

    Build::new()
        .include(out_dir)
        .compile("resources.rc")
        .unwrap();

    // println!("cargo:rerun-if-changed=resources.rc"); // windres already does this
    //println!("cargo:rerun-if-changed=hank.ico");
    println!("cargo:rerun-if-changed=app.manifest");
}
