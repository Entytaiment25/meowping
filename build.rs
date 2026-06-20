fn main() {
    #[cfg(windows)]
    {
        use std::env;
        use std::fs;
        use std::path::Path;

        let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();
        let resource_header = Path::new(&manifest_dir).join("versions.h");
        let major = env!("CARGO_PKG_VERSION_MAJOR");
        let minor = env!("CARGO_PKG_VERSION_MINOR");
        let patch = env!("CARGO_PKG_VERSION_PATCH");
        let full = env!("CARGO_PKG_VERSION");
        let description = env!("CARGO_PKG_DESCRIPTION");
        let author = env!("CARGO_PKG_AUTHORS");
        let name = env!("CARGO_PKG_NAME");

        fs::write(
            &resource_header,
            format!(
                "#define VERSION_MAJOR {major}\n\
                 #define VERSION_MINOR {minor}\n\
                 #define VERSION_PATCH {patch}\n\
                 #define VERSION_FULL \"{full}\"\n\
                 #define VERSION_DESCRIPTION \"{description}\"\n\
                 #define VERSION_AUTHOR \"{author}\"\n\
                 #define VERSION_NAME \"{name}\"\n"
            ),
        )
        .unwrap();

        embed_resource::compile("resources.rc", embed_resource::NONE)
            .manifest_optional()
            .unwrap();
    }
}
