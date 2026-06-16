use std::path::PathBuf;

fn main() {
    let crate_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"));
    let header = crate_dir
        .join("generated")
        .join("rule_engine")
        .join("yara_bridge.hpp");
    std::fs::create_dir_all(header.parent().expect("generated header has parent"))
        .expect("failed to create generated header directory");

    let config_path = crate_dir.join("cbindgen.toml");
    let config = cbindgen::Config::from_file(&config_path).expect("failed to read cbindgen.toml");
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("failed to generate C++ bridge header")
        .write_to_file(header);

    println!("cargo:rerun-if-changed=cbindgen.toml");
    let source_dir = crate_dir.join("src");
    for entry in std::fs::read_dir(source_dir).expect("failed to read source directory") {
        let entry = entry.expect("failed to read source directory entry");
        if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "rs")
        {
            println!("cargo:rerun-if-changed={}", entry.path().display());
        }
    }
}
