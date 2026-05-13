#![cfg(feature = "capi")]

use std::path::PathBuf;
use std::{env, fs};

use cbindgen::{Builder, Language};

#[test]
fn generate_header() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let header = crate_dir.join("upki.h");
    let old = fs::read_to_string(&header).unwrap();

    Builder::new()
        .with_crate(&crate_dir)
        .with_language(Language::C)
        .with_include_guard("UPKI_H")
        .generate()
        .expect("unable to generate bindings")
        .write_to_file(&header);

    let new = fs::read_to_string(&header).unwrap();
    similar_asserts::assert_eq!(
        old.replace('\r', ""),
        new.replace('\r', ""),
        "Generated header file has changed. Please review the changes and update the snapshot if they are expected."
    );
}
