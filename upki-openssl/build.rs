use std::env;
use std::path::PathBuf;

use cbindgen::Language;

fn main() {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_language(Language::C)
        .with_sys_include("openssl/x509_vfy.h")
        .with_include_guard("UPKI_OPENSSL_H")
        .generate()
        .expect("unable to generate bindings")
        .write_to_file(crate_dir.join("upki-openssl.h"));
}
