#!/bin/sh
# Build the `upki-openssl` C FFI artifacts for the target dist requested, then
# stage them in this directory where dist collects them (the cdylib named in
# dist.toml's `cdylibs`, and the headers named in `include`).
set -eu

target="${CARGO_DIST_TARGET:?CARGO_DIST_TARGET must be set by dist}"

# cargo-c builds the cdylib (and would generate the header, but ours is checked
# in and `capi.header.generation = false`). Build against the workspace and
# select the `upki-openssl` package; outputs land in ../target/<triple>/release/.
cargo cbuild \
    --manifest-path ../../Cargo.toml \
    --package upki-openssl \
    --release \
    --target "$target" \
    --library-type cdylib

out="../../target/$target/release"
case "$target" in
    *-apple-*)
        cp "$out/libupki_openssl.dylib" .
        # cargo-c bakes in an absolute /usr/local install name; use @rpath so
        # consumers control lookup (and dist's linkage check doesn't trip over
        # the nonexistent path). Re-sign: install_name_tool invalidates the
        # ad-hoc signature, which makes the dylib unloadable on arm64.
        install_name_tool -id @rpath/libupki_openssl.dylib libupki_openssl.dylib
        codesign -f -s - libupki_openssl.dylib
        ;;
    *)         cp "$out/libupki_openssl.so" . ;;
esac

# Stage the headers for `include`. upki-openssl.h includes upki.h, so ship both
# to keep the archive self-contained.
cp ../../upki-openssl/upki-openssl.h .
cp ../../upki/upki.h .
