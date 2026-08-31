//! Compiles the node protocol source into Rust types at build time.
//!
//! `protox` is a pure-Rust protobuf compiler, so building this crate does not
//! require a `protoc` binary on the machine or in CI. See `proto/README.md`.

use std::path::{Path, PathBuf};

const PROTO_FILES: &[&str] = ["fleet/node/v1/node.proto"].as_slice();

fn main() {
    let proto_root = proto_root();
    let sources = PROTO_FILES
        .iter()
        .map(|file| proto_root.join(file))
        .collect::<Vec<_>>();

    for source in &sources {
        println!("cargo:rerun-if-changed={}", source.display());
    }

    let descriptors = protox::compile(&sources, [&proto_root])
        .unwrap_or_else(|error| panic!("the node protocol source must compile: {error}"));

    let mut config = prost_build::Config::new();
    config.skip_protoc_run();
    config
        .compile_fds(descriptors)
        .unwrap_or_else(|error| panic!("the node protocol descriptors must generate: {error}"));
}

fn proto_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the protocol crate lives two directories below the repository root")
        .join("proto")
}
