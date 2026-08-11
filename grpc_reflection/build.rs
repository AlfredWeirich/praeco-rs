//! build.rs
//!
//! This script is executed by Cargo *before* the main code is compiled.
//! For gRPC applications, this is the standard place to instruct the `tonic-build`
//! crate to parse your `.proto` schema files and automatically generate the
//! corresponding Rust structs, client stubs, and server traits.
use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `OUT_DIR` is an environment variable provided by Cargo. It points to a
    // temporary directory inside `target/` where build scripts are allowed
    // to write generated files. We should never write generated code to `src/`.
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Configure the Tonic Protobuf compiler
    tonic_build::configure()
        // IMPORTANT FOR REFLECTION:
        // By default, tonic only generates Rust code (.rs files).
        // However, gRPC Server Reflection requires the raw layout of the schema
        // exactly as it was defined, stored as a binary "Descriptor Set".
        .file_descriptor_set_path(out_dir.join("system_services_descriptor.bin"))
        // Finally, compile the actual proto file located in our project, as well as the reflection proto
        .compile_protos(
            &[
                "proto/system_services.proto",
                "proto/reflection/v1/reflection.proto",
            ],
            &["proto"],
        )?;

    Ok(())
}
