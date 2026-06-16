use std::{
    env, fs,
    path::{Path, PathBuf},
};

use progenitor::{GenerationSettings, Generator, InterfaceStyle, TagStyle};
use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(whatever, display("Error was: {message}"))]
struct Error {
    message: String,
    #[snafu(source(from(Box<dyn std::error::Error>, Some)))]
    source: Option<Box<dyn std::error::Error>>,
}

fn main() -> Result<(), Error> {
    let root_path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/spec/openapi.yaml"));
    println!("cargo:rerun-if-changed={}", root_path.display());

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").whatever_context("OUT_DIR missing")?);
    let generated_path = out_dir.join("progenitor.rs");

    let spec: openapiv3::OpenAPI =
        serde_saphyr::from_reader(fs::File::open(root_path).whatever_context("open spec file")?)
            .whatever_context("parse spec file")?;

    let mut settings = GenerationSettings::default();
    settings
        .with_interface(InterfaceStyle::Builder)
        .with_tag(TagStyle::Merged)
        .with_inner_type(
            "crate::client::ApiHooks"
                .parse()
                .whatever_context("hook type tokens")?,
        )
        .with_pre_hook_async(
            "crate::client::prepare_generated_request"
                .parse()
                .whatever_context("pre-hook tokens")?,
        )
        .with_post_hook_async(
            "crate::client::store_generated_response_cookies"
                .parse()
                .whatever_context("post-hook tokens")?,
        )
        .with_derive("Clone")
        .with_derive("Debug")
        .with_derive("PartialEq");

    let mut generator = Generator::new(&settings);
    let tokens = generator
        .generate_tokens(&spec)
        .whatever_context("generate Progenitor client")?;
    let syntax = syn::parse2(tokens).whatever_context("parse generated Rust tokens")?;
    let content = prettyplease::unparse(&syntax);
    fs::write(generated_path, content).whatever_context("write generated Progenitor client")?;
    Ok(())
}
