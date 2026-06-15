use std::{
    env, fs,
    path::{Path, PathBuf},
};

use progenitor::{GenerationSettings, Generator, InterfaceStyle, TagStyle};
use serde_yaml::{Mapping, Value};

fn main() {
    generate_protobuf();
    generate_openapi_client();
}

fn generate_protobuf() {
    let proto_dir = Path::new("proto");
    let sign_proto = proto_dir.join("sign.proto");
    println!("cargo:rerun-if-changed={}", sign_proto.display());

    let descriptors = protox::compile([sign_proto.as_path()], [proto_dir])
        .expect("compile checked-in protobuf schemas");
    prost_build::Config::new()
        .compile_fds(descriptors)
        .expect("generate protobuf Rust types");
}

fn generate_openapi_client() {
    let spec_dir = Path::new("spec");
    let root_path = spec_dir.join("openapi.yaml");
    let paths_path = spec_dir.join("paths.yaml");
    let components_path = spec_dir.join("components.yaml");

    for path in [&root_path, &paths_path, &components_path] {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    let generated_path = out_dir.join("progenitor.rs");

    let spec = assemble_openapi(&root_path, &paths_path, &components_path)
        .expect("assemble checked-in OpenAPI spec");
    let spec: openapiv3::OpenAPI =
        serde_yaml::from_value(spec).expect("parse checked-in OpenAPI spec");

    let mut settings = GenerationSettings::default();
    settings
        .with_interface(InterfaceStyle::Builder)
        .with_tag(TagStyle::Merged)
        .with_inner_type("crate::client::ApiHooks".parse().expect("hook type tokens"))
        .with_pre_hook_async(
            "crate::client::prepare_generated_request"
                .parse()
                .expect("pre-hook tokens"),
        )
        .with_post_hook_async(
            "crate::client::store_generated_response_cookies"
                .parse()
                .expect("post-hook tokens"),
        )
        .with_derive("Clone")
        .with_derive("Debug")
        .with_derive("PartialEq");

    let mut generator = Generator::new(&settings);
    let tokens = generator
        .generate_tokens(&spec)
        .expect("generate Progenitor client");
    let syntax = syn::parse2(tokens).expect("parse generated Rust tokens");
    let content = prettyplease::unparse(&syntax);
    fs::write(generated_path, content).expect("write generated Progenitor client");
}

fn assemble_openapi(
    root_path: &Path, paths_path: &Path, components_path: &Path,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut root = read_yaml_mapping(root_path)?;
    root.insert(
        Value::String("paths".to_string()),
        Value::Mapping(read_yaml_mapping(paths_path)?),
    );
    root.insert(
        Value::String("components".to_string()),
        Value::Mapping(read_yaml_mapping(components_path)?),
    );
    Ok(Value::Mapping(root))
}

fn read_yaml_mapping(path: &Path) -> Result<Mapping, Box<dyn std::error::Error>> {
    match serde_yaml::from_reader(fs::File::open(path)?)? {
        Value::Mapping(mapping) => Ok(mapping),
        _ => Err(format!("{} must contain a YAML mapping", path.display()).into()),
    }
}
