use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use progenitor::{GenerationSettings, Generator, InterfaceStyle, TagStyle};

fn main() {
    println!("cargo:rerun-if-changed=spec/main.tsp");
    println!("cargo:rerun-if-changed=spec/tspconfig.yaml");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    let generated_path = out_dir.join("progenitor.rs");

    let tsp = find_tsp();
    assert!(
        Command::new(&tsp).arg("--version").output().is_ok(),
        "TypeSpec compiler `tsp` was not found. Enter `nix develop`, run `npm ci`, then build again."
    );

    let spec_dir = Path::new("spec");
    let typespec_out = out_dir.join("typespec");
    if typespec_out.exists() {
        fs::remove_dir_all(&typespec_out).expect("remove previous TypeSpec output");
    }

    let status = Command::new(&tsp)
        .arg("compile")
        .arg(spec_dir)
        .arg("--emit=@typespec/openapi3")
        .arg("--output-dir")
        .arg(&typespec_out)
        .status()
        .expect("run TypeSpec compiler");
    assert!(
        status.success(),
        "TypeSpec compilation failed with status {status}"
    );

    let Some(openapi_path) = find_openapi(&typespec_out) else {
        panic!(
            "TypeSpec completed but no OpenAPI JSON/YAML file was found under {}",
            typespec_out.display()
        );
    };

    let spec: openapiv3::OpenAPI =
        parse_openapi(&openapi_path).expect("parse TypeSpec OpenAPI output");
    let mut settings = GenerationSettings::default();
    settings
        .with_interface(InterfaceStyle::Builder)
        .with_tag(TagStyle::Merged)
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

fn find_tsp() -> PathBuf {
    if let Some(path) = env::var_os("TSP") {
        return PathBuf::from(path);
    }
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let local = manifest_dir.join("../../node_modules/.bin/tsp");
    if local.exists() {
        return local;
    }
    PathBuf::from("tsp")
}

fn parse_openapi(path: &Path) -> Result<openapiv3::OpenAPI, Box<dyn std::error::Error>> {
    let file = fs::File::open(path)?;
    match path.extension().and_then(OsStr::to_str) {
        Some("yaml" | "yml") => Ok(serde_yaml::from_reader(file)?),
        _ => Ok(serde_json::from_reader(file)?),
    }
}

fn find_openapi(root: &Path) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(path).ok()? {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Some(name) = path.file_name().and_then(OsStr::to_str) else {
                continue;
            };
            let Some(ext) = path.extension().and_then(OsStr::to_str) else {
                continue;
            };
            if name.contains("openapi") && matches!(ext, "json" | "yaml" | "yml") {
                return Some(path);
            }
        }
    }
    None
}
