use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    let spec_path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/spec/openapi.yaml"));
    println!("cargo:rerun-if-changed={}", spec_path.display());
    println!("cargo:rerun-if-env-changed=OPENAPI_GENERATOR_CLI");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR missing")?);
    let generated_dir = out_dir.join("openapi");
    if generated_dir.exists() {
        fs::remove_dir_all(&generated_dir)?;
    }

    let generator =
        env::var("OPENAPI_GENERATOR_CLI").unwrap_or_else(|_| "openapi-generator-cli".to_string());
    let status = Command::new(&generator)
        .args([
            "generate",
            "-g",
            "rust",
            "-i",
            spec_path.to_str().ok_or("spec path is not valid UTF-8")?,
            "-o",
            generated_dir
                .to_str()
                .ok_or("generated output path is not valid UTF-8")?,
            "--additional-properties=packageName=rustylink_api_codegen,packageVersion=0.1.0,library=reqwest,supportAsync=true,supportMiddleware=true,avoidBoxedModels=true",
        ])
        .status()
        .map_err(|source| {
            format!(
                "failed to execute `{generator}`; install openapi-generator-cli or set OPENAPI_GENERATOR_CLI: {source}"
            )
        })?;

    if !status.success() {
        return Err(format!("openapi-generator-cli exited with status {status}").into());
    }

    write_module_include(&out_dir, &generated_dir)?;
    Ok(())
}

fn write_module_include(out_dir: &Path, generated_dir: &Path) -> Result<()> {
    let apis_mod = generated_dir.join("src/apis/mod.rs");
    let models_mod = generated_dir.join("src/models/mod.rs");
    let content = format!(
        r#"
#[allow(clippy::all, clippy::cargo, clippy::nursery, clippy::pedantic, warnings)]
#[path = "{apis_mod}"]
pub mod apis;

#[allow(clippy::all, clippy::cargo, clippy::nursery, clippy::pedantic, warnings)]
#[path = "{models_mod}"]
pub mod models;
"#,
        apis_mod = rust_path_literal(&apis_mod),
        models_mod = rust_path_literal(&models_mod),
    );
    fs::write(out_dir.join("openapi_modules.rs"), content)?;
    Ok(())
}

fn rust_path_literal(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "\\\\")
}
