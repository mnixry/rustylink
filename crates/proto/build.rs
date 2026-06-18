use std::path::PathBuf;

fn main() {
    let proto_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/proto");
    println!("cargo:rerun-if-changed={proto_dir}");

    let mut proto_files = Vec::new();
    visit_proto_files(proto_dir, &mut proto_files).unwrap();
    proto_files.sort();

    connectrpc_build::Config::new()
        .files(&proto_files)
        .includes(&[proto_dir])
        .include_file("_connectrpc.rs")
        .compile()
        .unwrap();
}

fn visit_proto_files(
    path: impl Into<PathBuf>, proto_files: &mut Vec<PathBuf>,
) -> Result<(), std::io::Error> {
    let path = path.into();
    if path.is_file() && path.extension().unwrap_or_default() == "proto" {
        proto_files.push(path);
    } else if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            visit_proto_files(&path, proto_files)?;
        }
    }
    Ok(())
}
