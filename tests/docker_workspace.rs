use std::path::Path;

#[test]
fn docker_build_contexts_include_every_workspace_tool() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let manifest: toml::Value = toml::from_str(&manifest).unwrap();
    let members = manifest["workspace"]["members"].as_array().unwrap();

    for dockerfile_path in ["Dockerfile", "tests/e2e/client.Dockerfile"] {
        let dockerfile = std::fs::read_to_string(root.join(dockerfile_path)).unwrap();
        let (dependency_stage, source_stage) = dockerfile
            .split_once("# Copy real source and build.")
            .unwrap();

        for member in members.iter().filter_map(toml::Value::as_str) {
            if member == "." {
                continue;
            }

            let manifest_copy = format!("COPY {member}/Cargo.toml {member}/Cargo.toml");
            assert!(
                dependency_stage
                    .lines()
                    .any(|line| line.trim() == manifest_copy),
                "{dockerfile_path} does not copy the {member} manifest before building"
            );

            let source_copy = format!("COPY {member}/ {member}/");
            assert!(
                source_stage.lines().any(|line| line.trim() == source_copy),
                "{dockerfile_path} does not copy the {member} sources before building"
            );
        }
    }
}
