// Shared build script for workspace binaries that report their release version.
//
// `git semver` only creates and pushes tags; it does not edit Cargo manifests.
// Deriving the version from the exact checked-out tag keeps `--version` output
// (and the agent hello) in sync with the published release assets. Builds from
// source archives without git metadata fall back to the Cargo package version.

use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RTUNNEL_BUILD_VERSION");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_TYPE");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let repo_root = Path::new(&manifest_dir).join("../..");
    for path in [".git/HEAD", ".git/refs/tags"] {
        println!("cargo:rerun-if-changed={}", repo_root.join(path).display());
    }

    let version = env::var("RTUNNEL_BUILD_VERSION")
        .ok()
        .and_then(|value| normalized(&value))
        .or_else(github_tag)
        .or_else(|| git_exact_tag(&manifest_dir))
        .or_else(|| env::var("CARGO_PKG_VERSION").ok())
        .unwrap_or_else(|| "0.0.0".to_string());

    println!("cargo:rustc-env=RTUNNEL_VERSION={version}");
}

fn github_tag() -> Option<String> {
    if env::var("GITHUB_REF_TYPE").as_deref() != Ok("tag") {
        return None;
    }

    env::var("GITHUB_REF_NAME")
        .ok()
        .and_then(|value| normalized(&value))
}

fn git_exact_tag(manifest_dir: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--exact-match", "HEAD"])
        .current_dir(manifest_dir)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    normalized(&String::from_utf8(output.stdout).ok()?)
}

/// Accepts semantic versions with an optional leading `v`, including
/// pre-release and build-metadata suffixes (for example `v0.7.0-rc.1`).
fn normalized(value: &str) -> Option<String> {
    let value = value.trim();
    let value = value.strip_prefix('v').unwrap_or(value);
    let core_end = value.find(['-', '+']).unwrap_or(value.len());
    let parts: Vec<&str> = value[..core_end].split('.').collect();

    let numeric = parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()));

    numeric.then(|| value.to_string())
}
