//! Stamp the commit this build was made from into the binary.
//!
//! `sure doctor --format json` reports it as `details.build.commit`, and
//! `sure_core::doctor` reads it from the compile-time environment variable this
//! script sets. `docs/architecture/CLI.md` is the contract.
//!
//! # Why the build script and not the binary
//!
//! The question the field answers is which source *this binary* was made from.
//! A binary that ran `git` at run time would answer about whatever checkout it
//! happened to be next to — or about nothing, on a machine with no git and no
//! checkout, which is every machine a packaged build runs on. The one moment
//! the answer is knowable is the build, so it is recorded there.
//!
//! # It never fails the build
//!
//! Every failure — no `git`, not a checkout, output that is not a full SHA-1 —
//! is stamped as `unknown`, which is what a build from a source archive
//! honestly is. A build script that could fail would turn "this machine has no
//! git" into "this source cannot be compiled", which is the wrong statement.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The variable `sure_core::doctor` reads back with `option_env!`.
const VARIABLE: &str = "SURE_BUILD_COMMIT";

fn main() {
    let workspace = std::env::var_os("CARGO_MANIFEST_DIR").map(|dir| {
        // crates/sure-core -> the directory holding the workspace manifest.
        PathBuf::from(dir).join("..").join("..")
    });

    // The files whose change moves `HEAD`. `main` is watched by name because
    // it is the branch a release is cut from; the branch this checkout is
    // actually on is added below. A path that does not exist (a checkout of a
    // different branch, a source tree with no `.git` at all) is fine: cargo
    // treats it as changed and reruns this script, which is the conservative
    // direction.
    for path in watched(workspace.as_deref()) {
        println!("cargo:rerun-if-changed={path}");
    }

    let commit = workspace
        .as_deref()
        .and_then(git_head)
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env={VARIABLE}={commit}");
}

/// The paths whose change moves `HEAD`, relative to the package root.
fn watched(workspace: Option<&Path>) -> Vec<String> {
    let mut paths = vec![
        "../../.git/HEAD".to_owned(),
        "../../.git/packed-refs".to_owned(),
        "../../.git/refs/heads/main".to_owned(),
    ];
    // `HEAD` need not point at `main`. A commit on any other branch moves that
    // branch's ref and nothing above — `.git/HEAD` keeps saying `ref:
    // refs/heads/<name>` — so the branch the checkout is on is watched too, or
    // the stamp would keep naming the commit before the one being built.
    if let Some(path) = workspace.and_then(current_branch_ref)
        && !paths.contains(&path)
    {
        paths.push(path);
    }
    paths
}

/// The ref file `HEAD` points at, as a path from the package root, if `HEAD`
/// is on a branch.
///
/// In a linked worktree `.git` is a file rather than a directory, so this
/// names something that does not exist and cargo reruns this script on every
/// build. That is the right failure: a fresh answer is never stale.
fn current_branch_ref(workspace: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["symbolic-ref", "-q", "HEAD"])
        .current_dir(workspace)
        .output()
        .ok()?;
    if !output.status.success() {
        // A detached `HEAD`, or no repository at all. Neither has a branch ref
        // to watch, and `.git/HEAD` above covers the checkout moving.
        return None;
    }
    let reference = String::from_utf8(output.stdout).ok()?;
    let reference = reference.trim();
    reference
        .starts_with("refs/heads/")
        .then(|| format!("../../.git/{reference}"))
}

/// `git rev-parse HEAD` from the workspace root, if it answers with a full
/// SHA-1.
fn git_head(workspace: &Path) -> Option<String> {
    if !is_sure_workspace(workspace) {
        // A vendored copy of this crate sits at `<consumer>/vendor/sure-core`,
        // so `workspace` is the consumer's repository root. Running git there
        // succeeds and answers with a commit that has nothing to do with this
        // source; stamping it would be a plausible-looking lie. `unknown` is
        // the honest answer for a build that is not SURE's own checkout.
        return None;
    }
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(workspace)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let sha = stdout.trim();
    is_full_commit_sha(sha).then(|| sha.to_owned())
}

/// Whether `workspace` is SURE's own workspace root rather than an enclosing
/// repository a vendored copy of this crate happens to sit inside.
fn is_sure_workspace(workspace: &Path) -> bool {
    let manifest = workspace.join("Cargo.toml");
    let member = workspace
        .join("crates")
        .join("sure-core")
        .join("Cargo.toml");
    member.is_file()
        && std::fs::read_to_string(&manifest).is_ok_and(|text| text.contains("[workspace]"))
}

/// Whether `text` is exactly the 40 lowercase hexadecimal characters a full
/// commit SHA-1 is written as.
///
/// Checked rather than trusted so that a mangled answer — a warning on stdout,
/// a shortened abbreviation, a resolved tag name — is stamped `unknown` instead
/// of being printed as though it named a commit.
fn is_full_commit_sha(text: &str) -> bool {
    text.len() == 40
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
