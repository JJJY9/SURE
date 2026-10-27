//! What a Go project declares about itself.
//!
//! | File | What it answers |
//! |---|---|
//! | `go.mod` | the module path, the language version, and any pinned toolchain |
//! | `go.sum` | that a module download has run here |
//! | `.golangci.yml`, `.golangci.yaml`, `.golangci.toml`, `.golangci.json` | that the project configures its linter |
//!
//! `go.mod` is **not** a package graph and is not executed: SURE reads the few
//! directives it needs and never runs `go mod`, `go list` or `go test` here.
//! `go.sum` is read for its existence, for the same reason every other lockfile
//! is.
//!
//! A project with only `go.sum` is reported as a Go project whose manifest
//! SURE could not read; it is not a project with no commands. A `go.mod` SURE
//! cannot read is [`Unread`] and the checks become missing commands rather than
//! guesses.

use std::path::{Path, PathBuf};

use sure_domain::vocabulary::SupportLevel;

use super::read::{self, Budget, Probe, ReadFile, UnreadReason};
use super::{DiscoverOptions, Ecosystem, EcosystemReport, Findings, Unread};
use crate::scan::Scan;

/// The manifest every Go module has, relative to the project root.
pub const MANIFEST: &str = "go.mod";

/// The checksum file, whose existence says a module download has run here.
const LOCKFILE: &str = "go.sum";

/// Linter configuration files, recognised by existence only.
const LINTER_CONFIGS: &[&str] = &[
    ".golangci.yml",
    ".golangci.yaml",
    ".golangci.toml",
    ".golangci.json",
];

/// The directives this module reads from `go.mod`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GoManifest {
    /// The `module` directive, verbatim after removing surrounding quotes.
    pub module: Option<String>,
    /// The `go` directive, verbatim.
    pub go_version: Option<String>,
    /// The `toolchain` directive, verbatim.
    pub toolchain: Option<String>,
}

/// What discovery found for Go, and what it could read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoProject {
    /// The parsed manifest, when SURE read it.
    pub manifest: Option<GoManifest>,
    /// Why the manifest could not be read, when it was there.
    pub unread: Option<UnreadReason>,
    /// Whether `go.sum` is present.
    pub lockfile: bool,
    /// The linter configuration file that is present, if one is.
    pub linter_config: Option<&'static str>,
}

impl GoProject {
    /// Whether a `go.mod` was read into a value.
    #[must_use]
    pub const fn manifest_read(&self) -> bool {
        self.manifest.is_some()
    }
}

pub(super) fn look(
    root: &Path,
    scan: &Scan,
    options: &DiscoverOptions,
    budget: &mut Budget,
    unread: &mut Vec<Unread>,
) -> Option<EcosystemReport> {
    let tree = read::Tree::of(scan, options.scan.case);
    let mut found_by = Vec::new();
    let manifest_path = Path::new(MANIFEST);
    let lockfile_path = Path::new(LOCKFILE);
    let manifest_there = !matches!(tree.probe(manifest_path), Probe::Nothing);
    let lockfile_there = matches!(tree.probe(lockfile_path), Probe::File(_));
    if !manifest_there && !lockfile_there {
        return None;
    }
    if manifest_there {
        found_by.push(manifest_path.to_path_buf());
    }
    if lockfile_there {
        found_by.push(lockfile_path.to_path_buf());
    }
    let linter_config = LINTER_CONFIGS
        .iter()
        .copied()
        .find(|name| matches!(tree.probe(Path::new(name)), Probe::File(_)));
    if let Some(name) = linter_config {
        found_by.push(PathBuf::from(name));
    }

    let (manifest, unread_reason) = match (
        manifest_there,
        read::read_text_file(root, tree.probe(manifest_path), options, budget),
    ) {
        (false, _) => (None, None),
        (true, ReadFile::Absent) => (None, None),
        (true, ReadFile::Unread(reason)) => {
            unread.push(Unread {
                path: manifest_path.to_path_buf(),
                reason: reason.clone(),
            });
            (None, Some(reason))
        }
        (true, ReadFile::Parsed(value)) => {
            let text = value.as_str().unwrap_or_default();
            (Some(parse_manifest(text)), None)
        }
    };

    let level = if manifest.is_some() {
        SupportLevel::Generic
    } else {
        SupportLevel::InspectOnly
    };
    let reason = if manifest.is_some() {
        "SURE read go.mod, so it can plan Go's own test, build and vet commands when you allow them."
    } else {
        "SURE found a Go project marker but no readable go.mod, so it cannot plan Go's own commands."
    };

    Some(EcosystemReport {
        ecosystem: Ecosystem::Go,
        level,
        reason: reason.to_owned(),
        found_by,
        findings: Findings::Go(Box::new(GoProject {
            manifest,
            unread: unread_reason,
            lockfile: lockfile_there,
            linter_config,
        })),
    })
}

/// Read the directives this module needs, and nothing else.
///
/// A `go.mod` is a line-oriented format; unknown directives (`require`,
/// `replace`, `exclude`, `retract`) are left to the toolchain. Lines that are
/// not directive-shaped are ignored rather than rejected: a malformed line is
/// the toolchain's finding, and turning it into a discovery error here would
/// make SURE stop reading a file whose module path it can still state.
fn parse_manifest(text: &str) -> GoManifest {
    let mut manifest = GoManifest::default();
    for line in text.lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(directive) = parts.next() else {
            continue;
        };
        let value = parts.next().map(|word| word.trim_matches('"').to_owned());
        match directive {
            "module" => manifest.module = value,
            "go" => manifest.go_version = value,
            "toolchain" => manifest.toolchain = value,
            _ => {}
        }
    }
    manifest
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_three_directives_and_ignores_the_rest() {
        let manifest = parse_manifest(
            "module example.com/app\n\ngo 1.27\n\ntoolchain go1.27.0\n\nrequire (\n  example.com/dep v1.0.0\n)\n",
        );
        assert_eq!(manifest.module.as_deref(), Some("example.com/app"));
        assert_eq!(manifest.go_version.as_deref(), Some("1.27"));
        assert_eq!(manifest.toolchain.as_deref(), Some("go1.27.0"));
    }

    #[test]
    fn a_quoted_module_path_is_unquoted() {
        let manifest = parse_manifest("module \"example.com/app\"\n");
        assert_eq!(manifest.module.as_deref(), Some("example.com/app"));
    }
}
