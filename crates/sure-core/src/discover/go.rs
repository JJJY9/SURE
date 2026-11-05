//! What a Go project declares about itself.
//!
//! | File | What it answers |
//! |---|---|
//! | `go.mod` | the module path, the language version, and any pinned toolchain |
//! | `go.sum` | that a module download has run here |
//! | `go.work` | the modules a workspace `use`s, and the workspace's Go version |
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

/// The workspace file, whose `use` directives name the modules.
pub const WORKSPACE: &str = "go.work";

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

/// The directives this module reads from `go.work`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GoWorkspace {
    /// The `go` directive, verbatim.
    pub go_version: Option<String>,
    /// The `toolchain` directive, verbatim.
    pub toolchain: Option<String>,
    /// The `use` paths, relative to the workspace root, deduplicated.
    pub uses: Vec<PathBuf>,
}

/// One module a workspace names, and whether its `go.mod` was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoModule {
    /// The directory named by `use`, relative to the workspace root.
    pub path: PathBuf,
    /// The parsed module manifest, when SURE read it.
    pub manifest: Option<GoManifest>,
    /// Why the module manifest could not be read, when it was there.
    pub unread: Option<UnreadReason>,
}

impl GoModule {
    /// Whether this module's `go.mod` was read into a value.
    #[must_use]
    pub const fn manifest_read(&self) -> bool {
        self.manifest.is_some()
    }
}

/// What discovery found for Go, and what it could read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoProject {
    /// The parsed manifest, when SURE read it.
    pub manifest: Option<GoManifest>,
    /// Why the manifest could not be read, when it was there.
    pub unread: Option<UnreadReason>,
    /// The parsed workspace, when SURE read it.
    pub workspace: Option<GoWorkspace>,
    /// Why the workspace file could not be read, when it was there.
    pub workspace_unread: Option<UnreadReason>,
    /// The modules the workspace names, in declaration order.
    pub modules: Vec<GoModule>,
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
    let workspace_path = Path::new(WORKSPACE);
    let manifest_there = !matches!(tree.probe(manifest_path), Probe::Nothing);
    let lockfile_there = matches!(tree.probe(lockfile_path), Probe::File(_));
    let workspace_there = matches!(tree.probe(workspace_path), Probe::File(_));
    if !manifest_there && !lockfile_there && !workspace_there {
        return None;
    }
    if manifest_there {
        found_by.push(manifest_path.to_path_buf());
    }
    if lockfile_there {
        found_by.push(lockfile_path.to_path_buf());
    }
    if workspace_there {
        found_by.push(workspace_path.to_path_buf());
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

    let (workspace, workspace_unread) = if workspace_there {
        match read::read_text_file(root, tree.probe(workspace_path), options, budget) {
            ReadFile::Parsed(value) => {
                let text = value.as_str().unwrap_or_default();
                (Some(parse_workspace(text)), None)
            }
            ReadFile::Unread(reason) => {
                unread.push(Unread {
                    path: workspace_path.to_path_buf(),
                    reason: reason.clone(),
                });
                (None, Some(reason))
            }
            ReadFile::Absent => (None, None),
        }
    } else {
        (None, None)
    };

    let mut modules = Vec::new();
    if let Some(workspace) = &workspace {
        for path in &workspace.uses {
            modules.push(read_module(root, &tree, path, options, budget, unread));
        }
        for module in &modules {
            found_by.push(module.path.join(MANIFEST));
        }
    }

    let readable_modules = modules
        .iter()
        .filter(|module| module.manifest_read())
        .count();
    let level = if manifest.is_some() || readable_modules > 0 {
        SupportLevel::Generic
    } else {
        SupportLevel::InspectOnly
    };
    let reason = if let Some(workspace) = &workspace {
        if workspace.uses.is_empty() {
            "SURE read go.work, but it names no modules, so there is nothing to check."
        } else if readable_modules == 0 {
            "SURE read go.work but could not read any of the module go.mod files it names."
        } else {
            "SURE read go.work and its module go.mod files, so it can plan Go's own commands for each module."
        }
    } else if workspace_unread.is_some() {
        "SURE found a go.work it could not read, so it cannot plan commands for its modules."
    } else if manifest.is_some() {
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
            workspace,
            workspace_unread,
            modules,
            lockfile: lockfile_there,
            linter_config,
        })),
    })
}

/// Read one workspace module's `go.mod`, if it has one.
fn read_module(
    root: &Path,
    tree: &read::Tree<'_>,
    path: &Path,
    options: &DiscoverOptions,
    budget: &mut Budget,
    unread: &mut Vec<Unread>,
) -> GoModule {
    let manifest_path = path.join(MANIFEST);
    match read::read_text_file(root, tree.probe(&manifest_path), options, budget) {
        ReadFile::Parsed(value) => GoModule {
            path: path.to_path_buf(),
            manifest: Some(parse_manifest(value.as_str().unwrap_or_default())),
            unread: None,
        },
        ReadFile::Unread(reason) => {
            unread.push(Unread {
                path: manifest_path,
                reason: reason.clone(),
            });
            GoModule {
                path: path.to_path_buf(),
                manifest: None,
                unread: Some(reason),
            }
        }
        ReadFile::Absent => GoModule {
            path: path.to_path_buf(),
            manifest: None,
            unread: None,
        },
    }
}

/// Read `go.work`'s `go`, `toolchain` and `use` directives.
///
/// `replace` is left to the toolchain. A `use` path is a relative directory;
/// absolute paths are ignored because the workspace format names directories
/// relative to the file, and a component path has to be relative to the root for
/// the graph to merge two ecosystems naming one directory.
fn parse_workspace(text: &str) -> GoWorkspace {
    let mut workspace = GoWorkspace::default();
    let mut in_use = false;
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if in_use {
            if line.starts_with(')') {
                in_use = false;
            } else if let Some(path) = use_path(line) {
                push_use(&mut workspace.uses, path);
            }
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(directive) = parts.next() else {
            continue;
        };
        match directive {
            "go" => workspace.go_version = parts.next().map(str::to_owned),
            "toolchain" => workspace.toolchain = parts.next().map(str::to_owned),
            "use" => {
                let rest = line[directive.len()..].trim();
                if rest == "(" {
                    in_use = true;
                } else if let Some(path) = use_path(rest) {
                    push_use(&mut workspace.uses, path);
                }
            }
            _ => {}
        }
    }
    workspace
}

fn use_path(text: &str) -> Option<PathBuf> {
    let raw = text.split_whitespace().next()?.trim_matches('"');
    if raw.is_empty() {
        return None;
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        return None;
    }
    let mut cleaned = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            // A workspace may name a module outside its root; SURE's scope is the
            // checked project, so such a path is not planned rather than followed.
            std::path::Component::ParentDir => return None,
            other => cleaned.push(other.as_os_str()),
        }
    }
    if cleaned.as_os_str().is_empty() {
        Some(PathBuf::from("."))
    } else {
        Some(cleaned)
    }
}

fn push_use(uses: &mut Vec<PathBuf>, path: PathBuf) {
    if !uses.contains(&path) {
        uses.push(path);
    }
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
    fn reads_workspace_use_block_and_single_use() {
        let workspace = parse_workspace(
            "go 1.22

toolchain go1.22.0

use (
    ./app
    ./lib // comment
)
use ./tool
",
        );
        assert_eq!(workspace.go_version.as_deref(), Some("1.22"));
        assert_eq!(workspace.toolchain.as_deref(), Some("go1.22.0"));
        assert_eq!(
            workspace.uses,
            vec![
                PathBuf::from("app"),
                PathBuf::from("lib"),
                PathBuf::from("tool")
            ]
        );
    }

    #[test]
    fn duplicate_use_paths_are_kept_once() {
        let workspace = parse_workspace(
            "use ./app
use ./app
",
        );
        assert_eq!(workspace.uses, vec![PathBuf::from("app")]);
    }

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
    fn a_use_path_outside_the_root_is_ignored() {
        let outside = parse_workspace("use ../outside");
        assert!(outside.uses.is_empty());
        let current = parse_workspace("use ./app");
        assert_eq!(current.uses, vec![PathBuf::from("app")]);
    }

    #[test]
    fn a_quoted_module_path_is_unquoted() {
        let manifest = parse_manifest("module \"example.com/app\"\n");
        assert_eq!(manifest.module.as_deref(), Some("example.com/app"));
    }
}
