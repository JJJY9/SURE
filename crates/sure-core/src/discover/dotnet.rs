//! What a .NET project declares about itself.
//!
//! | File | What it answers |
//! |---|---|
//! | `*.sln`, `*.slnx` | the solution SURE passes to `dotnet` |
//! | `*.csproj`, `*.fsproj`, `*.vbproj` | a project file when there is no solution |
//! | `global.json` | that the project pins an SDK (presence only) |
//! | `.editorconfig` | that the project configures formatting (presence only) |
//!
//! **The solution or project file may sit at any depth.** Keeping the solution
//! under `Src/` is a common layout, and a repository whose root holds no .NET
//! file is still a .NET project (measured 2026-11-02 on `JamesNK/Newtonsoft.Json`,
//! whose solution lives in `Src/`). The shallowest manifest wins — a root file
//! is the project's own before a deeper one is — and ties are broken by path so
//! two runs choose the same file. `global.json` and `.editorconfig` count at the
//! root or beside the chosen manifest; they are recorded by existence only.
//!
//! The project/solution files are read as text to prove they are readable and
//! are **not parsed**: SURE does not expand the project graph, resolve package
//! references or run MSBuild here. A project with several project files and no
//! solution is reported as a .NET project with an ambiguous command target;
//! its checks become missing commands rather than a guess about which project
//! was meant.

use std::path::{Path, PathBuf};

use sure_domain::vocabulary::SupportLevel;

use super::read::{self, Budget, Probe, ReadFile, UnreadReason};
use super::{DiscoverOptions, Ecosystem, EcosystemReport, Findings, Unread};
use crate::scan::Scan;

/// Project-file extensions, lower-case and without the dot.
const PROJECT_EXTENSIONS: &[&str] = &["csproj", "fsproj", "vbproj"];
/// Solution-file extensions, lower-case and without the dot.
const SOLUTION_EXTENSIONS: &[&str] = &["sln", "slnx"];

/// Which file SURE hands to `dotnet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotnetManifestKind {
    /// A solution (`*.sln` / `*.slnx`).
    Solution,
    /// A single project file.
    Project,
}

impl DotnetManifestKind {
    /// The stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Solution => "solution",
            Self::Project => "project",
        }
    }
}

/// The file SURE read and the target it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotnetManifest {
    /// Solution or project.
    pub kind: DotnetManifestKind,
    /// The file, relative to the project root.
    pub file: PathBuf,
}

/// What discovery found for .NET, and what it could read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotnetProject {
    /// The manifest SURE read, when it read one.
    pub manifest: Option<DotnetManifest>,
    /// Why the manifest could not be read, when it was there.
    pub unread: Option<UnreadReason>,
    /// The file `dotnet` commands are pointed at. `None` means the project has
    /// several project files and no solution: SURE will not pick one.
    pub target: Option<PathBuf>,
    /// Every project file found at the root, in a stable order.
    pub projects: Vec<PathBuf>,
    /// Whether `global.json` is present (SDK pin; presence only).
    pub global_json: bool,
    /// Whether `.editorconfig` is present (formatting configuration).
    pub editorconfig: bool,
}

impl DotnetProject {
    /// Whether a manifest was read into a value.
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
    let mut solutions: Vec<PathBuf> = Vec::new();
    let mut projects: Vec<PathBuf> = Vec::new();
    for entry in scan.entries() {
        if !entry.kind.is_file() {
            continue;
        }
        let Some(extension) = entry.path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        let extension = extension.to_ascii_lowercase();
        if SOLUTION_EXTENSIONS.contains(&extension.as_str()) {
            solutions.push(entry.path.clone());
        } else if PROJECT_EXTENSIONS.contains(&extension.as_str()) {
            projects.push(entry.path.clone());
        }
    }
    // The shallowest manifest wins, ties by path: a repository keeps its
    // solution under `Src/` (or `src/`, or `build/`) as often as at the root,
    // and the run that chooses must not depend on directory order.
    solutions.sort_by(|a, b| depth(a).cmp(&depth(b)).then_with(|| a.cmp(b)));
    projects.sort_by(|a, b| depth(a).cmp(&depth(b)).then_with(|| a.cmp(b)));
    let find_file = |path: PathBuf| -> Option<PathBuf> {
        scan.entries()
            .iter()
            .any(|entry| entry.kind.is_file() && entry.path == path)
            .then_some(path)
    };
    let global_json = find_file(PathBuf::from("global.json"));
    let editorconfig = find_file(PathBuf::from(".editorconfig"));
    if solutions.is_empty() && projects.is_empty() {
        return None;
    }

    let (kind, chosen) = if let Some(solution) = solutions.first() {
        (DotnetManifestKind::Solution, solution.clone())
    } else if projects.len() == 1 {
        (DotnetManifestKind::Project, projects[0].clone())
    } else {
        // Several project files, no solution: report the project but refuse to
        // guess which one the checks are about.
        let mut found_by = projects.clone();
        found_by.extend(global_json.iter().cloned());
        found_by.extend(editorconfig.iter().cloned());
        return Some(EcosystemReport {
            ecosystem: Ecosystem::Dotnet,
            level: SupportLevel::InspectOnly,
            reason: "SURE found several .NET project files and no solution, so it cannot tell which one to check."
                .to_owned(),
            found_by,
            findings: Findings::Dotnet(Box::new(DotnetProject {
                manifest: None,
                unread: None,
                target: None,
                projects,
                global_json: global_json.is_some(),
                editorconfig: editorconfig.is_some(),
            })),
        });
    };

    let (manifest, unread_reason) =
        match read::read_text_file(root, Probe::File(&chosen), options, budget) {
            ReadFile::Parsed(_) => (
                Some(DotnetManifest {
                    kind,
                    file: chosen.clone(),
                }),
                None,
            ),
            ReadFile::Unread(reason) => {
                unread.push(Unread {
                    path: chosen.clone(),
                    reason: reason.clone(),
                });
                (None, Some(reason))
            }
            ReadFile::Absent => (None, None),
        };

    // `global.json` and `.editorconfig` apply to the manifest SURE chose: the
    // root's own file counts, and so does one beside a manifest that lives in a
    // subdirectory. They are recorded by existence; no SDK is resolved here.
    let beside = |name: &str, found: Option<PathBuf>| -> Option<PathBuf> {
        if found.is_some() {
            return found;
        }
        let directory = chosen.parent()?;
        if directory.as_os_str().is_empty() {
            return None;
        }
        find_file(directory.join(name))
    };
    let global_json = beside("global.json", global_json);
    let editorconfig = beside(".editorconfig", editorconfig);

    let mut found_by = vec![chosen.clone()];
    found_by.extend(projects.iter().filter(|path| *path != &chosen).cloned());
    found_by.extend(global_json.iter().cloned());
    found_by.extend(editorconfig.iter().cloned());
    let level = if manifest.is_some() {
        SupportLevel::Generic
    } else {
        SupportLevel::InspectOnly
    };
    let reason = if manifest.is_some() {
        "SURE read a .NET solution or project file, so it can plan dotnet test and build when you allow them."
    } else {
        "SURE found a .NET project file it could not read, so it cannot plan its commands."
    };

    Some(EcosystemReport {
        ecosystem: Ecosystem::Dotnet,
        level,
        reason: reason.to_owned(),
        found_by,
        findings: Findings::Dotnet(Box::new(DotnetProject {
            manifest,
            unread: unread_reason,
            target: Some(chosen),
            projects,
            global_json: global_json.is_some(),
            editorconfig: editorconfig.is_some(),
        })),
    })
}

/// Directory depth of a project-relative path, one for a root file.
fn depth(path: &Path) -> usize {
    path.components().count()
}
