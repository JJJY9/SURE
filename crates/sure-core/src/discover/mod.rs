//! What kind of project this is, and how SURE knows.
//!
//! This is step 1 of `docs/architecture/CHECK_PIPELINE.md`. The filesystem half
//! of it — which files SURE will look at, and which it will not — is
//! [`crate::scan`] and is described by `docs/architecture/PROJECT_DISCOVERY.md`.
//! This module is the other half: **reading a few named files and saying what
//! they claim the project is.** `docs/architecture/ECOSYSTEM_DISCOVERY.md` is
//! the authority for that half — the rule, the limits, and the gaps it does not
//! close — and the table at the end of it maps each statement to the test that
//! holds it.
//!
//! # The one rule everything here is arranged around
//!
//! **A manifest states a request, not a fact.** `"test": "jest"` in
//! `package.json` means the project *declares* that command; it does not mean
//! `jest` is installed, that the script runs, or that any test passes. `"react":
//! "^18"` is a range handed to a resolver, not the version on disk.
//!
//! That distinction is `docs/architecture/EVIDENCE_MODEL.md`'s, and it is why
//! every finding here is shaped the way it is:
//!
//! - A finding names the file it came from. There is no code path that produces
//!   a package manager, a script or a framework without a [`Source`] beside it.
//! - Dependency versions are recorded **verbatim** and never interpreted. SURE
//!   has not run a resolver, so it has nothing to say about what a range
//!   resolves to.
//! - What was *not* found is reported as prominently as what was.
//!   [`node::NodeProject::conventional_scripts`] returns a row for every
//!   conventional script whether or not it is declared, because "there is no
//!   test script" is a finding and silence is not.
//! - The only string a project can put into a finding is one SURE recorded as
//!   data — a script's name, a dependency's name. Every *sentence* is a
//!   constant.
//!
//! # What it does not do
//!
//! **It runs nothing.** No `npm`, no `node`, no resolver, no network. Reading a
//! manifest is not executing a project, and the whole of step 1 is on the
//! inspect-only side of `docs/architecture/EXECUTION_SAFETY.md`.
//!
//! **It does not look at `node_modules`**, and not only because the scan leaves
//! it out. What is installed is `node_modules`'s answer, and a directory that is
//! usually absent, usually stale, and never committed is not a fact about the
//! project a person can act on.
//!
//! **It does not decide whether the project is good.** It says what the project
//! declares and at what support level; whether the declaration is honest is what
//! the checks after it are for.
//!
//! **It is not the diagnostics module.** [`crate::diagnostics`] is what SURE
//! says about *its own* work and is explicitly never evidence about the project.
//! A manifest SURE could not parse is a finding about the *project*, so it is a
//! [`Unread`] in the result rather than a log line — the two are separate types
//! for the same reason [`crate::diagnostics`] gives.

pub mod dotnet;
pub mod go;
pub mod node;
mod pattern;
pub mod python;
mod read;
pub mod rust;

use std::path::{Path, PathBuf};

use sure_domain::vocabulary::{StackClassification, SupportLevel};

use crate::scan::{Scan, ScanError, ScanOptions, Skipped};

pub use node::NodeProject;
pub use pattern::{Unresolved, UnresolvedReason};
pub use python::PythonProject;
pub use read::UnreadReason;

// The case-folding rule a path is looked up by, for the checks that compare a
// path they know against the paths a walk found. Exposed rather than duplicated
// so that the rule is written once — see `read::lookup_key`'s own note.
pub use dotnet::DotnetProject;
pub use go::GoProject;
pub(crate) use read::lookup_key;
pub use rust::RustProject;

/// One ecosystem this build knows how to look for.
///
/// The list is the answer to "did SURE look and find nothing, or did it not
/// look?" — a question a discovery result that only reported what it found
/// could not answer, and one this product has to answer honestly rather than by
/// leaving it to the reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosystem {
    /// JavaScript and TypeScript: `package.json` and the lockfiles beside it.
    Node,
    /// Python: `pyproject.toml`, `Pipfile`, `requirements*.txt`, and the
    /// lockfiles beside them.
    Python,
    /// Rust: `Cargo.toml`, `Cargo.lock`, and the toolchain pin beside them.
    Rust,
    /// Go: `go.mod` and `go.sum`.
    Go,
    /// .NET: a solution or project file at the root.
    Dotnet,
}

impl Ecosystem {
    /// Every ecosystem this build looks for, in a fixed order.
    pub const ALL: &'static [Self] =
        &[Self::Node, Self::Python, Self::Rust, Self::Go, Self::Dotnet];

    /// The stable name, used in output and in the reason a level was assigned.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Python => "python",
            Self::Rust => "rust",
            Self::Go => "go",
            Self::Dotnet => "dotnet",
        }
    }

    /// What a person would call it.
    #[must_use]
    pub const fn plain_name(self) -> &'static str {
        match self {
            Self::Node => "JavaScript or TypeScript",
            Self::Python => "Python",
            Self::Rust => "Rust",
            Self::Go => "Go",
            Self::Dotnet => ".NET",
        }
    }
}

/// What was found, by ecosystem.
///
/// One variant per [`Ecosystem`]. It is an enum rather than a struct with an
/// `Option` per ecosystem so that a consumer has to answer for a new one: adding
/// a variant fails every `match` until somebody decides what the new ecosystem's
/// findings mean for that consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Findings {
    /// What a Node project declares.
    Node(Box<NodeProject>),
    /// What a Python project declares.
    Python(Box<PythonProject>),
    /// What a Rust project declares.
    Rust(Box<RustProject>),
    /// What a Go project declares.
    Go(Box<GoProject>),
    /// What a .NET project declares.
    Dotnet(Box<DotnetProject>),
}

/// What SURE concluded about one ecosystem, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcosystemReport {
    /// Which one.
    pub ecosystem: Ecosystem,
    /// How well SURE supports what it found.
    pub level: SupportLevel,
    /// The sentence a person reads, saying what the level is based on.
    ///
    /// Built from [`Source`]s and constants, never from project text.
    pub reason: String,
    /// The files this conclusion rests on, in the order they were read.
    ///
    /// Empty is possible and means the conclusion rests on the *absence* of
    /// every file that would have been evidence — which is itself recorded here
    /// as the level's reason rather than left as a bare classification.
    pub found_by: Vec<PathBuf>,
    /// The findings themselves.
    pub findings: Findings,
}

/// One file that was in the project and could not be read.
///
/// A value in the result rather than an error, because a project with an
/// unreadable `pnpm-workspace.yaml` and a readable `package.json` is a project
/// SURE can still say something true about. What it must not do is the other
/// thing: report the readable half and stay silent about the half it lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unread {
    /// Which file, relative to the project root.
    pub path: PathBuf,
    /// Why, and what SURE did instead.
    pub reason: UnreadReason,
}

/// Where a finding came from.
///
/// Every finding in [`node`] carries one. An anchorless claim is what
/// `docs/architecture/EVIDENCE_MODEL.md` calls unsupported, and the way to make
/// one impossible is to make the anchor part of the value rather than a
/// convention about filling it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The file, relative to the project root.
    pub path: PathBuf,
    /// What in that file said so, as a constant phrase.
    ///
    /// `&'static str` rather than a `String` on purpose: this text ends up in
    /// sentences a person reads, and a project must not be able to write them.
    pub says: &'static str,
}

impl Source {
    /// A source, from a path and the constant phrase describing what it said.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, says: &'static str) -> Self {
        Self {
            path: path.into(),
            says,
        }
    }
}

/// One command a discovery planned, as a program and the arguments it is started
/// with.
///
/// **A value rather than a rendered line, and that is `P18-T003`'s whole point.** A
/// caller that means to *start* something cannot use a string: cutting
/// `uv run pytest` at its spaces is parsing a display string into a program, and a
/// space in a path or a tool name is enough to make that the wrong program. So each
/// discovery that knows a command turns it into this, and the line a report carries
/// is [`Self::rendered`] — derived here, from the same two fields, so that a plan
/// and the sentence describing it cannot come apart.
///
/// **The program is a name and never a path.** `npm`, `uv` and `cargo` are what a
/// person types. Which executable those name on this machine — and whether this
/// machine can start them at all — is a question for the machine the work runs on,
/// so it is `planned_work::ProgramPath`'s answer and [`crate::checks`]'s callers
/// take it there. Resolving it here would resolve it against whatever machine the
/// *plan* was made on.
///
/// Shared between the ecosystems rather than re-declared in each: `npm run build`,
/// `uv run pytest` and `cargo clippy --all-targets` are the same three facts about
/// three different projects, and three copies of one type is three places for the
/// rendering rule to drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// The program's name, as a command line spells it.
    program: String,
    /// The arguments, one per argument, in the order they are passed.
    arguments: Vec<String>,
}

impl Invocation {
    /// A program and its arguments.
    ///
    /// The arguments are taken as string slices because every caller has constants
    /// or already-owned names, and the whole of the type's rule is that an argument
    /// with a space in it stays *one* argument: nothing here splits anything.
    #[must_use]
    pub fn of(program: &str, arguments: &[&str]) -> Self {
        Self {
            program: program.to_owned(),
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
        }
    }

    /// The program's name, as a command line spells it.
    ///
    /// **A name, not a path, and not necessarily startable.** See the type's own
    /// documentation.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// The arguments, one per argument.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    /// The same plan with one more argument.
    ///
    /// **An argument appended to the plan, not to its rendering.** `checks::rust`
    /// needs `cargo fmt --check` where the discovery plans `cargo fmt`, and doing
    /// that by formatting a string and splitting it again is the parse this type
    /// exists to make unnecessary.
    #[must_use]
    pub fn with_argument(&self, argument: &str) -> Self {
        let mut arguments = self.arguments.clone();
        arguments.push(argument.to_owned());
        Self {
            program: self.program.clone(),
            arguments,
        }
    }

    /// The line a person reads and a report prints.
    ///
    /// A space and the vector joined, which is how every command these modules have
    /// ever produced was spelled: none of the programs, tools or subcommands in one
    /// contains a space. **The string is a rendering and nothing reads it back into
    /// a program** — the vector is what a runner is handed.
    #[must_use]
    pub fn rendered(&self) -> String {
        format!("{} {}", self.program, self.arguments.join(" "))
    }
}

/// Whether a workspace member has a manifest of its own.
///
/// Answered without reading it, so this is about what is at the name rather than
/// about what it says. It is the cheap summary that lets a member be described
/// even when the manifest budget ran out before SURE reached it.
///
/// Here rather than in one ecosystem's module because every ecosystem that has
/// workspaces asks the same question about a member and answers it from the same
/// [`Probe`](read::Probe) — Node with `package.json`, Cargo with `Cargo.toml` —
/// and a member that could be `Present` in one module's vocabulary and
/// `NotReadable` in another would be one directory described two ways.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberManifest {
    /// There is a manifest at the member's expected name.
    Present,
    /// There is nothing at that name.
    Absent,
    /// There is something at that name that SURE does not read.
    NotReadable(&'static str),
}

/// Everything step 1 found out.
///
/// Carries the [`Scan`] it was built on rather than dropping it. The scan is the
/// file list every later stage reads, and a discovery that walked the project
/// and then threw the walk away would make each of them walk it again — with the
/// risk that two walks of one project disagree, which is the failure
/// `docs/architecture/PROJECT_DISCOVERY.md` is written to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The directory that was looked at, as it was given.
    pub root: PathBuf,
    /// The walk, so that "could SURE see everything?" stays answerable.
    pub scan: Scan,
    /// One report per ecosystem that was found, in [`Ecosystem::ALL`] order.
    ///
    /// [`discover`] pushes them in that order, so a project that is both a Node
    /// and a Python project reports Node first. The order is a property of the
    /// product rather than of the walk, and the walk's order is not visible here.
    pub ecosystems: Vec<EcosystemReport>,
    /// Files that were there and could not be read.
    pub unread: Vec<Unread>,
}

impl Discovery {
    /// The ecosystems this build looks for, whether or not they were found.
    ///
    /// The point of it: [`Self::ecosystems`] being empty means *none of these
    /// were found*, and a caller that renders that as "nothing here" without
    /// naming them is making a stronger claim than the data supports.
    #[must_use]
    pub fn looked_for(&self) -> &'static [Ecosystem] {
        Ecosystem::ALL
    }

    /// What was found for one ecosystem, if anything was.
    #[must_use]
    pub fn report(&self, ecosystem: Ecosystem) -> Option<&EcosystemReport> {
        self.ecosystems
            .iter()
            .find(|report| report.ecosystem == ecosystem)
    }

    /// Whether the walk this rests on saw everything.
    ///
    /// `false` is the honest answer to a great many questions and not a
    /// failure: it means some part of the project was not looked at, so a
    /// missing manifest may exist rather than be absent.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.scan.is_complete()
    }

    /// What the walk did not look at, for a caller that has to say so.
    pub fn losses(&self) -> impl Iterator<Item = &Skipped> {
        self.scan.losses()
    }

    /// The stacks, in the domain's own vocabulary.
    ///
    /// This is the form the check pipeline consumes — `Project::stacks` is a
    /// `Vec<StackClassification>` — and it is derived here rather than stored
    /// twice, so a report cannot disagree with the findings it came from.
    #[must_use]
    pub fn stacks(&self) -> Vec<StackClassification> {
        self.ecosystems
            .iter()
            .map(|report| StackClassification {
                stack: report.ecosystem.as_str().to_owned(),
                level: report.level,
                reason: report.reason.clone(),
            })
            .collect()
    }
}

/// How hard discovery is allowed to try.
///
/// Limits on work, in the same spirit as [`ScanOptions`] and
/// `FingerprintOptions`: every one that is reached is reported rather than
/// applied quietly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoverOptions {
    /// Limits on the walk. The same tables, the same rules.
    pub scan: ScanOptions,
    /// How many bytes of one manifest SURE will read.
    ///
    /// Reaching this is a [`UnreadReason::TooLarge`] and **not** a parse of the
    /// first however-many bytes: half a `package.json` is not a smaller
    /// `package.json`, it is a document that will fail to parse for a reason
    /// that has nothing to do with the project.
    pub max_manifest_bytes: u64,
    /// How many manifests SURE will read in one discovery.
    ///
    /// Reaching this is a [`UnreadReason::OutOfBudget`] for the manifests after
    /// it. A workspace with ten thousand members is a project SURE cannot
    /// describe member by member, and saying so is the useful answer.
    pub max_manifests: usize,
    /// How many workspace members are listed.
    pub max_workspace_members: usize,
}

impl Default for DiscoverOptions {
    fn default() -> Self {
        Self {
            scan: ScanOptions::default(),
            // 8 MiB. A `package.json` a person wrote is kilobytes; one that is
            // megabytes is generated, and reading it to find out it is generated
            // is the cost this limit avoids.
            max_manifest_bytes: 8 * 1024 * 1024,
            max_manifests: 512,
            max_workspace_members: 512,
        }
    }
}

impl DiscoverOptions {
    /// The same options with different limits on the walk.
    #[must_use]
    pub const fn with_scan(mut self, scan: ScanOptions) -> Self {
        self.scan = scan;
        self
    }

    /// The same options with a different per-manifest byte limit.
    #[must_use]
    pub const fn with_max_manifest_bytes(mut self, max_manifest_bytes: u64) -> Self {
        self.max_manifest_bytes = max_manifest_bytes;
        self
    }

    /// The same options with a different manifest limit.
    #[must_use]
    pub const fn with_max_manifests(mut self, max_manifests: usize) -> Self {
        self.max_manifests = max_manifests;
        self
    }

    /// The same options with a different workspace member limit.
    #[must_use]
    pub const fn with_max_workspace_members(mut self, max_workspace_members: usize) -> Self {
        self.max_workspace_members = max_workspace_members;
        self
    }
}

/// Look at a project and say what it declares itself to be.
///
/// **The only way this fails is by not being able to look at all.** Everything
/// that goes wrong *inside* the project — a manifest that is too large, one
/// that is not valid UTF-8, one that is not JSON — is a [`Unread`] in the
/// result, because a project with one unreadable file is still a project SURE
/// can say something true about, and an error would replace that with nothing.
///
/// # Errors
///
/// [`ScanError`], which is the whole list: the root is not absolute, is missing,
/// is not a directory, or could not be listed. Those are the cases where there
/// is nothing to describe rather than something SURE failed to describe.
///
/// # Examples
///
/// ```no_run
/// use sure_core::discover::{DiscoverOptions, discover};
///
/// # fn main() -> Result<(), sure_core::scan::ScanError> {
/// let found = discover(
///     std::path::Path::new(r"C:\work\project"),
///     &DiscoverOptions::default(),
/// )?;
/// for stack in found.stacks() {
///     println!("{} ({:?}): {}", stack.stack, stack.level, stack.reason);
/// }
/// # Ok(())
/// # }
/// ```
pub fn discover(root: &Path, options: &DiscoverOptions) -> Result<Discovery, ScanError> {
    let scan = crate::scan::scan(root, options.scan)?;

    let mut budget = read::Budget::new(options.max_manifests);
    let mut unread = Vec::new();
    let mut ecosystems = Vec::new();

    if let Some(report) = node::look(root, &scan, options, &mut budget, &mut unread) {
        ecosystems.push(report);
    }
    if let Some(report) = python::look(root, &scan, options, &mut budget, &mut unread) {
        ecosystems.push(report);
    }
    if let Some(report) = rust::look(root, &scan, options, &mut budget, &mut unread) {
        ecosystems.push(report);
    }
    if let Some(report) = go::look(root, &scan, options, &mut budget, &mut unread) {
        ecosystems.push(report);
    }
    if let Some(report) = dotnet::look(root, &scan, options, &mut budget, &mut unread) {
        ecosystems.push(report);
    }

    Ok(Discovery {
        root: root.to_path_buf(),
        scan,
        ecosystems,
        unread,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_ecosystem_this_build_looks_for_can_be_named_and_described() {
        for &ecosystem in Ecosystem::ALL {
            assert!(!ecosystem.as_str().is_empty());
            assert!(!ecosystem.plain_name().is_empty());
        }
        // The list is the answer to "did SURE look?", so a list that omitted
        // one would make an untouched ecosystem look like an absent one.
        assert_eq!(Ecosystem::ALL.len(), 5);
        assert!(Ecosystem::ALL.contains(&Ecosystem::Node));
        assert!(Ecosystem::ALL.contains(&Ecosystem::Python));
        assert!(Ecosystem::ALL.contains(&Ecosystem::Rust));
        assert!(Ecosystem::ALL.contains(&Ecosystem::Go));
        assert!(Ecosystem::ALL.contains(&Ecosystem::Dotnet));
        // Distinct, so that `report(ecosystem)` can find at most one and two
        // ecosystems cannot answer to one name.
        let names: std::collections::BTreeSet<&str> =
            Ecosystem::ALL.iter().map(|found| found.as_str()).collect();
        assert_eq!(names.len(), Ecosystem::ALL.len());
    }

    #[test]
    fn the_limits_are_limits_on_work_and_all_of_them_are_finite() {
        let options = DiscoverOptions::default();
        assert!(
            options.max_manifest_bytes > 0,
            "a limit of zero reads nothing"
        );
        assert!(options.max_manifests > 0);
        assert!(options.max_workspace_members > 0);
        assert!(options.scan.max_entries > 0);
    }

    #[test]
    fn discovery_covers_exactly_what_the_scan_could_read() {
        // The same property the fingerprint has, for the same reason: a check
        // can only be as good as the file list behind it, and these two must
        // come from one place rather than two that agree today.
        let options = DiscoverOptions::default();
        assert_eq!(options.scan, ScanOptions::default());
    }
}
