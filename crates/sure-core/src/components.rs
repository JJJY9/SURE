//! The project as a graph of components, built from what discovery read.
//!
//! Step 1 of `docs/architecture/CHECK_PIPELINE.md` says *"Discover
//! project/workspace, stacks, **components**, declared commands, config
//! references and support level."* [`crate::discover`] is the reading half of
//! that — what each manifest says. This module is the structuring half: **one
//! list of the places in a project that are a thing in their own right**, so
//! that a monorepo is represented as the several components it is rather than as
//! one project with some directories in it.
//!
//! `docs/architecture/COMPONENT_GRAPH.md` is the authority for the rules here.
//!
//! # The rule everything here is arranged around
//!
//! **A component SURE did not read a manifest at does not have a stack.** It has
//! an inference, or it has nothing, and the type says which. There is no
//! `stack: Option<Something>` a caller could render as "no stack", and no plain
//! value a caller could render as a fact.
//!
//! The temptation this is built against is the one that makes a graph look tidy:
//! a member directory whose `package.json` SURE did not open is not a component
//! with an unknown framework, it is **a directory a workspace declaration named
//! and SURE knows nothing else about** — and a reader told the first thing will
//! go looking for a framework that was never claimed.
//!
//! # Why the readings are kept per ecosystem
//!
//! [`Component::manifests`] holds one [`ComponentManifest`] per ecosystem at
//! that component rather than one merged verdict. A merge is where a bug would
//! live: Node and Rust can name the same directory, one of them read a manifest
//! and the other did not, and a single field would have to pick — losing a fact,
//! in one direction or the other, silently. Keeping both means there is no merge
//! to get wrong, and [`Component::stack`] is a *derivation* over the list rather
//! than a stored summary that could drift from it.
//!
//! # What it does not do
//!
//! **It does not resolve dependencies between components.** A `package.json`
//! saying `"@app/ui": "workspace:*"` is a request to a resolver SURE has not
//! run, and drawing that as an edge would be asserting the resolution. What is
//! here is *containment*, which is a fact about the paths in the walk, and
//! *declaration*, which is a fact about a file SURE read and which carries its
//! [`Source`].
//!
//! **It does not read anything.** It is a view over a [`Discovery`] and opens no
//! file, so it cannot disagree with the discovery it came from about what was in
//! the project.
//!
//! **It does not decide what kind of thing a component is.** An application, a
//! library and a service are not distinguishable from a manifest SURE has read,
//! and a guess about which one a directory is would be exactly the inference
//! this module refuses to promote.

use std::path::{Path, PathBuf};

use crate::discover::{
    Discovery, DotnetProject, Ecosystem, Findings, GoProject, MemberManifest, PythonProject,
    Source, UnreadReason, node, python, rust,
};

/// Every component in a project, and which contains which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentGraph {
    /// The project root, as discovery was given it.
    pub root: PathBuf,
    /// The root itself, then every member.
    ///
    /// Sorted by path, so the list does not depend on which ecosystem happened
    /// to be read first. A directory two ecosystems name is **one** component
    /// carrying two readings, not two components: it is one place in the
    /// project, and two entries for it would double every count taken over this
    /// list.
    pub components: Vec<Component>,
    /// What each ecosystem was able to say about members, in [`Ecosystem::ALL`]
    /// order and with one entry each, whether or not that ecosystem was found.
    ///
    /// This is the field that stops a reader concluding *"this project has one
    /// component"* from a graph that is one component wide because an ecosystem
    /// never looked — see [`Members`].
    pub resolution: Vec<EcosystemResolution>,
    /// Which component contains which, by path.
    pub contains: Vec<Containment>,
}

impl ComponentGraph {
    /// Build the graph from a discovery result.
    ///
    /// Reads nothing: every fact here is one discovery already established.
    #[must_use]
    pub fn of(discovery: &Discovery) -> Self {
        let mut components: Vec<Component> = vec![Component::root(discovery)];
        let mut resolution: Vec<EcosystemResolution> = Vec::new();
        for ecosystem in Ecosystem::ALL {
            let report = discovery.report(*ecosystem);
            resolution.push(EcosystemResolution::of(
                *ecosystem,
                report.map(|found| &found.findings),
            ));
            if let Some(report) = report {
                add_members(&mut components, *ecosystem, &report.findings);
            }
        }
        // By path, which is `Path`'s own order: component by component, so the
        // root — the empty path, with no components at all — sorts first and
        // `packages/alpha` sorts before `packages/zeta` whatever they are made
        // of. Without this the order would be whichever ecosystem was read
        // first, and two runs of one project would print their components
        // differently.
        components.sort_by(|left, right| left.path.cmp(&right.path));
        let contains = containments(&components);
        Self {
            root: discovery.root.clone(),
            components,
            resolution,
            contains,
        }
    }

    /// The project root.
    ///
    /// Always present: [`Self::of`] builds it before anything else and the root
    /// is the empty path, which sorts first for every input. A caller asking for
    /// the root never has to answer "what if there is no root".
    #[must_use]
    pub fn root_component(&self) -> &Component {
        &self.components[0]
    }

    /// One component by its path, relative to the project root.
    #[must_use]
    pub fn get(&self, path: &Path) -> Option<&Component> {
        self.components.iter().find(|part| part.path == path)
    }

    /// Every component that is not the root.
    pub fn members(&self) -> impl Iterator<Item = &Component> {
        self.components
            .iter()
            .filter(|part| part.role == ComponentRole::Member)
    }

    /// Whether the project is more than its root.
    ///
    /// **Check [`Self::resolution`] before reporting `false` as "this is a
    /// single-component project".** An ecosystem that never looked has no
    /// members here, and [`Members::NotRead`] is what says so.
    #[must_use]
    pub fn is_multi_component(&self) -> bool {
        self.members().next().is_some()
    }

    /// Every component SURE cannot state a stack for.
    ///
    /// The list a caller renders as "what SURE could not tell you". It exists
    /// rather than being derived at each call site because a component without a
    /// read stack is the one a report is most likely to describe as a fact by
    /// accident.
    pub fn not_read(&self) -> impl Iterator<Item = &Component> {
        self.components
            .iter()
            .filter(|part| part.stack() != Stack::Read)
    }

    /// What one ecosystem could say about members.
    #[must_use]
    pub fn resolution_of(&self, ecosystem: Ecosystem) -> Option<&EcosystemResolution> {
        self.resolution
            .iter()
            .find(|found| found.ecosystem == ecosystem)
    }

    /// The sentence a person reads, describing the project's shape.
    ///
    /// Built from constants and ecosystem names. **It names every ecosystem
    /// whose member list SURE did not read**, because that is the caveat which
    /// turns "one component" from a finding into a claim SURE has not earned.
    #[must_use]
    pub fn plain_description(&self) -> String {
        let members = self.members().count();
        let mut sentence = if members == 0 {
            "SURE found one component in this project.".to_owned()
        } else {
            format!("SURE found {members} components besides the project root.")
        };
        for found in &self.resolution {
            if let Members::NotRead { because } = found.members {
                sentence.push(' ');
                sentence.push_str(found.ecosystem.plain_name());
                sentence.push_str(": ");
                sentence.push_str(because);
            }
        }
        if self
            .resolution
            .iter()
            .any(|found| matches!(found.members, Members::Resolved { truncated: true }))
        {
            sentence.push_str(
                " Some member lists were longer than SURE reads in one run, so this \
                 is not the whole project.",
            );
        }
        sentence
    }
}

/// One place in the project that is a thing in its own right.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// The directory, relative to the project root. Empty for the root itself.
    pub path: PathBuf,
    /// Whether this is the root or something a workspace declaration named.
    pub role: ComponentRole,
    /// What each ecosystem found here, in [`Ecosystem::ALL`] order.
    ///
    /// Empty is possible for the root of a project SURE found nothing at, and is
    /// the honest answer there. It is impossible for a
    /// [`ComponentRole::Member`]: a member exists because an ecosystem named it.
    pub manifests: Vec<ComponentManifest>,
    /// The files that named this component as a member, in the order they were
    /// read.
    ///
    /// Empty for the root, which no file names: it is the project.
    pub declared_by: Vec<Source>,
}

impl Component {
    /// The root component, from the whole discovery result.
    fn root(discovery: &Discovery) -> Self {
        let manifests = discovery
            .ecosystems
            .iter()
            .map(|report| ComponentManifest {
                ecosystem: report.ecosystem,
                reading: match &report.findings {
                    Findings::Node(project) => root_reading(&project.manifest),
                    Findings::Python(project) => python_root_reading(project),
                    Findings::Rust(project) => rust_root_reading(&project.manifest),
                    Findings::Go(project) => go_root_reading(project),
                    Findings::Dotnet(project) => dotnet_root_reading(project),
                },
            })
            .collect();
        Self {
            path: PathBuf::new(),
            role: ComponentRole::Root,
            manifests,
            declared_by: Vec::new(),
        }
    }

    /// The ecosystems that named this component, in [`Ecosystem::ALL`] order.
    pub fn ecosystems(&self) -> impl Iterator<Item = Ecosystem> + '_ {
        self.manifests.iter().map(|found| found.ecosystem)
    }

    /// What SURE may state about what this component is built with.
    ///
    /// Derived from [`Self::manifests`] on every call rather than stored, so it
    /// cannot disagree with the readings it is derived from.
    #[must_use]
    pub fn stack(&self) -> Stack {
        let read = self.read_ecosystems().len();
        if self.manifests.is_empty() || read == 0 {
            Stack::Unknown
        } else if read == self.manifests.len() {
            Stack::Read
        } else {
            Stack::Partial
        }
    }

    /// What SURE knows about one ecosystem at this component.
    #[must_use]
    pub fn manifest_of(&self, ecosystem: Ecosystem) -> Option<&ComponentManifest> {
        self.manifests
            .iter()
            .find(|found| found.ecosystem == ecosystem)
    }

    /// The sentence a person reads about this component's stack.
    ///
    /// Built from ecosystem names and constants. **No project text can reach
    /// it** — the variable parts of an [`UnreadReason`] are reported through
    /// [`UnreadReason::detail`] and are not composed into a sentence here, which
    /// is the division `docs/architecture/EVIDENCE_MODEL.md` draws between what
    /// SURE says and what something else said.
    #[must_use]
    pub fn plain_description(&self) -> String {
        let read = self.read_ecosystems();
        let unread = self.unread_ecosystems();
        match self.stack() {
            Stack::Read => {
                format!("SURE read this component's {} manifest.", plain_list(&read))
            }
            Stack::Partial => format!(
                "SURE read this component's {} manifest and did not read its {}. What \
                 this component is built with is an inference.",
                plain_list(&read),
                plain_list(&unread)
            ),
            Stack::Unknown if unread.is_empty() => {
                "SURE read nothing at this component.".to_owned()
            }
            Stack::Unknown => format!(
                "SURE read nothing at this component, and what is there for its {} is \
                 something SURE does not read. What this component is built with is an \
                 inference.",
                plain_list(&unread)
            ),
        }
    }

    /// The ecosystems whose manifest at this component was read.
    #[must_use]
    pub fn read_ecosystems(&self) -> Vec<Ecosystem> {
        self.manifests
            .iter()
            .filter(|found| found.reading.is_read())
            .map(|found| found.ecosystem)
            .collect()
    }

    /// The ecosystems at this component whose manifest was not read.
    ///
    /// Includes an ecosystem with no manifest here at all, because that is also
    /// a stack SURE cannot state.
    #[must_use]
    pub fn unread_ecosystems(&self) -> Vec<Ecosystem> {
        self.manifests
            .iter()
            .filter(|found| !found.reading.is_read())
            .map(|found| found.ecosystem)
            .collect()
    }
}

/// Whether a component is the project itself or something a workspace named.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ComponentRole {
    /// The directory discovery was given.
    Root,
    /// A directory a workspace declaration named.
    Member,
}

impl ComponentRole {
    /// The stable name, used in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Member => "member",
        }
    }
}

/// What one ecosystem found at one component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentManifest {
    /// Which ecosystem.
    pub ecosystem: Ecosystem,
    /// Whether it read a manifest here, and if not, why not.
    pub reading: ManifestReading,
}

/// Whether one ecosystem's manifest at one component was read.
///
/// There is no arm for "there is a stack here". Nothing in a manifest SURE has
/// read says what a project is *built with* in the sense a reader wants; the
/// closest fact available is [`Self::Read`], and it means *a manifest was read*,
/// which is what it is named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestReading {
    /// SURE read this ecosystem's manifest at this component.
    Read,
    /// SURE tried to read it and did not get a value out, and this is why.
    ///
    /// The reason is [`UnreadReason`], whose own `plain_description` is all
    /// constants and whose variable parts are separated into `detail` — so
    /// carrying it here does not let project text into a sentence.
    Unread(UnreadReason),
    /// There is a manifest at this component's name and SURE did not open it.
    ///
    /// Distinguished from [`Self::Unread`] by what SURE knows: `Unread` means a
    /// read was attempted and its reason was recorded; this means the name was
    /// seen and nothing was attempted, so there is no reason to give. It is what
    /// a workspace member past the manifest budget looks like.
    NotOpened,
    /// Something is at the manifest's name and it is not a file SURE reads.
    NotAFile {
        /// What is there, as one of discovery's own phrases.
        kind: &'static str,
    },
    /// This ecosystem is at this component and has no manifest of its own here.
    ///
    /// **Not the same as a failed read.** An ecosystem found only by a lockfile,
    /// or a member directory a pattern named that holds nothing, is this — and
    /// there was nothing to read rather than something SURE missed.
    NoManifest,
}

impl ManifestReading {
    /// Whether SURE read a manifest here.
    #[must_use]
    pub const fn is_read(&self) -> bool {
        matches!(self, Self::Read)
    }

    /// The sentence a person reads. Every phrase is a constant.
    #[must_use]
    pub const fn plain_description(&self) -> &'static str {
        match self {
            Self::Read => "SURE read this component's manifest.",
            Self::Unread(reason) => reason.plain_description(),
            Self::NotOpened => {
                "A workspace named this directory, and it has a manifest SURE did not \
                 open."
            }
            Self::NotAFile { .. } => {
                "Something is at this manifest's name, and it is not a file SURE reads."
            }
            Self::NoManifest => {
                "This component has no manifest of its own for this kind of project."
            }
        }
    }
}

/// What SURE may state about what a component is built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stack {
    /// Every ecosystem at this component had its manifest read.
    ///
    /// The strongest thing available, and it is still a statement about files:
    /// SURE read them. It is not a statement about what is installed.
    Read,
    /// Some ecosystems were read and some were not.
    Partial,
    /// Nothing at this component was read.
    Unknown,
}

impl Stack {
    /// Whether every ecosystem at this component was read.
    #[must_use]
    pub const fn is_read(self) -> bool {
        matches!(self, Self::Read)
    }

    /// The stable name, used in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Partial => "partial",
            Self::Unknown => "unknown",
        }
    }
}

/// What one ecosystem was able to say about the members of the project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcosystemResolution {
    /// Which ecosystem.
    pub ecosystem: Ecosystem,
    /// Whether it resolved a member list, and if not, why not.
    pub members: Members,
}

impl EcosystemResolution {
    /// What one ecosystem said, from its findings.
    ///
    /// `findings` is `None` when the ecosystem was not found, which is *"SURE
    /// looked and there was nothing"* and not *"SURE did not look"* — the
    /// distinction [`Discovery::looked_for`] exists for.
    #[must_use]
    pub fn of(ecosystem: Ecosystem, findings: Option<&Findings>) -> Self {
        let members = match findings {
            None => Members::NoProject,
            Some(Findings::Node(project)) => members_of(
                project.workspaces.is_declared(),
                project.workspaces.truncated,
            ),
            Some(Findings::Rust(project)) => members_of(
                project.workspaces.is_declared(),
                project.workspaces.truncated,
            ),
            // Python resolves members through `[tool.uv.workspace]` and
            // `[tool.pdm.workspace]` tables that `python.rs` does not read, and
            // it reads no member list at all. So this is `NotRead` for **every**
            // Python project and not only for one whose `pyproject.toml` happens
            // to carry a workspace table: SURE cannot tell those apart, and an
            // answer that depended on telling them apart would be an answer SURE
            // has not earned.
            Some(Findings::Python(_)) => Members::NotRead {
                because: "Python projects can be several packages, and SURE does not \
                          read the tables that say so, so a Python project is \
                          reported as one component whether or not it is several.",
            },
            Some(Findings::Go(project)) => {
                if project.workspace.is_some() {
                    Members::Resolved { truncated: false }
                } else {
                    Members::NotRead {
                        because: "SURE could not read this project's go.work, so it \
                                  cannot tell which modules the workspace names.",
                    }
                }
            }
            Some(Findings::Dotnet(_)) => Members::NotRead {
                because: "A .NET solution names its projects, and SURE reads the solution \
                          marker but does not expand the project graph, so a .NET project \
                          is reported as one component whether or not it is several.",
            },
        };
        Self { ecosystem, members }
    }
}

/// Whether an ecosystem resolved the project's members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Members {
    /// The ecosystem was not found in this project, so it named no members.
    NoProject,
    /// The ecosystem was found and declares no workspace, so the project is one
    /// component as far as it is concerned.
    ///
    /// A real answer and not a gap: a `package.json` with no `workspaces` field
    /// is a project that is one package.
    NoWorkspace,
    /// A member list was read.
    Resolved {
        /// `true` means there were more members than the limit allowed and this
        /// graph is missing some. A caller that reports the member count without
        /// this is reporting on a project SURE did not finish looking at.
        truncated: bool,
    },
    /// The ecosystem can name members and SURE did not read the declaration.
    ///
    /// **This is the arm that must not be rendered as "no members".** `false`
    /// from [`ComponentGraph::is_multi_component`] under this arm means *SURE
    /// does not know*, and a report that says "one component" instead is making
    /// a claim the data does not support.
    NotRead {
        /// Why, as a constant.
        because: &'static str,
    },
}

impl Members {
    /// Whether SURE may say the project is one component.
    ///
    /// `true` only where SURE looked and found no workspace. `false` for
    /// [`Members::NotRead`], which is the whole point of the variant.
    #[must_use]
    pub const fn is_known_single(self) -> bool {
        matches!(self, Self::NoProject | Self::NoWorkspace)
    }

    /// The sentence a person reads.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::NoProject => "SURE found no project of this kind here.",
            Self::NoWorkspace => {
                "SURE read this project's declaration and it names no members, so this \
                 project is one component."
            }
            Self::Resolved { truncated: false } => {
                "SURE read this project's member list, and it is complete."
            }
            Self::Resolved { truncated: true } => {
                "SURE read this project's member list and it was longer than the \
                 limit, so some members are not in this graph."
            }
            Self::NotRead { because } => because,
        }
    }
}

/// One component's directory being inside another's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Containment {
    /// The component that contains.
    pub outer: PathBuf,
    /// The component contained.
    pub inner: PathBuf,
}

/// Add one ecosystem's members to the list, merging into components already
/// there.
fn add_members(components: &mut Vec<Component>, ecosystem: Ecosystem, findings: &Findings) {
    match findings {
        Findings::Node(project) => {
            for member in &project.workspaces.members {
                merge(
                    components,
                    ecosystem,
                    &member.path,
                    member_reading(member.package.is_some(), member.manifest),
                    &project.workspaces.declared_by,
                );
            }
        }
        Findings::Rust(project) => {
            for member in &project.workspaces.members {
                merge(
                    components,
                    ecosystem,
                    &member.path,
                    member_reading(member.package.is_some(), member.manifest),
                    &project.workspaces.declared_by,
                );
            }
        }
        // Reached by no caller today: `add_members` runs only for an ecosystem
        // whose report exists, and the Python report carries no member list. It
        // is written out rather than left to a wildcard so that giving Python a
        // member list later fails to compile here until somebody decides what a
        // Python member is — which is the reason [`Findings`] is an enum.
        Findings::Python(_) => {}
        Findings::Go(project) => {
            let declared_by = [Source::new(
                crate::discover::go::WORKSPACE,
                "the use directives",
            )];
            for module in &project.modules {
                merge(
                    components,
                    ecosystem,
                    &module.path,
                    go_member_reading(module),
                    &declared_by,
                );
            }
        }
        Findings::Dotnet(_) => {}
    }
}

/// Add one member to the list, or merge it into a component already there.
fn merge(
    components: &mut Vec<Component>,
    ecosystem: Ecosystem,
    path: &Path,
    reading: ManifestReading,
    declared_by: &[Source],
) {
    if let Some(existing) = components.iter_mut().find(|part| part.path == path) {
        // Two ecosystems naming one directory is two findings about one place.
        // Both are kept, in `Ecosystem::ALL` order, so there is no merge
        // decision for a bug to hide in.
        if existing.manifest_of(ecosystem).is_none() {
            existing
                .manifests
                .push(ComponentManifest { ecosystem, reading });
            existing.manifests.sort_by_key(|found| found.ecosystem);
        }
        for source in declared_by {
            if !existing.declared_by.contains(source) {
                existing.declared_by.push(source.clone());
            }
        }
        return;
    }
    components.push(Component {
        path: path.to_path_buf(),
        role: ComponentRole::Member,
        manifests: vec![ComponentManifest { ecosystem, reading }],
        declared_by: declared_by.to_vec(),
    });
}

/// What a workspace member's manifest is, from the two facts discovery kept.
///
/// `package_read` is whether the member's own manifest was parsed, and
/// `manifest` is what discovery saw at its name without parsing. The four
/// combinations are four different things and none of them collapses into
/// another.
fn go_member_reading(module: &crate::discover::go::GoModule) -> ManifestReading {
    if module.manifest.is_some() {
        ManifestReading::Read
    } else if let Some(reason) = &module.unread {
        ManifestReading::Unread(reason.clone())
    } else {
        ManifestReading::NoManifest
    }
}

fn member_reading(package_read: bool, manifest: MemberManifest) -> ManifestReading {
    if package_read {
        return ManifestReading::Read;
    }
    match manifest {
        MemberManifest::Absent => ManifestReading::NoManifest,
        MemberManifest::Present => ManifestReading::NotOpened,
        MemberManifest::NotReadable(kind) => ManifestReading::NotAFile { kind },
    }
}

/// What a Node or Rust root manifest is, from its own three-armed state.
fn root_reading(state: &node::ManifestState) -> ManifestReading {
    match state {
        node::ManifestState::Read(_) => ManifestReading::Read,
        node::ManifestState::Absent => ManifestReading::NoManifest,
        node::ManifestState::Unread(reason) => ManifestReading::Unread(reason.clone()),
    }
}

/// The same for Rust, whose `ManifestState` is a different type with the same
/// three arms. Written out rather than shared through a trait, because the
/// payloads differ and a trait would exist only to save these six lines.
fn rust_root_reading(state: &rust::ManifestState) -> ManifestReading {
    match state {
        rust::ManifestState::Read(_) => ManifestReading::Read,
        rust::ManifestState::Absent => ManifestReading::NoManifest,
        rust::ManifestState::Unread(reason) => ManifestReading::Unread(reason.clone()),
    }
}

/// Python's root is two files, and its manifest was read if either was.
///
/// `pyproject.toml` and `Pipfile` can both be present, they can disagree, and
/// `python.rs` keeps them apart on purpose. Here they are brought together for
/// one question only — *did SURE read a Python manifest at this root?* — and a
/// recorded failure outranks a missing file, because "there is a `pyproject.toml`
/// SURE could not read" is the answer a reader needs and "no manifest" would be
/// wrong.
fn dotnet_root_reading(project: &DotnetProject) -> ManifestReading {
    if project.manifest.is_some() {
        ManifestReading::Read
    } else if let Some(reason) = &project.unread {
        ManifestReading::Unread(reason.clone())
    } else {
        ManifestReading::NoManifest
    }
}

fn go_root_reading(project: &GoProject) -> ManifestReading {
    if project.manifest.is_some() {
        ManifestReading::Read
    } else if let Some(reason) = &project.unread {
        ManifestReading::Unread(reason.clone())
    } else {
        ManifestReading::NoManifest
    }
}

fn python_root_reading(project: &PythonProject) -> ManifestReading {
    let states = [&project.manifest, &project.pipfile];
    if states
        .iter()
        .any(|state| matches!(state, python::ManifestState::Read(_)))
    {
        return ManifestReading::Read;
    }
    for state in states {
        if let python::ManifestState::Unread(reason) = state {
            return ManifestReading::Unread(reason.clone());
        }
    }
    ManifestReading::NoManifest
}

/// The members answer for an ecosystem that resolves member lists.
fn members_of(declared: bool, truncated: bool) -> Members {
    if declared {
        Members::Resolved { truncated }
    } else {
        Members::NoWorkspace
    }
}

/// A plain-language list of ecosystem names.
fn plain_list(ecosystems: &[Ecosystem]) -> String {
    let names: Vec<&'static str> = ecosystems.iter().map(|one| one.plain_name()).collect();
    match names.as_slice() {
        [] => "no".to_owned(),
        [one] => (*one).to_owned(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Every containment between the components.
fn containments(components: &[Component]) -> Vec<Containment> {
    let mut found = Vec::new();
    for inner in components {
        if inner.path.as_os_str().is_empty() {
            continue;
        }
        // The nearest component above it, so a member inside a member is one
        // edge and not two. The root is the empty path, which every relative
        // path starts with, so it is always a candidate and always the last
        // resort.
        let outer = components
            .iter()
            .filter(|outer| {
                outer.path.as_os_str().is_empty()
                    || (inner.path != outer.path && inner.path.starts_with(&outer.path))
            })
            .max_by_key(|outer| outer.path.components().count());
        if let Some(outer) = outer {
            found.push(Containment {
                outer: outer.path.clone(),
                inner: inner.path.clone(),
            });
        }
    }
    found
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    //! Tests for **this** module.
    //!
    //! Every test builds a real project on disk and runs it through `scan` and
    //! `discover` before asking the graph a question, so a discovery that
    //! changed shape fails here rather than being papered over by a hand-built
    //! `Discovery` that no longer matches what discovery produces.

    use super::*;
    use crate::discover::{DiscoverOptions, discover};

    fn scratch(name: &str) -> PathBuf {
        sure_testkit::scratch::directory("components", name)
    }

    fn write(path: &Path, text: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
        }
        std::fs::write(path, text)
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
    }

    fn graph_of(dir: &Path) -> ComponentGraph {
        let found = discover(dir, &DiscoverOptions::default()).expect("discover the fixture");
        ComponentGraph::of(&found)
    }

    #[test]
    fn a_project_with_no_workspace_is_one_component_and_says_so() {
        let dir = scratch("single");
        write(&dir.join("package.json"), r#"{"name":"solo"}"#);
        let graph = graph_of(&dir);

        assert_eq!(graph.components.len(), 1, "{:?}", graph.components);
        assert_eq!(graph.root_component().role, ComponentRole::Root);
        assert_eq!(graph.root_component().stack(), Stack::Read);
        assert!(!graph.is_multi_component());
        // And the reason it is one component is a statement about the file, not
        // a gap: the declaration was read and it names nobody.
        assert_eq!(
            graph
                .resolution_of(Ecosystem::Node)
                .expect("node was looked for")
                .members,
            Members::NoWorkspace
        );
    }

    #[test]
    fn every_named_member_is_a_component_and_the_root_contains_it() {
        let dir = scratch("monorepo");
        write(
            &dir.join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        write(&dir.join("packages/app/package.json"), r#"{"name":"app"}"#);
        write(&dir.join("packages/ui/package.json"), r#"{"name":"ui"}"#);
        let graph = graph_of(&dir);

        let members: Vec<&Path> = graph.members().map(|part| part.path.as_path()).collect();
        assert_eq!(
            members,
            vec![Path::new("packages/app"), Path::new("packages/ui")]
        );
        assert!(graph.is_multi_component());
        for member in graph.members() {
            let edge = graph
                .contains
                .iter()
                .find(|edge| edge.inner == member.path)
                .unwrap_or_else(|| panic!("{} has no container", member.path.display()));
            assert_eq!(edge.outer, PathBuf::new(), "the root contains every member");
            assert_eq!(member.stack(), Stack::Read, "{}", member.path.display());
        }
        assert_eq!(
            graph.not_read().count(),
            0,
            "a member whose manifest was read is not a gap"
        );
        // One edge per member, and the root is in none of them as an inner
        // component — it contains rather than being contained.
        assert_eq!(
            graph.contains.len(),
            graph.members().count(),
            "{:?}",
            graph.contains
        );
        for edge in &graph.contains {
            assert!(
                !edge.inner.as_os_str().is_empty(),
                "the root is contained by something: {edge:?}"
            );
        }
    }

    #[test]
    fn a_member_whose_manifest_is_not_a_file_is_an_inference_and_not_a_stack() {
        let dir = scratch("member-not-a-file");
        write(
            &dir.join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        // A directory where the member's `package.json` would be. Discovery
        // reports this as present-but-not-readable rather than as absent, and
        // the two must not arrive here as the same thing.
        std::fs::create_dir_all(dir.join("packages/app/package.json"))
            .expect("create a directory where a manifest would be");
        let graph = graph_of(&dir);

        let member = graph
            .get(Path::new("packages/app"))
            .expect("the member is still a component");
        assert_eq!(member.stack(), Stack::Unknown, "{:?}", member.manifests);
        assert!(
            matches!(
                member
                    .manifest_of(Ecosystem::Node)
                    .expect("node named it")
                    .reading,
                ManifestReading::NotAFile { .. }
            ),
            "{:?}",
            member.manifest_of(Ecosystem::Node)
        );
        assert!(member.plain_description().contains("inference"));
        assert!(
            graph
                .not_read()
                .any(|part| part.path == Path::new("packages/app"))
        );
    }

    #[test]
    fn a_directory_named_as_a_member_with_no_manifest_has_no_manifest_and_no_stack() {
        let dir = scratch("bare-member");
        write(
            &dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/empty\"]\n",
        );
        std::fs::create_dir_all(dir.join("crates/empty")).expect("create the member");
        let graph = graph_of(&dir);

        let member = graph
            .get(Path::new("crates/empty"))
            .expect("the member is a component");
        assert_eq!(
            member
                .manifest_of(Ecosystem::Rust)
                .expect("rust named it")
                .reading,
            ManifestReading::NoManifest,
            "nothing is at the name, which is not a failed read"
        );
        assert_eq!(member.stack(), Stack::Unknown);
    }

    #[test]
    fn a_member_past_the_manifest_budget_is_not_opened_and_not_absent() {
        let dir = scratch("budget");
        write(
            &dir.join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        write(&dir.join("packages/app/package.json"), r#"{"name":"app"}"#);
        // One manifest is the root's, so the member's name is seen and not
        // opened. The distinction this test exists for: `NotOpened` is "there is
        // a manifest SURE did not open", and `NoManifest` would be a claim that
        // there is nothing there.
        let options = DiscoverOptions {
            max_manifests: 1,
            ..DiscoverOptions::default()
        };
        let found = discover(&dir, &options).expect("discover the fixture");
        let graph = ComponentGraph::of(&found);

        let member = graph
            .get(Path::new("packages/app"))
            .expect("the member is still a component");
        assert_eq!(
            member
                .manifest_of(Ecosystem::Node)
                .expect("node named it")
                .reading,
            ManifestReading::NotOpened,
            "{:?}",
            member.manifests
        );
        assert_eq!(member.stack(), Stack::Unknown);
        assert!(member.plain_description().contains("inference"));
    }

    #[test]
    fn python_reports_its_members_as_not_read_rather_than_as_none() {
        let dir = scratch("python-workspace");
        write(
            &dir.join("pyproject.toml"),
            "[project]\nname = \"root\"\n\n[tool.uv.workspace]\nmembers = [\"packages/app\"]\n",
        );
        write(
            &dir.join("packages/app/pyproject.toml"),
            "[project]\nname = \"app\"\n",
        );
        let graph = graph_of(&dir);

        let resolution = graph
            .resolution_of(Ecosystem::Python)
            .expect("python was looked for");
        assert!(
            matches!(resolution.members, Members::NotRead { .. }),
            "{:?}",
            resolution.members
        );
        // The point of the arm: SURE is not allowed to say "one component".
        assert!(
            !resolution.members.is_known_single(),
            "a Python project with an unread member list is not known to be one \
             component, and `is_known_single` is the question a report asks"
        );
        // And the caveat reaches the graph's own sentence, which is where a
        // caller that never looks at `resolution` will read it.
        assert!(
            graph.plain_description().contains("does not read"),
            "{}",
            graph.plain_description()
        );
    }

    #[test]
    fn the_three_member_answers_are_three_different_things() {
        // One project that is Node and Python and not Rust, so all three arms
        // are reachable and the test can tell them apart in a single graph.
        let dir = scratch("three-arms");
        write(&dir.join("package.json"), r#"{"name":"solo"}"#);
        write(&dir.join("pyproject.toml"), "[project]\nname = \"solo\"\n");
        let graph = graph_of(&dir);

        fn answer(graph: &ComponentGraph, ecosystem: Ecosystem) -> Members {
            graph
                .resolution_of(ecosystem)
                .map(|entry| entry.members)
                .unwrap_or_else(|| {
                    panic!(
                        "{ecosystem:?} has no entry, and every ecosystem is \
                         answered whether or not it was found"
                    )
                })
        }
        let answer = |ecosystem| answer(&graph, ecosystem);

        // Looked, found a project, and it names no members: SURE may say this
        // project is one component.
        assert_eq!(answer(Ecosystem::Node), Members::NoWorkspace);
        assert!(answer(Ecosystem::Node).is_known_single());

        // Looked and found nothing of this kind: also a real answer about
        // members, because there is no Rust project here to have any.
        assert_eq!(answer(Ecosystem::Rust), Members::NoProject);
        assert!(answer(Ecosystem::Rust).is_known_single());

        // Found a project and did not read its member list. This is the arm
        // that must not answer the single-component question — and the reason
        // the test needs Python to be **found**, because a Python that was not
        // found here would be `NoProject` and would answer it truthfully.
        assert!(
            matches!(answer(Ecosystem::Python), Members::NotRead { .. }),
            "{:?}",
            answer(Ecosystem::Python)
        );
        assert!(
            !answer(Ecosystem::Python).is_known_single(),
            "SURE did not read whether this project is several Python packages, \
             so it must not answer the question a report asks before saying \
             \"one component\""
        );
    }

    #[test]
    fn a_directory_two_ecosystems_name_is_one_component_keeping_both_readings() {
        let dir = scratch("both");
        write(
            &dir.join("package.json"),
            r#"{"name":"root","workspaces":["packages/app"]}"#,
        );
        write(&dir.join("packages/app/package.json"), r#"{"name":"app"}"#);
        write(
            &dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"packages/app\"]\n",
        );
        // A directory where the member's `Cargo.toml` would be, so the two
        // readings differ: Node read a manifest here and Rust did not.
        std::fs::create_dir_all(dir.join("packages/app/Cargo.toml"))
            .expect("a directory where Cargo.toml would be");
        let graph = graph_of(&dir);

        let named: Vec<&Component> = graph
            .components
            .iter()
            .filter(|part| part.path == Path::new("packages/app"))
            .collect();
        assert_eq!(
            named.len(),
            1,
            "one directory is one component, not one per ecosystem"
        );
        assert_eq!(
            named[0].ecosystems().collect::<Vec<_>>(),
            vec![Ecosystem::Node, Ecosystem::Rust],
            "both ecosystems, in Ecosystem::ALL order"
        );
        // The fact a merged field would have had to throw away.
        assert_eq!(
            named[0]
                .manifest_of(Ecosystem::Node)
                .expect("node named it")
                .reading,
            ManifestReading::Read
        );
        assert!(matches!(
            named[0]
                .manifest_of(Ecosystem::Rust)
                .expect("rust named it")
                .reading,
            ManifestReading::NotAFile { .. }
        ));
        assert_eq!(
            named[0].stack(),
            Stack::Partial,
            "one read and one not is neither"
        );
        assert!(
            named[0].plain_description().contains("inference"),
            "{}",
            named[0].plain_description()
        );
    }

    #[test]
    fn the_root_of_a_project_sure_read_nothing_at_has_no_stack() {
        let dir = scratch("nothing");
        write(&dir.join("README.md"), "nothing to see");
        let graph = graph_of(&dir);

        let root = graph.root_component();
        assert_eq!(root.stack(), Stack::Unknown);
        assert!(root.manifests.is_empty(), "{:?}", root.manifests);
        assert!(root.plain_description().contains("read nothing"));
    }

    #[test]
    fn a_root_manifest_that_could_not_be_parsed_is_unread_rather_than_absent() {
        let dir = scratch("bad-manifest");
        write(&dir.join("package.json"), "{ this is not json");
        let graph = graph_of(&dir);

        let root = graph.root_component();
        let reading = &root
            .manifest_of(Ecosystem::Node)
            .expect("node was found here")
            .reading;
        assert!(
            matches!(reading, ManifestReading::Unread(_)),
            "a manifest SURE could not parse is not one that is not there: {reading:?}"
        );
        assert_eq!(root.stack(), Stack::Unknown);
        // The reason reaches a person, and it is discovery's own constant.
        assert!(
            reading.plain_description().contains("format"),
            "{}",
            reading.plain_description()
        );
    }

    #[test]
    fn a_pyproject_toml_that_could_not_be_read_is_unread_rather_than_no_manifest() {
        // Python reads two root files and either can be the one that was read.
        // The arm this pins is the one that prefers a recorded failure over a
        // missing file: "there is a `pyproject.toml` SURE could not read" is the
        // answer a reader needs, and "no manifest" would be a different and
        // false one.
        let dir = scratch("python-bad");
        write(&dir.join("pyproject.toml"), "[project\nname = broken\n");
        let graph = graph_of(&dir);

        let root = graph.root_component();
        let reading = &root
            .manifest_of(Ecosystem::Python)
            .expect("python was found here")
            .reading;
        assert!(
            matches!(reading, ManifestReading::Unread(_)),
            "a pyproject.toml SURE could not parse is not one that is not there: {reading:?}"
        );
        assert_eq!(root.stack(), Stack::Unknown);
    }

    #[test]
    fn a_member_list_that_was_cut_short_is_not_reported_as_complete() {
        let dir = scratch("truncated");
        write(
            &dir.join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        write(&dir.join("packages/a/package.json"), r#"{"name":"a"}"#);
        write(&dir.join("packages/b/package.json"), r#"{"name":"b"}"#);
        // Room for one member and two declared, so the list is a prefix of the
        // workspace rather than the workspace.
        let found = discover(
            &dir,
            &DiscoverOptions {
                max_workspace_members: 1,
                ..DiscoverOptions::default()
            },
        )
        .expect("discover the fixture");
        let graph = ComponentGraph::of(&found);

        assert_eq!(
            graph
                .resolution_of(Ecosystem::Node)
                .expect("node was looked for")
                .members,
            Members::Resolved { truncated: true },
            "a prefix reported as a whole workspace is a count about a project \
             SURE did not finish looking at"
        );
        let sentence = graph.plain_description();
        assert!(
            sentence.contains("not the whole project"),
            "the caveat has to reach the graph's own sentence: {sentence}"
        );
    }

    #[test]
    fn a_member_inside_a_member_is_contained_by_its_nearest_parent() {
        let dir = scratch("nested");
        write(
            &dir.join("package.json"),
            r#"{"name":"root","workspaces":["packages/*","packages/app/deep"]}"#,
        );
        write(&dir.join("packages/app/package.json"), r#"{"name":"app"}"#);
        write(
            &dir.join("packages/app/deep/package.json"),
            r#"{"name":"deep"}"#,
        );
        let graph = graph_of(&dir);

        let edge = graph
            .contains
            .iter()
            .find(|edge| edge.inner == Path::new("packages/app/deep"))
            .expect("the nested member is contained");
        assert_eq!(
            edge.outer,
            Path::new("packages/app"),
            "the nearest component above it, not the root"
        );
        assert_eq!(
            graph
                .contains
                .iter()
                .filter(|edge| edge.inner == Path::new("packages/app/deep"))
                .count(),
            1,
            "one edge, not one per enclosing component"
        );
    }

    #[test]
    fn a_containment_is_by_path_component_and_not_by_the_text_of_a_path() {
        let dir = scratch("prefix");
        write(
            &dir.join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        write(&dir.join("packages/app/package.json"), r#"{"name":"app"}"#);
        write(
            &dir.join("packages/application/package.json"),
            r#"{"name":"application"}"#,
        );
        let graph = graph_of(&dir);

        let edge = graph
            .contains
            .iter()
            .find(|edge| edge.inner == Path::new("packages/application"))
            .expect("contained");
        assert_eq!(
            edge.outer,
            PathBuf::new(),
            "`packages/application` starts with the text of `packages/app` and is \
             not inside it"
        );
    }

    #[test]
    fn every_component_carries_the_files_that_named_it_and_no_project_text() {
        let dir = scratch("declared-by");
        write(
            &dir.join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        write(&dir.join("packages/app/package.json"), r#"{"name":"app"}"#);
        let graph = graph_of(&dir);

        let member = graph.get(Path::new("packages/app")).expect("the component");
        assert_eq!(member.declared_by.len(), 1);
        assert_eq!(member.declared_by[0].path, PathBuf::from("package.json"));
        assert!(
            graph.root_component().declared_by.is_empty(),
            "no file names the root; it is the project"
        );
        // Sentences come from constants and ecosystem names, so no project text
        // can reach one.
        for component in &graph.components {
            let sentence = component.plain_description();
            assert!(
                !sentence.contains("packages/app") && !sentence.contains("root"),
                "a project's own text reached a sentence: {sentence}"
            );
        }
    }

    #[test]
    fn a_dependency_naming_a_workspace_package_does_not_become_a_component() {
        let dir = scratch("dependency-not-component");
        write(
            &dir.join("package.json"),
            r#"{"name":"root","dependencies":{"@app/ui":"workspace:*"},"workspaces":["packages/*"]}"#,
        );
        write(&dir.join("packages/app/package.json"), r#"{"name":"app"}"#);
        let graph = graph_of(&dir);

        // A dependency naming another workspace package is a request to a
        // resolver SURE has not run. Only directories a pattern resolved to are
        // components.
        let members: Vec<&Path> = graph.members().map(|part| part.path.as_path()).collect();
        assert_eq!(members, vec![Path::new("packages/app")]);
        assert!(
            graph.get(Path::new("@app/ui")).is_none(),
            "a dependency is not a place in the project"
        );
    }

    #[test]
    fn the_graph_reads_nothing_of_its_own() {
        // The graph is a view: building it twice from one discovery gives one
        // answer, and building it after the directory has changed gives the same
        // one, because nothing here opens a file.
        let dir = scratch("view");
        write(
            &dir.join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        );
        write(&dir.join("packages/app/package.json"), r#"{"name":"app"}"#);
        let found = discover(&dir, &DiscoverOptions::default()).expect("discover");
        let first = ComponentGraph::of(&found);

        std::fs::write(
            dir.join("packages/app/package.json"),
            r#"{"name":"changed"}"#,
        )
        .expect("change the manifest behind the graph's back");
        std::fs::create_dir_all(dir.join("packages/late")).expect("a member that arrived later");
        std::fs::write(dir.join("packages/late/package.json"), r#"{"name":"late"}"#)
            .expect("write the late member's manifest");

        let second = ComponentGraph::of(&found);
        assert_eq!(first, second, "the graph is a view over the discovery");
    }

    #[test]
    fn the_components_are_in_one_order_whichever_ecosystem_named_them() {
        let dir = scratch("order");
        write(
            &dir.join("package.json"),
            r#"{"name":"root","workspaces":["packages/zeta","packages/alpha"]}"#,
        );
        write(
            &dir.join("packages/zeta/package.json"),
            r#"{"name":"zeta"}"#,
        );
        write(
            &dir.join("packages/alpha/package.json"),
            r#"{"name":"alpha"}"#,
        );
        write(
            &dir.join("Cargo.toml"),
            "[workspace]\nmembers = [\"packages/middle\"]\n",
        );
        write(
            &dir.join("packages/middle/Cargo.toml"),
            "[package]\nname = \"middle\"\n",
        );
        let graph = graph_of(&dir);

        let paths: Vec<&Path> = graph
            .components
            .iter()
            .map(|part| part.path.as_path())
            .collect();
        assert_eq!(
            paths,
            vec![
                Path::new(""),
                Path::new("packages/alpha"),
                Path::new("packages/middle"),
                Path::new("packages/zeta"),
            ],
            "the root first, then by path rather than by the order two ecosystems \
             happened to name them"
        );
    }
}
