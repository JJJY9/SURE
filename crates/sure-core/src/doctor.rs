//! What SURE can say about its own installation on this machine.
//!
//! `sure doctor` is the command; this module is the facts. How they are worded
//! is the CLI's, per `docs/adr/0001-*` — nothing here produces a sentence a user
//! reads.
//!
//! # What this is for
//!
//! `docs/architecture/STORAGE_AND_DATA_PATHS.md` requires the CLI to expose the
//! exact paths SURE keeps things in, "so users can see/delete what is stored",
//! and `docs/product/DEFINITION_OF_DONE.md` requires `sure doctor` to give
//! actionable environment information. Both are questions about SURE's own
//! installation rather than about a project, which is why nothing here reads a
//! project, and why `Store::open_at` rather than `Store::open` is the entry
//! point used below.
//!
//! # Three things this deliberately does not do
//!
//! **It does not read the settings file.** It reports the path and whether
//! something is there. `docs/architecture/DIAGNOSTICS.md` requires that a secret
//! never have to be handled in order to be reported, and the way to keep that
//! true is for the diagnostic never to open the file that may hold one. Reading
//! settings back is not implemented in this build — `sure config show` refuses,
//! which is where that question belongs. There
//! is a test in `tests/doctor.rs` that reads this file and fails if it grows a
//! reference to the settings module.
//!
//! **It does not create the store.** A store that does not exist is reported as
//! nothing recorded yet. A diagnostic that changes what it is diagnosing is
//! worse than one that says it did not look, and a `doctor` run that left a
//! database behind would do exactly that.
//!
//! **It does not run a program.** Finding a program on `PATH` is an observed
//! fact about the filesystem; running it is a different claim. SURE does have a
//! process runner — `P3-T001`'s, in `crate::process` — and this module
//! deliberately does not reach it: a command whose output a user pastes into a
//! bug report should not be a command that starts something. Everything a
//! program check here establishes is repeated in [`NotChecked`], so a reader
//! cannot mistake the one for the other.
//!
//! # It does not become evidence
//!
//! Nothing here produces a [`CheckResult`](crate::status::CheckResult) or a
//! `Finding`. Every value is `observed_fact` about this machine at this moment
//! and none of it is a statement about a project.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::container::Availability;
// `APP_DIR` is named at its one use site rather than imported here, and that is
// deliberate rather than untidy. This module needs it only inside the
// `#[cfg(windows)]` `per_user_install`, so importing it unconditionally leaves
// it unused on Unix — where `-D warnings` turns that into an error and the whole
// crate stops compiling. CI run 35438699664 found exactly that on `e1be7ba`, and
// no gate on a Windows machine can: the clippy gate here compiles the Windows
// `cfg` set, where the import *is* used. **Do not add it back to this list.**
use crate::paths::{Origin, PathError, Paths};
use crate::store::{HistoryFilter, LATEST_SCHEMA_VERSION, Store, StoreError};

/// The external programs this build calls, and what for.
///
/// One entry, and that is still the honest count: SQLite is compiled in
/// (`docs/architecture/STORAGE_AND_DATA_PATHS.md` §The store), and everything
/// else SURE will invoke — a project's `npm test`, a container runtime, a
/// model-backed analysis — is asked for by a *setting or a project* rather than
/// being a dependency of SURE itself.
///
/// `P15-T001` is where that picture arrived, and it widened the **report**
/// rather than this list: the container runtime is
/// [`DoctorReport::container`], the analysis providers are
/// [`DoctorReport::providers`], the compilers are [`DoctorReport::toolchain`]
/// and the harnesses are [`DoctorReport::integrations`]. Each is a filesystem
/// search for a program this build *would* run if something asked it to, and
/// this build asks none of them — which is why they are not here.
const TOOLS: &[(&str, &str)] = &[(
    "git",
    "identifying which state of a project a result belongs to",
)];

/// The programs a native build on this platform uses, and what each is for.
///
/// Separate from [`TOOLS`] because none of these is something SURE calls: they
/// are the compilers and build tools a *project* would need, and the ones this
/// build was itself made with. **Nothing here is run**, so a name that is not
/// found is a fact about `PATH` and not a statement that the tool is missing —
/// each entry's own sentence says where the program usually lives, because a
/// Microsoft C compiler is normally installed and still not on `PATH`.
///
/// The list is per platform rather than one list with the Windows entries
/// filtered out at runtime: a report that named `vswhere` on Linux would be
/// naming a program no machine running it has.
#[cfg(windows)]
const TOOLCHAIN: &[(&str, &str)] = &[
    (
        "rustc",
        "compiling Rust code, which this build is made of and a checked project may be",
    ),
    (
        "cargo",
        "building a Rust project, which is how this one is built",
    ),
    (
        "cl",
        "the Microsoft C compiler a native msvc build links through. A Visual Studio \
         install keeps it off PATH until you are in a Developer Command Prompt, so \
         *not found here* is not evidence that it is missing",
    ),
    (
        "vswhere",
        "finding a Visual Studio installation. It normally lives at a fixed path under \
         Program Files rather than on PATH, for the same reason as `cl`",
    ),
];

/// The same, where there is no Microsoft C toolchain to look for.
#[cfg(not(windows))]
const TOOLCHAIN: &[(&str, &str)] = &[
    (
        "rustc",
        "compiling Rust code, which this build is made of and a checked project may be",
    ),
    (
        "cargo",
        "building a Rust project, which is how this one is built",
    ),
];

/// The C library this build links against, as the compiler named it.
///
/// A compile-time fact rather than a probe, because it is a fact about *this
/// binary*: a program cannot discover which C library it was linked against by
/// looking at the machine, and `cfg!` is the only honest source for it. It is
/// what `scripts/Test-SureEnvironment.ps1` calls the *MSVC host* from the other
/// side — it reads `rustc -vV`, which is a program, and this is the same fact
/// without running one.
const TARGET_ENV: &str = if cfg!(target_env = "msvc") {
    "msvc"
} else if cfg!(target_env = "gnu") {
    "gnu"
} else if cfg!(target_env = "musl") {
    "musl"
} else {
    "none"
};

/// The analysis providers this build can be configured with.
///
/// `(name, what it needs from this machine, the program it would run if it runs
/// one)`. **The names are the settings file's own names and the list is held to
/// it by a test rather than by a copy that can drift** — this module must not
/// name the configuration module at all (`tests/doctor.rs` fails the build if it
/// does), so the names are strings here and `tests/doctor.rs` reads the type
/// that defines them and fails if the two disagree.
///
/// **A provider is where a credential lives, and nothing here can hold one.**
/// The only question asked of each entry is a filesystem one: is the program it
/// would run on `PATH`. `openai_compatible`'s needs a key, which is exactly why
/// there is no field a key could be read into.
const PROVIDERS: &[(&str, &str, Option<&str>)] = &[
    (
        "disabled",
        "nothing: the deterministic checks run and no model is consulted",
        None,
    ),
    (
        "local_command",
        "a command your settings name, run on this machine",
        None,
    ),
    (
        "claude_cli",
        "the Claude CLI already installed on this machine",
        Some("claude"),
    ),
    (
        "openai_compatible",
        "an endpoint and a key your settings name. This report never reads either",
        None,
    ),
];

/// The harnesses this build can be told about by a hook.
///
/// `(source name, what SURE's package for that harness adds)`. These are the
/// names `sure hook ingest --source` accepts, and the list is held to that
/// command rather than to this comment: `crates/sure-cli/tests/cli_contract.rs`
/// runs every one of them through the real binary and asserts it is taken, and
/// runs a name that is not on the list and asserts it is refused.
///
/// **A harness SURE ships a package for but cannot ingest from is deliberately
/// not here.** The Copilot package's launcher passes `--source copilot`, which
/// this build refuses, so naming it would be claiming a route that does not
/// work; what is on the list is what the command takes.
const INTEGRATIONS: &[(&str, &str)] = &[
    (
        "claude-code",
        "hooks that record what an agent did, and SURE's tools over MCP",
    ),
    ("cursor", "the same hooks and the same tools, for Cursor"),
    (
        "codex",
        "hooks, skills and SURE's tools, added to the harness's own config",
    ),
    (
        "miqi",
        "hooks that record what an agent did, wired into the harness's own plugin layer",
    ),
];

/// The questions this report does not answer, and why not.
///
/// Not the same as [`Problem`]: a problem is something wrong that SURE found, and
/// this is the boundary of what it looked at. `docs/product/UX_AND_LANGUAGE.md`
/// requires the second to be visible, because a report that does not say what it
/// skipped invites the reader to assume it covered everything.
const NOT_CHECKED: &[(&str, &str)] = &[
    (
        "whether a program found on PATH runs",
        "SURE does not run a program to find out. Finding a file is not running it, \
         and a diagnostic whose output is pasted into a bug report is the last \
         command that should start something.",
    ),
    (
        "what is in your settings files",
        "no command in this build reads them back — `sure config show` refuses — \
         so that a diagnostic never has a secret to handle. This report says where \
         the file is and nothing more; `sure config set` writes them.",
    ),
    (
        "which analysis provider your settings choose",
        "that is a value in the settings file, and the same rule keeps this report \
         out of it. What this report does answer is which providers this build \
         offers, and whether the program one of them would run is on PATH — never \
         an endpoint, never a key.",
    ),
    (
        "whether SURE can write to its own directories",
        "finding out means creating a file, and a diagnostic that changes what it \
         is diagnosing is worse than one that says it did not look.",
    ),
    (
        "whether a harness is installed on this machine, and whether it is wired up",
        "SURE ships a package for each harness it can be told about, and this report \
         lists the ones it can ingest from. It does not look for a harness's own \
         files, so a harness that is present and unwired looks from here exactly \
         like one that is not installed.",
    ),
];

/// Whether something is at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    /// Something is there.
    Present,
    /// Nothing is there. Not a problem: a fresh installation has nothing yet.
    Absent,
    /// Something is there and SURE could not look at it.
    ///
    /// Distinct from [`Presence::Absent`] because "I could not look" and "there
    /// is nothing" are different answers, and reporting the first as the second
    /// is how a permission problem becomes invisible.
    Unreadable {
        /// The operating system's own words.
        detail: String,
    },
}

/// One thing SURE keeps, and whether it is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    /// The path, as the platform reported it.
    pub path: PathBuf,
    /// What was found there.
    pub presence: Presence,
}

/// The four locations SURE uses, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locations {
    /// Where durable evidence and history go.
    pub data_dir: Place,
    /// Where user-level settings go.
    pub config_dir: Place,
    /// The user-level settings file.
    ///
    /// Named and stat-ed. Never opened — see the module documentation.
    pub settings_file: Place,
    /// The local record store.
    pub store_file: Place,
    /// Where the store's location came from.
    ///
    /// Reported because a caller who named a store and a caller who did not get
    /// the same shape of report, and a redirect that was ignored looks exactly
    /// like one that worked until the location is asked for. See
    /// [`sure_core::paths::Origin`].
    pub store_origin: Origin,
    /// Where the settings file's location came from.
    ///
    /// The same fact about the other file a caller can name, and reported for
    /// the same reason: `--settings-file` and the platform's own settings file
    /// both print a path, and a run has to be able to say which of the two it is
    /// about to read — a caller who named one and got the other is the mistake
    /// this answer exists to make visible. See [`sure_core::paths::Origin`].
    pub settings_origin: Origin,
    /// Where a per-user installation of SURE puts its executable.
    ///
    /// `None` on a platform where SURE has no per-user install convention. This
    /// is **the platform's location for this user, not where this build is**:
    /// that is [`Build::running_from`], and the two are different answers —
    /// a machine can run a build out of a checkout, a cargo cache or a package
    /// manager while a per-user installation sits where the launchers expect it.
    ///
    /// Deliberately **not** derived from [`Locations::data_dir`]: `--store-dir`
    /// moves the data directory, and reporting the redirected store's directory
    /// as the installation would tell a user their installation moved when only
    /// their history did.
    pub install_file: Option<Place>,
}

/// Where SURE keeps things, or why it cannot say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Places {
    /// The platform reported them.
    Known(Box<Locations>),
    /// The platform did not report them.
    ///
    /// A finding rather than a gap: with no location for its evidence, SURE
    /// cannot record anything, so this is the first thing a user needs to fix.
    /// `Paths` refuses to guess for the reason in [`PathError::Unavailable`].
    Unknown {
        /// Which location, in the words a user would use.
        what: &'static str,
        /// SURE's own explanation of why it did not guess.
        detail: String,
    },
}

/// What the record store looks like from here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreState {
    /// There is no store file yet. Nothing has been recorded on this machine.
    NotCreated,
    /// The store is there and readable.
    Open(StoreFacts),
    /// The store is there and SURE could not read it.
    ///
    /// Carries SURE's own message, which says what it did instead. A damaged
    /// store is not read from: a record out of one is a wrong answer about a
    /// project, which is why [`Store::integrity_check`] runs before the count.
    Unreadable {
        /// SURE's explanation, from [`StoreError`].
        detail: String,
    },
    /// SURE had nowhere to look, so it does not know whether anything is
    /// recorded. The [`Problem`] in [`DoctorReport::problems`] says why.
    ///
    /// Not [`StoreState::NotCreated`]: without a resolved data directory SURE
    /// cannot tell an empty installation from one it failed to find, and a
    /// report that called the second the first would be inventing an answer.
    NotLookedFor,
}

/// What an open store reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreFacts {
    /// The journal mode the file actually has. Reported rather than assumed —
    /// a WAL request can come back as something else.
    pub journal_mode: String,
    /// The schema version, which on an open store is always
    /// [`LATEST_SCHEMA_VERSION`]: opening migrates, and a file from a newer
    /// build is refused rather than opened. There is no field for "and this is
    /// the current one" because it cannot be otherwise.
    pub schema_version: u32,
    /// How many records are stored, **including full recordings**.
    ///
    /// The history filter defaults to excluding recordings so that a check does
    /// not drag them in by accident. This count is the opposite question — how
    /// much is on this machine — and a doctor that undercounted the user's own
    /// stored data would be answering a question nobody asked. No record's
    /// contents are read: `count` is a `SELECT count(*)`.
    pub records: u64,
}

/// One external program, and whether it is reachable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tool {
    /// The program's name, as SURE would invoke it.
    pub name: &'static str,
    /// What SURE needs it for, in the words a user would use.
    pub needed_for: &'static str,
    /// Where a program of that name was found on `PATH`.
    ///
    /// `None` means no directory on `PATH` holds one. It does **not** mean the
    /// program is unusable — an alias, a function or a copy outside `PATH` is
    /// not visible here — so the wording a caller prints must say where SURE
    /// looked.
    pub found_at: Option<PathBuf>,
}

/// One program a build on this machine uses, and whether it is reachable.
///
/// Deliberately not [`Tool`]: that one is a program *SURE calls*, and its
/// wording says so. Reusing it here would make `sure doctor` say it calls a C
/// compiler, which it does not and must not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiler {
    /// The program's name, as it would be invoked.
    pub name: &'static str,
    /// What it is used for, in the words a user would use.
    pub used_for: &'static str,
    /// Where a program of that name was found on the search path.
    ///
    /// `None` means no directory on the search path holds one. **Not** a
    /// statement that the program is missing from the machine: see
    /// [`Compiler::used_for`], where the two entries that are normally installed
    /// and still off `PATH` say so in their own sentence.
    pub found_at: Option<PathBuf>,
}

/// One analysis provider this build offers, and what it needs from here.
///
/// The list is the *build's* offering rather than the user's choice: which one
/// is in effect is a value in the settings file, which this module does not read
/// (see the module documentation, and the test that holds it to that).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    /// The provider's name, spelled exactly as a settings file spells it.
    pub name: &'static str,
    /// What it needs from this machine, in the words a user would use.
    pub needs: &'static str,
    /// The program it would run, if it runs one.
    ///
    /// `None` for a provider that runs none, which is not the same as a program
    /// that was looked for and not found — [`Provider::found_at`] is the answer
    /// to that question, and a report that carried only one field could not tell
    /// the two apart.
    pub program: Option<&'static str>,
    /// Where that program is on the search path, if one was looked for.
    pub found_at: Option<PathBuf>,
}

/// One harness this build can be told about by a hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integration {
    /// The source name, spelled exactly as `sure hook ingest --source` spells it.
    pub name: &'static str,
    /// What SURE's package for that harness puts there.
    pub adds: &'static str,
}

/// Something that is wrong with this installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// A fixed sentence naming what is wrong. `&'static str` for the reason
    /// `docs/architecture/DIAGNOSTICS.md` gives for diagnostic messages: a
    /// sentence SURE says about itself is fixed, so no call site can reword it
    /// into something weaker.
    pub what: &'static str,
    /// The variable part — the operating system's words, or SURE's.
    pub detail: String,
}

/// A question this report does not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotChecked {
    /// What was not looked at.
    pub what: &'static str,
    /// Why not.
    pub why: &'static str,
}

/// What this build is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Build {
    /// The version number of this build, without the product name.
    ///
    /// The number alone because every renderer of this report already says the
    /// product's name, and a field holding "SURE 0.1.2" makes each of
    /// them have to take it apart again. See [`crate::VERSION`].
    pub version: String,
    /// The harness protocol version it speaks.
    pub protocol_version: u32,
    /// The operating system this binary was built for.
    pub os: &'static str,
    /// The processor it was built for.
    pub arch: &'static str,
    /// The C library this binary was linked against, as its compiler names it.
    ///
    /// "msvc" on a native Windows build, which is the second half of the target
    /// triple and the one a Windows user is usually asking about: a binary built
    /// for the same processor and linked against a different C library is not
    /// the same build, and a toolchain problem looks different depending on
    /// which it is. See [`TARGET_ENV`].
    pub target_env: &'static str,
    /// Where the running executable is.
    ///
    /// `None` only if the platform will not say. Reported because the first
    /// question about a broken installation is which SURE is running, and a
    /// machine can hold several.
    pub running_from: Option<PathBuf>,
}

/// Everything `sure doctor` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    /// This build.
    pub build: Build,
    /// Where SURE keeps things.
    pub places: Places,
    /// What is in the record store.
    pub store: StoreState,
    /// The external programs SURE calls.
    pub tools: Vec<Tool>,
    /// The programs a build on this machine uses, and where they are.
    ///
    /// Found and not run. A program that is absent from this list's `found_at`
    /// is absent from the search path, which on Windows is a different statement
    /// from "not installed" — see [`Compiler`].
    pub toolchain: Vec<Compiler>,
    /// Whether a container runtime is here, and which.
    ///
    /// [`Availability::Absent`] is an answer rather than a failure: it says this
    /// machine has no runtime on the search path it was given, and it is **not a
    /// fallback** — what decides whether a check runs on this computer is the
    /// execution mode the user's own settings file names, which decides more
    /// since `P18-T007` wired a runner into
    /// [`crate::pipeline`](crate::pipeline::Pipeline) — and **no check runs in a
    /// container**, with a runtime or without one, because this build has no
    /// executor that would start one. **Nothing is run and no container is
    /// started** — this is the same filesystem search as
    /// [`DoctorReport::tools`], and planning or running a container is
    /// elsewhere, deliberately.
    pub container: Availability,
    /// The analysis providers this build offers, and what each needs from here.
    ///
    /// Never which one is configured: that is in the settings file. See
    /// [`Provider`].
    pub providers: Vec<Provider>,
    /// The harnesses this build can be told about by a hook.
    pub integrations: Vec<Integration>,
    /// Everything found wrong. Empty means SURE found nothing wrong.
    pub problems: Vec<Problem>,
    /// What was not looked at.
    pub not_checked: Vec<NotChecked>,
}

impl DoctorReport {
    /// Whether SURE found anything wrong with its own installation.
    ///
    /// The single predicate the exit status and the `outcome` both come from, so
    /// that a script reading the status and a script reading the frame cannot be
    /// told different things.
    ///
    /// `const` so that the CLI's status table stays a table of constants rather
    /// than becoming a function that reads a value.
    #[must_use]
    pub const fn is_well(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Examine this machine, as the platform reports it.
///
/// `store` is the directory the caller named for the store, or `None` for the
/// platform's own location. It is [`Paths::discover_at`]'s argument and it means
/// what that function's documentation says it means: `sure` fills it from
/// `--store-dir`, which is a value in this process's argument vector and not
/// something a project can set.
///
/// The locations this run used are reported, with their [`Origin`], in `places`
/// — a caller who cannot tell a named location from the platform's own will
/// debug the wrong thing when a redirect appears to have been ignored. Both of
/// them can be named: [`examine_this_machine_with`] carries
/// `--settings-file` as well, and this is that function with nothing named for
/// the settings.
#[must_use]
pub fn examine_this_machine(store: Option<&Path>) -> DoctorReport {
    examine_this_machine_with(store, None)
}

/// The same, with the settings file named by the caller if they named one.
///
/// `settings_file` is [`Paths::discover_with`]'s second argument: the file this
/// run reads its user-level settings from, or `None` for the platform's own. It
/// is reported as the path of `places.settings_file` with its origin beside it,
/// so that this command — the one a person runs to find out what a run is doing
/// — says which settings file a run is about to read rather than which one this
/// machine has.
///
/// Doctor reads no settings either way: it names the file and whether something
/// is there. See the module documentation.
#[must_use]
pub fn examine_this_machine_with(
    store: Option<&Path>,
    settings_file: Option<&Path>,
) -> DoctorReport {
    examine(Paths::discover_with(store, settings_file))
}

/// Examine an installation whose locations are already decided.
///
/// The entry point a test uses, and the one that keeps "where things belong"
/// separable from "what is there". A [`PathError`] is a result rather than an
/// early return because it is the most important thing this command can report:
/// without a location, SURE cannot store anything.
///
/// The programs are looked for on this process's `PATH`. [`examine_in`] is the
/// same with the search path given, which is how a test reaches both answers —
/// found and not found — on one machine in one run.
#[must_use]
pub fn examine(places: Result<Paths, PathError>) -> DoctorReport {
    let search_path = std::env::var_os("PATH").unwrap_or_default();
    examine_in(places, &search_path)
}

/// The same, against a given search path.
///
/// **One argument carries every program answer in the report** — the tools, the
/// toolchain, the container runtime and the providers' programs — so that the
/// two-sided test this repository asks for is possible at all: an empty search
/// path and a populated one differ in this argument and in nothing else, on the
/// machine running the suite. A check that could only ever find what this
/// machine happens to have cannot fail, and a check that cannot fail is the
/// defect.
///
/// A search path with no entries is not an error state. It is a machine on which
/// nothing is on `PATH`, and every program answer is then "not found" — which is
/// a thing a report has to be able to say.
#[must_use]
pub fn examine_in(places: Result<Paths, PathError>, search_path: &OsStr) -> DoctorReport {
    let mut problems = Vec::new();

    let places = match places {
        Ok(paths) => Places::Known(Box::new(locations(&paths))),
        Err(error) => {
            problems.push(Problem {
                what: "SURE cannot tell where it should keep its files on this machine.",
                detail: error.to_string(),
            });
            Places::Unknown {
                what: match &error {
                    PathError::Unavailable { what } => what,
                    PathError::NotAbsolute { what, .. } => what,
                    PathError::InsideProject { .. } => "its evidence and history",
                    // Reached the same way, and by a caller that pointed the
                    // settings at a project rather than at a store. It says the
                    // settings file and not the evidence, because those are the
                    // two different things this command did not find.
                    PathError::SettingsInsideProject { .. } => "its user-level settings",
                },
                detail: error.to_string(),
            }
        }
    };

    let store = match &places {
        // With no store path there is nothing to look at, which is not the same
        // as having looked and found nothing. The problem above already says
        // why, so this does not add a second one.
        Places::Unknown { .. } => StoreState::NotLookedFor,
        Places::Known(locations) => examine_store(&locations.store_file.path),
    };

    if let StoreState::Unreadable { detail } = &store {
        problems.push(Problem {
            what: "SURE has recorded history on this machine and cannot read it.",
            detail: detail.clone(),
        });
    }

    DoctorReport {
        build: Build {
            version: crate::VERSION.to_owned(),
            protocol_version: crate::PROTOCOL_VERSION,
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            target_env: TARGET_ENV,
            running_from: std::env::current_exe().ok(),
        },
        places,
        store,
        tools: TOOLS
            .iter()
            .map(|&(name, needed_for)| Tool {
                name,
                needed_for,
                found_at: find_in(search_path, name),
            })
            .collect(),
        toolchain: TOOLCHAIN
            .iter()
            .map(|&(name, used_for)| Compiler {
                name,
                used_for,
                found_at: find_in(search_path, name),
            })
            .collect(),
        container: Availability::in_path(search_path),
        providers: PROVIDERS
            .iter()
            .map(|&(name, needs, program)| Provider {
                name,
                needs,
                program,
                // Only the program is looked for. What a provider also needs —
                // an endpoint, a key — is in the settings file and is not read.
                found_at: program.and_then(|program| find_in(search_path, program)),
            })
            .collect(),
        integrations: INTEGRATIONS
            .iter()
            .map(|&(name, adds)| Integration { name, adds })
            .collect(),
        problems,
        not_checked: NOT_CHECKED
            .iter()
            .map(|(what, why)| NotChecked { what, why })
            .collect(),
    }
}

/// The four locations, with what is at each.
fn locations(paths: &Paths) -> Locations {
    let place = |path: PathBuf| {
        let presence = presence(&path);
        Place { path, presence }
    };
    Locations {
        data_dir: place(paths.data_dir().to_path_buf()),
        config_dir: place(paths.config_dir().to_path_buf()),
        settings_file: place(paths.user_config_file()),
        store_file: place(paths.store_file()),
        store_origin: paths.origin(),
        settings_origin: paths.settings_origin(),
        install_file: per_user_install(),
    }
}

/// Where a per-user installation puts its executable, if this platform has such
/// a convention for SURE.
///
/// **Read from the platform's own per-user local data directory, not from
/// [`Paths`]** — and that is the point of the function rather than an
/// implementation detail. `Paths::data_dir` moves when a caller passes
/// `--store-dir`, so deriving this from it would make a redirected store report
/// the redirect as the installation. `sure doctor --store-dir X` would then tell
/// a user their installation is at `X`, which is a false statement about a
/// machine, made by the command that exists to catch those.
///
/// On Windows that directory is what `dirs::data_local_dir` returns —
/// `SHGetKnownFolderPath(FOLDERID_LocalAppData)`, which is `%LOCALAPPDATA%` and
/// is deliberately not read from the environment variable of that name: a
/// process can be started with `LOCALAPPDATA` pointing anywhere, and an
/// installation path read from the environment is one a user can be told they
/// have.
///
/// The **location** is `%LOCALAPPDATA%\SURE\bin\sure.exe`, which is not invented
/// here: it is the path `docs/architecture/MCP_BRIDGE.md` documents as the
/// per-user install location, and the last resort of every launcher under
/// `integrations/`. Whether an installer should use it is `P15-T003`'s question;
/// this reports the path the launchers already agree on.
///
/// `None` where there is no such convention. On Unix-like platforms the
/// launchers look in a cargo bin directory, Homebrew's prefix and `/usr/local`
/// by turns — three system-wide-and-per-user places with no single SURE path
/// among them — so naming one of them would be inventing a location rather than
/// reporting one, and nothing is reported.
#[cfg(windows)]
fn per_user_install() -> Option<Place> {
    let path = dirs::data_local_dir()?
        .join(crate::paths::APP_DIR)
        .join("bin")
        .join("sure.exe");
    let presence = presence(&path);
    Some(Place { path, presence })
}

/// No per-user installation path is reported where SURE has no convention for
/// one. See the Windows function above.
#[cfg(not(windows))]
fn per_user_install() -> Option<Place> {
    None
}

/// What is at a path, distinguishing "nothing" from "could not look".
fn presence(path: &Path) -> Presence {
    match fs::metadata(path) {
        Ok(_) => Presence::Present,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Presence::Absent,
        Err(error) => Presence::Unreadable {
            detail: error.to_string(),
        },
    }
}

/// Open the store, if there is one, and report what it says.
///
/// The existence test comes first and is what keeps this read-only in the sense
/// that matters: `Store::open_at` creates the file, so calling it on a fresh
/// installation would make `sure doctor` the command that put a database there.
fn examine_store(store_file: &Path) -> StoreState {
    match presence(store_file) {
        Presence::Absent => StoreState::NotCreated,
        Presence::Unreadable { detail } => StoreState::Unreadable { detail },
        Presence::Present => match Store::open_at(store_file) {
            Ok(store) => match facts(&store) {
                Ok(facts) => StoreState::Open(facts),
                Err(error) => StoreState::Unreadable {
                    detail: error.to_string(),
                },
            },
            Err(error) => StoreState::Unreadable {
                detail: error.to_string(),
            },
        },
    }
}

/// Read what the store says about itself.
///
/// Integrity first. A count read out of a damaged file is a number, and a number
/// with nothing behind it is exactly what this program exists to refuse.
fn facts(store: &Store) -> Result<StoreFacts, StoreError> {
    let schema_version = store.schema_version()?;
    store.integrity_check()?;
    let records = store.count(&HistoryFilter {
        include_recordings: true,
        ..HistoryFilter::default()
    })?;
    Ok(StoreFacts {
        journal_mode: store.journal_mode().to_owned(),
        schema_version,
        records,
    })
}

/// Where a program of this name is, if it is anywhere on the search path.
///
/// Split out so it can be tested, and shared with [`crate::container`], which
/// looks for a runtime by exactly this rule. Visibility is `pub(crate)` rather
/// than `pub` because the rule this function implements is *what SURE would
/// execute*, and a crate that found a program by a different rule would be able
/// to disagree with `sure doctor` about what is installed.
///
/// `P15-T001` gave this function several callers inside this module — the tools,
/// the toolchain, each provider's program and, by way of
/// [`Availability::in_path`], the container runtime — which is past the point
/// the earlier note here said would move it into a module of its own. It has not
/// moved: a move is a change to every caller and to nothing a user can see, and
/// this task's job was the report. **The move is still owed**, and the reason to
/// make it is the one that has not changed: four questions about what is
/// installed should not be answered from a module about diagnostics.
///
/// Setting `PATH` for a test would need
/// `std::env::set_var`, which is `unsafe` in edition 2024 and therefore
/// unavailable in a workspace that forbids `unsafe` — so the variable is a
/// parameter instead of ambient state.
///
/// # What "found" means, exactly
///
/// The search is for what **SURE would execute**, not what a shell would. On
/// Windows a name with no extension is completed with `.exe` and **nothing
/// else**, which is `CreateProcess`'s rule and the one this function copies: a
/// machine whose Git is a `git.cmd` shim has no `git.exe`, and SURE finds
/// nothing. Say that precisely, because the loose version — "a `.cmd` is not
/// something SURE can run" — is false and would be the wrong reason for a right
/// answer: a batch file named *with* its extension does run, by way of an
/// interpreter Windows starts for it, which is exactly what a search for `git`
/// is not doing. On other platforms it is `name`, carrying an execute bit.
///
/// An empty entry is skipped rather than read as the current directory. On Unix
/// it *is* the current directory, which would make the answer depend on where
/// SURE was started; on Windows it is nothing at all. Reporting a file in the
/// working directory as "on PATH" would be wrong on one platform and a way to
/// shadow a system program on the other. A quoted entry is unquoted, because
/// Windows `PATH` entries are quoted when they contain spaces and the quotes are
/// not part of the path.
pub(crate) fn find_in(search_path: &OsStr, name: &str) -> Option<PathBuf> {
    std::env::split_paths(search_path)
        .filter(|entry| !entry.as_os_str().is_empty())
        .find_map(|entry| candidate_in(&unquote(&entry), name))
}

/// The name a program is stored under, given what to suffix it with.
///
/// On Windows, a name with no extension gets `.exe` and nothing else — the rule
/// `Command::new("git")` inherits from `CreateProcess`. `.cmd` and `.bat` are
/// not tried because the operating system would not try them here either: a
/// batch file is started when it is named *with* its extension, and that is not
/// what a search for `git` is doing. `.com` is a legacy format. A name that
/// already carries an extension is used as given.
#[cfg(windows)]
const EXECUTABLE_SUFFIXES: &[&str] = &[".exe"];

/// On a Unix-like platform the name is the file name.
#[cfg(not(windows))]
const EXECUTABLE_SUFFIXES: &[&str] = &[""];

/// Whether a directory holds a runnable program of this name.
fn candidate_in(directory: &Path, name: &str) -> Option<PathBuf> {
    let suffixes: &[&str] = if Path::new(name).extension().is_some() {
        &[""]
    } else {
        EXECUTABLE_SUFFIXES
    };
    suffixes.iter().find_map(|suffix| {
        let candidate = directory.join(format!("{name}{suffix}"));
        can_be_run(&candidate).then_some(candidate)
    })
}

/// Whether a path holds something SURE could execute.
///
/// A directory named `git.exe` is not a program, and a file with no execute bit
/// on a Unix-like platform is not one either.
#[cfg(unix)]
fn can_be_run(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.is_file() && fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
}

/// The same, where executable-ness is the file extension rather than a bit.
#[cfg(not(unix))]
fn can_be_run(path: &Path) -> bool {
    path.is_file()
}

/// A `PATH` entry without the quotes Windows allows around one.
///
/// Left alone if it is not valid UTF-8, rather than round-tripped through a lossy
/// conversion: a corrupted path would silently turn a found program into a
/// missing one.
fn unquote(entry: &Path) -> PathBuf {
    let Some(text) = entry.to_str() else {
        return entry.to_path_buf();
    };
    match text
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
    {
        Some(inner) => PathBuf::from(inner),
        None => entry.to_path_buf(),
    }
}

/// The version of the store schema this build writes, re-exported so a caller of
/// [`examine`] does not have to reach into `store` for it.
#[must_use]
pub const fn latest_schema_version() -> u32 {
    LATEST_SCHEMA_VERSION
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::store::RecordKind;
    use sure_protocol::documents::DocumentKind;

    /// A scratch directory under `target/tmp`, as the other store tests use.
    ///
    /// The name carries the process id, and the clear stops the test if it does
    /// not happen, for the reason `store_concurrency.rs` records in full: the
    /// freshness of a reused path depends on a deletion succeeding, and on Windows
    /// a deletion can fail silently. These two tests were seen to fail under a
    /// loaded run — `the store was readable: NotCreated`, and `Unreadable` with
    /// `os error 5` on the history file — and both stopped failing once the path
    /// was unique to the process. **That is not proof that the reused path caused
    /// them**, and `progress/HANDOFF.md` records it as the weaker of the two kinds
    /// of evidence in this change.
    fn scratch(name: &str) -> PathBuf {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("tmp")
            .join("doctor")
            .join(format!("{name}-{}", std::process::id()));
        match fs::remove_dir_all(&root) {
            Ok(()) => {}
            // The ordinary case, and now the expected one.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!(
                "cannot clear {}: {error}. This process id was used before and its \
                 history file is still on disk, so this test could not tell it apart \
                 from the one it writes.",
                root.display()
            ),
        }
        fs::create_dir_all(&root).expect("a scratch directory");
        root
    }

    fn places_for(root: &Path) -> Paths {
        Paths::from_roots(root.join("data"), root.join("config")).expect("absolute roots")
    }

    fn the_problem(report: &DoctorReport) -> &Problem {
        assert_eq!(report.problems.len(), 1, "{:#?}", report.problems);
        &report.problems[0]
    }

    #[test]
    fn a_fresh_installation_is_not_a_problem() {
        // Nothing exists yet, which is what a new install looks like. Reporting
        // that as a fault would teach the user to ignore the command on the one
        // day it has something to say.
        let root = scratch("fresh");
        let report = examine(Ok(places_for(&root)));

        assert!(report.is_well(), "{:#?}", report.problems);
        assert_eq!(report.store, StoreState::NotCreated);
        let Places::Known(locations) = &report.places else {
            panic!("the locations were given");
        };
        assert_eq!(locations.data_dir.presence, Presence::Absent);
        assert_eq!(locations.store_file.presence, Presence::Absent);
    }

    #[test]
    fn looking_does_not_create_the_store() {
        // The property that makes this command safe to run: a diagnostic that
        // leaves a database behind has changed the machine it was asked about.
        let root = scratch("read_only");
        let paths = places_for(&root);
        let store_file = paths.store_file();

        let report = examine(Ok(paths));

        assert_eq!(report.store, StoreState::NotCreated);
        assert!(
            !store_file.exists(),
            "sure doctor created {}, so it is not a read-only question",
            store_file.display()
        );
        assert!(
            !store_file.parent().expect("a parent").exists(),
            "sure doctor created the data directory, which nothing asked it to do"
        );
    }

    #[test]
    fn an_installation_with_history_reports_what_is_in_it() {
        let root = scratch("with_history");
        let paths = places_for(&root);

        {
            let store = Store::open_at(&paths.store_file()).expect("a store");
            store
                .append(RecordKind::Document(DocumentKind::Finding), &a_finding())
                .expect("a record");
        }

        let report = examine(Ok(paths));
        let StoreState::Open(facts) = &report.store else {
            panic!("the store was readable: {:#?}", report.store);
        };
        assert_eq!(facts.records, 1);
        assert_eq!(facts.schema_version, LATEST_SCHEMA_VERSION);
        assert_eq!(facts.journal_mode, "wal", "the store did not stay in WAL");
        assert!(report.is_well(), "{:#?}", report.problems);
    }

    #[test]
    fn a_store_that_is_not_a_store_is_a_finding_rather_than_a_repair() {
        // The file is there and is not a SURE database — a truncated file, or
        // something else entirely. SURE must not replace it: whatever is in
        // there is the user's, and overwriting it would destroy the evidence
        // that something went wrong.
        let root = scratch("foreign");
        let paths = places_for(&root);
        fs::create_dir_all(paths.data_dir()).expect("the data directory");
        fs::write(paths.store_file(), b"this is not a database\n").expect("a foreign file");

        let report = examine(Ok(paths));
        let StoreState::Unreadable { detail } = &report.store else {
            panic!(
                "a foreign file was reported as readable: {:#?}",
                report.store
            );
        };
        assert!(!detail.is_empty(), "the finding does not say what happened");
        assert!(!report.is_well());

        let problem = the_problem(&report);
        assert!(
            problem.what.contains("cannot read"),
            "the problem does not say what is wrong: {}",
            problem.what
        );
    }

    #[test]
    fn nothing_there_and_could_not_look_are_different_answers() {
        // "There is nothing here" and "I could not look" are different facts,
        // and reporting the second as the first is how a permission problem
        // becomes invisible — which is the failure this whole program is about.
        //
        // A path containing a NUL cannot be looked at on either platform: the
        // standard library rejects it before the system call, with a kind that
        // is not `NotFound`. That makes the arm reachable in a test rather than
        // argued about, on Windows and on Unix alike.
        match presence(Path::new("a\0b")) {
            Presence::Unreadable { detail } => {
                assert!(!detail.is_empty(), "the finding says nothing");
            }
            other => panic!("a path that cannot be looked at was reported as {other:?}"),
        }
    }

    /// The same distinction, on the platform where the operating system supplies
    /// a second way to reach it.
    ///
    /// On Unix a path whose parent is a file is `ENOTDIR`. On Windows the same
    /// path is `ERROR_PATH_NOT_FOUND`, which is `NotFound`, so `presence` says
    /// [`Presence::Absent`] there — and that is truthful: on Windows the path
    /// genuinely does not name an entry. Recorded rather than smoothed over,
    /// because the difference is real and a test asserting one answer on both
    /// platforms would be asserting something false on one of them.
    #[cfg(unix)]
    #[test]
    fn a_path_through_a_file_cannot_be_looked_at() {
        let root = scratch("through_a_file");
        let blocking = root.join("a_file");
        fs::write(&blocking, b"x").expect("a file");
        assert!(
            matches!(
                presence(&blocking.join("child")),
                Presence::Unreadable { .. }
            ),
            "a path through a file was reported as {:?}",
            presence(&blocking.join("child"))
        );
    }

    #[test]
    fn where_the_platform_will_not_say_that_is_the_finding() {
        let report = examine(Err(PathError::Unavailable {
            what: "its evidence and history",
        }));

        assert!(!report.is_well(), "no location and nothing to report");
        assert!(matches!(report.places, Places::Unknown { .. }));
        // Not `NotCreated`. With no data directory SURE cannot tell an empty
        // installation from one it could not find, and calling the second the
        // first is inventing an answer.
        assert_eq!(report.store, StoreState::NotLookedFor);
        let problem = the_problem(&report);
        assert!(
            problem.detail.contains("could not work out where"),
            "the finding does not carry SURE's own explanation: {}",
            problem.detail
        );
    }

    #[test]
    fn the_report_always_says_what_it_did_not_look_at() {
        let report = examine(Ok(places_for(&scratch("not_checked"))));
        let named: Vec<&str> = report.not_checked.iter().map(|each| each.what).collect();
        assert!(
            named.iter().any(|what| what.contains("runs")),
            "the report does not say it never ran anything: {named:?}"
        );
        assert!(
            named.iter().any(|what| what.contains("settings")),
            "the report does not say it never read settings: {named:?}"
        );
        for entry in &report.not_checked {
            assert!(
                !entry.why.is_empty(),
                "{:?} is not looked at for no stated reason",
                entry.what
            );
        }
    }

    #[test]
    fn every_tool_says_what_it_is_for() {
        // A list of program names with no reasons is a list a user cannot act
        // on: "git not found" is only useful if the reader knows why SURE wants
        // it.
        let report = examine(Ok(places_for(&scratch("tools"))));
        assert!(!report.tools.is_empty(), "SURE calls no programs at all");
        for tool in &report.tools {
            assert!(!tool.name.is_empty());
            assert!(
                !tool.needed_for.is_empty(),
                "{} is required for no stated reason",
                tool.name
            );
        }
    }

    // --- the path search ------------------------------------------------

    fn a_program(directory: &Path, name: &str) -> PathBuf {
        fs::create_dir_all(directory).expect("a directory");
        let file = directory.join(name);
        fs::write(&file, b"#!/bin/sh\n").expect("a file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&file).expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&file, permissions).expect("an execute bit");
        }
        file
    }

    /// The file name a program of this name would have on this platform.
    fn stored_as(name: &str) -> String {
        format!("{name}{}", EXECUTABLE_SUFFIXES[0])
    }

    /// A search path built from directories, as the operating system spells one.
    fn search_path<I, S>(entries: I) -> std::ffi::OsString
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        std::env::join_paths(entries).expect("directories without a separator in them")
    }

    #[test]
    fn a_program_on_the_search_path_is_found_where_it_is() {
        let root = scratch("path_found");
        let elsewhere = root.join("elsewhere");
        let file = a_program(&elsewhere, &stored_as("git"));

        let found = find_in(&search_path([&elsewhere]), "git");
        assert_eq!(found.as_deref(), Some(file.as_path()));
    }

    #[test]
    fn a_program_that_is_not_there_is_not_found() {
        let root = scratch("path_missing");
        let empty = root.join("empty");
        fs::create_dir_all(&empty).expect("a directory");

        assert_eq!(find_in(&search_path([&empty]), "git"), None);
        // The second half of the claim: the search is running at all, so the
        // `None` above is not a search that never looked.
        let file = a_program(&empty, &stored_as("git"));
        assert_eq!(
            find_in(&search_path([&empty]), "git").as_deref(),
            Some(file.as_path())
        );
    }

    #[test]
    fn a_directory_named_like_a_program_is_not_a_program() {
        let root = scratch("path_directory");
        let trampoline = root.join("trampoline");
        fs::create_dir_all(trampoline.join(stored_as("git"))).expect("a directory");

        assert_eq!(find_in(&search_path([&trampoline]), "git"), None);
    }

    #[test]
    fn an_empty_entry_is_skipped_rather_than_read_as_the_current_directory() {
        // On Unix an empty `PATH` entry is the current directory, so a `git` in
        // the working directory would be found; on Windows it is nothing. The
        // answer must not depend on where SURE was started, and a file next to
        // the project is not an installed program.
        let root = scratch("path_empty");
        let empty = root.join("empty");
        fs::create_dir_all(&empty).expect("a directory");
        // The trailing empty entry survives `join_paths` as a trailing
        // separator, which is exactly how the operating system spells one.
        let search = search_path([empty.as_path(), Path::new("")]);

        assert_eq!(find_in(&search, "git"), None);
    }

    #[test]
    fn a_quoted_entry_is_read_as_the_path_it_quotes() {
        // Windows `PATH` entries are quoted when the directory has a space in
        // it, and the quotes are not part of the path. A search that kept them
        // would report an installed program as missing.
        let root = scratch("path_quoted");
        let with_space = root.join("Program Files").join("Git");
        let file = a_program(&with_space, &stored_as("git"));
        //
        // Built by hand rather than with `join_paths`, which refuses a quote on
        // Windows — a real `PATH` arrives from the environment and no such check
        // ran on it.
        let search = std::ffi::OsString::from(format!("\"{}\"", with_space.display()));

        assert_eq!(find_in(&search, "git").as_deref(), Some(file.as_path()));
    }

    #[test]
    fn the_first_match_wins_so_the_answer_is_what_would_be_run() {
        // `PATH` is ordered, and so is the answer. Reporting the last match
        // would name a program that is not the one SURE would invoke.
        let root = scratch("path_order");
        let first = root.join("first");
        let second = root.join("second");
        let expected = a_program(&first, &stored_as("git"));
        a_program(&second, &stored_as("git"));

        assert_eq!(
            find_in(&search_path([&first, &second]), "git").as_deref(),
            Some(expected.as_path())
        );
    }

    #[test]
    fn the_schema_version_is_this_builds_own() {
        // The re-export is the same constant, not a copy that can drift.
        assert_eq!(latest_schema_version(), LATEST_SCHEMA_VERSION);
    }

    /// A finding document, shaped as `sure_core::store`'s own tests shape one:
    /// enough to satisfy the kind's schema, and nothing that depends on the
    /// domain model gaining a field. What is under test here is the store's
    /// state, not the document.
    fn a_finding() -> serde_json::Value {
        serde_json::json!({
            "id": "fnd_01j2m8q5aaaabbbbccccddddee",
            "title": "Email is reported as sent but nothing is sent",
            "severity": "must_fix",
            "status": "open",
            "explanation": "the handler returns before the send call",
            "evidence": [],
            "assessment_source": "deterministic_check",
            "severity_rationale": "blocks_hand_off",
        })
    }

    #[test]
    fn a_record_the_store_accepted_is_counted() {
        // The count is the number a user reads to decide whether to delete
        // anything, so it has to be the real one. This checks the two halves
        // agree: what `append` accepted, and what the report says is there.
        let root = scratch("counted");
        let paths = places_for(&root);
        {
            let store = Store::open_at(&paths.store_file()).expect("a store");
            for _ in 0..3 {
                store
                    .append(RecordKind::Document(DocumentKind::Finding), &a_finding())
                    .expect("a record");
            }
            store
                .append_recording(&serde_json::json!({"stdout": "build ok"}), None)
                .expect("a recording");
        }

        let report = examine(Ok(paths));
        let StoreState::Open(facts) = &report.store else {
            panic!("the store was readable: {:#?}", report.store);
        };
        assert_eq!(
            facts.records, 4,
            "the count leaves out full recordings, which is the opposite of \
             what a user asking what is on this machine needs"
        );
    }
}
