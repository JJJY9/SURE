//! `sure doctor`, in the two forms a result can take.
//!
//! The facts are `sure_core::doctor`'s. This module decides what a person reads
//! and what a script reads, and the two are written independently — neither is a
//! formatting of the other — for the reason in `crate::report`'s module
//! documentation.
//!
//! # The wording rule
//!
//! `docs/product/UX_AND_LANGUAGE.md`: consequence first, no jargon. "journal
//! mode wal" appears because a user pasting this into a bug report should not
//! have to translate it back, and it is under a heading that says what it is.
//!
//! # What is deliberately not printed
//!
//! Nothing from the settings file, and no record's contents. The report has no
//! field that could hold either, which is what makes that a property of the
//! design rather than of this function's self-control.

use std::io::{self, Write};

use serde_json::{Value, json};
use sure_core::container::Availability;
use sure_core::doctor::{
    Compiler, DoctorReport, Integration, Places, Presence, Problem, Provider, StoreState, Tool,
};
use sure_core::paths::Origin;

/// The column a value begins in: two spaces of indent, the label, then a gap.
///
/// Fixed rather than computed from the longest label, so that two runs on two
/// machines line up and a diff between two pasted reports shows only what
/// changed. The longest label here is "evidence and history", twenty characters,
/// so the gap is what is left over.
const COLUMN: usize = 23;

/// The width the label is padded to, so that [`COLUMN`] is where its value
/// starts.
///
/// One less than the span from the indent to the value column, because the
/// space between them is a real space rather than part of the padding: padding
/// to the full width put "evidence and history" and `C:\Users\…` against each
/// other as `historyC:\Users\…`. A label longer than this is not truncated and
/// not wrapped — the line simply runs long, which is visible, whereas a glued
/// pair of columns reads as one value.
const LABEL: usize = COLUMN - 3;

/// The heading over the container answer.
///
/// A constant because two readers need to find that section by name: the
/// renderer, which prints it, and the guard that reads the answer under it. The
/// guard cannot search for the answer alone — the sentence it prints is the
/// module's, and a copy of it here would be a second wording to keep in step —
/// so it finds the heading and reads the rows below, which is what a person
/// does.
const CONTAINER_HEADING: &str = "Running a check in a container";

/// Write the human form.
///
/// # Errors
///
/// Any failure from `out`.
pub fn human(report: &DoctorReport, out: &mut impl Write) -> io::Result<()> {
    let build = &report.build;
    writeln!(
        out,
        "SURE {} (harness protocol {}), built for {} {}, C library {}",
        build.version, build.protocol_version, build.os, build.arch, build.target_env
    )?;
    if let Some(from) = &build.running_from {
        writeln!(out, "running from {}", from.display())?;
    }
    writeln!(out)?;

    places_in_words(&report.places, out)?;

    writeln!(out, "What SURE found there")?;
    match &report.places {
        Places::Unknown { .. } => {
            row(out, "everything", "nowhere to look")?;
        }
        Places::Known(locations) => {
            row(
                out,
                "evidence and history",
                &presence_in_words(locations.data_dir.presence.clone()),
            )?;
            row(
                out,
                "settings",
                &presence_in_words(locations.config_dir.presence.clone()),
            )?;
            row(
                out,
                "settings file",
                &presence_in_words(locations.settings_file.presence.clone()),
            )?;
            row(
                out,
                "record store",
                &store_in_words(&report.store, &locations.store_file.presence),
            )?;
        }
    }
    writeln!(out)?;

    writeln!(out, "Programs SURE calls")?;
    for tool in &report.tools {
        match &tool.found_at {
            Some(path) => row(out, tool.name, &format!("found at {}", path.display()))?,
            None => row(out, tool.name, "not found on PATH")?,
        }
        // The reason is on its own line because it is a sentence: putting it in
        // the value column would push every later line across the terminal.
        writeln!(out, "{:COLUMN$}{}", "", tool.needed_for)?;
    }
    writeln!(out)?;

    // Found, never run — and the reason on each line says why a name that is
    // missing here is not the same as a compiler that is missing from the
    // machine. A Microsoft C compiler is normally installed and normally off
    // `PATH`, which is the one thing a reader of this section has to be told.
    writeln!(out, "Programs a build on this machine uses")?;
    for compiler in &report.toolchain {
        match &compiler.found_at {
            Some(path) => row(out, compiler.name, &format!("found at {}", path.display()))?,
            None => row(out, compiler.name, "not found on PATH")?,
        }
        writeln!(out, "{:COLUMN$}{}", "", compiler.used_for)?;
    }
    writeln!(out)?;

    writeln!(out, "{CONTAINER_HEADING}")?;
    row(out, "container", &container_in_words(&report.container))?;
    // The module's own sentence, verbatim, rather than a second wording written
    // here: it is the sentence `crates/sure-core/src/container.rs` also offers
    // to any other caller, and two renderings of one fact is how they drift.
    writeln!(out, "{:COLUMN$}{}", "", report.container.explain())?;
    writeln!(out)?;

    // What each provider needs *from this machine*, and never which one is
    // configured: that is a value in the settings file, and this command does
    // not read it. A provider whose program is missing here is not unusable —
    // the program may be somewhere `PATH` does not reach.
    writeln!(out, "Analysis providers this build offers")?;
    for provider in &report.providers {
        row(out, provider.name, &provider_in_words(provider))?;
        writeln!(out, "{:COLUMN$}{}", "", provider.needs)?;
    }
    writeln!(out)?;

    writeln!(out, "Harnesses that can tell SURE what an agent did")?;
    for integration in &report.integrations {
        row(out, integration.name, integration.adds)?;
    }
    writeln!(out)?;

    if report.problems.is_empty() {
        writeln!(out, "SURE found nothing wrong with its own files.")?;
    } else {
        writeln!(out, "What is wrong")?;
        for problem in &report.problems {
            writeln!(out, "  {}", problem.what)?;
            writeln!(out, "      {}", problem.detail)?;
        }
        writeln!(out)?;
        writeln!(
            out,
            "SURE exited with status {} rather than {}, because a script checking this \
             machine has to be able to tell it apart from one that is fine.",
            crate::report::exit::NOT_GREEN,
            crate::report::exit::OK
        )?;
    }
    writeln!(out)?;

    writeln!(out, "What this did not check")?;
    for entry in &report.not_checked {
        writeln!(out, "  {}", entry.what)?;
        writeln!(out, "      {}", entry.why)?;
    }
    writeln!(out)?;

    writeln!(out, "{CLOSING_LINE}")
}

/// The last line of the report: where a reader goes next, and what this build
/// actually answers there.
///
/// It names `sure config set`, which writes one setting into the file only the
/// user can write; `sure config show`, which reports the settings in effect and
/// shows an analysis provider's endpoint, model and command only as set or not
/// set; and `sure history delete`.
///
/// # The statuses, which are measurements rather than composition
///
/// Every command this line names was run in one session against a store and a
/// settings file under `target/tmp` — named with `--store-dir` and
/// `--settings-file`, so that neither this machine's own store nor the user's own
/// settings file was read or written — and the status each one returned is kept
/// beside the sentence it belongs to:
///
/// ```text
/// sure config set privacy.full_recording true   exit 0   "sure config set wrote your settings file."
/// sure config show                              exit 0   "SURE settings in effect"
/// sure history delete --all                     exit 0   "Nothing was deleted."
/// ```
///
/// The first line of `sure config set` is the one quoted for a store where the
/// value changed; run the same command again and it answers *"sure config set
/// wrote nothing."* and still exits 0, because the setting was already what was
/// asked for. **The status is what the line claims and the status is what the
/// test asserts**, not this wording — a sentence that promised one spelling of a
/// success message would be the same drift in the other direction.
///
/// A sentence and a measurement kept in two places drift apart, so the two are
/// held together by a test rather than by this paragraph:
/// `the_commands_the_closing_line_names_answer_the_way_it_says_they_do` drives
/// each command above through [`crate::commands::Command::report`] — the dispatch
/// the binary itself runs — and asserts the status recorded here, the word the
/// line uses for it, and the machine-facing list in `crate::commands` that the
/// same claim is written in. A command that started or stopped answering fails
/// that test rather than quietly making this line false.
const CLOSING_LINE: &str = "Settings are written with `sure config set` and read with \
                            `sure config show`. Anything SURE has recorded is deleted with \
                            `sure history delete`.";

/// The four locations, with the heading that says what they are.
fn places_in_words(places: &Places, out: &mut impl Write) -> io::Result<()> {
    match places {
        Places::Known(locations) => {
            writeln!(out, "Where SURE keeps things on this machine")?;
            row(
                out,
                "evidence and history",
                &locations.data_dir.path.display().to_string(),
            )?;
            row(
                out,
                "settings",
                &locations.config_dir.path.display().to_string(),
            )?;
            row(
                out,
                "settings file",
                &locations.settings_file.path.display().to_string(),
            )?;
            // The other location a caller can name, and the same line about it
            // for the same reason: `sure --settings-file X doctor` and
            // `sure doctor` print the same *shape* of report, and which file the
            // run is about to read is a fact a path can only half carry. This is
            // where a named file that was honoured and a named file that was
            // ignored are told apart.
            row(
                out,
                "settings location",
                &origin_in_words(locations.settings_origin),
            )?;
            row(
                out,
                "record store",
                &locations.store_file.path.display().to_string(),
            )?;
            row(
                out,
                "store location",
                &origin_in_words(locations.store_origin),
            )?;
            // Where an installation for this user goes, which is a different
            // question from where *this* build is running from — that one is on
            // the first two lines of the report. A machine can run a build out
            // of a checkout while a per-user install sits where the launchers
            // look for it, and a reader who cannot tell the two apart will go
            // looking in the wrong directory.
            match &locations.install_file {
                Some(install) => row(
                    out,
                    "per-user install",
                    &format!(
                        "{} ({})",
                        install.path.display(),
                        install_in_words(&install.presence)
                    ),
                )?,
                None => row(
                    out,
                    "per-user install",
                    "this platform has no such location",
                )?,
            }
        }
        Places::Unknown { what, detail } => {
            // The one thing this command must never do is print a path it
            // guessed. `docs/architecture/STORAGE_AND_DATA_PATHS.md`: the
            // nearest guess is the project being checked.
            writeln!(out, "SURE does not know where to keep its files here")?;
            writeln!(out, "It could not find {what}.")?;
            writeln!(out)?;
            writeln!(out, "{detail}")?;
        }
    }
    writeln!(out)
}

/// Where a location a caller can name came from, in the words a person reads.
///
/// The same sentences for both of them — the store and the settings file —
/// because the question and the answers are the same: this location is the one
/// the platform reported for this user, or this location is the one the caller
/// named for this run.
///
/// A path alone cannot say this, and the two cases are the two things a caller
/// debugging a redirect needs told apart: a location they named that was
/// honoured, and the platform's own location that was used because nothing was
/// named.
fn origin_in_words(origin: Origin) -> String {
    match origin {
        Origin::Platform => "the platform's own location for this user".to_owned(),
        Origin::Caller => "named for this run, not the platform's own".to_owned(),
    }
}

/// A label and its value, in the column layout.
fn row(out: &mut impl Write, label: &str, value: &str) -> io::Result<()> {
    writeln!(out, "  {label:<LABEL$} {value}")
}

/// Whether a container runtime is here, in the words a person uses.
///
/// The name and the path, and no sentence about what a container gives a check:
/// that sentence is the module's own ([`Availability::explain`]) and is printed
/// on the line below, so this is the short value a reader scans for and the
/// other is the one they read.
///
/// **Both arms have to be true of this build, and the absent one is the one
/// that was not.** It used to read *"none found, so checks run on this
/// computer"* — and nothing runs on this computer because a runtime is missing:
/// `Authority::execution_mode` answers `inspect_only` unless the **user's own**
/// settings file grants project code, and since `P18-T007` a granted run does
/// reach the runner, so the absent arm may not say that a check runs here at all
/// without saying what decides it. Nor may it say one runs in a container: this
/// build has no executor that would start one. A missing runtime is a fact about
/// the machine and not a fallback, so the value says which machine this is and
/// what that does and does not change.
fn container_in_words(availability: &Availability) -> String {
    match availability {
        Availability::Found { runtime, program } => {
            format!("{} at {}", runtime.as_str(), program.display())
        }
        Availability::Absent => {
            "none found, and no check runs in a container in this build".to_owned()
        }
    }
}

/// What a provider needs *from this machine*, in the words a person uses.
///
/// Never whether the provider is the configured one: that is in the settings
/// file. A provider with no program of its own says so rather than showing a
/// blank, and a program that was not found says where SURE looked.
fn provider_in_words(provider: &Provider) -> String {
    match (provider.program, &provider.found_at) {
        (Some(_), Some(path)) => format!("found at {}", path.display()),
        (Some(program), None) => format!("{program} not found on PATH"),
        (None, _) => "no program to run".to_owned(),
    }
}

/// What is at the per-user install path, in the words a person uses.
///
/// Not [`presence_in_words`]: "not created yet" is right about a data directory
/// and wrong about an installation — a user asking this question has already
/// installed SURE somewhere, and what is missing is a copy in the place the
/// launchers look, which is a different sentence.
fn install_in_words(presence: &Presence) -> String {
    match presence {
        Presence::Present => "a SURE executable is there".to_owned(),
        Presence::Absent => "nothing there".to_owned(),
        Presence::Unreadable { detail } => format!("SURE could not look at it ({detail})"),
    }
}

/// What was found at a path, in the words a person uses.
fn presence_in_words(presence: Presence) -> String {
    match presence {
        Presence::Present => "there".to_owned(),
        Presence::Absent => "not created yet".to_owned(),
        Presence::Unreadable { detail } => {
            format!("there, and SURE could not look at it ({detail})")
        }
    }
}

/// What the store holds, in the words a person uses.
fn store_in_words(state: &StoreState, file: &Presence) -> String {
    match state {
        StoreState::NotCreated => "not created yet, so nothing is recorded".to_owned(),
        StoreState::NotLookedFor => "not looked at".to_owned(),
        StoreState::Unreadable { .. } => match file {
            Presence::Unreadable { .. } => "there, and SURE could not look at it".to_owned(),
            _ => "there, and SURE could not read it".to_owned(),
        },
        StoreState::Open(facts) => format!(
            "{} record{}, schema {}, journal mode {}",
            facts.records,
            if facts.records == 1 { "" } else { "s" },
            facts.schema_version,
            facts.journal_mode
        ),
    }
}

/// The `details` object of the response frame.
///
/// One object holding everything this command found, so that the frame's four
/// fixed fields keep meaning what `crate::report` says they mean and a reader
/// switches on `outcome` before looking in here.
#[must_use]
pub fn machine(report: &DoctorReport) -> Value {
    json!({
        "build": {
            "version": report.build.version,
            "protocol_version": report.build.protocol_version,
            "os": report.build.os,
            "arch": report.build.arch,
            // The second half of the target triple, so a script can tell a
            // native Windows build from one linked against a different C
            // library on the same machine and the same processor.
            "target_env": report.build.target_env,
            "running_from": report.build.running_from.as_ref().map(|path| path.display().to_string()),
        },
        "places": places_machine(&report.places),
        "store": store_machine(&report.store),
        "tools": report.tools.iter().map(tool_machine).collect::<Vec<Value>>(),
        "toolchain": report.toolchain.iter().map(compiler_machine).collect::<Vec<Value>>(),
        "container": container_machine(&report.container),
        "providers": report.providers.iter().map(provider_machine).collect::<Vec<Value>>(),
        "integrations": report.integrations.iter().map(integration_machine).collect::<Vec<Value>>(),
        "problems": report.problems.iter().map(problem_machine).collect::<Vec<Value>>(),
        "not_checked": report.not_checked.iter().map(|entry| json!({
            "what": entry.what,
            "why": entry.why,
        })).collect::<Vec<Value>>(),
    })
}

fn places_machine(places: &Places) -> Value {
    match places {
        Places::Known(locations) => json!({
            "state": "known",
            "data_dir": place_machine(&locations.data_dir.path, &locations.data_dir.presence),
            "config_dir": place_machine(&locations.config_dir.path, &locations.config_dir.presence),
            "settings_file": place_machine(&locations.settings_file.path, &locations.settings_file.presence),
            "store_file": place_machine(&locations.store_file.path, &locations.store_file.presence),
            // `null` rather than a missing key where the platform has no such
            // location, for the reason a tool that is not found is a `null`: a
            // script that looks for the key must find either an answer or
            // SURE's own "there is none", never nothing at all.
            "install_file": locations
                .install_file
                .as_ref()
                .map(|place| place_machine(&place.path, &place.presence)),
            // Which of the two the store's location is: "platform" for the
            // per-user location SURE discovered, "caller" for one a caller
            // named — `sure --store-dir`. A script that has to know whether the
            // store it is about to read is the one its caller meant must not
            // have to compare paths to find out.
            "store_location": origin_name(locations.store_origin),
            // The same fact about the settings file, because it is the same
            // question: whether the file this run will read is the one the
            // platform reported or the one its caller named with
            // `--settings-file`. A script that has to know whether the settings
            // about to be in force are the user's own must not have to guess it
            // from a path.
            "settings_location": origin_name(locations.settings_origin),
        }),
        Places::Unknown { what, detail } => json!({
            "state": "unknown",
            "what": what,
            "detail": detail,
        }),
    }
}

fn origin_name(origin: Origin) -> &'static str {
    match origin {
        Origin::Platform => "platform",
        Origin::Caller => "caller",
    }
}

fn place_machine(path: &std::path::Path, presence: &Presence) -> Value {
    json!({
        "path": path.display().to_string(),
        "presence": presence_name(presence),
    })
}

fn presence_name(presence: &Presence) -> &'static str {
    match presence {
        Presence::Present => "present",
        Presence::Absent => "absent",
        Presence::Unreadable { .. } => "unreadable",
    }
}

fn store_machine(state: &StoreState) -> Value {
    match state {
        StoreState::NotCreated => json!({"state": "not_created"}),
        StoreState::NotLookedFor => json!({"state": "not_looked_for"}),
        StoreState::Unreadable { detail } => json!({"state": "unreadable", "detail": detail}),
        StoreState::Open(facts) => json!({
            "state": "open",
            "journal_mode": facts.journal_mode,
            "schema_version": facts.schema_version,
            "records": facts.records,
        }),
    }
}

fn tool_machine(tool: &Tool) -> Value {
    json!({
        "name": tool.name,
        "needed_for": tool.needed_for,
        "found_at": tool.found_at.as_ref().map(|path| path.display().to_string()),
    })
}

fn compiler_machine(compiler: &Compiler) -> Value {
    json!({
        "name": compiler.name,
        "used_for": compiler.used_for,
        "found_at": compiler.found_at.as_ref().map(|path| path.display().to_string()),
    })
}

/// One container answer, in the shape a script reads.
///
/// `program` is `null` when no runtime was found, and `found` is a boolean
/// beside it rather than the whole answer: a script that only wants to know
/// whether to offer the mode has one field to read, and one that wants the path
/// has it without parsing the sentence.
fn container_machine(availability: &Availability) -> Value {
    match availability {
        Availability::Found { runtime, program } => json!({
            "found": true,
            "runtime": runtime.as_str(),
            "program": program.display().to_string(),
            "sentence": availability.explain(),
        }),
        Availability::Absent => json!({
            "found": false,
            "runtime": Value::Null,
            "program": Value::Null,
            "sentence": availability.explain(),
        }),
    }
}

fn provider_machine(provider: &Provider) -> Value {
    json!({
        "name": provider.name,
        "needs": provider.needs,
        "program": provider.program,
        "found_at": provider.found_at.as_ref().map(|path| path.display().to_string()),
    })
}

fn integration_machine(integration: &Integration) -> Value {
    json!({
        "name": integration.name,
        "adds": integration.adds,
    })
}

fn problem_machine(problem: &Problem) -> Value {
    json!({
        "what": problem.what,
        "detail": problem.detail,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sure_core::container::Runtime;
    use sure_core::doctor::{Build, DoctorReport, Locations, Place, StoreFacts};

    fn a_place(path: &str, presence: Presence) -> Place {
        Place {
            path: std::path::PathBuf::from(path),
            presence,
        }
    }

    fn a_program(path: &str) -> Option<std::path::PathBuf> {
        Some(std::path::PathBuf::from(path))
    }

    fn a_compiler(
        name: &'static str,
        used_for: &'static str,
        found_at: Option<std::path::PathBuf>,
    ) -> Compiler {
        Compiler {
            name,
            used_for,
            found_at,
        }
    }

    fn a_provider(
        name: &'static str,
        needs: &'static str,
        program: Option<&'static str>,
        found_at: Option<std::path::PathBuf>,
    ) -> Provider {
        Provider {
            name,
            needs,
            program,
            found_at,
        }
    }

    /// A report of an installation that works, on a root this test names.
    ///
    /// Every list a person can read a row from is non-empty here, one entry
    /// found and one not: the label test below can only check the labels that
    /// are actually printed, so a list left empty in this fixture is a list
    /// whose labels nothing checks.
    fn a_healthy_report() -> DoctorReport {
        DoctorReport {
            build: Build {
                version: "0.0.0-test".to_owned(),
                protocol_version: 1,
                os: "windows",
                arch: "x86_64",
                target_env: "msvc",
                running_from: Some(std::path::PathBuf::from(r"C:\tools\sure.exe")),
            },
            places: Places::Known(Box::new(Locations {
                data_dir: a_place(r"C:\Users\a\AppData\Local\SURE", Presence::Present),
                config_dir: a_place(r"C:\Users\a\AppData\Roaming\SURE", Presence::Absent),
                settings_file: a_place(
                    r"C:\Users\a\AppData\Roaming\SURE\sure.yaml",
                    Presence::Absent,
                ),
                store_file: a_place(r"C:\Users\a\AppData\Local\SURE\sure.db", Presence::Present),
                store_origin: Origin::Platform,
                settings_origin: Origin::Platform,
                install_file: Some(a_place(
                    r"C:\Users\a\AppData\Local\SURE\bin\sure.exe",
                    Presence::Present,
                )),
            })),
            store: StoreState::Open(StoreFacts {
                journal_mode: "wal".to_owned(),
                schema_version: 4,
                records: 12,
            }),
            tools: vec![
                Tool {
                    name: "git",
                    needed_for: "identifying which state of a project a result belongs to",
                    found_at: a_program(r"C:\Program Files\Git\cmd\git.exe"),
                },
                Tool {
                    name: "not-installed",
                    needed_for: "something this test made up",
                    found_at: None,
                },
            ],
            toolchain: vec![
                a_compiler(
                    "rustc",
                    "compiling Rust code, which this build is made of",
                    a_program(r"C:\Users\a\.cargo\bin\rustc.exe"),
                ),
                a_compiler(
                    "cl",
                    "the Microsoft C compiler a native msvc build links through",
                    None,
                ),
            ],
            container: Availability::Found {
                runtime: Runtime::Docker,
                program: std::path::PathBuf::from(r"C:\Program Files\Docker\docker.exe"),
            },
            providers: vec![
                a_provider(
                    "disabled",
                    "nothing: the deterministic checks run and no model is consulted",
                    None,
                    None,
                ),
                a_provider(
                    "claude_cli",
                    "the Claude CLI already installed on this machine",
                    Some("claude"),
                    None,
                ),
            ],
            integrations: vec![
                Integration {
                    name: "claude-code",
                    adds: "hooks that record what an agent did",
                },
                Integration {
                    name: "codex",
                    adds: "hooks, skills and SURE's tools",
                },
            ],
            problems: Vec::new(),
            not_checked: vec![sure_core::doctor::NotChecked {
                what: "whether a program found on PATH runs",
                why: "SURE does not run a program to find out.",
            }],
        }
    }

    fn rendered(report: &DoctorReport) -> String {
        let mut buffer = Vec::new();
        human(report, &mut buffer).expect("the human form writes");
        String::from_utf8(buffer).expect("the human form is utf-8")
    }

    #[test]
    fn every_label_the_report_prints_is_separated_from_its_value() {
        // The regression this exists for: the value column was first computed so
        // that the longest label filled it exactly, and the two ran together as
        // `evidence and historyC:\Users\…`. A label and the thing it labels are
        // two pieces of text, and no reader should have to work out where one
        // stops.
        //
        // Every label the renderer can print is named here, including the
        // longest — if a label outgrows the column this fails on the row it
        // outgrew, rather than on whichever row a scan happened to reach.
        //
        // `P15-T001` added rows to four sections and this list is the reason
        // they are covered at all: the test iterates this list, not the
        // renderer's output, so a label missing from here is a row nothing
        // checks. The fixture's lists are therefore non-empty — one row per
        // section at least, and both answers (found and not found) among them.
        const LABELS: &[&str] = &[
            "evidence and history",
            "settings",
            "settings file",
            "record store",
            "store location",
            "per-user install",
            "git",
            "not-installed",
            "rustc",
            "cl",
            "container",
            "disabled",
            "claude_cli",
            "claude-code",
            "codex",
        ];
        let text = rendered(&a_healthy_report());

        for label in LABELS {
            let line = text
                .lines()
                .find(|line| label_of(line).trim_end() == *label)
                .unwrap_or_else(|| panic!("no row is labelled {label:?}:\n{text}"));
            assert_eq!(
                label_of(line).chars().count(),
                LABEL,
                "the padding for {label:?} is not the column width, so the values below it \
                 do not line up: {line:?}"
            );
            assert_eq!(
                line.chars().nth(COLUMN - 1),
                Some(' '),
                "the value is glued to {label:?}: {line:?}"
            );
            assert_ne!(
                line.chars().nth(COLUMN),
                Some(' '),
                "there is no value after {label:?}: {line:?}"
            );
        }
    }

    /// The label field of a line: the two spaces of indent, then up to the value
    /// column.
    fn label_of(line: &str) -> String {
        line.chars().skip(2).take(LABEL).collect()
    }

    #[test]
    fn what_was_found_wrong_is_never_left_out() {
        // The false-green rule in its last line of defence. A report carrying a
        // problem must say so on the terminal, and a report carrying none must
        // not say it found something — the two sentences are exclusive.
        let healthy = rendered(&a_healthy_report());
        assert!(healthy.contains("SURE found nothing wrong"), "{healthy}");
        assert!(!healthy.contains("What is wrong"), "{healthy}");

        let mut damaged = a_healthy_report();
        damaged.store = StoreState::Unreadable {
            detail: "the file is not a database".to_owned(),
        };
        damaged.problems.push(Problem {
            what: "SURE has recorded history on this machine and cannot read it.",
            detail: "the file is not a database".to_owned(),
        });
        let text = rendered(&damaged);

        assert!(text.contains("What is wrong"), "{text}");
        assert!(!text.contains("SURE found nothing wrong"), "{text}");
        assert!(
            text.contains("the file is not a database"),
            "the report does not say what was wrong, only that something was:\n{text}"
        );
        assert!(
            text.contains("exited with status 1"),
            "the human form does not say what the status will be, so a reader piping it \
             somewhere cannot tell:\n{text}"
        );
    }

    #[test]
    fn what_the_report_did_not_look_at_is_always_printed() {
        // The honesty rule: a report that stops at what it found invites the
        // reader to assume it looked everywhere.
        let text = rendered(&a_healthy_report());
        assert!(text.contains("What this did not check"), "{text}");
        assert!(
            text.contains("whether a program found on PATH runs"),
            "{text}"
        );
        assert!(
            !a_healthy_report().not_checked.is_empty(),
            "the fixture cannot demonstrate this with an empty list"
        );
    }

    #[test]
    fn a_tool_that_was_not_found_says_so_rather_than_showing_a_blank() {
        let text = rendered(&a_healthy_report());
        assert!(text.contains("not found on PATH"), "{text}");
        assert!(text.contains("found at"), "{text}");
    }

    #[test]
    fn which_location_the_store_is_says_which_it_is_in_both_forms() {
        // The report has to distinguish a location the caller named from the
        // platform's own, in both forms and in the same words each time: a
        // caller who cannot tell a redirect that worked from one that was
        // ignored will go and debug the wrong thing. The two cases are checked
        // against one fixture so that the only difference between them is the
        // origin.
        let platform = a_healthy_report();
        let text = rendered(&platform);
        assert!(
            text.contains("the platform's own location for this user"),
            "the human form does not say where the location came from:\n{text}"
        );
        assert_eq!(machine(&platform)["places"]["store_location"], "platform");

        let mut named = a_healthy_report();
        let Places::Known(locations) = &mut named.places else {
            panic!("the fixture names its locations");
        };
        locations.store_origin = Origin::Caller;
        let text = rendered(&named);
        assert!(
            text.contains("named for this run"),
            "the human form does not say the location was the caller's:\n{text}"
        );
        assert_eq!(machine(&named)["places"]["store_location"], "caller");
    }

    #[test]
    fn the_machine_form_puts_what_was_found_under_one_key() {
        // A script switches on the frame's outcome before it looks anywhere
        // else, so everything a doctor run found lives under one key rather than
        // being spread across the frame's own fields.
        let value = machine(&a_healthy_report());

        assert_eq!(value["places"]["state"], "known");
        assert_eq!(value["store"]["state"], "open");
        assert_eq!(value["store"]["journal_mode"], "wal");
        assert_eq!(value["store"]["records"], 12);
        assert!(value["problems"].as_array().expect("a list").is_empty());
        assert_eq!(
            value["tools"][1]["found_at"],
            Value::Null,
            "a tool that was not found is a null rather than a missing key"
        );
        assert_eq!(
            value["toolchain"][1]["found_at"],
            Value::Null,
            "a compiler that was not found is a null rather than a missing key"
        );
        assert_eq!(
            value["not_checked"][0]["what"],
            "whether a program found on PATH runs"
        );
        assert_eq!(value["build"]["version"], "0.0.0-test");
        assert_eq!(value["build"]["target_env"], "msvc");
    }

    #[test]
    fn every_answer_a_machine_reads_is_present_whichever_way_it_came_out() {
        // A script switches on `outcome` and then reads a fixed set of keys. A
        // key that is present when a runtime is found and absent when it is not
        // would make the two runs different shapes, and the script would have to
        // guess which one it had — which is how a missing answer becomes a
        // plausible-looking default. Both answers are produced here from the one
        // fixture with only the container's variant moved, so the two shapes can
        // be compared.
        let found = machine(&a_healthy_report());

        let mut absent = a_healthy_report();
        absent.container = Availability::Absent;
        let none = machine(&absent);

        for (what, value, is_found) in [("found", &found, true), ("absent", &none, false)] {
            assert_eq!(value["container"]["found"], is_found, "{what}: {value}");
            assert!(
                value["container"]["sentence"]
                    .as_str()
                    .is_some_and(|sentence| !sentence.is_empty()),
                "{what}: the container answer carries no sentence: {value}"
            );
            for key in ["runtime", "program"] {
                assert!(
                    value["container"].get(key).is_some(),
                    "{what}: `container.{key}` is missing rather than null: {value}"
                );
            }
        }
        assert_eq!(found["container"]["runtime"], "docker");
        assert_eq!(none["container"]["runtime"], Value::Null);
        assert_eq!(none["container"]["program"], Value::Null);

        // Which provider a *settings file* chooses is not here, and neither is
        // any field one could be read out of: what each entry carries is the
        // name, what it needs, and where a program is. The absence is the point
        // — a report that could carry a key would eventually carry one.
        let provider = &found["providers"][1];
        assert_eq!(provider["name"], "claude_cli");
        assert_eq!(provider["program"], "claude");
        assert_eq!(provider["found_at"], Value::Null);
        assert_eq!(
            provider.as_object().expect("an object").len(),
            4,
            "a provider answer gained a field. The four it has are the name, \
             what it needs, its program and where that program is; a fifth is \
             something this report has no honest source for — the settings file \
             is where a provider's endpoint and key live, and this command does \
             not read it: {provider}"
        );

        // The harness list is what SURE can be *told* by, and it says so without
        // claiming anything about what is installed.
        assert_eq!(found["integrations"][0]["name"], "claude-code");
        assert!(
            found["integrations"][0]["adds"]
                .as_str()
                .is_some_and(|adds| !adds.is_empty()),
            "{found}"
        );
        // Mutation, run rather than described: take the `"sentence"` key out of
        // the `Availability::Absent` arm of `container_machine` above. This test
        // fails on the missing key and prints the whole frame, and `cargo test
        // -p sure-cli --lib doctor` shows it is the only failure the mutation
        // causes. The run is reported in this task's hand-back.
    }

    #[test]
    fn the_two_forms_agree_about_which_sections_there_are() {
        // The human form grew four sections in `P15-T001`; the machine form grew
        // four keys plus one under `build`. A section added to one and not the
        // other is a fact a person can see and a script cannot, which is exactly
        // the asymmetry this file's two renderings exist to avoid.
        let report = a_healthy_report();
        let text = rendered(&report);
        let value = machine(&report);

        for (heading, key) in [
            ("Programs SURE calls", "tools"),
            ("Programs a build on this machine uses", "toolchain"),
            ("Running a check in a container", "container"),
            ("Analysis providers this build offers", "providers"),
            (
                "Harnesses that can tell SURE what an agent did",
                "integrations",
            ),
        ] {
            assert!(
                text.contains(heading),
                "the human form has no {heading:?} section:\n{text}"
            );
            assert!(
                value.get(key).is_some(),
                "the machine form has no `{key}` for the {heading:?} section: {value}"
            );
        }
        // Mutation, run rather than described: rename the heading the renderer
        // writes — `"Running a check in a container"` in `human` above — to
        // `"Running a check in a box"`. This test fails, prints the text, and
        // the failure message is `the human form has no "Running a check in a
        // container" section`; `cargo test -p sure-cli --lib doctor` shows it is
        // the only failure the mutation causes. Reported in this task's
        // hand-back.
    }

    /// The rows of the report's container section: what a person reads there,
    /// without the heading over it.
    ///
    /// The heading is [`CONTAINER_HEADING`], and both rules in
    /// `sure_core::container` read it as a claim — *a check in a container* is a
    /// running word and a container place with nothing denying it. That is
    /// written down there as a limit of the rules rather than fixed here,
    /// because the heading names the topic of a section and the section's
    /// answers are its rows; a guard that asked the rules about the heading
    /// would be asking them about a topic.
    ///
    /// Taken from the rendered form rather than assembled out of the same
    /// pieces, so that a row which stopped reaching a terminal — a sentence
    /// printed somewhere else, or not printed at all — fails the test rather
    /// than passing on a value nobody sees.
    fn container_rows(text: &str) -> Vec<String> {
        let mut lines = text.lines().skip_while(|line| *line != CONTAINER_HEADING);
        assert!(
            lines.next().is_some(),
            "the human form has no {CONTAINER_HEADING:?} section:\n{text}"
        );
        let rows: Vec<String> = lines
            .take_while(|line| line.starts_with("  "))
            .map(|line| line.trim().to_owned())
            .collect();
        assert!(
            !rows.is_empty(),
            "the {CONTAINER_HEADING:?} section prints a heading and no answer:\n{text}"
        );
        rows
    }

    #[test]
    fn neither_container_answer_tells_a_reader_that_a_check_ran_here() {
        // **The regression this exists for.** `sure doctor` used to print, on a
        // machine with no runtime, `none found, so checks run on this computer`
        // and *"No container runtime was found, so checks run on this computer
        // instead."* — and neither is true of this build: a missing runtime is
        // not a fallback, and since `P18-T007` what decides whether a check runs
        // here is `Authority::execution_mode`, which answers the **user's own**
        // settings file (`support::CEILING` is `Generic` since ADR 0017; the
        // level is a capability claim, not a statement that a check runs here).
        // The
        // guard over the module's sentence asked whether it contained a phrase,
        // so it stayed green while the sentence was false.
        //
        // `P16-T012` found the other half of it in the other arm: with a runtime
        // found, the report said *"Checks can run in a container: docker was
        // found at …"*, and the rule written for the first sentence does not
        // read it — `claims_local_execution` wants a place on this computer, and
        // *"in a container"* is not one. So both arms are asserted here against
        // both rules, and the arm with a runtime is the one that was wrong: what
        // the machine has on its search path is not a fact about whether the
        // project was checked.
        //
        // What is asserted is the claim, on both lines a person reads — the
        // short value in the column and the sentence under it — and in both
        // forms, the report and the frame. `sure_core`'s own rules do the
        // reading, because one copy of a rule is one rule, and the sentence
        // still has to say what happens instead, which is that no check runs.
        //
        // **The scan is the section's rows and not the whole report**, which is
        // what the row rule above is for: the rules read sentences, and a report
        // is more sentences than this one. A sentence about what a *provider*
        // needs from this machine is read by the local rule as a claim about a
        // check — `P16-T012` measured that, and the case is kept as a value in
        // `sure_core::container`'s own tests — and it is `sure_core::doctor`'s
        // to correct rather than this guard's to cover, which is why this guard
        // names the section it is about.
        let found = Availability::Found {
            runtime: Runtime::Docker,
            program: std::path::PathBuf::from(r"C:\Program Files\Docker\docker.exe"),
        };
        for (which, answer, names) in [
            ("an absence", Availability::Absent, vec!["docker", "podman"]),
            (
                "a runtime",
                found,
                vec!["docker", r"C:\Program Files\Docker\docker.exe"],
            ),
        ] {
            let mut report = a_healthy_report();
            report.container = answer;
            let text = rendered(&report);
            let rows = container_rows(&text);
            assert_eq!(
                rows.len(),
                2,
                "{which}: the section is a value and the sentence under it:\n{text}"
            );
            let (value, sentence) = (&rows[0], &rows[1]);

            for (what, row) in [("the column value", value), ("the sentence", sentence)] {
                for (name, reads) in [
                    (
                        "claims_local_execution",
                        sure_core::container::claims_local_execution as fn(&str) -> bool,
                    ),
                    (
                        "claims_container_execution",
                        sure_core::container::claims_container_execution,
                    ),
                ] {
                    assert!(
                        !reads(row),
                        "{which}: {what} is read by {name} as a claim that a check runs, and \
                         none does: {row}"
                    );
                }
            }
            // The denial belongs to the sentence rather than to the column: a
            // value can say what was found — *docker at C:\…* — and the place a
            // reader is told what that means is the sentence under it. An
            // absence happens to carry it in both, which is not a rule the arm
            // with a runtime could keep.
            assert!(
                sure_core::container::denies_that_anything_runs(sentence),
                "{which}: the sentence has to say what happens instead of only what was found \
                 or not found, and what happens is that no container runs one and nothing runs \
                 here unasked: {sentence}"
            );
            // What the answer is about: what was looked for, or what was found
            // and where. An answer that said neither would pass every rule above
            // by saying nothing.
            for name in &names {
                assert!(
                    sentence.contains(name),
                    "{which}: the sentence does not name {name:?}, so a reader cannot act on \
                     it: {sentence}"
                );
            }

            // And the frame a script reads carries the sentence a person reads,
            // word for word, held to both rules the same way. This is the pair
            // of assertions that would have caught the defect where it was
            // seen: the report on a terminal and the frame under
            // `container.sentence`.
            let frame = machine(&report);
            let framed = frame["container"]["sentence"]
                .as_str()
                .expect("the container answer carries a sentence");
            assert_eq!(
                framed, sentence,
                "{which}: the frame and the report do not carry the same sentence"
            );
            assert!(
                !sure_core::container::claims_local_execution(framed)
                    && !sure_core::container::claims_container_execution(framed),
                "{which}: the frame carries a sentence that claims a check runs: {framed}"
            );
        }
    }

    /// Which way the closing line says a command ends.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Said {
        Works,
        Refuses,
    }

    /// Every command under test here lives in one scratch directory, so that
    /// what a run writes is a file this test named and nothing else.
    ///
    /// The settings file is **outside** the process's working directory, which
    /// is what `sure config set` requires of every path it writes
    /// ([`sure_core::paths::Paths::ensure_settings_outside`]): the interesting
    /// refusal — a settings file a project could edit — is asserted in
    /// `crate::settings`' own tests, and a copy of it here would only make this
    /// test about a second thing.
    fn a_store_and_a_settings_file_of_our_own() -> (std::path::PathBuf, std::path::PathBuf) {
        let directory = sure_testkit::scratch::directory("sure doctor", "closing-line");
        (
            directory.join("store"),
            directory.join("SURE").join("sure.yaml"),
        )
    }

    /// Every command the closing line names, what the line says about it, and
    /// what this build answers it with.
    ///
    /// **The third column is a measurement, not composition.** Each status is
    /// the one the built binary returned when the command was run in the
    /// session `P16-T012` was worked in, against a store and a settings file
    /// under `target/tmp`:
    ///
    /// ```text
    /// sure config set privacy.full_recording true   exit 0   "sure config set wrote your settings file."
    /// sure config show                              exit 0   "SURE settings in effect"
    /// sure history delete --all                     exit 0   "Nothing was deleted."
    /// ```
    ///
    /// The test below drives the same three through
    /// [`crate::commands::Command::report`] — the dispatch that binary runs —
    /// so the sentence and the measurement cannot drift apart quietly. When one
    /// of them changes, the closing line is what needs rewording and
    /// re-measuring; relaxing an assertion here would be the drift itself.
    const NAMED_BY_THE_CLOSING_LINE: &[(&str, Said, u8)] = &[
        ("sure config set", Said::Works, crate::report::exit::OK),
        ("sure config show", Said::Works, crate::report::exit::OK),
        ("sure history delete", Said::Works, crate::report::exit::OK),
    ];

    /// The names `line` writes inside backticks, in the order it writes them.
    fn named_in(line: &str) -> Vec<String> {
        let mut found = Vec::new();
        let mut rest = line;
        while let Some(open) = rest.find('`') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('`') else {
                break;
            };
            found.push(after[..close].to_owned());
            rest = &after[close + 1..];
        }
        found
    }

    /// The part of `line` that names `invocation`.
    ///
    /// Split where the line ends a statement, at a semicolon or a full stop, so
    /// that what comes back is about the one command: the line makes three
    /// statements and only one of them says *refuses*, and a part that carried
    /// a neighbour's word would make the verb below meaningless.
    fn the_part_naming<'a>(line: &'a str, invocation: &str) -> &'a str {
        line.split([';', '.'])
            .find(|part| part.contains(invocation))
            .unwrap_or_else(|| panic!("{line:?} has no part naming {invocation:?}"))
    }

    /// The command an invocation names, built the way the grammar would.
    ///
    /// Written out rather than parsed, so that a name in
    /// [`NAMED_BY_THE_CLOSING_LINE`] is tied to a command that exists: a
    /// literal there that lands in the `panic!` arm is a claim about nothing,
    /// which is the failure this shape is for.
    fn command_named(invocation: &str) -> crate::cli::Command {
        use crate::cli::{Command, ConfigAction, HistoryAction};
        match invocation {
            "sure config set" => Command::Config {
                action: Some(ConfigAction::Set {
                    setting: "privacy.full_recording".to_owned(),
                    value: "true".to_owned(),
                }),
            },
            "sure config show" => Command::Config {
                action: Some(ConfigAction::Show { path: None }),
            },
            "sure history delete" => Command::History {
                action: Some(HistoryAction::Delete {
                    all: true,
                    session: None,
                    project: None,
                }),
            },
            other => panic!(
                "{other} is named by the closing line and this test knows how to build no \
                 command for it, so nothing measures what it answers"
            ),
        }
    }

    #[test]
    fn the_commands_the_closing_line_names_answer_the_way_it_says_they_do() {
        // A sentence telling a reader where to go next is a claim about what
        // this build does, and it is the claim a reader is most likely to act
        // on without testing — they have just been told their installation is
        // fine. So the three things are held together here: the names the line
        // writes, the statuses the record above holds, and the machine-facing
        // lists in `crate::commands` that write the same claim for an agent.
        use crate::report::Report;

        // First, that the sentence being measured is the sentence a person
        // reads. `human` prints this constant rather than a copy of it, and a
        // copy is exactly how a report and the record kept beside it come apart:
        // the rest of this test would go on measuring a sentence nothing prints.
        //
        // Mutation, run rather than described: put the old sentence back into
        // `human` as a literal in place of `{CLOSING_LINE}`. This assertion fails
        // and prints both sentences, the printed one above the one the record
        // belongs to — and without it, that mutation left every other assertion
        // in this test green. The run is reported in this task's hand-back.
        let text = rendered(&a_healthy_report());
        assert_eq!(
            text.lines().last(),
            Some(CLOSING_LINE),
            "the last line of the report is not the sentence these measurements are kept beside"
        );

        // What the line names, and what the record says is named. A command
        // added to either one and not the other fails here rather than going
        // unmeasured.
        let named = named_in(CLOSING_LINE);
        let recorded: Vec<String> = NAMED_BY_THE_CLOSING_LINE
            .iter()
            .map(|(invocation, _, _)| (*invocation).to_owned())
            .collect();
        assert_eq!(
            named, recorded,
            "the closing line names {named:?} and the record covers {recorded:?}, so one of the \
             two is telling a reader about a command nothing checks"
        );

        let (store, settings) = a_store_and_a_settings_file_of_our_own();
        for (invocation, said, status) in NAMED_BY_THE_CLOSING_LINE {
            // The two names are not one name, and that is the whole of the
            // asymmetry this test keeps: `config set` is the invocation a user
            // types and `config` is the command it belongs to, and the two
            // lists in `crate::commands` record the two separately for exactly
            // that reason.
            let bare = invocation
                .strip_prefix("sure ")
                .expect("the line names commands as a user types them");
            let name = bare
                .split(' ')
                .next()
                .expect("an invocation names a command");
            let command = command_named(invocation);
            assert_eq!(
                command.name(),
                name,
                "{invocation} is not an invocation of {name:?} in this build's grammar, so the \
                 record and the command it is compared against are two different things"
            );

            let report = command.report(crate::commands::Named {
                store: Some(&store),
                settings_file: Some(&settings),
                commands_file: None,
            });
            assert_eq!(
                report.exit_code(),
                *status,
                "{invocation} answered {} where the record beside the closing line says {status}: \
                 {report:?}",
                report.exit_code()
            );
            // The verb and the status are one claim in two places: a command
            // the line says refuses has to be the refusal, and one it says
            // works has to be an answer rather than a refusal that happens to
            // exit the right way.
            assert_eq!(
                matches!(report, Report::Unavailable(_)),
                *said == Said::Refuses,
                "{invocation} is described by the closing line as {said:?} and this build \
                 answered it: {report:?}"
            );
            assert_eq!(
                the_part_naming(CLOSING_LINE, invocation).contains("refuses"),
                *said == Said::Refuses,
                "the part naming {invocation} does not say what the record says about it: {}",
                the_part_naming(CLOSING_LINE, invocation)
            );

            // And the machine-facing record, which is where the same claim is
            // written for an agent: `sure mcp` reads `IMPLEMENTED` out as
            // `commands_implemented` and into every tool description, so an
            // invocation the report tells a person works has to be in one of
            // the two lists, and one it tells them refuses has to be in
            // neither. This is the assertion that keeps the human report and
            // `sure mcp` from disagreeing about the same build — which is what
            // this task found them doing.
            let in_the_whole_command = crate::commands::IMPLEMENTED.contains(&command.name());
            let in_part = crate::commands::IMPLEMENTED_IN_PART.contains(&bare);
            assert_eq!(
                in_the_whole_command || in_part,
                *said == Said::Works,
                "the closing line says {invocation} is {said:?} and `crate::commands` records it \
                 as implemented={in_the_whole_command} in_part={in_part}, so the report a person \
                 reads and the list an agent reads are telling two different stories"
            );
        }
    }
}
