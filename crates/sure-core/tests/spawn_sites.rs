//! Where SURE starts a process, and what stands in front of each site.
//!
//! `P3-T001` added the general process runner, and with it the first thing in
//! this crate that *can* be pointed at a project. Until `P18-T007` everything
//! the product claimed about not running project code rested on that runner
//! having no caller at all; it has one now — `pipeline.rs` builds a
//! `PermissionPlan`, asks `Enforcement::of` about every check the schedule holds,
//! and hands the admitted ones to `planned_check_runner` — so the claim this file
//! holds is no longer *"nothing calls it"* but **"what calls it can only start
//! what the mode admitted, and every file that may name the types on that route
//! is named here"**. The default run is still inert, and what makes it inert is
//! the plan and the enforcement rather than the runner's isolation. That is a
//! claim about source text, so it is checked here rather than written down and
//! hoped for — the same technique, and for the same reason, as
//! `fingerprint_git.rs`'s `git_is_started_in_exactly_one_place` and
//! `scan_project.rs`'s rule about the scanner not opening files.
//!
//! # Why a source check is the only thing that can hold this
//!
//! An absence cannot be demonstrated by running anything. If a product path
//! started calling the runner, every behavioural test in the suite would still
//! pass — the runner works, which is the point of it — and the only visible
//! change would be that SURE had begun executing code out of a directory it was
//! asked to inspect. That is the exact failure this product exists to prevent,
//! and the check for it has to be made of the source text, because the source
//! text is the only place the fact lives.
//!
//! # The four rules, and what each is standing in for
//!
//! **One: every file in `crates/` that builds a `Command` is named here.** The
//! census is not the interesting fact; the interesting fact is that the list
//! *cannot grow quietly*. A fifth `Command::new` is a new way for SURE to run
//! something, and adding one means editing this list, which means reading this
//! paragraph. **This rule has not moved for two callers now**: neither
//! `service.rs` nor `runtime_start.rs` builds a `Command` of its own — the first
//! builds a `ProcessRequest` and the request builds the command, and the second
//! builds neither — so those two are covered by the rules below rather than
//! here.
//!
//! **The count is four since `P5-T004`, and the fourth entry is the one to
//! argue for.** `browser_driver/launch.rs` starts a browser, which is a program
//! that is not part of this repository and is not a project's either — and it is
//! here because *every* way SURE runs something belongs in one list, not because
//! starting a browser is safe by nature. **A product path builds the type that
//! starts it since `P18-T010`**: `sure-cli/src/check.rs` binds a
//! `browser_driver::Browser` to the runner that carries a browser check out, and
//! that file is the composition root — the layer allowed to know which
//! implementations exist. A new caller inside the product is not evidence about
//! macOS or Linux; the ceiling moved on 2026-10-23 on the tracked CLI reading
//! (ADR 0017), not on a browser caller. The census that made this a deliberate
//! edit rather than a quiet one is `tests/browser_probe.rs`'s rule five.
//!
//! **The count is five since `P15-T020`, and the fifth is the one that is not a
//! way for the product to run anything.** `sure-testkit/src/source_manifest.rs`
//! runs `git ls-files --stage` and `git cat-file --batch` — both read-only —
//! over **this repository's own index**, because that is what the digests in
//! `SHA256SUMS.txt` are of, and a manifest with no reader is a manifest nobody
//! can check. It is in the list rather than excused from it for rule one's own
//! reason: the fact worth keeping is that the list *cannot grow quietly*, and a
//! rule with a door cut in its side for the entries somebody did not want to
//! argue for is exactly the growth rule one exists to catch. What separates it
//! from the four above is where it sits rather than how it reads:
//! `sure-testkit` is the crate `repository_shape.rs`'s
//! `nothing_depends_on_the_testkit_in_production` keeps out of the product, so
//! no ship path reaches this line, and every caller gives it
//! `sure_testkit::repository_root()` — the checkout it was compiled in, never a
//! directory SURE was pointed at. The ceiling is B since ADR 0017; this entry's
//! evidence is a read-only `git` call over SURE's own tree, not a project
//! command, and it runs over SURE's own checkout besides.
//!
//! **Two: nothing outside [`MAY_NAME_A_PROCESS_REQUEST`] mentions
//! [`ProcessRequest`].** This is the tightest of the three, and until `P3-T009`
//! it was the whole of the claim `process/mod.rs` used to make in its own words
//! — *"no product path calls `run` yet"* — because `run` takes a
//! `&ProcessRequest` and there is no other way to call it. A file that never
//! names the type cannot be a caller, whatever else it does, and that is a
//! stronger statement than searching for `process::run`, which a `use`
//! statement, an alias or a re-export would walk straight past. `P3-T009` made
//! the list two entries long rather than one: `sure-core/src/service.rs` is a
//! real caller, and the honest response to a rule breaking is to say why the
//! exception is one rather than to widen the rule until it stops noticing.
//!
//! **The fourth entry is this task's, and it is the one the exempted file's own
//! comment asked for.** `planned_work.rs` deliberately has no method that turns
//! a `CommandSpec` into a request, and says why in the place a reader would look
//! for it: *"doing that is the moment this module names
//! `process::ProcessRequest` in code rather than in prose, and
//! `tests/spawn_sites.rs` reads that name as the statement 'this file can call
//! the runner'."* So the translation needed a file, and
//! `planned_check_runner.rs` is the one that owns it: `CommandSpec`'s program,
//! arguments, working directory, environment and limits go into
//! `ProcessRequest::new(...).with_arguments(...).with_environment(...)` field for
//! field, and nothing there is rendered, split or re-parsed. That is what the
//! exemption is for, and the reason it is an exemption rather than a widening is
//! that the file **cannot run anything the mode did not admit**: its only way to
//! see a command is `Enforcement::admitted`, whose item type has a private
//! constructor and is produced by exactly one function, and the type a runner is
//! handed cannot be built without one. The seam itself is a trait, so every test
//! of that property is made with a value that has no process behind it — no test
//! in the file starts anything, which is why it is not also an entry in
//! [`THE_SPAWN_SITES`]: it builds no `Command`, and the runner it names is
//! `process::run`, which `request.rs` above already accounts for.
//!
//! **A product path reaches it, as of `P18-T007`, and this paragraph is the one
//! that moved.** `pipeline.rs` now builds a `PermissionPlan` from the mode and
//! the permissions the run was handed plus the commands the schedule holds, asks
//! `Enforcement::of` about every check, and passes the admitted ones to
//! `run_scheduled_checks`; so the runner is not a door with nothing behind it any
//! more, and *"no product path reaches it"* is a sentence this file may not say.
//! What the file says instead is what is still true, and it is the whole of what
//! holds the default run inert: **the plan admits nothing under `inspect_only`,
//! the default mode, and the mode a project file cannot move**, so the tests in
//! `pipeline.rs` and `planned_check_runner.rs` that record a runner being called
//! observe an empty list. That is a weaker claim than an absence, and the entry
//! is here so that a reader can see it weakened rather than find a paragraph that
//! still reads like the old one.
//!
//! **The ceiling is B since 2026-10-23, and the reason is the tracked reading
//! rather than a product path alone (ADR 0017).** `finished_declared_check.rs`
//! runs a real Rust project's declared `cargo test` through the CLI under
//! `host_confirmed`, asserts `pass`, and runs on all three CI legs. The platform
//! fact this paragraph used to weigh — a bare `npm` on Windows resolving to a
//! `npm.cmd` batch file — still holds at the resolver, and the product runner
//! answers it by starting the manager's own JavaScript entry
//! (`crate::package_launcher`). `planned_check_runner.rs` still not being in
//! [`THE_SPAWN_SITES`] is the one entry decision `P18-T007` did not change: it
//! builds no `Command`, and the runner it names is `process::run`, which
//! `request.rs` above already accounts for. The census is about which files may
//! *name* a request, not about the ceiling.
//!
//! **Three: nothing outside [`MAY_NAME_A_SUPERVISOR`] mentions `Supervisor`.**
//! This is the rule that carries the claim the second one used to carry. The
//! runner is no longer uncalled, so "nothing calls the runner" is now false and
//! would have been a rule that had to be deleted; what is still true is one
//! level up — **`service.rs` can start a process, and the one file that reaches
//! it is `runtime_start.rs`** — so the route out of the product is what this
//! rule is about, and it moved from "one file may name it" to "two files may,
//! and here is what each is for".
//!
//! **Four: nothing outside [`MAY_NAME_A_START_SMOKE`] mentions `StartSmoke`.**
//! This is rule three's own technique applied one level higher again, and for
//! rule three's own reason: `runtime_start.rs` can start **and stop** a service,
//! and the files that may name a `StartSmoke` are the files that decide *when* one
//! is started. The list is two files as of `P18-T009`. `runtime_start.rs` builds
//! one for a render line; `planned_check_runner.rs` builds one too, through
//! `StartSmoke::planned`, for a scheduled `CheckOperation::Service` — so **a
//! product path does construct a `StartSmoke`, and this is the moment the section
//! below was written to catch.** What the rule holds now is the part a name check
//! can hold, and it is the part rule three holds after its own moment came: the
//! list is the answer and a third file naming one is a decision somebody has to
//! write down. What is **not** the rule, and was never quite it, is the ceiling:
//! `sure_core::support`'s level is a claim about every platform SURE runs on, and
//! an absent caller was one argument for it rather than the whole of it — the
//! paragraph on `support::CEILING` is where that reason lives.
//!
//! All three `contains` rules have the same known hole and it is the same hole
//! rule one's matcher was fixed for once: a `use crate::service::Supervisor as
//! S;` would name the type without the word appearing. None of them forbids a
//! *program* from being started, which no source check can do — they forbid the
//! route being added quietly, which is what a reviewer can act on.
//!
//! # This test is meant to fail
//!
//! The moment it predicted has come twice, and the second one is the one it was
//! written for. A false green is more serious than a visible error, and this is
//! the error that would rather be visible.
//!
//! **Predicted**: the day anything wires a `StartSmoke` up to `sure check`, this
//! fails, and it should. **Two things have to move together at that moment**: a
//! product path exists, so this list and the paragraphs above it are wrong; and
//! `sure_core::support`'s ceiling is a claim about what SURE can run, so the
//! constant and `the_ceiling_todays_build_claims_is_generic` are the other half
//! of such a change.
//!
//! **The first failure, in `P18-T007`, was not this test.** The pipeline began
//! handing admitted commands to the runner — the first product path to reach it —
//! and this test passed both before and after, because the file that changed names
//! no type this census is about. What was wrong was the paragraph above, and a
//! paragraph is not a name a source check can see. So the rule this file earned is
//! the one written here for the next reader: **this file catches a new name, and a
//! claim that goes false without one is caught by a test that measures the path —
//! `pipeline.rs`'s `a_run_a_user_did_not_grant_starts_nothing` is the one that does
//! it for the default run — or it is not caught at all.**
//!
//! **The second failure is this test, in `P18-T009`**, and it failed exactly where
//! it said it would: `planned_check_runner.rs` began naming `StartSmoke`, and this
//! rule flagged the two lines (`use crate::runtime_start::{LimitsError, StartSmoke}`
//! and `StartSmoke::planned(`). The first of the two things above moved with it —
//! the list, this section and the failure message are `P18-T009`'s edit. The second
//! did not, and that is a decision rather than an omission: `support::CEILING`'s
//! reason was rewritten in `P18-T007` to the platform argument rather than the
//! absence of a caller, so *a caller exists now* is not evidence against it.
//! The ceiling moved to B on 2026-10-23 when the tracked three-platform CLI
//! reading existed (ADR 0017), not because a caller appeared; a reader who thinks
//! a product path alone should move the ceiling should read the paragraph beside
//! the ceiling before changing it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sure_core::scan::{ScanOptions, scan};

/// Every file in `crates/` that builds a command, and what it runs.
///
/// The path is the one the scan reports, which is relative to `crates/`. The
/// second half of each entry is what the file is for, so that a reader deleting
/// one has to say what they deleted.
const THE_SPAWN_SITES: &[(&str, &str)] = &[
    (
        "sure-core/src/fingerprint/git/mod.rs",
        "system Git, read-only, for the content fingerprint — the one on a product path",
    ),
    (
        "sure-core/src/process/request.rs",
        "the general runner: what `sure-core/src/service.rs` starts a service with, \
         and what `sure-core/src/planned_check_runner.rs` carries an admitted \
         project command to since `P18-T007`",
    ),
    (
        "sure-core/src/process/terminate.rs",
        "`taskkill`, to stop a process tree that did not stop",
    ),
    (
        "sure-core/src/browser_driver/launch.rs",
        "a browser this machine has, headless and sandboxed, for the page check — \
         reachable only from a `browser_driver::Browser`, which `P18-T010` binds \
         once, at the composition root `sure-cli/src/check.rs`",
    ),
    (
        "sure-testkit/src/source_manifest.rs",
        "system Git, read-only, over this repository's own index, so `SHA256SUMS.txt` \
         has a reader that can fail — a dev-only crate, which no ship path depends on",
    ),
];

/// The directory the runner lives in, which is the whole of what rule two
/// exempts.
const THE_RUNNER: &str = "sure-core/src/process/";

/// The files that may name a [`ProcessRequest`], which is the whole of what rule
/// two exempts.
///
/// Four entries. The runner builds requests; `service.rs` is the caller
/// `P3-T009` added; `analysis_provider/mod.rs` is the one `P12-T001` added for
/// the local-command analysis backend; `planned_check_runner.rs` is the one
/// `P18-T006` added, and it is the one the rule is *for* — it owns the
/// `CommandSpec`-to-request translation that `planned_work.rs` declined to hold,
/// and rule two's paragraph above is its argument. The rule is not "the runner is
/// the only place a request is named" — that was never the point — but "**a file
/// that names a request is a file that can run something, so every one of them is
/// named here and a new one is a decision**". The local-command provider runs a
/// command the user configured for analysis; the planned-check runner can run
/// only what `Enforcement::admitted` produced. The provider is still not reached
/// from a product path in this release; **the planned-check runner is, since
/// `P18-T007`**, and neither changes `support::CEILING` — the ceiling is B since
/// ADR 0017 on the tracked three-platform reading, not on a caller.
const MAY_NAME_A_PROCESS_REQUEST: &[&str] = &[
    THE_RUNNER,
    THE_SUPERVISOR,
    "sure-core/src/analysis_provider/mod.rs",
    THE_PLANNED_CHECK_RUNNER,
];

/// The two files that may name a [`Supervisor`], which is the whole of what rule
/// three exempts.
///
/// **`service.rs` builds one and `runtime_start.rs` uses one**, and the two are
/// here for the same reason with different arguments: the file that may build a
/// request is the file that may build the thing that builds one, and a file that
/// starts a service is a file that has decided *when* one should be started —
/// which is a decision `P5-T002` made and which is named here rather than left
/// to be discovered.
///
/// Split from [`MAY_NAME_A_PROCESS_REQUEST`] even though the first entry is the
/// same file, because they are two rules that today share an entry and the
/// failure messages differ. Rule four is the same technique one level up again,
/// and since `P18-T009` it is a list too: **the answer is the list, not an
/// absence.**
const MAY_NAME_A_SUPERVISOR: &[&str] = &[THE_SUPERVISOR, THE_START_SMOKE];

/// The two files that may name a [`StartSmoke`], which is the whole of what rule
/// four exempts.
///
/// **`runtime_start.rs` builds one and `planned_check_runner.rs` builds one**, and
/// the second entry is `P18-T009`'s, added deliberately and not because a test
/// asked for it. `StartSmoke::planned` is the second door into that module: the
/// first takes a probe's command and answers a render line, and the second takes a
/// scheduled [`ServiceCheckSpec`] and carries out a check the plan holds. Routing a
/// service check anywhere else would have been a second implementation of *start
/// it, wait for the window, ask the one question, stop it on every path* — the
/// verdict table this repository has already measured once, in
/// `tests/runtime_start.rs`, against real processes. So the file is here because
/// the alternative was a second answer to *did this service work*, not because the
/// route was convenient.
///
/// **What this entry does not do is move `support::CEILING`**, and a reader
/// arriving from the failure message needs that sentence: the ceiling moved to B
/// on 2026-10-23 on the tracked CLI reading (ADR 0017), not because a caller
/// exists. That a caller exists now is not evidence about where SURE has been
/// shown to run a project's own check.
///
/// Split from [`MAY_NAME_A_SUPERVISOR`] even though the first entry is the same
/// file, because they are two rules that today share an entry and the failure
/// messages differ.
const MAY_NAME_A_START_SMOKE: &[&str] = &[THE_START_SMOKE, THE_PLANNED_CHECK_RUNNER];

/// The file that may build a [`StartSmoke`] and start, question and stop a
/// service.
const THE_START_SMOKE: &str = "sure-core/src/runtime_start.rs";

/// The file that builds a [`Supervisor`] and admits what it starts.
const THE_SUPERVISOR: &str = "sure-core/src/service.rs";

/// The file that carries an admitted command to the process runner.
///
/// `P18-T006` added it, and rule two's paragraph above is why it may name a
/// [`ProcessRequest`]: it owns the translation `planned_work.rs` declined to
/// hold, and it takes its work from `Enforcement::admitted` rather than from the
/// plan.
const THE_PLANNED_CHECK_RUNNER: &str = "sure-core/src/planned_check_runner.rs";

/// Every **shipped** `.rs` file under `crates/`, with its text.
///
/// Narrowed to `src/`, because the rule is about code that ships. A test file
/// is *supposed* to start processes — that is what most of them are for, and
/// `process_runner.rs` and `fingerprint_git.rs` between them account for a
/// dozen — and a check that counted them would be a check nobody could satisfy.
/// The same narrowing, for the same reason, is in
/// `git_is_started_in_exactly_one_place`.
///
/// The product's own scanner does the walking, so "a file in this crate" means
/// the same thing here as it does everywhere else in the suite — and it is
/// asserted to have been complete, because a source check over an unknown subset
/// of the sources is the false green this test exists to prevent.
fn shipped_sources() -> Vec<(String, String)> {
    let crates = sure_testkit::repository_root().join("crates");
    let walked = scan(&crates, ScanOptions::default()).expect("crates/ is a directory");
    assert!(
        walked.is_complete(),
        "the source tree could not be read completely, so this test would be \
         checking an unknown subset of it"
    );

    let shipped: Vec<(String, String)> = walked
        .files()
        .filter(|entry| {
            entry
                .path
                .extension()
                .is_some_and(|extension| extension == "rs")
        })
        .map(|entry| {
            let path = crates.join(&entry.path);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            (entry.display_path(), text)
        })
        // Filtered on the reported path rather than on the filesystem one, so
        // that the string the assertions print and the string the rule is
        // stated against are the same string. Only `src` is tested for, without
        // a separator, because the separator is the platform's and this runs on
        // three of them.
        .filter(|(path, _)| path.contains("src"))
        .collect::<Vec<_>>();

    // The vacuity guard, in the helper so that both tests below get it. A walk
    // that found nothing would make every rule below true and every claim here
    // worthless — the "a test that passes because its premise did not hold is
    // worse than no test" rule this repository states about skipped cases,
    // applied to a check whose premise is a directory listing.
    assert!(
        shipped.len() > 10,
        "the source walk found {} shipped files, which is not this repository — \
         the filter is matching the wrong thing",
        shipped.len()
    );
    shipped
}

/// Whether a line is prose rather than code.
///
/// Doc comments are skipped rather than searched, because they are where the
/// rules themselves are written down and a check that forbade *mentioning* the
/// thing would make the rules impossible to explain. `doctor.rs` says
/// `Command::new("git")` in a paragraph about `CreateProcess` appending `.exe`,
/// and that paragraph is the reason this function exists.
fn is_prose(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

/// Whether a line of **code** builds a [`std::process::Command`].
///
/// The token boundary is the whole of the rule, and it is here because
/// `consent.rs`'s `PlannedCommand::new` is not a way to run anything while
/// `request.rs`'s `Command::new` is — and a substring search cannot tell them
/// apart, because the first contains the second. The character before `Command`
/// therefore has to be one that cannot be part of an identifier, which is true
/// of every spelling that really builds one (`Command::new(` after a `use`,
/// `std::process::Command::new(`, `process::Command::new(`) and false of every
/// type whose *name* merely ends in `Command`.
///
/// This was found by the check itself: `P3-T005` added a type called
/// `PlannedCommand` and this test failed on a file that cannot start a process
/// — it imports nothing from `std::process`, and
/// `nothing_outside_the_runner_names_a_process_request` passes on it. So the
/// census was matching a name rather than a spawn, and the honest fix is to
/// make the matcher mean what the rule says. The rule is unchanged and neither
/// of the two holes a tripwire like this can have — a bare alias such as
/// `use std::process::Command as C;` — is widened by it, because the old
/// substring search missed that spelling too.
fn builds_a_command(line: &str) -> bool {
    const PATTERN: &str = "Command::new(";
    let mut rest = line;
    while let Some(index) = rest.find(PATTERN) {
        let before = rest[..index].chars().next_back();
        if before.is_none_or(|character| !(character.is_alphanumeric() || character == '_')) {
            return true;
        }
        rest = &rest[index + PATTERN.len()..];
    }
    false
}

/// The files whose **code** builds a command, in scan order.
fn command_builders() -> Vec<String> {
    let mut found: Vec<String> = shipped_sources()
        .into_iter()
        .filter(|(_, text)| {
            text.lines()
                .any(|line| !is_prose(line) && builds_a_command(line))
        })
        .map(|(path, _)| path)
        .collect();
    found.sort();
    found
}

#[test]
fn the_matcher_tells_a_command_apart_from_a_type_whose_name_ends_in_command() {
    for line in [
        "let output = Command::new(&self.program)",
        "        let mut command = Command::new(\"taskkill\");",
        "std::process::Command::new(program)",
        "process::Command::new(program)",
        "\tCommand::new(\"git\")",
    ] {
        assert!(builds_a_command(line), "{line:?} builds a command");
    }
    for line in [
        "PlannedCommand::new(check, program, arguments, mode, permissions)",
        "let planned = PlannedCommand::new(",
        "my_Command::new(x)",
        "someCommand::new(x)",
    ] {
        assert!(
            !builds_a_command(line),
            "{line:?} does not build a std::process::Command"
        );
    }

    // A comment saying `Command::new` is not a spawn either, and this function
    // cannot tell — which is why the caller asks [`is_prose`] first. Stated as
    // the pair, so that a reader changing one of them sees the other.
    let commented = "// Command::new(\"git\") in a comment, not in code";
    assert!(builds_a_command(commented));
    assert!(is_prose(commented));
}

#[test]
fn every_place_sure_builds_a_command_is_named_here() {
    let mut expected: Vec<String> = THE_SPAWN_SITES
        .iter()
        .map(|(path, _)| (*path).to_owned())
        .collect();
    expected.sort();

    assert_eq!(
        command_builders(),
        expected,
        "the set of files that build a command has changed. Every one of them is \
         a way for SURE to run something, so the list above is the list of ways, \
         and a new one is a decision rather than an edit:\n  {}",
        THE_SPAWN_SITES
            .iter()
            .map(|(path, why)| format!("{path} — {why}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

/// Every line of **code** in a shipped file outside `exempt` that names `token`,
/// as `path:line: text`.
///
/// Shared by rules two and three because they are one check applied to two
/// names, and writing it twice is how the two would drift apart — a fix to the
/// prose filter reaching one of them and not the other is exactly the kind of
/// difference that makes one rule weaker than it reads.
///
/// The exemption is a path **prefix** match, so an entry ending in `/` exempts a
/// directory and an entry naming a file exempts that file. Nothing here checks
/// that an exemption is needed: an entry for a file that does not exist, or that
/// no longer names the token, would sit in the list looking like a decision.
/// That is what the third test below is for.
fn namers_of(token: &str, exempt: &[&str]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();

    for (path, text) in shipped_sources() {
        if exempt.iter().any(|allowed| path.starts_with(allowed)) {
            continue;
        }
        for (number, line) in text.lines().enumerate() {
            if is_prose(line) {
                continue;
            }
            if line.contains(token) {
                found.push(format!("{path}:{}: {}", number + 1, line.trim()));
            }
        }
    }

    found
}

#[test]
fn nothing_outside_the_named_files_names_a_process_request() {
    // `run` takes a `&ProcessRequest` and there is no other entry point, so a
    // file that cannot name the type cannot run anything through it. This is
    // what `process/mod.rs` said as "no product path calls `run` yet" until
    // `P3-T009` gave the runner a caller; the caller is on the list above, and
    // the claim that moved is rule three's. Since `P18-T007` one of those callers
    // is on a product path, which is the thing this rule was always about: the
    // list is the answer, not the absence.
    let callers = namers_of("ProcessRequest", MAY_NAME_A_PROCESS_REQUEST);

    assert!(
        callers.is_empty(),
        "a shipped file has begun naming `ProcessRequest`, so it can call the \
         runner. That is a real change and not a test to update: it means SURE \
         is able to execute code from a project. Either name it in \
         MAY_NAME_A_PROCESS_REQUEST and say why in the paragraph above, or take \
         the name back out — and if the new caller is on a product path, it is \
         `sure_core::support`'s paragraphs and this file's own that have to move: \
         the ceiling's reason is a claim about every platform SURE runs on, not \
         the absence of a caller. \
         Found:\n  {}",
        callers.join("\n  ")
    );
}

#[test]
fn nothing_outside_the_named_files_names_a_supervisor() {
    // The rule the second one used to be. A `Supervisor` is the only thing that
    // can start a service, and the files that may name one are the files that
    // can start one: so "nothing in the product starts a service" is this list,
    // one level above the runner rather than in the middle of it.
    let namers = namers_of("Supervisor", MAY_NAME_A_SUPERVISOR);

    assert!(
        namers.is_empty(),
        "a shipped file has begun naming `Supervisor`, so it can start a \
         service. That is a real change and not a test to update: it means SURE \
         is able to start a project's service. Either name it in \
         MAY_NAME_A_SUPERVISOR and say why in the paragraph above, or take the \
         name back out — and if the new caller is on a product path, it is \
         `sure_core::support`'s paragraphs and this file's own that have to move: \
         the ceiling's reason is a claim about every platform SURE runs on, not \
         the absence of a caller. \
         Found:\n  {}",
        namers.join("\n  ")
    );
}

#[test]
fn nothing_outside_the_start_smoke_names_a_start_smoke() {
    // The rule the third one used to be, one level higher up again. The file
    // that may name a `Supervisor` is the file that *can* start a service; the
    // files that may name a `StartSmoke` are the files that *decide when one
    // should be started*, and that decision is the one a product path reaches
    // before any project code runs. Two files may, since `P18-T009`, and the
    // paragraph on `MAY_NAME_A_START_SMOKE` is why the second one is there.
    let namers = namers_of("StartSmoke", MAY_NAME_A_START_SMOKE);

    assert!(
        namers.is_empty(),
        "a shipped file has begun naming `StartSmoke`, so it can start and stop \
         a service. That is a real change and not a test to update: it means a \
         new path through the product reaches a service start. Either name it in \
         MAY_NAME_A_START_SMOKE and say why in the paragraph above — the entries \
         there are decisions, and the two that exist are `runtime_start.rs`, \
         which builds one for a render line, and `planned_check_runner.rs`, \
         which builds one to carry out a scheduled service check — or take the \
         name back out. **Do not move `sure_core::support`'s ceiling because a \
         caller exists**: the reason beside it is the platform argument written \
         in `P18-T007`, and `P18-T012` owns the measurements that could change \
         it. \
         Found:\n  {}",
        namers.join("\n  ")
    );
}

#[test]
fn every_exemption_is_one_a_file_actually_needs() {
    // An exemption list rots in the direction nobody notices: a file gets
    // renamed, or the name it was exempted for is taken back out, and the entry
    // stays — exempting nothing, and reading to the next person as a decision
    // somebody made. This is the check that makes an entry mean something, and
    // it is the same shape as the census itself: the fact is not the list, it is
    // that the list cannot be wrong quietly.
    for (path, token) in [
        (THE_RUNNER, "ProcessRequest"),
        (THE_SUPERVISOR, "ProcessRequest"),
        ("sure-core/src/analysis_provider/mod.rs", "ProcessRequest"),
        (THE_PLANNED_CHECK_RUNNER, "ProcessRequest"),
        (THE_SUPERVISOR, "Supervisor"),
        (THE_START_SMOKE, "Supervisor"),
        (THE_START_SMOKE, "StartSmoke"),
        (THE_PLANNED_CHECK_RUNNER, "StartSmoke"),
    ] {
        // Asked as "would the rule have flagged this file if it were not
        // exempt?" — which is the only question that makes an exemption a
        // decision rather than a hole.
        let mut needed = false;
        for (seen, text) in shipped_sources() {
            if seen != path && !(path.ends_with('/') && seen.starts_with(path)) {
                continue;
            }
            if text
                .lines()
                .any(|line| !is_prose(line) && line.contains(token))
            {
                needed = true;
            }
        }
        assert!(
            needed,
            "{path} is exempt from the rule about `{token}` and no longer names \
             it, so the exemption is covering nothing. Either the file moved and \
             the entry did not, or the check is now the weaker for an entry \
             nobody would think to question."
        );
    }
}
