//! The promises `sure doctor` makes about itself, checked from outside the crate.
//!
//! `sure_core::doctor`'s module documentation makes four claims that its own
//! unit tests cannot hold it to, because each is about a boundary rather than
//! about a value:
//!
//! 1. it never reads the settings file;
//! 2. it never creates the store;
//! 3. it names this build by its number alone;
//! 4. it always says what it did not look at.
//!
//! The first is an *absence* — no run of the binary can demonstrate that a line
//! of code was never written — so it is checked against the source, the way
//! `cli_contract.rs` checks that only `output.rs` writes to a stream. The rest
//! are checked against what the public API returns, because a promise about the
//! shape of a report is only worth anything if the report a caller gets has that
//! shape.

// The workspace forbids `unwrap`, `expect` and `panic` in shipped code, because
// a panic is a message nobody chose. A test is the one place they are the point:
// the panic *is* the report, and it names the value that was wrong.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

use sure_core::config::AnalysisProvider;
use sure_core::container::{Availability, Runtime};
use sure_core::doctor::{self, Places, Presence, StoreState};
use sure_core::paths::{Origin, Paths};

/// A scratch directory under `target/tmp`, which is git-ignored and on the same
/// volume as the checkout, as the store tests use.
///
/// The name carries the process id, so no other process can compute this path.
/// The reason is the one `store_concurrency.rs` records in full, and one more
/// that is particular to this file: `the_report_never_creates_what_it_reports_on`
/// was seen to fail with `os error 3` on a directory it had just created, and the
/// only code in the repository that deletes that path is `scratch` itself. A path
/// another instance of this test cannot compute is a path another instance
/// cannot delete. **That mechanism was not confirmed** — the failure appears
/// roughly once in ten runs of the whole workspace and never once in twelve runs
/// of this binary alone — so this removes a shared resource rather than
/// repairing a proven fault, and it is recorded that way in `progress/HANDOFF.md`.
fn scratch(name: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("tmp")
        .join("doctor_contract")
        .join(format!("{name}-{}", std::process::id()));
    match fs::remove_dir_all(&root) {
        Ok(()) => {}
        // The ordinary case, and now the expected one.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!(
            "cannot clear {}: {error}. This process id was used before and its files \
             are still on disk, so this test could not tell them from the ones it \
             writes.",
            root.display()
        ),
    }
    fs::create_dir_all(&root).expect("a scratch directory");
    root
}

fn places_for(root: &Path) -> Paths {
    Paths::from_roots(root.join("data"), root.join("config")).expect("absolute roots")
}

/// The doctor module's source.
fn source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("doctor.rs");
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

#[test]
fn the_diagnostic_never_reaches_for_the_settings_module() {
    // `docs/architecture/DIAGNOSTICS.md`: a secret must never have to be handled
    // in order to be reported. The way to keep that true is for the diagnostic
    // never to open the file that may hold one, and the way to keep *that* true
    // is for the module not to name the reader that would.
    //
    // A source scan rather than a run, because what is being ruled out is an
    // absence. Prose about settings is fine and appears in the report itself —
    // `sure config show` is named as the command that reports them, with
    // provider values hidden — which is why the tokens are module paths and
    // constructors rather than the word.
    const REACHES: &[&str] = &[
        "crate::config",
        "config::Config",
        "Config::load",
        "LoadedConfig",
    ];

    let text = source();
    for token in REACHES {
        assert!(
            !text.contains(token),
            "src/doctor.rs names `{token}`. The diagnostic reports where the settings \
             file is and must not read it, so that no secret has to pass through a \
             command whose output is pasted into bug reports."
        );
    }
}

#[test]
fn the_diagnostic_names_the_files_the_store_actually_uses() {
    // The report tells a user which file to delete, and the store tells them
    // which file it writes. Those are two modules' idea of the same path, and
    // the failure mode of them disagreeing is a user deleting the wrong file
    // while their history stays on disk.
    let root = scratch("same_files");
    let paths = places_for(&root);
    let report = doctor::examine(Ok(paths.clone()));

    let Places::Known(locations) = &report.places else {
        panic!("the roots were given: {:?}", report.places);
    };
    assert_eq!(locations.store_file.path, paths.store_file());
    assert_eq!(locations.settings_file.path, paths.user_config_file());
    assert_eq!(locations.data_dir.path, paths.data_dir());
    assert_eq!(locations.config_dir.path, paths.config_dir());
    // And where it came from, which is the one thing a path alone cannot say.
    assert_eq!(locations.store_origin, Origin::Caller);
}

#[test]
fn a_store_the_caller_named_is_reported_as_theirs_rather_than_as_the_platforms() {
    // The report has to distinguish "you named this" from "this is the
    // platform's own", because those are the two things a caller who cannot see
    // the difference will debug in the wrong place. Nothing is created here: the
    // location is named and the report is about what is *at* it, which is
    // nothing.
    let root = scratch("named_store");
    let named = root.join("somewhere else with spaces");
    let report = doctor::examine_this_machine(Some(&named));

    let Places::Known(locations) = &report.places else {
        panic!("a location was named: {:?}", report.places);
    };
    assert_eq!(locations.store_file.path, named.join("sure.db"));
    assert_eq!(locations.data_dir.path, named);
    assert_eq!(locations.store_origin, Origin::Caller);
    assert!(
        !named.exists(),
        "sure doctor created the location it was asked about"
    );

    // Not silently replaced by the platform's own location, and not silently
    // reported as if the caller had said nothing.
    let platform = Paths::discover().expect("this machine reports per-user locations");
    assert_ne!(locations.store_file.path, platform.store_file());

    // The install path is the *platform's per-user location*, and the store the
    // caller named did not move it. `P15-T001`: "reports per-user data/install
    // paths clearly" is about a machine, and a diagnostic that let `--store-dir`
    // move the installation would tell a user their installation is in a
    // directory they named for a redirect.
    //
    // Mutation, run rather than described: in `locations()` of
    // `crates/sure-core/src/doctor.rs`, replace
    //
    //   install_file: per_user_install(),
    //
    // with the install path derived from the store the caller named:
    //
    //   install_file: Some(Place {
    //       path: paths.data_dir().join("bin").join("sure.exe"),
    //       presence: Presence::Absent,
    //   }),
    //
    // The two assertions below then fail on the named path, and the run is
    // reported in this task's hand-back with what else it reddened.
    #[cfg(windows)]
    {
        let install = locations
            .install_file
            .as_ref()
            .expect("a Windows build has a per-user install location");
        assert!(
            install
                .path
                .ends_with(Path::new("SURE").join("bin").join("sure.exe")),
            "the per-user install path is not the one the launchers look for: {}",
            install.path.display()
        );
        assert!(
            !install.path.starts_with(&named),
            "the store the caller named moved the installation to {}: a redirect was reported \
             as an installation",
            install.path.display()
        );
    }
    // No such convention where the platform has none, and `None` is an answer
    // rather than a path this build guessed at.
    #[cfg(not(windows))]
    assert!(
        locations.install_file.is_none(),
        "a per-user install path was invented for a platform that has no such convention: {:?}",
        locations.install_file
    );
}

#[test]
fn the_report_never_creates_what_it_reports_on() {
    // The promise that makes the command safe to run on a machine somebody is
    // trying to diagnose: it leaves the machine as it found it. Checked from
    // outside the crate, on a root that is given rather than discovered, so that
    // the assertion is about this code rather than about this machine.
    let root = scratch("untouched");
    let paths = places_for(&root);
    let before = listing(&root);

    let report = doctor::examine(Ok(paths.clone()));

    assert_eq!(report.store, StoreState::NotCreated);
    assert!(report.is_well(), "{:#?}", report.problems);
    assert!(
        !paths.store_file().exists(),
        "sure doctor created {}",
        paths.store_file().display()
    );
    assert_eq!(
        listing(&root),
        before,
        "sure doctor changed the directories it was asked about"
    );
}

/// Everything under a directory, as paths relative to it, sorted.
fn listing(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
        for entry in entries {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                pending.push(path.clone());
            }
            found.push(
                path.strip_prefix(root)
                    .expect("under the root")
                    .to_path_buf(),
            );
        }
    }
    found.sort();
    found
}

#[test]
fn the_report_names_this_build_by_its_number_alone() {
    // Every renderer of this report prints the product's name itself. A `version`
    // holding the name as well is how the human form first read
    // `SURE SURE 0.0.0-bootstrap`, and the check that it cannot come back is
    // that the number does not contain the name.
    // A store this test names rather than the one this machine uses. The facts
    // asserted below are about the build, not about the installation, so
    // reading the machine's own store would only put this test's result at the
    // mercy of whatever is in it.
    let report = doctor::examine_this_machine(Some(&scratch("build_name").join("data")));

    assert_eq!(report.build.version, sure_core::VERSION);
    assert!(
        !report.build.version.contains(sure_core::NAME),
        "the version in the report is \"{}\", which repeats the product name every \
         renderer already prints",
        report.build.version
    );
    assert_eq!(report.build.protocol_version, sure_core::PROTOCOL_VERSION);
    assert_eq!(report.build.os, std::env::consts::OS);
    assert_eq!(report.build.arch, std::env::consts::ARCH);
}

/// One directory holding a runnable file named after each program, as a search
/// path of exactly that directory.
///
/// `OsString` rather than `PathBuf`, because a search path is the value
/// `examine_in` takes and a directory is not.
fn search_path_holding(directory: &Path, names: &[&str]) -> OsString {
    fs::create_dir_all(directory).expect("a directory");
    for name in names {
        let path = directory.join(format!("{name}{EXECUTABLE_SUFFIX}"));
        fs::write(&path, b"#!/bin/sh\n").expect("a file");
        // On a Unix-like platform a file with no execute bit is not a program
        // the search will accept, so the bit is part of writing it there.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&path).expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("an execute bit");
        }
    }
    std::env::join_paths([directory]).expect("a search path with one entry in it")
}

/// The suffix a program is stored under on this platform — the same rule
/// `crate::doctor` searches with, restated here because this test writes the
/// file the search is supposed to find.
#[cfg(windows)]
const EXECUTABLE_SUFFIX: &str = ".exe";
/// See above: on a Unix-like platform the name is the file name.
#[cfg(not(windows))]
const EXECUTABLE_SUFFIX: &str = "";

#[test]
fn every_program_the_report_names_is_looked_for_on_the_search_path_it_was_given() {
    // Two runs on this machine in this process, the search path the only thing
    // that differs — the shape `fixtures/adversarial/container-unavailable`'s
    // control uses for the same reason. A test that only ever searched this
    // machine's own `PATH` would be a test of the machine: it could pass on a
    // developer's laptop and fail in a container, and neither result would be
    // about this code.
    //
    // The names are read **out of the report** rather than written here, so a
    // program added to any of the four lists is exercised without this test
    // being edited. A list that stopped being searched shows up as a `found_at`
    // that is null in the second half, where a directory holding that program
    // was handed in.
    //
    // Mutation, run rather than described: in `examine_in` of
    // `crates/sure-core/src/doctor.rs`, replace the two searches that read the
    // argument —
    //
    //   found_at: find_in(search_path, name),
    //
    // in the `TOOLS` and `TOOLCHAIN` loops, and
    //
    //   container: Availability::in_path(search_path),
    //
    // — with `find_in(OsStr::new(""), name)` and
    // `Availability::in_path(OsStr::new(""))`. The function's argument stops
    // being used and every `found_at` below stays null in the populated half.
    // The run is reported in this task's hand-back with what else it reddened.
    let root = scratch("search_path");
    let paths = places_for(&root);
    let nothing_to_find = OsStr::new("");

    let none = doctor::examine_in(Ok(paths.clone()), nothing_to_find);

    assert!(!none.tools.is_empty(), "the report names no tools at all");
    assert!(
        !none.toolchain.is_empty(),
        "the report names no toolchain programs at all"
    );
    assert!(
        !none.providers.is_empty(),
        "the report offers no analysis providers at all"
    );
    assert!(
        none.providers.iter().any(|it| it.program.is_some()),
        "no provider in the list names a program, so the half of this check that is about a \
         provider's program cannot fail: {:#?}",
        none.providers
    );
    for tool in &none.tools {
        assert_eq!(
            tool.found_at, None,
            "{} was found at {:?} on a search path with no entries in it",
            tool.name, tool.found_at
        );
    }
    for compiler in &none.toolchain {
        assert_eq!(
            compiler.found_at, None,
            "{} was found at {:?} on a search path with no entries in it",
            compiler.name, compiler.found_at
        );
    }
    for provider in &none.providers {
        assert_eq!(
            provider.found_at, None,
            "the program for {} was found at {:?} on a search path with no entries in it",
            provider.name, provider.found_at
        );
    }
    assert_eq!(
        none.container,
        Availability::Absent,
        "a search path with no entries in it found a container runtime"
    );

    // Every program any list names, in one directory, so one call produces the
    // found answer for all of them.
    let where_ = root.join("bin");
    let mut names: Vec<&str> = none.tools.iter().map(|tool| tool.name).collect();
    names.extend(none.toolchain.iter().map(|compiler| compiler.name));
    names.extend(
        none.providers
            .iter()
            .filter_map(|provider| provider.program),
    );
    names.extend(Runtime::ALL.iter().map(|runtime| runtime.program()));
    let populated = search_path_holding(&where_, &names);

    let found = doctor::examine_in(Ok(paths), &populated);

    // Only the program answers moved: the same locations, the same build, on
    // the same machine, in the same process. This is what makes the difference
    // between the two halves the search path rather than a second variable.
    assert_eq!(none.places, found.places, "{:#?}", found.places);
    assert_eq!(none.build, found.build, "{:#?}", found.build);
    assert_eq!(none.store, found.store, "{:#?}", found.store);

    for tool in &found.tools {
        let expected = where_.join(format!("{}{EXECUTABLE_SUFFIX}", tool.name));
        assert_eq!(
            tool.found_at.as_deref(),
            Some(expected.as_path()),
            "{} was not found where it was written, so the answer is not read off the search path \
             it was given",
            tool.name
        );
    }
    for compiler in &found.toolchain {
        let expected = where_.join(format!("{}{EXECUTABLE_SUFFIX}", compiler.name));
        assert_eq!(
            compiler.found_at.as_deref(),
            Some(expected.as_path()),
            "{} was not found where it was written",
            compiler.name
        );
    }
    for provider in &found.providers {
        match provider.program {
            Some(program) => {
                let expected = where_.join(format!("{program}{EXECUTABLE_SUFFIX}"));
                assert_eq!(
                    provider.found_at.as_deref(),
                    Some(expected.as_path()),
                    "the program for {} was not found where it was written",
                    provider.name
                );
            }
            None => assert_eq!(
                provider.found_at, None,
                "{} runs no program, and a path was reported for it anyway",
                provider.name
            ),
        }
    }
    let first = Runtime::ALL[0];
    assert_eq!(
        found.container,
        Availability::Found {
            runtime: first,
            program: where_.join(format!("{}{EXECUTABLE_SUFFIX}", first.program())),
        },
        "the container answer is not the runtime that was written into the search path"
    );
    // The other half of the same claim: with only the second runtime present,
    // the reported one is that runtime. Without this, an answer that always
    // named the first of `Runtime::ALL` would pass everything above.
    let only_second = Runtime::ALL[1];
    let just_it = search_path_holding(&root.join("only it"), &[only_second.program()]);
    assert_eq!(
        doctor::examine_in(Ok(places_for(&root)), &just_it).container,
        Availability::Found {
            runtime: only_second,
            program: root
                .join("only it")
                .join(format!("{}{EXECUTABLE_SUFFIX}", only_second.program())),
        }
    );
}

#[test]
fn the_providers_this_build_offers_are_the_ones_a_settings_file_takes() {
    // The names are written as strings in `crates/sure-core/src/doctor.rs`
    // because that module may not name the configuration module at all — the
    // scan in this file fails the build if it does — and a copy that can drift
    // from the vocabulary it claims to spell is exactly what a check like this
    // is for. This test may import the type, so the two lists are held to each
    // other here rather than by care.
    //
    // Mutation, run rather than described: in `PROVIDERS` of
    // `crates/sure-core/src/doctor.rs`, rename `"claude_cli"` to `"claude-cli"`.
    // The list comparison below fails with the two lists printed. The run is
    // reported in this task's hand-back with what else it reddened.
    let report = doctor::examine_in(
        Ok(places_for(&scratch("providers"))),
        OsStr::new("nothing on this search path"),
    );

    let offered: Vec<&str> = report.providers.iter().map(|it| it.name).collect();
    let spelled: Vec<&str> = AnalysisProvider::ALL.iter().map(|it| it.as_str()).collect();
    assert_eq!(
        offered, spelled,
        "the providers this build lists and the providers a settings file may name are not the \
         same list, and a user told about a provider they cannot configure has been told \
         something false"
    );

    assert!(!report.providers.is_empty());
    for provider in &report.providers {
        assert!(
            !provider.needs.is_empty(),
            "{} is offered with no statement of what it needs",
            provider.name
        );
        assert!(
            provider.found_at.is_none() || provider.program.is_some(),
            "{} was reported at {:?} and runs no program, so a path came from nowhere",
            provider.name,
            provider.found_at
        );
    }
}

#[test]
fn the_report_always_says_what_it_did_not_look_at() {
    // `docs/product/UX_AND_LANGUAGE.md`: a report that does not state its
    // boundary invites the reader to assume it covered everything. An empty list
    // would read as "nothing was skipped", which is never true of a program that
    // has no process runner.
    // Named for the same reason as above: this is a claim about the list of
    // things SURE says it did not look at, and it must not depend on — or reach
    // — the store on the machine running the suite.
    let report = doctor::examine_this_machine(Some(&scratch("not_checked").join("data")));

    assert!(
        !report.not_checked.is_empty(),
        "the report claims to have covered everything"
    );
    for entry in &report.not_checked {
        assert!(
            !entry.what.is_empty() && !entry.why.is_empty(),
            "{entry:#?}"
        );
        assert!(
            entry.why.ends_with('.'),
            "the reason is not a sentence: {:?}",
            entry.why
        );
    }
    for tool in &report.tools {
        assert!(
            !tool.needed_for.is_empty(),
            "{} is listed with no reason it is called",
            tool.name
        );
    }
}

#[test]
fn a_report_with_no_problems_is_well_and_one_with_a_problem_is_not() {
    // `is_well` is the single predicate the exit status and the frame's `outcome`
    // both come from, so it has to be exactly "nothing was found wrong" rather
    // than a second opinion about the report's contents. Both states are reached
    // here on a root this test owns, rather than on whatever the machine running
    // it happens to hold.
    let fresh = doctor::examine(Ok(places_for(&scratch("well"))));
    assert!(fresh.is_well(), "{:#?}", fresh.problems);
    assert!(fresh.problems.is_empty());

    // A store that is not a store. The file is where the store would be and its
    // contents are not a database, which is the one thing a user can do to this
    // installation by hand.
    let root = scratch("damaged");
    let paths = places_for(&root);
    fs::create_dir_all(root.join("data")).expect("the data directory");
    fs::write(paths.store_file(), b"this is not a database\n").expect("a damaged store");

    let damaged = doctor::examine(Ok(paths.clone()));
    assert_eq!(damaged.is_well(), damaged.problems.is_empty());
    assert!(
        !damaged.is_well(),
        "a file that is not a database was reported as a healthy installation"
    );
    assert!(matches!(damaged.store, StoreState::Unreadable { .. }));
    let Places::Known(locations) = &damaged.places else {
        panic!("the roots were given");
    };
    assert_eq!(locations.store_file.presence, Presence::Present);
    // And the repair is the user's: the diagnostic says what it found rather
    // than deleting or rebuilding the file it could not read.
    assert_eq!(
        fs::read(paths.store_file()).expect("the file is still there"),
        b"this is not a database\n"
    );
    let names_the_store = damaged
        .problems
        .iter()
        .any(|problem| problem.what.contains("recorded history"));
    assert!(
        names_the_store,
        "the problem does not say what it is about: {:#?}",
        damaged.problems
    );
}
