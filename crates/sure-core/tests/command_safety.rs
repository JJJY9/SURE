//! `P3-T004` acceptance: *"Static/read-only, dynamic host, install, network,
//! destructive categories are distinct."*
//!
//! "Distinct" is the whole of the acceptance sentence, and distinctness is a
//! property of *pairs* — so the test below is a matrix rather than five
//! assertions. For every ordered pair of categories there is a command line that
//! carries the first and not the second, which is what makes the five of them
//! five rather than one ladder with five names.
//!
//! The matrix is written against **single-class witnesses**: one command per
//! category that falls into that category and no other. That is the stronger
//! form of the same statement — if every category has a command that carries it
//! alone, then no two categories can be a relabelling of one another — and it is
//! also the form that fails loudly when a category is added to
//! `CommandClass::ALL` without a command that reaches it.
//!
//! The second half of the file is the other direction: the categories are only
//! worth having if the commands SURE does not understand are kept out of them.
//! `Static` is the one every mistake would land on, so the tests below name
//! every way a command can escape this table's knowledge and check that none of
//! them reads as read-only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sure_core::safety::{Source, classify};
use sure_domain::execution::{CommandClass, CommandEffects};

/// One command per category that carries that category and no other.
///
/// Every entry is a real command line rather than a shape: `cargo add serde
/// --offline` is single-class only because `--offline` takes away the network
/// the install would otherwise reach, and that is a fact about the two flag
/// rules rather than about the row.
const WITNESSES: &[(CommandClass, &str, &[&str])] = &[
    (CommandClass::Static, "git", &["status"]),
    (CommandClass::DynamicHost, "npm", &["test"]),
    (
        CommandClass::Install,
        "cargo",
        &["add", "serde", "--offline"],
    ),
    (CommandClass::Network, "git", &["fetch"]),
    (CommandClass::Destructive, "git", &["reset", "--hard"]),
];

/// A command line that no rule in the table can narrow, and why SURE says so.
const UNREADABLE: &[(&str, &[&str], Source)] = &[
    // A program no rule knows.
    ("esbuild", &["--bundle"], Source::UnknownProgram),
    ("docker", &["compose", "up"], Source::UnknownProgram),
    // A program a rule knows, and an operation it does not.
    ("cargo", &["clean"], Source::UnknownOperation),
    ("git", &["commit", "-m", "x"], Source::UnknownOperation),
    (
        "git",
        &["branch", "-m", "old", "new"],
        Source::UnknownOperation,
    ),
    ("npm", &["audit", "fix"], Source::UnknownOperation),
    // A wrapper, which is an argument grammar this table does not implement.
    ("env", &["npm", "test"], Source::UnknownProgram),
    ("timeout", &["30", "cargo", "test"], Source::UnknownProgram),
    ("sudo", &["rm", "-rf", "/"], Source::UnknownProgram),
    ("xargs", &["rm"], Source::UnknownProgram),
];

#[test]
fn every_category_has_a_command_that_carries_it_alone() {
    for (class, program, arguments) in WITNESSES {
        let effects = classify(*program, *arguments).effects().clone();
        assert_eq!(
            effects,
            CommandEffects::single(*class),
            "{program} {arguments:?} was meant to witness {class:?} alone and carried {effects}"
        );
    }
    assert_eq!(
        WITNESSES.len(),
        CommandClass::ALL.len(),
        "a category was added and has no command that reaches it"
    );
}

#[test]
fn every_ordered_pair_of_categories_can_be_told_apart() {
    // The acceptance sentence, run: for every ordered pair there is a command
    // that carries the first and not the second, so no two of the five are the
    // same category under two names.
    for (left, left_program, left_arguments) in WITNESSES {
        for (right, _, _) in WITNESSES {
            if left == right {
                continue;
            }
            let effects = classify(*left_program, *left_arguments);
            assert!(
                effects.effects().contains(*left),
                "{left_program} {left_arguments:?} does not carry {left:?}"
            );
            assert!(
                !effects.effects().contains(*right),
                "{left_program} {left_arguments:?} carries {right:?} as well as {left:?}, \
                 so the two categories cannot be told apart by this command"
            );
            assert_ne!(left.as_str(), right.as_str());
            assert_ne!(left.required_permission(), right.required_permission());
        }
    }
}

#[test]
fn a_command_can_be_in_two_categories_at_once() {
    // The categories are independent rather than rungs, and an answer that had
    // to be one value would have to drop one of these two facts.
    let effects = classify("cargo", ["add", "serde"]).effects().clone();
    assert!(effects.contains(CommandClass::Install));
    assert!(effects.contains(CommandClass::Network));
    assert_eq!(effects.to_string(), "install, network");
}

#[test]
fn nothing_sure_could_not_read_is_ever_static() {
    for (program, arguments, expected) in UNREADABLE {
        let classification = classify(*program, *arguments);
        assert_eq!(
            classification.source(),
            *expected,
            "{program} {arguments:?} was not reported as {expected:?}"
        );
        assert!(
            !classification.is_static_only(),
            "{program} {arguments:?} read as read-only"
        );
        assert_eq!(
            classification.effects(),
            &CommandEffects::anything(),
            "{program} {arguments:?} was narrowed although its source says it could not be read"
        );
    }
}

#[test]
fn the_three_sources_that_cannot_narrow_carry_every_category_but_static() {
    // The two halves of the same fact: the source says why, and the effects are
    // the same set three times. A caller that read only the effects would still
    // be safe; a caller that read only the source would not.
    let anything = CommandEffects::anything();
    assert!(!anything.contains(CommandClass::Static));
    for (_, _, source) in UNREADABLE {
        let classification = match source {
            Source::UnknownProgram => classify("an-unknown-program", Vec::<String>::new()),
            Source::UnknownOperation => classify("cargo", ["an-unknown-operation"]),
            Source::UnreadText(_) => classify("sh", ["-c", "anything at all"]),
            Source::Rule { .. } => continue,
        };
        assert_eq!(classification.source(), *source);
        assert_eq!(classification.effects(), &anything);
    }
}

#[test]
fn a_batch_file_name_is_never_read_as_the_program_behind_it() {
    // `npm.cmd` on a Windows `PATH` is a batch file that forwards to a
    // JavaScript file, and reading the name would be comfortable and would be
    // reading a name rather than a behaviour. The name is answered by naming it
    // — including when the file it forwards to is one this table has a row for.
    for name in [
        "npm.cmd",
        "build.bat",
        "C:\\tools\\nodejs\\npm.cmd",
        "NPM.CMD",
        "thing.Bat",
    ] {
        let classification = classify(name, ["install"]);
        assert!(
            matches!(classification.source(), Source::UnreadText(_)),
            "{name} was not read as unread text"
        );
        assert!(!classification.is_static_only(), "{name} read as read-only");
    }
}

#[test]
fn an_interpreter_handed_text_is_never_read_as_its_own_program() {
    // The command SURE assembled is replaced, before it runs, by text that is
    // not on it. Every one of these has a row in the table, and every one of
    // them is a different thing when it is handed text.
    let unread: &[(&str, &[&str])] = &[
        ("sh", &["-c", "npm install"]),
        ("bash", &["-c", "rm -rf /"]),
        ("cmd", &["/c", "del /f /s /q C:\\"]),
        ("powershell", &["-Command", "Remove-Item -Recurse -Force ."]),
        ("pwsh", &["-c", "npm install"]),
        ("node", &["-e", "require('fs').rmSync('/')"]),
        ("node", &["--eval", "1"]),
        ("python", &["-c", "import shutil"]),
        ("python3", &["-c", "import shutil"]),
    ];
    for (program, arguments) in unread {
        let classification = classify(*program, *arguments);
        assert!(
            matches!(classification.source(), Source::UnreadText(_)),
            "{program} {arguments:?} was read as {source:?}",
            source = classification.source()
        );
        assert_eq!(classification.effects(), &CommandEffects::anything());
    }

    // The other half, and the reason the reading is positional rather than a
    // search of the whole line: a `-c` after the script belongs to the script.
    let script = classify("python", ["script.py", "-c", "something"]);
    assert_eq!(
        script.effects(),
        &CommandEffects::of(&[CommandClass::DynamicHost])
    );
}

#[test]
fn a_shell_given_a_file_runs_the_file_and_not_text_of_sures_choosing() {
    // `sh script.sh` and `sh -c "text"` are not the same command: the first
    // runs the project's own code, which is what the project's code is, and the
    // second runs text nobody read.
    for (program, arguments) in [
        ("sh", &["script.sh"][..]),
        ("bash", &["scripts/build.sh", "--release"]),
        ("dash", &["./configure"]),
    ] {
        let classification = classify(program, arguments);
        assert_eq!(
            classification.effects(),
            &CommandEffects::of(&[CommandClass::DynamicHost]),
            "{program} {arguments:?}"
        );
        assert!(matches!(classification.source(), Source::Rule { .. }));
    }
}

#[test]
fn a_program_with_nothing_to_run_reads_its_program_from_somewhere_else() {
    // `python` with no arguments is a prompt, and what it runs arrives on
    // standard input — which is not the command line, and is not something this
    // module read. The same is true of every interpreter here.
    for program in [
        "python",
        "python3",
        "node",
        "sh",
        "bash",
        "cmd",
        "powershell",
    ] {
        let classification = classify(program, Vec::<String>::new());
        assert!(
            matches!(classification.source(), Source::UnreadText(_)),
            "{program} with no arguments was read as {source:?}",
            source = classification.source()
        );
    }
}

#[test]
fn the_commands_sures_own_discovery_names_are_all_classified() {
    // The table's reason to exist. Every one of these is a command SURE's
    // discovery builds today, and a row that stops covering one of them should
    // fail here rather than at the moment the runner is wired up.
    let planned: &[(&str, &[&str])] = &[
        ("cargo", &["test"]),
        ("cargo", &["build"]),
        ("npm", &["test"]),
        ("npm", &["run", "build"]),
        ("python", &["-m", "pytest"]),
        ("python", &["-m", "ruff", "check", "."]),
        ("python", &["-m", "mypy", "."]),
        (
            "python",
            &["-m", "pip", "install", "-r", "requirements.txt"],
        ),
        ("uv", &["run", "pytest"]),
        ("uv", &["run", "ruff", "check", "."]),
        ("uv", &["run", "mypy", "."]),
        ("uv", &["sync"]),
        ("poetry", &["run", "pytest"]),
        ("pytest", &[]),
        ("pytest", &["tests/"]),
    ];
    for (program, arguments) in planned {
        let classification = classify(*program, *arguments);
        assert!(
            matches!(classification.source(), Source::Rule { .. }),
            "{program} {arguments:?} is a command SURE builds and the table does not know it: {source:?}",
            source = classification.source()
        );
        assert!(
            !classification.is_static_only(),
            "{program} {arguments:?} runs the project's own code and read as read-only"
        );
        assert!(
            classification.effects().contains(CommandClass::DynamicHost),
            "{program} {arguments:?} does not carry the category for running the project's code"
        );
    }

    // `python -m pip install` is the wording SURE uses for a Python install, so
    // it must carry the install category and not merely the one for code.
    let install = classify("python", ["-m", "pip", "install", "-r", "requirements.txt"]);
    assert!(install.effects().contains(CommandClass::Install));
    assert!(install.effects().contains(CommandClass::Network));

    // A module nobody wrote a row for is not read as anything in particular.
    assert_eq!(
        classify("python", ["-m", "shutil"]).source(),
        Source::UnknownOperation
    );
}

#[test]
fn a_dry_run_takes_away_what_changes_this_machine_and_leaves_what_looks() {
    // The install goes and the network stays, because a dry run still looks.
    let online = classify("npm", ["install"]);
    let dry = classify("npm", ["install", "--dry-run"]);
    assert!(online.effects().contains(CommandClass::Install));
    assert!(dry.effects().contains(CommandClass::Network));
    assert!(!dry.effects().contains(CommandClass::Install));

    // A command whose one category was the one taken away is the report the
    // flag makes it, and not an empty set.
    let clean = classify("git", ["clean", "--dry-run"]);
    assert_eq!(clean.effects(), &CommandEffects::static_only());
    assert!(clean.is_static_only());
    assert_eq!(classify("git", ["clean", "-n"]).effects(), clean.effects());
    assert_eq!(
        classify("git", ["clean"]).effects(),
        &CommandEffects::of(&[CommandClass::Destructive])
    );

    // `-n` is a number elsewhere on the same command line, which is why it is
    // read per operation rather than everywhere.
    assert_eq!(
        classify("git", ["log", "-n", "5"]).effects(),
        &CommandEffects::static_only()
    );
}

#[test]
fn an_offline_flag_takes_the_network_away_and_nothing_else() {
    let offline = classify("cargo", ["test", "--offline"]);
    assert_eq!(
        offline.effects(),
        &CommandEffects::of(&[CommandClass::DynamicHost])
    );
    assert!(
        classify("cargo", ["test"])
            .effects()
            .contains(CommandClass::Network)
    );

    // Only the spelling whose meaning does not depend on the tool. `--frozen`
    // means "do not update the lockfile" to npm and "do not touch the network"
    // to cargo, and a rule that picked one would be reading two grammars as one.
    assert!(
        classify("cargo", ["test", "--frozen"])
            .effects()
            .contains(CommandClass::Network)
    );
}

#[test]
fn a_destructive_command_has_no_permission_that_covers_it() {
    // `Destructive` is the one category whose `required_permission` is `None`,
    // and the classifier reports that rather than folding it into the nearest
    // permission. A user who granted consent to write inside the project has not
    // granted consent to delete outside it.
    for (program, arguments) in [
        ("git", &["reset", "--hard"][..]),
        ("git", &["clean"]),
        ("rm", &["-rf", "/"]),
        ("git", &["push", "--force"]),
        ("npm", &["unpublish", "thing"]),
    ] {
        let classification = classify(program, arguments);
        assert_eq!(
            classification.ungrantable(),
            Some(CommandClass::Destructive),
            "{program} {arguments:?} did not report a category nobody can grant"
        );
    }

    // And a command that is merely an install has something to ask for.
    assert_eq!(classify("npm", ["install"]).ungrantable(), None);
}

#[test]
fn a_name_is_read_the_way_the_operating_system_resolves_it() {
    // The last path component, on either separator, because that is the part
    // the operating system looks for on `PATH`.
    for name in [
        "/usr/bin/git",
        "C:\\Program Files\\Git\\cmd\\git",
        "C:/Program Files/Git/cmd/git",
        "./git",
        "../bin/git",
    ] {
        assert_eq!(
            classify(name, ["status"]).effects(),
            &CommandEffects::static_only(),
            "{name} was not read as git"
        );
    }

    // A directory named like a program is not a program: the component after
    // the last separator is the whole of what is looked up.
    assert_eq!(
        classify("/opt/git/status", Vec::<String>::new()).source(),
        Source::UnknownProgram
    );
}

#[test]
fn windows_elides_an_exe_suffix_and_ignores_case_and_unix_does_neither() {
    // Both of these are the operating system's own rule, so the classifier
    // follows it on the platform it is true of and not on the other. `cfg!` and
    // not `#[cfg]`: both arms compile everywhere, so the difference is a value
    // this test reads rather than a branch that disappears on one platform and
    // takes its test with it.
    let exe = classify("node.exe", ["script.js"]);
    let plain = classify("node", ["script.js"]);
    let upper = classify("GIT", ["status"]);

    if cfg!(windows) {
        assert_eq!(
            exe.effects(),
            plain.effects(),
            "node.exe is node on Windows"
        );
        assert!(
            upper.is_static_only(),
            "GIT is git on a filesystem that does not distinguish them"
        );
    } else {
        assert_eq!(
            exe.source(),
            Source::UnknownProgram,
            "node.exe is not node on a platform that does not elide .exe"
        );
        assert_eq!(
            upper.source(),
            Source::UnknownProgram,
            "lowercasing on Unix would classify a program SURE never looked at"
        );
    }

    // On both platforms a name with a `.exe`-shaped argument is unaffected, and
    // a name that is only a suffix has nothing to look up.
    assert_eq!(
        classify(".exe", Vec::<String>::new()).source(),
        Source::UnknownProgram
    );
    assert_eq!(
        classify("", Vec::<String>::new()).source(),
        Source::UnknownProgram
    );
}

#[test]
fn an_argument_sure_cannot_read_makes_the_whole_command_unreadable() {
    // Dropping the token would be the quiet failure: `git <bytes> status` has an
    // unknown operation in it, and a classifier that discarded the token would
    // read the `status` behind it and answer that git only reads.
    #[cfg(windows)]
    let unreadable: std::ffi::OsString = {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&[0xD800])
    };
    #[cfg(not(windows))]
    let unreadable: std::ffi::OsString = {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(vec![0xFF, 0xFE])
    };

    let classification = classify("git", [unreadable, "status".into()]);
    assert!(matches!(classification.source(), Source::UnreadText(_)));
    assert_eq!(classification.effects(), &CommandEffects::anything());

    // The program name too, and there the answer is a different one: a name
    // that is not text is not a name in the table.
    let program = classify(
        {
            #[cfg(windows)]
            {
                use std::os::windows::ffi::OsStringExt;
                std::ffi::OsString::from_wide(&[0xD800])
            }
            #[cfg(not(windows))]
            {
                use std::os::unix::ffi::OsStringExt;
                std::ffi::OsString::from_vec(vec![0xFF, 0xFE])
            }
        },
        ["status"],
    );
    assert_eq!(program.source(), Source::UnknownProgram);
}

#[test]
fn the_source_never_claims_a_rule_for_a_command_no_rule_matched() {
    // The invariant that ties the two halves of the answer together, checked
    // over a wide sample: a `Rule` source always means a table row answered,
    // and every other source means nothing was narrowed.
    let sample: &[(&str, &[&str])] = &[
        ("git", &["status"]),
        ("git", &["commit"]),
        ("git", &["branch"]),
        ("cargo", &["test"]),
        ("cargo", &["frobnicate"]),
        ("npm", &["run", "build"]),
        ("python", &["-m", "pytest"]),
        ("python", &["-m", "nothing"]),
        ("python", &["-c", "1"]),
        ("sh", &["-c", "1"]),
        ("cmd", &["/c", "1"]),
        ("rm", &["-rf", "."]),
        ("something-nobody-heard-of", &[]),
        ("env", &["git", "status"]),
        ("build.cmd", &[]),
        ("git.exe", &["status"]),
    ];
    for (program, arguments) in sample {
        let classification = classify(*program, *arguments);
        match classification.source() {
            Source::Rule { program: row, .. } => {
                assert!(
                    !row.is_empty(),
                    "{program} {arguments:?} claims a rule with no name"
                );
            }
            Source::UnknownProgram | Source::UnknownOperation | Source::UnreadText(_) => {
                assert_eq!(
                    classification.effects(),
                    &CommandEffects::anything(),
                    "{program} {arguments:?} was narrowed by a rule that did not match it"
                );
            }
        }
        assert_eq!(
            classification.is_static_only(),
            classification.effects() == &CommandEffects::static_only(),
            "{program} {arguments:?} disagrees with itself about being read-only"
        );
    }
}

#[test]
fn every_spelling_of_a_row_answers_as_the_row_rather_than_as_itself() {
    // A row is filed under one name and answers to several, and a report names
    // the row: `py script.py` and `python script.py` read the same in a log, and
    // so do `yarn test` and `npm test`. This is also the test that notices a
    // spelling dropped from a row, which no test inside the module can — there,
    // the list of spellings and the thing being checked are the same list.
    let rows: &[(&str, &str, Option<&str>, &[&str])] = &[
        ("python", "python", None, &["script.py"]),
        ("python3", "python", None, &["script.py"]),
        ("py", "python", None, &["script.py"]),
        ("node", "node", None, &["script.js"]),
        ("pytest", "pytest", None, &["tests/"]),
        ("npm", "npm", Some("test"), &["test"]),
        ("yarn", "npm", Some("test"), &["test"]),
        ("pnpm", "npm", Some("test"), &["test"]),
        ("sh", "sh", None, &["script.sh"]),
        ("bash", "sh", None, &["script.sh"]),
        ("dash", "sh", None, &["script.sh"]),
        ("zsh", "sh", None, &["script.sh"]),
        ("ksh", "sh", None, &["script.sh"]),
        ("fish", "sh", None, &["script.sh"]),
        ("powershell", "powershell", None, &["-File", "x.ps1"]),
        ("pwsh", "powershell", None, &["-File", "x.ps1"]),
        ("rm", "rm", None, &["-rf", "somewhere"]),
        ("rmdir", "rm", None, &["somewhere"]),
        ("del", "rm", None, &["somewhere"]),
        ("erase", "rm", None, &["somewhere"]),
        ("shred", "rm", None, &["somewhere"]),
    ];
    for (program, canonical, decided_by, arguments) in rows {
        assert_eq!(
            classify(*program, *arguments).source(),
            Source::Rule {
                program: canonical,
                decided_by: *decided_by,
            },
            "{program} {arguments:?} did not answer as {canonical}'s row"
        );
    }
}

#[test]
fn a_flag_that_takes_a_value_does_not_hide_the_operation() {
    // `git -C <path> status` is how a caller runs git somewhere else, and the
    // path is that flag's value rather than the operation. Reading it as the
    // operation would make every one of these unclassifiable, which is the safe
    // direction and also a table that answers nothing.
    let known: &[(&str, &[&str], &[CommandClass])] = &[
        (
            "git",
            &["-C", "/somewhere", "status"],
            &[CommandClass::Static],
        ),
        (
            "git",
            &["--git-dir", "/somewhere", "log"],
            &[CommandClass::Static],
        ),
        (
            "cargo",
            &["--manifest-path", "Cargo.toml", "test"],
            &[CommandClass::DynamicHost, CommandClass::Network],
        ),
        (
            "npm",
            &["--prefix", "/somewhere", "ls"],
            &[CommandClass::Static],
        ),
        // The same flag written the other way round, which needs no skipping
        // because it is one token.
        (
            "npm",
            &["--prefix=/somewhere", "ls"],
            &[CommandClass::Static],
        ),
    ];
    for (program, arguments, expected) in known {
        let classification = classify(*program, *arguments);
        assert!(
            matches!(classification.source(), Source::Rule { .. }),
            "{program} {arguments:?} was not read as a rule: {source:?}",
            source = classification.source()
        );
        assert_eq!(
            classification.effects(),
            &CommandEffects::of(expected),
            "{program} {arguments:?}"
        );
    }
}
