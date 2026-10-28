//! The Windows quickstart, and the journey it describes.
//!
//! `P15-T014`'s acceptance is that *"a nontechnical Windows user can install
//! CLI + one harness integration and run first check"*. `docs/development/
//! QUICKSTART_WINDOWS.md` is that walk written out, and this file is the two
//! things a document like that needs to be worth anything here:
//!
//! 1. **The journey, run.** Section 3 installs an archive, section 4 installs
//!    an integration, section 5 runs a check and reads the verdict. Every one of
//!    those steps is a process and a filesystem, so this file does them rather
//!    than describing them: it stages a real archive, runs
//!    `scripts/Install-Sure.ps1` into a scratch per-user directory, runs
//!    `integrations/claude-code/scripts/install.ps1 -ForceCopy` against it with
//!    `SURE_BIN` removed and nothing on `PATH`, and runs `sure check` with the
//!    binary the install wrote.
//! 2. **The document's claims, measured.** `docs/development/INSTALL_WINDOWS.md`
//!    says what the standard is at *"How 'documented and tested' is satisfied
//!    here"*: a documentation claim is named to the test that measures it. The
//!    rules at the bottom of this file hold the quickstart to the same standard,
//!    and `every_rule_is_turned_red_by_an_edit_that_breaks_it` shows each one
//!    failing when the thing it names is taken away.
//!
//! # The one claim this file cannot make
//!
//! The quickstart's section 1 says there is no published archive and that the
//! only path to one today needs a Rust toolchain. That is not a limitation of
//! this file — it is the finding the task was for, and what can be measured is
//! the reason for it: the rules `release_workflow_violations` and
//! `dry_run_violations` read the two workflow files and hold the tree to what
//! the document says about them. The moment either stops being true, the
//! document is wrong and this goes red.
//!
//! # The archive these tests install
//!
//! The same staged archive `crates/sure-cli/tests/install_flow.rs` installs, for
//! the same reason: `scripts/Build-Release.ps1 -Phase All` refuses to package
//! without the release gate and takes a full release build, so the *documented
//! layout* is staged around the binary cargo just built. `the_two_stagers_are_one
//! _stager` below is what keeps this file from being a second invention: it reads
//! `install_flow.rs`'s own copy of the staging script out of its bytes and
//! requires the copy here to be character for character the same.
//!
//! **What the environment override does and does not move.** Every process here
//! is given a `LOCALAPPDATA` under this repository's git-ignored `target/tmp`.
//! The two PowerShell scripts read that variable themselves, so the install
//! lands in a directory this test made and the integration installer resolves
//! the binary there. **`sure check` does not.** The run below names no
//! `--store-dir` and no `--settings-file`, so its store and settings locations
//! come from the platform's own known folders — `crates/sure-core/src/paths/
//! mod.rs` says why, and it is deliberate: there is no environment variable a
//! checked project could set to decide where the store goes. (A caller may name
//! either with a flag, which is why this journey names neither; that is still
//! not the environment.) Measured on a
//! machine with a store, `sure check` given a scratch `LOCALAPPDATA` and
//! `APPDATA` still opened the real `%LOCALAPPDATA%\SURE\sure.db` and left the
//! scratch directory empty. That is why the number of stages the run marks
//! `(NOT CHECKED)` is 1 on this machine and 2 on a fresh runner: stage 8 is not
//! run wherever no analysis provider is configured, and stage 9 is not run where
//! there is no recorded history. The rules below therefore hold the run's
//! sentence to the markers in that same run rather than to a number, and
//! `a_check_leaves_the_store_of_the_person_running_it_byte_identical` — the one
//! process started with no override at all, the shape
//! `crates/sure-cli/tests/cli_contract.rs` already uses — is where the claim "a
//! check writes nothing" is measured against the person's own store.

// Windows-only: a per-user `%LOCALAPPDATA%` install, two PowerShell scripts, and
// a plugin destination under the same directory. `CLAUDE.md`'s portability
// requirement is about the Rust core, not about this file.
#![cfg(windows)]
// The workspace forbids `unwrap`, `expect` and `panic` in shipped code, because
// a panic is a message nobody chose. A test is the one place they are the point:
// the panic *is* the report, and it names the value that was wrong.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sure_core::paths::Paths;

/// The binary this package builds, as cargo hands it to its integration tests.
const SURE: &str = env!("CARGO_BIN_EXE_sure");

// --- Where everything lives ---------------------------------------------

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .to_path_buf()
}

fn install_script() -> PathBuf {
    repository_root().join("scripts").join("Install-Sure.ps1")
}

/// The integration installer section 4 of the quickstart runs.
fn integration_installer() -> PathBuf {
    repository_root()
        .join("integrations")
        .join("claude-code")
        .join("scripts")
        .join("install.ps1")
}

/// A directory of this test's own, under the workspace's git-ignored `target/tmp`.
///
/// Unique per call, by way of `sure_testkit::scratch` — the same fixture, for
/// the same reasons, as `a_directory_of_our_own` in
/// `crates/sure-cli/tests/install_flow.rs`, and the reasoning lives with the
/// helper rather than in each of the twenty-five files that used to repeat it.
/// The space and the non-ASCII character are `CLAUDE.md`'s rule and are
/// load-bearing here: this journey carries a path through PowerShell's argument
/// parsing, a ZIP, a copy, and back out to a check.
fn a_directory_of_our_own(what: &str) -> PathBuf {
    sure_testkit::scratch::directory("sure quickstart flow é中文 and spaces", what)
}

// --- The PowerShell hosts ------------------------------------------------

/// The PowerShell that ships with Windows, found the way Windows finds it.
fn windows_powershell() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    PathBuf::from(root).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe")
}

/// PowerShell 7, when this machine has it.
fn powershell_seven() -> Option<PathBuf> {
    let from_path = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join("pwsh.exe"))
            .find(|candidate| candidate.is_file())
    });
    from_path.or_else(|| {
        let installed = PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe");
        installed.is_file().then_some(installed)
    })
}

/// The hosts this suite walks the document through.
///
/// The first is always Windows PowerShell, so the walk is deterministic. PowerShell
/// 7 is added when it is installed, because `CLAUDE.md` names PowerShell 7+ for
/// this repository's scripts and a walk that was only ever driven by the older
/// host would be a claim about the newer one that nothing measured.
fn hosts() -> Vec<(&'static str, PathBuf)> {
    let mut found = vec![("Windows PowerShell", windows_powershell())];
    if let Some(seven) = powershell_seven() {
        found.push(("PowerShell 7", seven));
    }
    found
}

// --- Running things ------------------------------------------------------

/// What one process run did.
struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn of(output: &Output) -> Self {
        Self {
            status: output.status.code().expect("the process exited on its own"),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// Both streams, for a message that has to show why something failed.
    fn everything(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

/// Run one of this repository's scripts with typed arguments.
///
/// A `Command` with an argument vector and no shell string, which is `CLAUDE.md`'s
/// Windows rule and is also why a path with a space or a non-ASCII character
/// survives: the quoting is `Command`'s.
fn run_script(host: &Path, script: &Path, arguments: &[&str]) -> Run {
    assert!(
        script.is_file(),
        "{} is not there, so there is nothing to test",
        script.display()
    );
    let output = Command::new(host)
        .arg("-NoProfile")
        .arg("-File")
        .arg(script)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("could not start {}: {error}", host.display()));
    Run::of(&output)
}

// --- The archive the installer is given ----------------------------------

/// The staging script, copied character for character from `install_flow.rs`.
///
/// `the_two_stagers_are_one_stager` below is the rule that holds the copy to the
/// original, because two fixtures for one documented layout are two layouts the
/// moment they disagree.
const STAGE_AND_PACK: &str = r#"
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PayloadExe,
    [Parameter(Mandatory)][string] $ScratchRoot,
    [Parameter(Mandatory)][string] $Version,
    [string] $Target = 'x86_64-pc-windows-msvc'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
$name = "sure-$Version-$Target"
$stage = Join-Path (Join-Path $ScratchRoot 'stage') $name
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item -LiteralPath $PayloadExe -Destination (Join-Path $stage 'sure.exe') -Force
$license = "test fixture: the archive's LICENSE entry`n"
[System.IO.File]::WriteAllText((Join-Path $stage 'LICENSE'), $license, [System.Text.ASCIIEncoding]::new())
$release = "SURE $Version - a test fixture in the documented archive layout`n"
[System.IO.File]::WriteAllText((Join-Path $stage 'RELEASE.txt'), $release, [System.Text.ASCIIEncoding]::new())
$archive = Join-Path $ScratchRoot "$name.zip"
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $archive, [System.IO.Compression.CompressionLevel]::Optimal, $true)
# .NET rather than `Get-FileHash`, so that this fixture runs in the same
# environment the scripts are tested in: a PowerShell 7 session's `PSModulePath`
# reaching Windows PowerShell 5.1 leaves `Get-FileHash` undefined there while
# every other command either script uses still resolves. The scripts' own
# headers carry the measurement, and `Get-Sha256` in `Install-Sure.ps1` carries
# the diagnostic output it came from. No test here asserts that property: it is
# a fact about this machine's environment, not about the product, and a test
# asserting it would fail anywhere the parent session is not PowerShell 7.
$stream = [System.IO.File]::OpenRead($archive)
try { $hasher = [System.Security.Cryptography.SHA256]::Create(); try { $hash = $hasher.ComputeHash($stream) } finally { $hasher.Dispose() } } finally { $stream.Dispose() }
$digest = ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
$line = "$digest  $name.zip`n"
[System.IO.File]::WriteAllText("$archive.sha256", $line, [System.Text.Encoding]::ASCII)
# The Rust reader expects UTF-8; Windows PowerShell 5.1 otherwise writes the
# console's code page, which corrupts the Unicode path returned below.
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Write-Output $archive
"#;

/// The staging script as `install_flow.rs` holds it, read out of that file.
///
/// `None` when the marker is not there at all, which is a complaint from the
/// rule rather than a pass: a rule that reads one file's bytes and finds nothing
/// has stopped measuring anything.
fn stager_in(source: &str) -> Option<String> {
    let marker = "const STAGE_AND_PACK: &str = r#\"";
    let start = source.find(marker)? + marker.len();
    let end = source[start..].find("\"#;")? + start;
    Some(source[start..end].to_owned())
}

/// Why the two stagings disagree, or nothing when they are one staging.
///
/// A function of the two texts so that the way this could go false — one
/// character changed in either copy — can be fed to it.
fn stager_disagreement(install_flow: &str, ours: &str) -> Option<String> {
    let Some(theirs) = stager_in(install_flow) else {
        return Some(format!(
            "{INSTALL_FLOW} no longer carries a `STAGE_AND_PACK` literal, so the rule that the two \
             stagings are one staging has stopped being able to measure anything"
        ));
    };
    if theirs == ours {
        return None;
    }
    let at = theirs
        .char_indices()
        .zip(ours.chars())
        .find(|&((_, a), b)| a != b)
        .map(|((index, _), _)| index)
        .unwrap_or_else(|| theirs.len().min(ours.len()));
    Some(format!(
        "the staging script in {INSTALL_FLOW} and the one in this file are two stagings, not one. \
         They first differ at byte {at}: {:?} against {:?}. Two fixtures for one documented layout \
         are two layouts the moment they disagree, and the archive this file installs is then not \
         the archive the install suite installs.",
        snippet(&theirs, at),
        snippet(ours, at)
    ))
}

/// Twenty characters from `at`, so a complaint can show the divergence.
fn snippet(text: &str, at: usize) -> String {
    text.get(at..).unwrap_or("").chars().take(20).collect()
}

/// An archive in the layout `docs/development/RELEASE_PROCESS.md` records, with
/// its checksum, both inside `scratch`.
fn a_release_archive(host: &Path, scratch: &Path) -> (PathBuf, PathBuf) {
    let stager = scratch.join("stage-and-pack.ps1");
    // `run_script` hands this path to PowerShell and PowerShell starts it, so it
    // is a program and is put at its path by the door for programs.
    sure_testkit::write_program(&stager, STAGE_AND_PACK.as_bytes(), 0o755)
        .expect("the staging script can be written");
    let scratch_text = scratch.to_string_lossy().into_owned();
    let run = run_script(
        host,
        &stager,
        &[
            "-PayloadExe",
            SURE,
            "-ScratchRoot",
            &scratch_text,
            "-Version",
            "0.0.0-quickstart-test",
        ],
    );
    assert_eq!(
        run.status,
        0,
        "staging the test archive failed:\n{}",
        run.everything()
    );
    let archive = PathBuf::from(run.stdout.trim());
    let checksum = PathBuf::from(format!("{}.sha256", archive.display()));
    (archive, checksum)
}

#[test]
fn a_unicode_archive_path_returns_intact_from_the_stager() {
    for (label, host) in hosts() {
        let scratch = a_directory_of_our_own("stager output encoding");
        let (archive, checksum) = a_release_archive(&host, &scratch);
        assert!(archive.starts_with(&scratch), "{label}: {archive:?}");
        assert!(archive.is_file(), "{label}: {archive:?}");
        assert!(checksum.is_file(), "{label}: {checksum:?}");
    }
}

// --- The journey sections 3, 4 and 5 walk --------------------------------

/// The install step of section 3, into a root the caller names.
fn install(host: &Path, archive: &Path, root: &Path) -> Run {
    let archive = archive.to_string_lossy().into_owned();
    let root = root.to_string_lossy().into_owned();
    run_script(
        host,
        &install_script(),
        &["-Archive", &archive, "-InstallRoot", &root],
    )
}

/// A project the first check has something to read, with an absolute path.
fn a_project_of_our_own(scratch: &Path) -> PathBuf {
    let project = scratch.join("a project to check");
    std::fs::create_dir_all(&project).expect("the project directory");
    std::fs::write(
        project.join("package.json"),
        b"{\"name\":\"my-project\",\"version\":\"1.0.0\"}\n",
    )
    .expect("the project's manifest");
    std::fs::write(project.join("index.js"), b"console.log('hello');\n")
        .expect("the project's file");
    project
}

/// `sure check <absolute path>` with the binary the install wrote, section 5.
///
/// `per_user` is what `%LOCALAPPDATA%` and `%APPDATA%` are set to. **It does not
/// move `sure check`'s store, and was measured not to** — see the note at the top
/// of this file; the run below a scratch override is still a run against the store
/// the person running it really has, which is the machine-dependence this task is
/// about. Passing `None` is the shape the documented command has on a real machine,
/// and is what `a_check_leaves_the_store_of_the_person_running_it_byte_identical`
/// needs.
fn run_check(installed: &Path, project: &Path, per_user: Option<&Path>) -> Run {
    assert!(
        installed.is_file(),
        "there is nothing at {} to run a check with, so the install above did not happen",
        installed.display()
    );
    let mut command = Command::new(installed);
    command.arg("check").arg(project);
    if let Some(per_user) = per_user {
        // `APPDATA` too, because the two scripts and the installer resolve their
        // destinations from the environment even though `sure check` does not: the
        // variable is the boundary this walk can name, and it is still what the
        // assertion below — about the directory this walk made — is about.
        command
            .env("LOCALAPPDATA", per_user)
            .env("APPDATA", per_user);
    }
    Run::of(
        &command
            .output()
            .unwrap_or_else(|error| panic!("could not run {}: {error}", installed.display())),
    )
}

/// Sections 3, 4 and 5, in order, as one run.
///
/// A helper rather than a copy because `the_integration_installer_finds_the_cli_
/// this_document_installed` needs the same journey up to its falsifier, and two
/// arrangements of one journey would be two journeys.
struct Journey {
    scratch: PathBuf,
    /// What `%LOCALAPPDATA%` is set to; the install root is `<per_user>\SURE`.
    per_user: PathBuf,
    installed: PathBuf,
    plugin: PathBuf,
    project: PathBuf,
}

fn walk_the_document(host: &Path) -> Journey {
    let scratch = a_directory_of_our_own("quickstart");
    // `%LOCALAPPDATA%\SURE` is the install root and also the per-user data
    // directory, which is the fact `docs/development/INSTALL_WINDOWS.md` is built
    // around. Setting `LOCALAPPDATA` to this test's scratch directory is what
    // makes the whole walk land inside it.
    let per_user = scratch.join("local app data");
    std::fs::create_dir_all(&per_user).expect("the per-user directory");
    let installed = per_user.join("SURE").join("bin").join("sure.exe");

    // Section 3: the archive, and the installer.
    let (archive, checksum) = a_release_archive(host, &scratch);
    assert!(
        checksum.is_file(),
        "the staging script wrote no checksum, so the install below would be refused for a reason \
         that has nothing to do with this document"
    );
    let run = install(host, &archive, &per_user.join("SURE"));
    assert_eq!(
        run.status,
        0,
        "section 3's install command failed:\n{}",
        run.everything()
    );

    // Section 4: one harness integration, with the override removed and a `PATH`
    // that cannot answer, so what it finds is what section 3 wrote.
    let nothing_on_path = scratch.join("a path with nothing on it");
    std::fs::create_dir_all(&nothing_on_path).expect("the empty directory");
    let plugin = per_user.join("claude-plugins").join("sure");
    let integrator = integration_installer();
    assert!(integrator.is_file(), "{} is missing", integrator.display());
    let output = Command::new(host)
        .arg("-NoProfile")
        .arg("-File")
        .arg(&integrator)
        .arg("-ForceCopy")
        .env_remove("SURE_BIN")
        .env_remove("CLAUDE_PLUGIN_DIR")
        .env("LOCALAPPDATA", &per_user)
        .env("PATH", &nothing_on_path)
        .output()
        .unwrap_or_else(|error| panic!("could not start {}: {error}", integrator.display()));
    let run = Run::of(&output);
    assert_eq!(
        run.status,
        0,
        "section 4's integration install failed:\n{}",
        run.everything()
    );

    Journey {
        project: a_project_of_our_own(&scratch),
        scratch,
        per_user,
        installed,
        plugin,
    }
}

// --- The journey, as a test ----------------------------------------------

#[test]
fn the_whole_documented_journey_installs_the_cli_an_integration_and_answers_a_check() {
    for (label, host) in hosts() {
        let walked = walk_the_document(&host);

        // Section 3's outcome: the binary the document names, in the place it
        // names, holding the bytes cargo built rather than a stand-in.
        assert!(
            walked.installed.is_file(),
            "{label}: nothing was installed at {}",
            walked.installed.display()
        );
        assert_eq!(
            std::fs::read(&walked.installed).expect("the installed binary"),
            std::fs::read(SURE).expect("the built binary"),
            "{label}: the installed binary is not the one that went into the archive"
        );

        // Section 4's outcome: the package, copied, with the token Claude Code
        // substitutes left for Claude Code.
        assert!(
            walked.plugin.join(".mcp.json").is_file(),
            "{label}: the package did not land at {}",
            walked.plugin.display()
        );
        let mcp =
            std::fs::read_to_string(walked.plugin.join(".mcp.json")).expect("the copied .mcp.json");
        assert!(
            mcp.contains("${CLAUDE_PLUGIN_ROOT}"),
            "{label}: the copy rendered a token Claude Code substitutes itself, so the packager \
             and the renderer disagree about who owns it:\n{mcp}"
        );

        // Section 5: the first check, run by the binary section 3 installed,
        // against an absolute path, with the per-user directory this walk made.
        let check = run_check(&walked.installed, &walked.project, Some(&walked.per_user));
        assert_eq!(
            check.status,
            1,
            "{label}: the documented check returned {} rather than 1. The document says a check of \
             a project it can read returns 1 — not 0, and not 3, which would mean this build cannot \
             check a project at all:\n{}",
            check.status,
            check.everything()
        );
        for sentence in [
            "SURE checked ",
            "No unresolved findings from the checks that ran.",
            "SURE exited with status 1.",
        ] {
            assert!(
                check.stdout.contains(sentence),
                "{label}: the run the document quotes does not carry {sentence:?}, so the quoted \
                 output is no longer a run of this command:\n{}",
                check.everything()
            );
        }

        // The count this run prints about itself, against the markers in the same
        // run. What is checked is the relation and not the number, because the
        // number is the machine's: stage 8 is not run wherever no analysis
        // provider is configured, and stage 9 is not run on a machine that has
        // never used SURE, so a bare machine counts 2 and a machine with a store
        // counts 1. `1 of the 12` was the assertion here, and it could only be
        // satisfied on the machine the document's quote was taken from.
        if let Some(disagreement) = not_checked_disagreement(
            &format!("{label}: the run this walk just made"),
            &check.stdout,
        ) {
            panic!("{disagreement}\n{}", check.everything());
        }

        // And the claim the document makes about a first check: it creates no
        // store. The scratch directory is left behind on purpose, so the run that
        // was measured can be read back. What this can see is the directory this
        // walk named, and no more than that: `sure check` does not read
        // `LOCALAPPDATA`, so the claim about the store the person running it
        // really has is the other test's business —
        // `a_check_leaves_the_store_of_the_person_running_it_byte_identical`,
        // which takes that store's digest across a real run.
        let store = walked.per_user.join("SURE").join("sure.db");
        assert!(
            !store.exists(),
            "{label}: the check created a store at {}, so the document's `a first check on a \
             machine that has never used SURE leaves no file behind` is false",
            store.display()
        );
    }
}

#[test]
fn the_integration_installer_finds_the_cli_this_document_installed() {
    for (label, host) in hosts() {
        let walked = walk_the_document(&host);

        // The same command section 4 documents, run again after the binary is
        // gone. Without this, a run that passed the test above could have been
        // passing for some other reason — a `sure` on `PATH`, a `SURE_BIN` this
        // test forgot to remove — and the document's sentence that the installer
        // resolves `%LOCALAPPDATA%\SURE\bin\sure.exe` would be measuring nothing.
        std::fs::remove_file(&walked.installed).expect("the installed binary");
        let nothing_on_path = walked.scratch.join("a path with nothing on it");
        let output = Command::new(&host)
            .arg("-NoProfile")
            .arg("-File")
            .arg(integration_installer())
            .arg("-ForceCopy")
            .env_remove("SURE_BIN")
            .env_remove("CLAUDE_PLUGIN_DIR")
            .env("LOCALAPPDATA", &walked.per_user)
            .env("PATH", &nothing_on_path)
            .output()
            .expect("the host starts");
        let run = Run::of(&output);

        assert_ne!(
            run.status,
            0,
            "{label}: the integration installer still succeeded with no binary where section 3 \
             puts one, so the passing run was not measuring the install:\n{}",
            run.everything()
        );
        assert!(
            run.everything().contains("SURE not found."),
            "{label}: the integration installer failed for some other reason than the missing \
             binary, so what it was measuring is not what the document says it \
             measures:\n{}",
            run.everything()
        );
    }
}

/// The claim in section 5 that a check writes nothing, against a real machine.
///
/// The journey above proves it for a scratch per-user directory. This one runs
/// the documented command the documented way — no environment override at all —
/// and asserts the bytes of the store belonging to whoever runs the suite are the
/// same afterwards. It is the shape `crates/sure-cli/tests/cli_contract.rs` uses,
/// including its honesty about what it cannot see: a write from a `sure` process
/// somebody started by hand is outside this test, and a workspace run with the
/// store's digest taken before and after is what covers that.
#[test]
fn a_check_leaves_the_store_of_the_person_running_it_byte_identical() {
    let path = Paths::discover()
        .expect("this machine reports a per-user location for SURE's files")
        .store_file();
    let before = std::fs::read(&path).ok();

    let scratch = a_directory_of_our_own("store");
    let project = a_project_of_our_own(&scratch);
    let run = run_check(&PathBuf::from(SURE), &project, None);
    assert_eq!(
        run.status,
        1,
        "the documented check did not return 1:\n{}",
        run.everything()
    );

    let after = std::fs::read(&path).ok();
    assert!(
        before.is_some() || after.is_none(),
        "{} did not exist before the check and exists now, so the check created the store of the \
         person running this suite",
        path.display()
    );
    assert!(
        before == after,
        "{} was {} bytes before the check and is {} bytes after it, so a check wrote the store of \
         the person running this suite. Every process this file starts is given a per-user \
         directory under `target/tmp` and the store belongs to no such directory: if the writer \
         was not this check, it came from outside this file — another test binary, a `sure` process \
         somebody started, or a harness hook.",
        path.display(),
        before.map(|bytes| bytes.len()).unwrap_or(0),
        after.map(|bytes| bytes.len()).unwrap_or(0)
    );
}

// --- The document's own rules --------------------------------------------

/// The document this file is about.
const QUICKSTART: &str = "docs/development/QUICKSTART_WINDOWS.md";

/// The reference the walk is reached from, and the file that says what the
/// standard for a documented claim in this repository is.
const INSTALL_WINDOWS: &str = "docs/development/INSTALL_WINDOWS.md";

/// The one workflow in this tree that builds a Windows archive.
const RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";

/// The workflow that packages archives where anyone can see them.
const DRY_RUN_WORKFLOW: &str = ".github/workflows/release-dry-run.yml";

/// The file the staging script is shared with.
const INSTALL_FLOW: &str = "crates/sure-cli/tests/install_flow.rs";

/// Every file a rule in this file reads.
const CORPUS: [&str; 4] = [
    QUICKSTART,
    INSTALL_WINDOWS,
    RELEASE_WORKFLOW,
    DRY_RUN_WORKFLOW,
];

/// What the quickstart has to keep carrying for its walk to be walkable.
///
/// Each entry is a literal substring of the document as it stands, and the
/// sentence is what its disappearance would mean. These are presence rules, and
/// what a presence rule cannot prove is that the thing still works — which is
/// why the journey above exists and why these rules are the cheap half.
const QUICKSTART_REQUIRED: &[(&str, &str)] = &[
    (
        "## 1. There is no SURE to download today",
        "the section that says where an archive can and cannot come from is gone, and a reader \
         is left to assume there is one to fetch",
    ),
    (
        "**Rust 1.98.1.**",
        "the one path to an archive today is not stated as needing a Rust toolchain, so the \
         document reads as though section 2 needed nothing a reader might not have",
    ),
    (
        "Visual Studio Build Tools",
        "the build's second prerequisite is gone, and a reader on a machine without it meets a \
         linker error the document did not warn them about",
    ),
    (
        "cargo test -p sure-core --test acceptance_report_runner",
        "the release gate is no longer named, and `Build-Release.ps1` refuses to package without \
         it — a reader following the document would hit a refusal the document never mentioned",
    ),
    (
        "& .\\scripts\\Build-Release.ps1 -Phase All",
        "the step that produces the archive is gone",
    ),
    (
        "Install-Sure.ps1 -Archive",
        "section 3 no longer names the command it is a walk through",
    ),
    (
        "%LOCALAPPDATA%\\SURE\\bin\\sure.exe",
        "the destination is gone, and with it the one path eight launcher scripts resolve",
    ),
    (
        "integrations\\claude-code\\scripts\\install.ps1 -ForceCopy",
        "section 4 no longer names the integration it installs, so the acceptance's second half \
         is a paragraph rather than a command",
    ),
    (
        "%LOCALAPPDATA%\\claude-plugins\\sure",
        "the integration's destination is gone, so a reader cannot tell whether it worked",
    ),
    (
        "**The path has to be absolute.**",
        "the one way to make `sure check` refuse a command that looks right is not said, so a \
         reader who typed a relative path reads status 5 as a broken tool",
    ),
    (
        "SURE exited with status 1.",
        "the quoted run stops saying what it returned, and a status is the whole answer a check \
         gives",
    ),
    (
        // Deliberately without a number in it: the count is the machine's, and the
        // rule `quoted_run_violations` is what holds the sentence to the markers
        // above it. What this anchor holds is that the sentence is there at all —
        // a quote that dropped it would otherwise satisfy a rule about a
        // disagreement by having nothing to disagree with.
        "stages did not run, and each is marked NOT CHECKED above. A run with a stage that did not \
         run is never reported as clean.",
        "the quoted run stops saying how many stages did not run and that a run with such a stage \
         is never reported as clean, which is the sentence the whole of section 5's reading of a \
         status rests on",
    ),
    (
        // The two marked lines the sentence counts are required **inside the
        // quoted run** rather than here, so that a line moved out of the fence is
        // a complaint: `BARE_MACHINE_LINES` below is where they are named, and it
        // is also where the document's decision — that its quote is a run of a
        // machine that has never used SURE — became a fact a rule reads.
        "It is a run of a machine that has never used SURE",
        "the paragraph that says which machine the quoted run is a run of is gone, and a reader \
         with a store would take the numbers above it for their own",
    ),
    (
        "## How \"documented and tested\" is satisfied here",
        "the section that names the tests behind this document's claims is gone, which is the one \
         thing `docs/development/INSTALL_WINDOWS.md` asks of a document in this repository",
    ),
    (
        "## What is not covered",
        "the limits are gone, and a document that states no limits reads as though it had none",
    ),
];

/// Phrasings that would send a reader to something that is not there.
///
/// The whole finding of this task is that the first step of a quickstart cannot be
/// "fetch the archive". A document that says so in one paragraph and then offers
/// the fetch somewhere else is worse than one that never mentioned it, so the
/// phrasings a quickstart would really carry are listed and forbidden.
///
/// Each is written so that the honest sentence does not satisfy it: this file's
/// own document says *there is no published archive*, *nothing is on a releases
/// page*, and *the one path today needs a Rust toolchain*, and none of those is
/// any of the strings below.
const DOWNLOAD_PROMISES: &[(&str, &str)] = &[
    (
        "download SURE",
        "the first step of the walk is a download that does not exist",
    ),
    (
        "download it from",
        "the same, and it also names no place, which is the shape a stale sentence takes",
    ),
    (
        "download the archive",
        "the same, written as the step the reader is about to take",
    ),
    ("download the .zip", "the same, naming the file"),
    (
        "from the releases page",
        "sends a reader to a page with no releases on it",
    ),
    ("from the release page", "the same"),
    (
        "winget install",
        "an install command for a package manager this project has submitted no package to",
    ),
    (
        "click Download",
        "a button that is not rendered anywhere, because there is nothing to download",
    ),
];

/// What the install reference has to keep carrying: the way in.
const INSTALL_WINDOWS_REQUIRED: &[(&str, &str)] = &[(
    "docs/development/QUICKSTART_WINDOWS.md",
    "the reference a reader arriving at the install page meets no longer links the walk, so \
         the quickstart is reachable only by knowing its name — which is the state this task was \
         dispatched to fix",
)];

/// The lines a workflow runs, with its comment lines removed.
///
/// A YAML comment is a line whose first non-space character is `#`. That is
/// deliberately not "everything after the first `#`", which is the rule for the
/// PowerShell scripts `install_flow.rs` reads: a `#` later on a YAML line can be
/// inside a quoted scalar, and a rule about what a workflow runs must not damage
/// the thing it is reading. The property being measured is *a line this workflow
/// runs*, and neither file's own account of itself — both of them say at length
/// that they never un-draft a release — is a line it runs.
fn workflow_code_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect()
}

/// The job names of a workflow, read out of the file rather than listed here.
fn workflow_jobs(text: &str) -> Vec<String> {
    let mut in_jobs = false;
    let mut out = Vec::new();
    for line in workflow_code_lines(text) {
        if line.trim_end() == "jobs:" {
            in_jobs = true;
            continue;
        }
        if !in_jobs {
            continue;
        }
        // A job key is indented exactly two spaces. Anything deeper is a key
        // inside a job — `name:`, `runs-on:`, a step — and anything at column 0
        // has left the block.
        let Some(rest) = line.strip_prefix("  ") else {
            continue;
        };
        if rest.starts_with(' ') {
            continue;
        }
        if let Some(name) = rest.strip_suffix(':')
            && !name.is_empty()
            && !name.contains(' ')
            && !name.starts_with('-')
        {
            out.push(name.to_owned());
        }
    }
    out
}

/// The input names under `workflow_dispatch: inputs:`, read out of the file.
///
/// The quickstart says the release workflow takes exactly one input, a required
/// `tag`. That sentence was wrong when it was first written — it said five — and
/// nothing here read the input list, which is why the rule exists rather than a
/// second paragraph promising to be careful.
fn workflow_dispatch_inputs(text: &str) -> Vec<String> {
    let mut inside = false;
    let mut out = Vec::new();
    for line in workflow_code_lines(text) {
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !inside {
            if indent == 4 && trimmed == "inputs:" {
                inside = true;
            }
            continue;
        }
        // The block ends at the first code line that is not indented under it.
        if indent < 6 {
            break;
        }
        // An input key is indented exactly six spaces: eight is a key *inside*
        // an input (`description:`, `required:`, `type:`).
        if indent == 6
            && let Some(name) = trimmed.strip_suffix(':')
            && !name.contains(' ')
        {
            out.push(name.to_owned());
        }
    }
    out
}

/// The release workflow can create a draft and must not be able to publish one.
///
/// This is the rule behind *"there is no published archive"*. It reads the lines
/// the workflow runs rather than the file's own paragraphs about itself, because
/// the paragraphs are exactly what a reader would be misled by.
fn release_workflow_violations(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let code = workflow_code_lines(text);

    for (needed, why) in [
        (
            // The invocation and not the bare name. The bare name is satisfied by
            // a line that *prints* it — this workflow has one, an `echo` that warns
            // a person about `gh release create` without `--verify-tag` — and a
            // rule the message can satisfy is a check on the message. The tag
            // argument is code that does the thing and prose cannot carry it.
            "gh release create \"$TAG\"",
            "the release workflow no longer creates a release, so the one path this document \
             describes to an archive has stopped existing",
        ),
        (
            "--draft",
            "the release workflow creates releases without the draft flag, so this document's \
             `there is no published archive` has stopped being true",
        ),
    ] {
        if !code.iter().any(|line| line.contains(needed)) {
            out.push(format!(
                "{RELEASE_WORKFLOW} runs no line carrying {needed:?}, and {why}"
            ));
        }
    }

    let inputs = workflow_dispatch_inputs(text);
    if inputs != ["tag"] {
        out.push(format!(
            "{RELEASE_WORKFLOW}'s `workflow_dispatch` inputs are {inputs:?} rather than [\"tag\"]. \
             The quickstart says the workflow takes exactly one input, a required tag, and an input \
             list that grew a second entry without a person deciding whether the document should \
             mention it is the case this rule exists for"
        ));
    }

    for (forbidden, why) in [
        (
            "--draft=false",
            "the release workflow can now publish a release, so there may be an archive to \
             download and this document's answer to `where does an archive come from` is wrong in \
             the other direction",
        ),
        (
            "gh release edit",
            "the same, by a step that edits the draft into a release",
        ),
        (
            "gh release delete",
            "the workflow can now delete a release, which is a publication act this document says \
             nothing in it performs",
        ),
    ] {
        if let Some(line) = code.iter().find(|line| line.contains(forbidden)) {
            out.push(format!(
                "{RELEASE_WORKFLOW} runs a line carrying {forbidden:?} ({:?}), and {why}",
                line.trim()
            ));
        }
    }
    out
}

/// The dry-run workflow packages three platforms and no Windows archive.
///
/// This is the rule behind *"no workflow that can run today packages a Windows
/// archive"*, which is the reason a reader cannot get one from CI. The job list
/// is read out of the file, so a fourth job is a complaint rather than a silent
/// addition; and the target triple is checked for the same reason a job name is
/// not enough on its own — a job can be renamed without changing what it builds.
fn dry_run_violations(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let code = workflow_code_lines(text);

    for (forbidden, why) in [
        (
            "x86_64-pc-windows-msvc",
            "the dry run now builds for the Windows target, so a Windows archive may exist as a \
             workflow artifact and this document's account of where one comes from is incomplete",
        ),
        (
            ".zip",
            "the dry run now produces a `.zip`, which is the shape the Windows archive is the only \
             one of here, so it is unlikely to be a rename",
        ),
    ] {
        if let Some(line) = code.iter().find(|line| line.contains(forbidden)) {
            out.push(format!(
                "{DRY_RUN_WORKFLOW} runs a line carrying {forbidden:?} ({:?}), and {why}",
                line.trim()
            ));
        }
    }

    let jobs = workflow_jobs(text);
    let wanted = [
        "validate",
        "package-macos",
        "package-macos-intel",
        "package-linux",
    ];
    if jobs != wanted {
        out.push(format!(
            "{DRY_RUN_WORKFLOW}'s jobs are {jobs:?} rather than {wanted:?}. This document says \
             which platforms it packages, and a job this repository added without a person \
             deciding whether it belongs in this list is the case this rule exists for: if the \
             new job is one this document should mention, the document has to change with it"
        ));
    }
    out
}

/// Collapse every run of whitespace to a single space.
///
/// A Markdown paragraph is reflowed by every editor that has ever touched it, so
/// a rule about a *sentence* must not be a rule about where the line breaks
/// happen to fall. The same helper, for the same reason, as `squashed` in
/// `crates/sure-testkit/tests/notarization_status.rs` and `signing_status.rs`.
fn squashed(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Every anchor that has to be present, checked against one file's text.
fn required_in(path: &str, text: &str, required: &[(&str, &str)]) -> Vec<String> {
    if text.trim().is_empty() {
        return vec![format!(
            "{path} was read as empty, so nothing here says whether it still carries what this \
             file's rules ask of it"
        )];
    }
    let haystack = squashed(text);
    required
        .iter()
        .filter(|(anchor, _)| !haystack.contains(&squashed(anchor)))
        .map(|(anchor, why)| format!("{path} does not carry {anchor:?}, and {why}"))
        .collect()
}

/// Every anchor that has to be absent, checked against one file's text.
fn forbidden_in(path: &str, text: &str, forbidden: &[(&str, &str)]) -> Vec<String> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    let haystack = squashed(text).to_lowercase();
    forbidden
        .iter()
        .filter(|(phrase, _)| haystack.contains(&squashed(phrase).to_lowercase()))
        .map(|(phrase, why)| format!("{path} carries {phrase:?}, and {why}"))
        .collect()
}

// --- The count a run prints about the stages it did not run -----------------

/// The marker a run puts on a stage it did not run.
///
/// With the parentheses, because the sentence that counts them names the marker
/// without them: `marked NOT CHECKED above` is part of the sentence and is not a
/// stage line, and a count that included it would be counting the count.
const NOT_CHECKED_MARKER: &str = "(NOT CHECKED)";

/// The rest of the sentence, with **both** numbers left out of it.
///
/// The numbers are the run's own and nothing here fixes either one: what the
/// rule is about is that the first agrees with the marked lines beside it. The
/// words around them are a literal, so a rewrite that keeps the sentence's shape
/// and changes what it counts — `did not run` becoming `did not finish`, the
/// marker renamed — stops being read as this sentence at all, which is a
/// complaint from the rule rather than a quiet pass.
const NOT_RUN_TAIL: &str = " stages did not run, and each is marked NOT CHECKED above. A run with a \
                            stage that did not run is never reported as clean.";

/// The two numbers of that sentence: the count, then the number of stages.
///
/// `None` when the text carries no such sentence, which is what a run in which
/// every stage ran prints. Matched on the squashed text, because a Markdown
/// paragraph is reflowed by every editor that touches it and a rule about a
/// sentence must not be a rule about where its line breaks fell.
fn gap_counts(text: &str) -> Option<(usize, usize)> {
    let squashed_text = squashed(text);
    let at = squashed_text.find(NOT_RUN_TAIL)?;
    // The sentence reads `N of the M stages …`, so reading it backwards from the
    // tail yields the stage count, then `the`, then `of`, then the count of the
    // stages that did not run. A number that is not a number, or a word out of
    // place, is `None`: a rewritten sentence is not this sentence.
    let mut words = squashed_text[..at].rsplit(' ');
    let stages = words.next()?.parse::<usize>().ok()?;
    if words.next()? != "the" {
        return None;
    }
    if words.next()? != "of" {
        return None;
    }
    let gaps = words.next()?.parse::<usize>().ok()?;
    Some((gaps, stages))
}

/// What is wrong with a text whose own count of the stages it did not run
/// disagrees with the markers in it, or `None` when the two are one fact.
///
/// The rule is a relation and not a number. A run prints how many of its stages
/// did not run and marks each of them in the stage log above that sentence, so
/// the number in the sentence and the number of marked lines in the same text
/// are one fact about one run — **on a machine with a store and on a machine
/// without one, at whatever count each of them produces.** `1 of the 12` cannot
/// be the assertion: it is a reading of one machine, and a check that fails
/// because the reader's machine differs from the author's is worse than no check.
///
/// `what` names the text, because this is applied to two of them: the output the
/// journey just produced here, and the transcript the document quotes.
fn not_checked_disagreement(what: &str, text: &str) -> Option<String> {
    let marked = text.matches(NOT_CHECKED_MARKER).count();
    let Some((gaps, stages)) = gap_counts(text) else {
        if marked == 0 {
            // A run in which every stage ran prints no such sentence and marks
            // nothing, and there is nothing here to disagree with.
            return None;
        }
        return Some(format!(
            "{what}: {marked} line(s) carry the {NOT_CHECKED_MARKER} marker and nothing in it says \
             how many stages did not run, so a reader is shown a list of gaps with no count beside \
             it — which is what a deleted number looks like."
        ));
    };
    if gaps == marked {
        return None;
    }
    Some(format!(
        "{what}: the run says {gaps} of the {stages} stages did not run, and {marked} line(s) in \
         the same text carry the {NOT_CHECKED_MARKER} marker. The sentence counts the marked lines \
         above it, so this text says two different things about one run: the number was edited, or \
         a line was. Both machines satisfy the rule at their own count — 2 on a machine that has \
         never used SURE and 1 on a machine with a store — and what no machine satisfies is a \
         number that disagrees with its own markers."
    ))
}

/// The two stage lines that make a quoted run a run of a machine that has never
/// used SURE — the document's decision, held as a fact its rules read.
///
/// A relation rule alone can be satisfied by editing both sides at once: drop
/// stage 9's line and lower the count to match, and the sentence still agrees
/// with the markers in front of it while the document has gone back to being the
/// transcript of a machine that has used SURE, under a paragraph that says the
/// opposite. That is the shape this pins shut.
///
/// Stage 8 is not run wherever no analysis provider is configured, and stage 9 is
/// not run where nothing has been recorded — so a run of a machine that has never
/// used SURE marks both, and **both lines are required inside the quoted run**,
/// not anywhere in the file: a line that moved out of the fence stopped being
/// part of the transcript a reader copies from. With the two lines held, `2` is
/// the only count the sentence under them can honestly carry: any other number
/// either disagrees with the markers (the relation rule) or counts a run this
/// document does not quote (this one).
///
/// It is a fact about the file and not about the machine reading it, which is why
/// it is safe to require on every runner: nothing here reads a store, an
/// environment variable or a provider. The live run keeps only the relation
/// rule — on a machine with a store the command really does mark one stage and
/// print `1`, and that is a measurement of the machine rather than a claim about
/// the document.
const BARE_MACHINE_LINES: &[(&str, &str)] = &[
    (
        "This is a scope limit and not a failure: the deterministic checks are unaffected. (NOT CHECKED)",
        "stage 8 is not run on any machine this document is written for, so a run that stopped \
         showing it stopped showing the first line the count is counting",
    ),
    (
        "Check what was claimed against the evidence: SURE has no recorded history for this \
         machine, so there are no agent claims to check against evidence. (NOT CHECKED)",
        "stage 9 is the one line a reader who has already used SURE sees differently, and the \
         document's decision is that its quote is the bare-machine run: without this line the \
         transcript is a with-store run and the paragraph above it says the opposite, which is a \
         document contradicting itself with no rule to notice",
    ),
];

/// The lines a quoted run must show, looked for inside the run itself.
///
/// Squashed, for the same reason the sentence is: a Markdown paragraph is
/// reflowed by every editor that touches it, and this is a rule about a line the
/// product printed rather than about where a document broke it.
fn bare_machine_disagreements(what: &str, run: &str) -> Vec<String> {
    let squashed_run = squashed(run);
    BARE_MACHINE_LINES
        .iter()
        .filter(|(line, _)| !squashed_run.contains(&squashed(line)))
        .map(|(line, why)| format!("{what} does not carry {line:?}, and {why}"))
        .collect()
}

/// The fenced blocks of a Markdown document that hold a run of `sure check`.
///
/// A run opens with the line the command prints about the project it read, and
/// that is what is looked for rather than a particular fence or heading: a
/// document that moved its transcript, or grew a second one, is a document whose
/// runs are all held to this rule rather than one whose run is no longer read at
/// all.
fn quoted_runs(text: &str) -> Vec<String> {
    let mut runs = Vec::new();
    let mut inside = false;
    let mut block = String::new();
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            if inside && block.contains("SURE checked ") {
                runs.push(block.clone());
            }
            block.clear();
            inside = !inside;
            continue;
        }
        if inside {
            block.push_str(line);
            block.push('\n');
        }
    }
    runs
}

/// Every run a document quotes, held to what it is a run of and to the count it
/// prints about itself.
///
/// The document is what a reader follows, so the transcript in it is held to the
/// same rule the live run is held to. A document whose quote says one number
/// while marking another is a document describing a run that did not happen,
/// whether or not the machine it was taken on is the machine you are reading it
/// on.
///
/// And the quoted run is held to being **the run this document decided to quote**
/// — the bare-machine one — because the relation alone is satisfiable by editing
/// the number and the lines together. Two rules, because they fail differently:
/// `bare_machine_disagreements` says which run this is not, and
/// `not_checked_disagreement` says the run it is does not agree with itself.
fn quoted_run_violations(path: &str, text: &str) -> Vec<String> {
    if text.trim().is_empty() {
        return vec![format!(
            "{path} was read as empty, so nothing here says whether the run it quotes still counts \
             the stages it did not run"
        )];
    }
    let runs = quoted_runs(text);
    if runs.is_empty() {
        return vec![format!(
            "{path} quotes no run of `sure check`, so the walk a reader follows ends in a command \
             whose output the document no longer shows them, and the rule that holds a quoted \
             count to the quoted markers has nothing to read"
        )];
    }
    let mut out: Vec<String> = Vec::new();
    for (index, run) in runs.iter().enumerate() {
        let what = if runs.len() == 1 {
            format!("the run {path} quotes")
        } else {
            format!("run {} of the runs {path} quotes", index + 1)
        };
        // Which run this is, before what it counts: a transcript that stopped
        // being the bare-machine run is a different run rather than a wrong sum.
        out.extend(bare_machine_disagreements(&what, run));
        out.extend(not_checked_disagreement(&what, run));
    }
    out.dedup();
    out
}

/// A tracked file of the checkout, with its line endings normalized to LF.
fn read(relative: &str) -> String {
    let path = repository_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        .replace("\r\n", "\n")
}

/// Every file of the corpus, as text, in the order `CORPUS` names them.
fn corpus_texts() -> Vec<(&'static str, String)> {
    CORPUS.iter().map(|path| (*path, read(path))).collect()
}

/// Every rule, over the corpus.
///
/// Empty means the quickstart still walks a reader from nothing to a verdict and
/// still says honestly where an archive can come from. It is a function of the
/// texts so that the ways each rule could go false can be fed to it: the edits in
/// `BREAKS` never touch the real files.
fn quickstart_violations(files: &[(&str, String)]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let text_of = |wanted: &str| -> Option<&str> {
        files
            .iter()
            .find(|(path, _)| *path == wanted)
            .map(|(_, text)| text.as_str())
    };

    // Every file a rule is about has to be there. A file that went missing is a
    // rule passing because it had nothing to read.
    for path in CORPUS {
        if text_of(path).is_none() {
            out.push(format!(
                "{path} is a file a rule here reads and it was not read at all, so every rule \
                 about it passed on nothing"
            ));
        }
    }

    if let Some(text) = text_of(QUICKSTART) {
        out.extend(required_in(QUICKSTART, text, QUICKSTART_REQUIRED));
        out.extend(forbidden_in(QUICKSTART, text, DOWNLOAD_PROMISES));
        out.extend(quoted_run_violations(QUICKSTART, text));
    }
    if let Some(text) = text_of(INSTALL_WINDOWS) {
        out.extend(required_in(INSTALL_WINDOWS, text, INSTALL_WINDOWS_REQUIRED));
    }
    if let Some(text) = text_of(RELEASE_WORKFLOW) {
        out.extend(release_workflow_violations(text));
    }
    if let Some(text) = text_of(DRY_RUN_WORKFLOW) {
        out.extend(dry_run_violations(text));
    }

    out.dedup();
    out
}

// --- The repository, against every rule ----------------------------------

#[test]
fn the_windows_quickstart_satisfies_every_rule() {
    let found = quickstart_violations(&corpus_texts());
    assert!(
        found.is_empty(),
        "the Windows quickstart no longer carries what this task asks of it:\n{}",
        found
            .iter()
            .map(|violation| format!("  - {violation}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The reader found the mechanism rather than inventing a pass.
///
/// Without this, a reader that came back with an empty string would satisfy every
/// "does not carry" rule — the failure mode of a checker that is green because it
/// is blind.
#[test]
fn the_reader_sees_the_mechanism_that_is_there() {
    for (path, text) in &corpus_texts() {
        assert!(
            text.len() > 200,
            "{path} was read as {} bytes, which is not a file this repository has",
            text.len()
        );
    }

    // The document really does say the thing the rules are about, in the words
    // the rules forbid the neighbours of.
    let quickstart = read(QUICKSTART);
    for anchor in [
        "no published archive",
        "no SURE to download today",
        "runs through a Rust toolchain",
        "& .\\scripts\\Build-Release.ps1 -Phase All",
    ] {
        assert!(
            quickstart.contains(anchor),
            "the reader did not find {anchor:?} in {QUICKSTART}, so the rule that holds it is \
             passing because the reader is blind rather than because the document is right"
        );
    }

    // And the structural rules are reading files that carry the structure they
    // look for, rather than two files that happen to be empty of it.
    let workflow = read(RELEASE_WORKFLOW);
    assert!(
        workflow_code_lines(&workflow)
            .iter()
            .any(|line| line.contains("gh release create \"$TAG\"")),
        "the release workflow's lines were read without finding the create in them, so the rule \
         about it is passing because it is blind rather than because the file is right"
    );
    assert_eq!(
        workflow_dispatch_inputs(&workflow),
        ["tag"],
        "the input reader did not find the one `tag` input this document names in {RELEASE_WORKFLOW}"
    );
    let dry_run = read(DRY_RUN_WORKFLOW);
    assert_eq!(
        workflow_jobs(&dry_run),
        [
            "validate",
            "package-macos",
            "package-macos-intel",
            "package-linux"
        ],
        "the job reader did not find the four jobs this document names in {DRY_RUN_WORKFLOW}"
    );
}

/// An empty corpus is not a pass, and neither is one file missing.
#[test]
fn a_file_that_is_not_there_is_not_a_pass() {
    let found = quickstart_violations(&[]);
    assert!(
        !found.is_empty(),
        "an empty corpus satisfied every rule, so the rules here prove nothing about the files \
         that are there"
    );
    for wanted in CORPUS {
        assert!(
            found.iter().any(|violation| violation.contains(wanted)),
            "a corpus with nothing in it produced no complaint about {wanted}: {found:#?}"
        );
    }

    // A file that is there and empty is not a pass either: `required_in` has to
    // complain rather than find every one of its anchors absent from nothing.
    let with_an_empty_quickstart = corpus_texts()
        .into_iter()
        .map(|(path, text)| {
            if path == QUICKSTART {
                (path, String::new())
            } else {
                (path, text)
            }
        })
        .collect::<Vec<_>>();
    let found = quickstart_violations(&with_an_empty_quickstart);
    assert!(
        found
            .iter()
            .any(|violation| violation.contains("was read as empty")),
        "an empty {QUICKSTART} was read as satisfying its presence rules: {found:#?}"
    );
}

/// The two stagings are one staging.
///
/// This file and `install_flow.rs` both stage the archive
/// `docs/development/RELEASE_PROCESS.md` specifies, because neither can depend on
/// `Build-Release.ps1 -Phase All`. Two copies of a fixture are two fixtures unless
/// something reddens when they drift, and the thing they would drift about is the
/// documented layout itself.
#[test]
fn the_two_stagers_are_one_stager() {
    let install_flow = read(INSTALL_FLOW);
    assert_eq!(stager_disagreement(&install_flow, STAGE_AND_PACK), None);

    // And the rule can fail: one character changed in one copy is a complaint,
    // which is the only reason the assertion above is worth anything.
    let broken = STAGE_AND_PACK.replace("$Version-$Target", "$Version.$Target");
    assert_ne!(
        broken, STAGE_AND_PACK,
        "the mutation has to change something"
    );
    let complaint =
        stager_disagreement(&install_flow, &broken).expect("a changed copy is a disagreement");
    assert!(
        complaint.contains("first differ at byte"),
        "the disagreement did not say where: {complaint}"
    );
    let gone = stager_disagreement("fn main() {}\n", STAGE_AND_PACK)
        .expect("a file with no literal at all is a disagreement");
    assert!(
        gone.contains("stopped being able to measure anything"),
        "a source with no literal in it was read as agreement: {gone}"
    );
}

// --- The rules against edits that break them ------------------------------

/// An edit to one of the real files that must turn a rule red.
struct Break {
    /// What the edit is, in a sentence.
    what: &'static str,
    /// Which file the edit is made to.
    file: &'static str,
    /// Text taken out of that file as it stands.
    from: &'static str,
    /// What goes in its place.
    to: &'static str,
    /// Text the resulting violation has to carry.
    wanted: &'static str,
}

/// Every rule, broken the way it would really be broken.
///
/// Same discipline as `BREAKS` in `crates/sure-testkit/tests/
/// notarization_status.rs`, `signing_status.rs` and `ci_workflow.rs`: the edits
/// are taken from the files' own bytes rather than written as fixtures, so each
/// one proves the checker reacts to *these* files; and a `replace` that found
/// nothing is a failure rather than a pass, because that is the way this kind of
/// table rots into decoration.
///
/// The phrase entries are the ones a reader would actually write, and
/// `every_forbidden_phrase_is_one_this_reader_reports` below covers the rest of
/// the list.
const BREAKS: &[Break] = &[
    Break {
        what: "the section that says there is nothing to download is retitled out of existence",
        file: QUICKSTART,
        from: "## 1. There is no SURE to download today",
        to: "## 1. Getting SURE",
        wanted: "There is no SURE to download today",
    },
    Break {
        what: "the toolchain requirement stops being named as a requirement",
        file: QUICKSTART,
        from: "**Rust 1.98.1.** `rust-toolchain.toml` pins",
        to: "**A Rust toolchain.** `rust-toolchain.toml` pins",
        wanted: "**Rust 1.98.1.**",
    },
    Break {
        what: "the second prerequisite stops being named",
        file: QUICKSTART,
        from: "**Visual Studio Build Tools with the Desktop development with C++ workload**",
        to: "**a C++ linker**",
        wanted: "Visual Studio Build Tools",
    },
    Break {
        what: "the release gate stops being named",
        file: QUICKSTART,
        from: "cargo test -p sure-core --test acceptance_report_runner",
        to: "cargo test",
        wanted: "acceptance_report_runner",
    },
    Break {
        what: "the packager stops being named",
        file: QUICKSTART,
        from: "& .\\scripts\\Build-Release.ps1 -Phase All",
        to: "& .\\scripts\\Build-Release.ps1",
        wanted: "-Phase All",
    },
    Break {
        what: "the install command stops being named",
        file: QUICKSTART,
        from: "& .\\scripts\\Install-Sure.ps1 -Archive .\\target\\tmp\\release\\sure-0.1.3-x86_64-pc-windows-msvc.zip",
        to: "Run the installer, naming the archive.",
        wanted: "Install-Sure.ps1 -Archive",
    },
    Break {
        // The complaint quotes the anchor with `{:?}`, so a `wanted` that holds a
        // backslash has to spell it the way Debug prints it — the same reason
        // `signing_status.rs` writes `\"` inside a `wanted` of its own.
        what: "the install destination changes",
        file: QUICKSTART,
        from: "%LOCALAPPDATA%\\SURE\\bin\\sure.exe",
        to: "%LOCALAPPDATA%\\SURE\\sure.exe",
        wanted: "%LOCALAPPDATA%\\\\SURE\\\\bin\\\\sure.exe",
    },
    Break {
        what: "the integration command stops being named",
        file: QUICKSTART,
        from: "& .\\integrations\\claude-code\\scripts\\install.ps1 -ForceCopy",
        to: "Install the Claude Code integration from its directory.",
        wanted: "install.ps1 -ForceCopy",
    },
    Break {
        what: "the integration's destination changes",
        file: QUICKSTART,
        from: "%LOCALAPPDATA%\\claude-plugins\\sure",
        to: "%LOCALAPPDATA%\\sure-plugin",
        wanted: "%LOCALAPPDATA%\\\\claude-plugins\\\\sure",
    },
    Break {
        what: "the absolute-path rule stops being stated",
        file: QUICKSTART,
        from: "**The path has to be absolute.**",
        to: "The path is used as given.",
        wanted: "The path has to be absolute",
    },
    Break {
        what: "the quoted run stops saying what it returned",
        file: QUICKSTART,
        from: "SURE exited with status 1. That is what it returns when it checked the project",
        to: "SURE finished. That is what it returns when it checked the project",
        wanted: "SURE exited with status 1.",
    },
    Break {
        // The edit this task exists for, from the other side: the sentence keeps
        // the shape it had and the number in it stops being the number of lines
        // above it. A rule that accepted any digit would call this a pass.
        what: "the quoted run's count stops counting the lines it sits under",
        file: QUICKSTART,
        from: "2 of the 12 stages did not run",
        to: "3 of the 12 stages did not run",
        wanted: "says two different things about one run",
    },
    Break {
        // The same substitution from the other direction: the number is left
        // alone and one of the lines it counts stops being marked. A rule that
        // read only the sentence would call this a pass.
        what: "a stage the quoted run did not run stops being marked as one",
        file: QUICKSTART,
        from: "so there are no agent claims to check against evidence. (NOT CHECKED)",
        to: "so there are no agent claims to check against evidence.",
        wanted: "says two different things about one run",
    },
    Break {
        what: "the quoted run stops saying how many stages did not run",
        file: QUICKSTART,
        from: "2 of the 12 stages did not run, and each is marked NOT CHECKED above.",
        to: "Some of the stages above did not run.",
        wanted: "nothing in it says how many stages did not run",
    },
    Break {
        // The supervisor's probe of this task's acceptance, kept as a row: the
        // number and the lines it counts are edited **together**, so the sentence
        // still agrees with the markers in front of it and a rule that only
        // compares the two calls this a pass. That is the joint edit a
        // self-consistency rule cannot see, and it puts the document back where
        // this task found it — quoting a machine that has a store, under a
        // paragraph that says the quote is a bare machine's. What catches it is
        // the run-scoped anchor: the transcript stopped being a run of the
        // machine this document says it is a run of.
        what: "the quoted run goes back to a machine with a store, and its number goes back with it",
        file: QUICKSTART,
        from: "  9/12. Check what was claimed against the evidence: SURE has no recorded history for \
               this machine, so there are no agent claims to check against evidence. (NOT CHECKED)\n  \
               ...\n\n2 of the 12 stages did not run",
        to: "1 of the 12 stages did not run",
        wanted: "Check what was claimed against the evidence",
    },
    Break {
        // The same decision from the other side: the transcript is left as the
        // bare-machine run and the paragraph saying so is reworded to claim the
        // opposite. A claim in the document with no reader is the defect this
        // task is about, so the paragraph that names the machine is an anchor.
        what: "the paragraph says the quoted run came from a machine that has used SURE",
        file: QUICKSTART,
        from: "It is a run of a machine that has never used SURE",
        to: "It is a run of a machine that has used SURE before",
        wanted: "It is a run of a machine that has never used SURE",
    },
    Break {
        what: "the section naming the tests behind these claims is retitled out of existence",
        file: QUICKSTART,
        from: "## How \"documented and tested\" is satisfied here",
        to: "## Notes",
        // Without the quotes: the complaint quotes the anchor with `{:?}`, and a
        // `wanted` holding a `"` would have to spell the escape Debug prints.
        wanted: "documented and tested",
    },
    Break {
        what: "the limits stop being stated",
        file: QUICKSTART,
        from: "## What is not covered",
        to: "## Notes",
        wanted: "What is not covered",
    },
    Break {
        what: "a reader is sent to a download that does not exist",
        file: QUICKSTART,
        from: "If they are not on the machine, section 1 is why",
        to: "If they are not on the machine, download the archive. Section 1 is why",
        wanted: "download the archive",
    },
    Break {
        what: "the walk stops being reachable from the reference",
        file: INSTALL_WINDOWS,
        from: "docs/development/QUICKSTART_WINDOWS.md",
        to: "the quickstart",
        wanted: "QUICKSTART_WINDOWS.md",
    },
    Break {
        what: "the release workflow stops creating a release at all",
        file: RELEASE_WORKFLOW,
        from: "          gh release create \"$TAG\" \\",
        to: "          gh release view \"$TAG\" \\",
        wanted: "gh release create",
    },
    Break {
        what: "the release workflow gains a dispatch input",
        file: RELEASE_WORKFLOW,
        from: "    inputs:\n",
        to: "    inputs:\n      dry_run:\n        description: x\n        required: false\n        type: boolean\n",
        wanted: "workflow_dispatch",
    },
    Break {
        what: "the release workflow can publish a release",
        file: RELEASE_WORKFLOW,
        from: "            --draft \\",
        to: "            --draft=false \\",
        wanted: "--draft=false",
    },
    Break {
        what: "a step edits the draft into a release",
        file: RELEASE_WORKFLOW,
        from: "          gh release view \"$TAG\" --repo \"$GITHUB_REPOSITORY\" \\",
        to: "          gh release edit \"$TAG\" --repo \"$GITHUB_REPOSITORY\" --draft=false\n          gh release view \"$TAG\" --repo \"$GITHUB_REPOSITORY\" \\",
        wanted: "gh release edit",
    },
    Break {
        what: "the dry run gains a Windows packaging job",
        file: DRY_RUN_WORKFLOW,
        from: "jobs:\n",
        to: "jobs:\n  package-windows:\n    runs-on: windows-latest\n",
        wanted: "package-windows",
    },
    Break {
        what: "the dry run builds for the Windows target",
        file: DRY_RUN_WORKFLOW,
        from: "  validate:\n",
        to: "  validate:\n    env:\n      SURE_TARGET: x86_64-pc-windows-msvc\n",
        wanted: "x86_64-pc-windows-msvc",
    },
    Break {
        what: "the dry run starts producing a zip",
        file: DRY_RUN_WORKFLOW,
        from: "  validate:\n",
        to: "  validate:\n    env:\n      ARCHIVE: sure-0.0.0.zip\n",
        wanted: ".zip",
    },
];

#[test]
fn every_rule_is_turned_red_by_an_edit_that_breaks_it() {
    let real = corpus_texts();
    assert!(
        quickstart_violations(&real).is_empty(),
        "the files are already failing a rule, so no edit below can be said to have broken it:\n{:#?}",
        quickstart_violations(&real)
    );
    for edit in BREAKS {
        let mut edited = real.clone();
        let mut applied = false;
        for (path, text) in edited.iter_mut() {
            if *path != edit.file {
                continue;
            }
            let after = text.replace(edit.from, edit.to);
            assert_ne!(
                after, *text,
                "\"{}\" edits text that is not in {} any more ({}), so it would have mutated \
                 nothing and passed for that reason instead. The table has to be re-pointed at what \
                 the file says now.",
                edit.what, edit.file, edit.from
            );
            *text = after;
            applied = true;
        }
        assert!(
            applied,
            "\"{}\" names the file {} and no such file was read",
            edit.what, edit.file
        );
        let found = quickstart_violations(&edited);
        assert!(
            found
                .iter()
                .any(|violation| violation.contains(edit.wanted)),
            "breaking `{}` produced no violation carrying {:?}:\n{found:#?}",
            edit.what,
            edit.wanted
        );
    }
}

/// Every forbidden phrase is one this reader reports.
///
/// The same test `FORBIDDEN_ACTS` and `PUBLICATION_CHANNELS` have in
/// `ci_workflow.rs`, and `every_forbidden_phrase_is_one_this_reader_reports` has
/// in `signing_status.rs`, for the same reason: a list of phrases is decoration
/// unless each entry is one the rule actually finds. Each phrase is injected
/// into the real document as a real sentence and the rules are required to name
/// it, so a typo in the list, or an entry the rule stopped reading, is a red
/// test rather than a line in a table that looks like a check.
#[test]
fn every_forbidden_phrase_is_one_this_reader_reports() {
    let real = corpus_texts();
    assert!(quickstart_violations(&real).is_empty());

    for (phrase, why) in DOWNLOAD_PROMISES {
        let mut edited = real.clone();
        for (path, text) in edited.iter_mut() {
            if *path == QUICKSTART {
                *text = format!("{text}\nAnd then: {phrase}.\n");
            }
        }
        let found = quickstart_violations(&edited);
        assert!(
            found.iter().any(|violation| violation.contains(phrase)),
            "injecting {phrase:?} ({why}) into {QUICKSTART} produced no violation naming it, so the \
             entry is a line in a list rather than a check:\n{found:#?}"
        );
    }
}
