//! The WinGet manifest template, and the script that renders it from an archive.
//!
//! `P15-T004`'s acceptance is that the template "references stable release
//! artifact/checksum and documents update process", and that publication itself
//! may stay external. The hazard behind that sentence is the reason this file
//! exists: a manifest is a set of confident claims about a file that is not in
//! this repository — a version, a URL and a SHA-256 — and a plausible-looking
//! 64-hex constant in a committed YAML is exactly the artefact SURE exists to
//! refuse. So the tests below are in two groups:
//!
//! * the **template** is read as text, on every platform, and has to carry the
//!   two placeholders and no digest at all;
//! * the **script** (`scripts/New-WingetManifest.ps1`) is run against a real
//!   archive, and what it writes has to match the bytes it was given — with
//!   falsifiers for the three ways that could be quietly untrue (a corrupt
//!   archive, a hand-edited digest, a version the binary does not report).
//!
//! # What "a real archive" means here, and what it does not
//!
//! `P15-T002`'s archive is produced by `scripts/Build-Release.ps1`, which
//! refuses to package without the release gate and takes minutes to run a
//! release build. A test cannot depend on that, so — exactly as
//! `crates/sure-cli/tests/install_flow.rs` does — this file stages the
//! *documented layout* around the binary cargo just built. What the script
//! reads is a real ZIP with real bytes in it and a real `sure.exe` inside; what
//! it is not is the release build, and this comment is where that difference is
//! stated rather than left for a reader to assume.
//!
//! One thing the staged archive does carry that a stand-in would not: its name
//! and the version the binary reports are **the same string**, because the test
//! asks the binary for its own version first. That is the property the manifest
//! depends on, so a fixture that made it up would be testing a fiction.
//!
//! # What this file cannot check
//!
//! `winget validate` reads a manifest and answers about its schema. It does not
//! download an archive, and it cannot: `InstallerUrl` points at a GitHub release
//! asset that does not exist yet. Nothing here installs a package (`winget
//! install` changes the machine, and the rules this task was given forbid it),
//! so "WinGet installs this correctly" is **not** measured anywhere in this
//! repository. `docs/development/INSTALL_WINGET.md` says so where a reader will
//! meet it, and `install_flow.rs` is the file that measures what SURE's own
//! installer does.
//!
//! The template half of this file needs no Windows; the script and launcher
//! halves are gated, because a per-user `%LOCALAPPDATA%` install and a
//! PowerShell host are Windows things and `CLAUDE.md`'s portability requirement
//! is about the Rust core.
//!
//! # One `winget` at a time
//!
//! `cargo test` runs one binary's cases in parallel, and this file has four that
//! end in `winget validate`. Two of those at once make winget exit
//! `-1978335231` — a failure to run the check at all, not a verdict on the
//! manifest — and the run that meets it fails about one time in three. Every
//! call here that can reach winget holds one process-wide lock, so the file
//! passes however cargo schedules it. The lock's own comment has the
//! measurement.

// The workspace forbids `unwrap`, `expect` and `panic` in shipped code, because
// a panic is a message nobody chose. A test is the one place they are the point:
// the panic *is* the report, and it names the value that was wrong.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .to_path_buf()
}

fn template_directory() -> PathBuf {
    repository_root()
        .join("packaging")
        .join("winget")
        .join("template")
}

fn manifest_script() -> PathBuf {
    repository_root()
        .join("scripts")
        .join("New-WingetManifest.ps1")
}

/// The three template files, read with their line endings normalized.
///
/// `.gitattributes` declares `*.ps1 text eol=crlf` and everything else LF, and
/// this machine's checkout is not the only place these are read, so a comparison
/// written against LF has to normalize rather than assume. The same reason — and
/// the same shape — as `script_text` in `install_flow.rs`.
fn template_text(name: &str) -> String {
    let path = template_directory().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        .replace("\r\n", "\n")
}

/// What `Cargo.toml` says the repository is and under what license.
///
/// Read rather than restated: the manifest's identity is a claim about *this*
/// repository, so a test that hard-codes the same string twice would agree with
/// itself while the repository moved.
fn workspace_metadata() -> (String, String) {
    let text = std::fs::read_to_string(repository_root().join("Cargo.toml"))
        .expect("the workspace manifest can be read");
    let field = |name: &str| -> String {
        let prefix = format!("{name} = \"");
        text.lines()
            .find_map(|line| line.trim().strip_prefix(prefix.as_str()))
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or_else(|| panic!("no `{name} = \"...\"` line in the workspace Cargo.toml"))
            .to_owned()
    };
    (field("repository"), field("license"))
}

/// The value a manifest line carries, or a panic naming what was missing.
///
/// A YAML sequence entry is `- Name: value`, so the leading dash is part of the
/// line and not of the name. This reads one value and refuses when there is more
/// than one, because "which of the two `InstallerSha256` lines did you mean" is
/// a question a test should never be able to ask by accident.
fn manifest_field(text: &str, name: &str) -> String {
    let prefix = format!("{name}:");
    let found: Vec<&str> = text
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let line = line.strip_prefix("- ").unwrap_or(line);
            line.strip_prefix(prefix.as_str())
        })
        .collect();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one `{name}:` line, found {}: {found:?}",
        found.len()
    );
    found[0].trim().to_owned()
}

/// The two placeholders, and the fence that keeps the template's notes out of
/// what gets published. These spellings are the contract between the templates
/// and `scripts/New-WingetManifest.ps1`; both ends are checked against them.
const VERSION_TOKEN: &str = "<version>";
const DIGEST_TOKEN: &str = "<sha256-of-the-archive>";
const NOTES_BEGIN: &str = "# >>> template notes: removed when this file is rendered";
const NOTES_END: &str = "# <<< end of template notes";

fn template_files() -> [&'static str; 3] {
    [
        "lichman0405.SURE.yaml",
        "lichman0405.SURE.installer.yaml",
        "lichman0405.SURE.locale.en-US.yaml",
    ]
}

// --- The template, on every platform -------------------------------------

/// The test this task exists for.
///
/// A 64-hex run anywhere in a committed template is a digest nobody computed
/// from bytes anybody built, and it is the one thing a manifest must never
/// carry without a build behind it. `target/tmp` holds digests during a real
/// run; the repository does not. This is checked on every platform, in every CI
/// job, because the check costs nothing and the hazard does not care which
/// machine noticed it.
#[test]
fn no_committed_template_carries_a_digest() {
    for name in template_files() {
        let text = template_text(name);
        for (index, line) in text.lines().enumerate() {
            let lowercase = line.to_lowercase();
            let mut run = String::new();
            for character in lowercase.chars() {
                if character.is_ascii_hexdigit() {
                    run.push(character);
                    if run.len() == 64 {
                        panic!(
                            "{name}:{}: a 64-hex run is in the template, and no build of any \
                             bytes produced it:\n{line}",
                            index + 1
                        );
                    }
                } else {
                    run.clear();
                }
            }
        }
    }
}

/// Every placeholder is one of the two known ones, and each of the two is
/// present where it has to be.
///
/// The first half is what stops a third placeholder appearing that the renderer
/// would substitute nothing for, leaving a literal token in a published field.
/// The second half is what stops a template quietly losing the digest token and
/// gaining a hand-written value instead.
#[test]
fn the_only_placeholders_are_the_two_the_renderer_substitutes() {
    for name in template_files() {
        let text = template_text(name);
        let mut tokens: Vec<String> = Vec::new();
        for line in text.lines() {
            // The fence lines carry `>>>` and `<<<`, which are not placeholders
            // and are not published either; the fence itself has its own test.
            if line.contains(NOTES_BEGIN) || line.contains(NOTES_END) {
                continue;
            }
            let mut rest = line;
            while let Some(start) = rest.find('<') {
                let after = &rest[start..];
                let Some(end) = after.find('>') else { break };
                let token = &after[..=end];
                // A placeholder is `<name>` and nothing else: no spaces, no
                // sentence inside it. Prose that happens to use the two
                // characters is prose, and is left alone.
                let inner = &token[1..token.len() - 1];
                if !inner.is_empty()
                    && inner
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    tokens.push(token.to_owned());
                }
                rest = &after[end + 1..];
            }
        }
        for token in &tokens {
            assert!(
                token == VERSION_TOKEN || token == DIGEST_TOKEN,
                "{name} carries {token}, which is neither {VERSION_TOKEN} nor {DIGEST_TOKEN}"
            );
        }
        assert!(
            tokens.iter().any(|token| token == VERSION_TOKEN),
            "{name} does not carry {VERSION_TOKEN}"
        );
    }

    // The installer manifest is where the digest token has to be, in the field
    // that decides what a user's machine checks after the download.
    let installer = template_text("lichman0405.SURE.installer.yaml");
    assert_eq!(
        manifest_field(&installer, "InstallerSha256"),
        DIGEST_TOKEN,
        "the installer template's InstallerSha256 is not the placeholder"
    );
    let version = template_text("lichman0405.SURE.yaml");
    assert_eq!(
        manifest_field(&version, "PackageVersion"),
        VERSION_TOKEN,
        "the version template's PackageVersion is not the placeholder"
    );
}

/// The identity the manifest claims is the repository's own.
///
/// `P15-T004`'s rule is that the publisher identity is not this task's to
/// invent. The `PackageIdentifier`'s prefix is a claim on a name someone owns
/// — the owner of the repository URL — the URLs are the repository URL, and the
/// license is the workspace's. A fork that changes `Cargo.toml` fails here, and
/// `scripts/New-WingetManifest.ps1` refuses to render until the templates say
/// the same thing.
#[test]
fn the_identity_is_the_one_cargo_toml_states() {
    let (repository, license) = workspace_metadata();
    let owner = repository
        .rsplit('/')
        .nth(1)
        .unwrap_or_else(|| panic!("{repository} does not name an owner"));
    let locale = template_text("lichman0405.SURE.locale.en-US.yaml");

    assert_eq!(manifest_field(&locale, "PackageUrl"), repository);
    assert_eq!(manifest_field(&locale, "License"), license);
    assert_eq!(manifest_field(&locale, "Publisher"), owner);

    for name in template_files() {
        let text = template_text(name);
        let identifier = manifest_field(&text, "PackageIdentifier");
        assert!(
            identifier.starts_with(&format!("{owner}.")),
            "{name} claims the identifier {identifier}, and {repository} belongs to {owner}"
        );
        assert_eq!(
            manifest_field(&text, "PackageVersion"),
            VERSION_TOKEN,
            "{name} does not carry the version placeholder"
        );
    }

    // `PublisherUrl` is the origin plus the owner, spelled out here rather than
    // derived from the identifier, because a `PackageIdentifier` is
    // reverse-DNS-*shaped* and not a URL. The assertion above is the equality;
    // this one says which string it is, so a wrong URL is reported as one.
    let origin = repository
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .map(|host| format!("https://{host}"))
        .unwrap_or_else(|| panic!("{repository} is not an https repository URL"));
    assert_eq!(
        manifest_field(&locale, "PublisherUrl"),
        format!("{origin}/{owner}")
    );
}

/// The templates carry the fence the renderer removes, exactly once each.
///
/// Without it a rendered manifest opens with "THIS IS A TEMPLATE, NOT A
/// MANIFEST" and a note saying no digest is written down — next to a digest.
/// The script refuses a template without the fence; this is the other end of the
/// same contract.
#[test]
fn every_template_carries_the_fence_that_is_stripped_when_it_is_rendered() {
    for name in template_files() {
        let text = template_text(name);
        assert_eq!(
            text.matches(NOTES_BEGIN).count(),
            1,
            "{name} does not carry the opening fence line exactly once"
        );
        assert_eq!(
            text.matches(NOTES_END).count(),
            1,
            "{name} does not carry the closing fence line exactly once"
        );
        let first = text.lines().next().unwrap_or_default();
        assert!(
            first.starts_with("# yaml-language-server: $schema=https://aka.ms/winget-manifest."),
            "{name} does not open with the schema comment, so an editor cannot tell which \
             schema it is: {first}"
        );
    }
}

/// The schema version the script writes is the one the templates declare.
///
/// They are two files and one value, so a bump on either side has to redden
/// here rather than produce manifests the script then refuses for a reason
/// nobody expected.
#[test]
fn the_script_checks_against_the_schema_version_the_templates_declare() {
    let script = std::fs::read_to_string(manifest_script()).expect("the script can be read");
    let declaration = script
        .lines()
        .find(|line| line.contains("$SchemaVersion = '"))
        .expect("the script declares the schema version it writes")
        .trim()
        .trim_start_matches("$SchemaVersion = '")
        .trim_end_matches('\'')
        .to_owned();
    for name in template_files() {
        let text = template_text(name);
        assert_eq!(
            manifest_field(&text, "ManifestVersion"),
            declaration,
            "{name} declares a different schema version from the script's $SchemaVersion"
        );
    }
}

// --- The script and the launchers, on Windows ----------------------------

#[cfg(windows)]
mod driven_by_powershell {
    use std::ffi::OsStr;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};
    use std::sync::{Mutex, MutexGuard};

    use serde_json::json;
    use sure_cli::mcp::PROTOCOL_VERSION;

    use super::{
        DIGEST_TOKEN, VERSION_TOKEN, manifest_field, manifest_script, repository_root,
        template_directory,
    };

    /// One `winget` at a time on this machine.
    ///
    /// Measured, and it cost this file a flake before it was understood: two of
    /// these tests each ending in `winget validate`, running at the same time,
    /// make winget exit `-1978335231` — a failure to *run* the check at all,
    /// which is a different code from the `-1978335192` it returns for a
    /// manifest it will not accept. The run that meets it fails, and it fails
    /// about one run in three, which is the worst way for a test to be wrong.
    /// The script is right to report it as a failure rather than a pass; what
    /// was wrong is asking for it, and that is what this lock is for.
    ///
    /// A poisoned lock is taken rather than propagated: a panic while holding it
    /// says something about the test that panicked, and making every other test
    /// in the file fail with "poisoned" would hide which one that was.
    static WINGET: Mutex<()> = Mutex::new(());

    fn one_winget_at_a_time() -> MutexGuard<'static, ()> {
        WINGET
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The binary this package builds, as cargo hands it to its integration
    /// tests. It is what goes into the staged archive, so the `sure.exe` the
    /// script runs and reads a version from is the one cargo produced.
    const SURE: &str = env!("CARGO_BIN_EXE_sure");

    /// The version the binary reports about itself, as `sure version --format
    /// json` gives it. Read from the binary rather than taken from
    /// `Cargo.toml`, because the manifest's `PackageVersion` is a claim about
    /// the program a user runs.
    fn reported_version(host: &Path) -> String {
        let output = Command::new(host)
            .arg("-NoProfile")
            .arg("-Command")
            .arg(format!("& '{}' version --format json", SURE))
            .output()
            .expect("the built binary can be asked its version");
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        let value: serde_json::Value = serde_json::from_str(text.trim())
            .unwrap_or_else(|error| panic!("`sure version --format json` gave {text:?}: {error}"));
        value["sure_version"]
            .as_str()
            .unwrap_or_else(|| panic!("no `sure_version` in {text:?}"))
            .to_owned()
    }

    // --- The hosts --------------------------------------------------------

    fn windows_powershell() -> PathBuf {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        PathBuf::from(root).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    }

    /// Windows PowerShell, which is always there. `install_flow.rs` runs the
    /// whole flow under both hosts; this file drives one, because what is being
    /// tested here is a text transformation and a schema check rather than a
    /// second PowerShell's idea of them.
    fn a_host() -> PathBuf {
        windows_powershell()
    }

    /// A directory of this test's own, under the workspace's git-ignored
    /// `target/tmp`, by way of `sure_testkit::scratch` — which holds the
    /// reasoning these helpers used to repeat.
    ///
    /// The name carries a space and a non-ASCII character because `CLAUDE.md`
    /// says to test paths with spaces and Unicode, and this flow carries one
    /// path through PowerShell's argument parsing, a ZIP, a YAML file and back
    /// out. A failed test's directory survives the run that made it, which is
    /// what it is for; a later run under the same process id reclaims it.
    fn a_directory_of_our_own(what: &str) -> PathBuf {
        sure_testkit::scratch::directory("sure winget manifest é中文 and spaces", what)
    }

    // --- Running things ---------------------------------------------------

    struct Run {
        status: i32,
        stdout: String,
        stderr: String,
    }

    impl Run {
        fn of(output: Output) -> Self {
            Self {
                status: output.status.code().expect("the process exited on its own"),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
        }

        fn everything(&self) -> String {
            format!("{}{}", self.stdout, self.stderr)
        }
    }

    /// Run one of this repository's scripts with typed arguments, which is
    /// `CLAUDE.md`'s Windows rule and the reason a path with a space and a
    /// non-ASCII character survives to the other side.
    fn run_script(host: &Path, script: &Path, arguments: &[&OsStr]) -> Run {
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
            .unwrap_or_else(|error| panic!("could not start {}: {error}", script.display()));
        Run::of(output)
    }

    /// The same, with a `PATH` the caller chooses: this is how "winget is not
    /// installed" is asked, without uninstalling anything.
    fn run_script_with_path(host: &Path, script: &Path, arguments: &[&OsStr], path: &Path) -> Run {
        let output = Command::new(host)
            .arg("-NoProfile")
            .arg("-File")
            .arg(script)
            .args(arguments)
            .env("PATH", path)
            .output()
            .unwrap_or_else(|error| panic!("could not start {}: {error}", script.display()));
        Run::of(output)
    }

    // --- The archive the test renders from --------------------------------

    /// The staging script, written into a scratch directory and run by a host.
    ///
    /// This is the fixture `crates/sure-cli/tests/install_flow.rs` uses, and it
    /// is deliberately a second copy rather than a shared helper: a test file
    /// in this repository stands on its own, the way `mcp_protocol.rs` and
    /// `install_flow.rs` each carry their own `powershell()`, so that reading
    /// one file is enough to know what a test does. `Build-Release.ps1` is the
    /// real producer of this layout; this only has to be the documented shape,
    /// and the comment at the top of this file says what that leaves out.
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
[System.IO.File]::WriteAllText((Join-Path $stage 'LICENSE'), "test fixture: the archive's LICENSE entry`n", [System.Text.ASCIIEncoding]::new())
[System.IO.File]::WriteAllText((Join-Path $stage 'RELEASE.txt'), "SURE $Version - a test fixture in the documented archive layout`n", [System.Text.ASCIIEncoding]::new())
$archive = Join-Path $ScratchRoot "$name.zip"
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $archive, [System.IO.Compression.CompressionLevel]::Optimal, $true)
# .NET rather than `Get-FileHash`: a PowerShell 7 session's `PSModulePath`
# reaching Windows PowerShell 5.1 leaves `Get-FileHash` undefined there.
$stream = [System.IO.File]::OpenRead($archive)
try { $hasher = [System.Security.Cryptography.SHA256]::Create(); try { $hash = $hasher.ComputeHash($stream) } finally { $hasher.Dispose() } } finally { $stream.Dispose() }
$digest = ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
[System.IO.File]::WriteAllText("$archive.sha256", "$digest  $name.zip`n", [System.Text.Encoding]::ASCII)
# The Rust reader expects UTF-8; Windows PowerShell 5.1 otherwise writes the
# console's code page, which corrupts the Unicode path returned below.
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Write-Output $archive
"#;

    /// An archive in the layout `docs/development/RELEASE_PROCESS.md` records,
    /// with its checksum, both inside `scratch`. `version` is what goes in the
    /// file name — and, when the caller passes the version the binary reports,
    /// it is the same string the binary in it will answer with.
    fn a_release_archive(host: &Path, scratch: &Path, version: &str) -> (PathBuf, PathBuf) {
        let stager = scratch.join("stage-and-pack.ps1");
        // `run_script` hands this path to PowerShell and PowerShell starts it, so
        // it goes in by the door for programs — written beside its own name,
        // closed there, renamed onto it — rather than straight to the path the
        // interpreter is about to be given. See `sure_testkit::program`.
        sure_testkit::write_program(&stager, STAGE_AND_PACK.as_bytes(), 0o755)
            .expect("the staging script can be written");
        let scratch_text = scratch.to_string_lossy().into_owned();
        let run = run_script(
            host,
            &stager,
            &[
                OsStr::new("-PayloadExe"),
                OsStr::new(SURE),
                OsStr::new("-ScratchRoot"),
                OsStr::new(&scratch_text),
                OsStr::new("-Version"),
                OsStr::new(version),
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
        let scratch = a_directory_of_our_own("stager output encoding");
        let (archive, checksum) = a_release_archive(&a_host(), &scratch, "0.0.0-stager-test");
        assert!(archive.starts_with(&scratch), "{archive:?}");
        assert!(archive.is_file(), "{archive:?}");
        assert!(checksum.is_file(), "{checksum:?}");
    }

    /// The SHA-256 of a file, from a program that is not SURE and not the
    /// script under test.
    ///
    /// `certutil` ships with Windows, and it is the second implementation the
    /// digest is checked against: the script computes it with .NET, the staging
    /// script computes it with .NET, and this asks a third tool. Two copies of
    /// one implementation agreeing is what a wrong digest looks like when
    /// nobody notices.
    fn digest_by_certutil(path: &Path) -> String {
        let output = Command::new("certutil")
            .args(["-hashfile"])
            .arg(path)
            .arg("SHA256")
            .output()
            .unwrap_or_else(|error| {
                panic!(
                    "certutil could not be run ({error}), so this test cannot check the digest \
                     against a second implementation; it ships with Windows and this test needs \
                     it"
                )
            });
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.lines()
            .map(str::trim)
            .find(|line| line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or_else(|| panic!("certutil printed no digest for {}: {text}", path.display()))
            .to_lowercase()
    }

    // --- Rendering --------------------------------------------------------

    fn render(host: &Path, archive: &Path, output: &Path) -> Run {
        let _one_at_a_time = one_winget_at_a_time();
        let archive = archive.to_string_lossy().into_owned();
        let output = output.to_string_lossy().into_owned();
        run_script(
            host,
            &manifest_script(),
            &[
                OsStr::new("-Archive"),
                OsStr::new(&archive),
                OsStr::new("-OutputDirectory"),
                OsStr::new(&output),
            ],
        )
    }

    fn verify(host: &Path, manifests: &Path, archive: &Path) -> Run {
        let _one_at_a_time = one_winget_at_a_time();
        let manifests = manifests.to_string_lossy().into_owned();
        let archive = archive.to_string_lossy().into_owned();
        run_script(
            host,
            &manifest_script(),
            &[
                OsStr::new("-Phase"),
                OsStr::new("Verify"),
                OsStr::new("-ManifestDirectory"),
                OsStr::new(&manifests),
                OsStr::new("-Archive"),
                OsStr::new(&archive),
            ],
        )
    }

    /// Whether this machine has `winget` on `PATH`, which is where the script
    /// looks for it too.
    fn winget_on_path() -> bool {
        std::env::var_os("PATH").is_some_and(|path| {
            std::env::split_paths(&path).any(|directory| {
                directory.join("winget.exe").is_file() || directory.join("winget.cmd").is_file()
            })
        })
    }

    fn manifest_directory(output: &Path, identifier: &str, version: &str) -> PathBuf {
        output.join(identifier).join(version)
    }

    /// A step that has to have succeeded, with winget's absence named.
    ///
    /// The script exits 3 when it cannot run `winget validate`, and everything
    /// else it does has already passed at that point — so a bare
    /// `assert_eq!(status, 0)` would report a missing optional tool as a
    /// failure of the checks that did run. This says which one it was, and
    /// still fails: a step that could not be checked is not a step that passed,
    /// and a test that turned that into a green would be the thing this
    /// repository exists to refuse.
    fn succeeded(run: &Run, what: &str) -> String {
        let text = run.everything();
        if run.status == 3 {
            panic!(
                "{what} could not run `winget validate`, so it did not finish and this test \
                 cannot pass. Every check that did not need winget passed; the output below says \
                 which one did not happen. Install App Installer \
                 (https://aka.ms/getwinget) and run this again.\n{text}"
            );
        }
        assert_eq!(run.status, 0, "{what} failed:\n{text}");
        text
    }

    // --- The tests --------------------------------------------------------

    /// The whole point of the generator, end to end, against real bytes.
    ///
    /// It renders, then reads back every value the manifest claims and compares
    /// it with the archive it was given: the digest with a second hashing
    /// implementation, the version with the file name and the binary's own
    /// answer, the path inside the archive with the layout the ZIP extracted to,
    /// and the URL with what the repository metadata implies. Then `Verify`
    /// re-derives the same values from the written files, which is the check
    /// that a directory someone else produced can also pass.
    #[test]
    fn a_manifest_rendered_from_an_archive_claims_nothing_the_archive_does_not() {
        let host = a_host();
        let scratch = a_directory_of_our_own("render");
        let version = reported_version(&host);
        let (archive, checksum) = a_release_archive(&host, &scratch, &version);
        assert!(checksum.is_file(), "the staging script wrote no checksum");
        let output = scratch.join("manifests");

        let run = render(&host, &archive, &output);
        let text = succeeded(&run, "rendering a manifest from an archive");
        assert!(
            run.stdout.contains("OK: manifests rendered"),
            "the run did not say what it had done:\n{text}"
        );

        let manifests = manifest_directory(&output, "lichman0405.SURE", &version);
        let installer = std::fs::read_to_string(manifests.join("lichman0405.SURE.installer.yaml"))
            .expect("the installer manifest was written");
        let version_manifest = std::fs::read_to_string(manifests.join("lichman0405.SURE.yaml"))
            .expect("the version manifest was written");
        let locale = std::fs::read_to_string(manifests.join("lichman0405.SURE.locale.en-US.yaml"))
            .expect("the locale manifest was written");

        // The digest, against a third implementation.
        let expected = digest_by_certutil(&archive);
        assert_eq!(
            manifest_field(&installer, "InstallerSha256"),
            expected,
            "the manifest's digest is not the digest of the archive it was rendered from"
        );

        // The version, against the archive's name and the binary inside it.
        assert_eq!(manifest_field(&version_manifest, "PackageVersion"), version);
        assert_eq!(manifest_field(&installer, "PackageVersion"), version);
        assert_eq!(manifest_field(&locale, "PackageVersion"), version);

        // The path inside the archive, which is the one a wrong manifest gets
        // wrong *after* a user's download.
        assert_eq!(
            manifest_field(&installer, "RelativeFilePath"),
            format!("sure-{version}-x86_64-pc-windows-msvc/sure.exe")
        );
        assert_eq!(manifest_field(&installer, "PortableCommandAlias"), "sure");
        assert_eq!(manifest_field(&installer, "Architecture"), "x64");
        assert_eq!(manifest_field(&installer, "InstallerType"), "zip");
        assert_eq!(
            manifest_field(&installer, "NestedInstallerType"),
            "portable"
        );

        // No placeholder survived, and the notes the template carries for a
        // reader of this repository were not published.
        for (name, text) in [
            ("installer", &installer),
            ("version", &version_manifest),
            ("locale", &locale),
        ] {
            for token in [VERSION_TOKEN, DIGEST_TOKEN] {
                assert!(
                    !text.contains(token),
                    "the {name} manifest still carries {token}"
                );
            }
            assert!(
                !text.contains("THIS IS A TEMPLATE"),
                "the {name} manifest was published with the template's notes in it"
            );
            assert!(
                text.contains("# Rendered from"),
                "the {name} manifest does not say it was rendered from an archive"
            );
        }

        // And the second reader: `Verify` re-derives every value from the
        // archive rather than trusting the writer.
        let recheck = verify(&host, &manifests, &archive);
        let text = succeeded(&recheck, "verifying the manifest the renderer wrote");
        assert!(
            recheck.stdout.contains("OK: every value in"),
            "Verify did not say what it had checked:\n{text}"
        );
    }

    /// The falsifier for the sentence above: change the digest and the same
    /// `Verify` must refuse.
    ///
    /// The value written here is all zeros rather than a plausible digest, and
    /// it lives in `target/tmp` for the length of one test. No fabricated
    /// digest is ever written into this repository — that is the hazard this
    /// whole task is about, and a test that committed one to prove a point would
    /// be the defect it is guarding against.
    #[test]
    fn a_hand_edited_digest_is_refused_even_though_it_is_well_formed() {
        let host = a_host();
        let scratch = a_directory_of_our_own("edited-digest");
        let version = reported_version(&host);
        let (archive, _) = a_release_archive(&host, &scratch, &version);
        let output = scratch.join("manifests");

        succeeded(
            &render(&host, &archive, &output),
            "rendering a manifest before editing its digest",
        );
        let manifests = manifest_directory(&output, "lichman0405.SURE", &version);
        let installer = manifests.join("lichman0405.SURE.installer.yaml");
        let text = std::fs::read_to_string(&installer).expect("the installer manifest");
        let edited = text.replace(
            &manifest_field(&text, "InstallerSha256"),
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_ne!(text, edited, "the digest was not there to replace");
        std::fs::write(&installer, edited).expect("the edited manifest can be written");

        let run = verify(&host, &manifests, &archive);
        assert_ne!(
            run.status,
            0,
            "a manifest carrying a digest that is not the archive's was accepted:\n{}",
            run.everything()
        );
        assert!(
            run.everything()
                .contains("carries a digest that is not the digest of the archive"),
            "the run did not say what was wrong:\n{}",
            run.everything()
        );
    }

    /// An archive whose bytes no longer match its `.sha256` is refused before
    /// anything is written.
    ///
    /// This is the state a truncated download arrives in, and the state a
    /// rebuilt — and therefore different — archive is in when a stale checksum
    /// is left beside it. The manifest's digest has to come from bytes that were
    /// checked, so a mismatch is a refusal rather than a warning.
    #[test]
    fn an_archive_that_does_not_match_its_checksum_is_refused() {
        let host = a_host();
        let scratch = a_directory_of_our_own("corrupt-archive");
        let version = reported_version(&host);
        let (archive, _) = a_release_archive(&host, &scratch, &version);
        let output = scratch.join("manifests");

        let mut bytes = std::fs::read(&archive).expect("the archive can be read");
        bytes.push(0);
        std::fs::write(&archive, &bytes).expect("the archive can be changed");

        let run = render(&host, &archive, &output);
        assert_ne!(
            run.status,
            0,
            "a manifest was rendered from an archive that does not match its checksum:\n{}",
            run.everything()
        );
        assert!(
            run.everything()
                .contains("does not match its checksum file"),
            "the run did not say what was wrong:\n{}",
            run.everything()
        );
        assert!(
            !output.exists(),
            "something was written at {} for an archive that failed its checksum",
            output.display()
        );
    }

    /// The archive's name says one version and the binary inside it reports
    /// another. `PackageVersion` would describe a program that is not the one
    /// being packaged, and that has to be a refusal.
    #[test]
    fn an_archive_named_for_a_version_the_binary_does_not_report_is_refused() {
        let host = a_host();
        let scratch = a_directory_of_our_own("wrong-version");
        let version = reported_version(&host);
        let not_this_build = "0.0.0-not-this-build";
        let (archive, _) = a_release_archive(&host, &scratch, not_this_build);
        let output = scratch.join("manifests");

        assert_ne!(
            not_this_build, version,
            "this test needs a version the binary does not report"
        );
        let run = render(&host, &archive, &output);
        assert_ne!(
            run.status,
            0,
            "a manifest was rendered for a version the binary does not report:\n{}",
            run.everything()
        );
        let text = run.everything();
        assert!(
            text.contains(not_this_build) && text.contains(&version),
            "the refusal did not name both versions, so a reader cannot see which is which:\n{text}"
        );
        assert!(
            text.contains("is named for one version and holds another"),
            "the run failed for some other reason:\n{text}"
        );
    }

    /// The check that did not run says so, and exits neither 0 nor 1.
    ///
    /// `winget` is treated here the way the tree treats `pwsh`: an optional
    /// tool. The difference is what happens when it is missing — a skipped
    /// dynamic check is not a pass, so the script prints `--- NOT CHECKED ---`,
    /// exits 3, and must not print OK. Asked with a `PATH` holding nothing,
    /// which is how a machine without winget behaves without anything being
    /// uninstalled from this one.
    #[test]
    fn the_script_says_so_when_winget_cannot_validate_the_result() {
        let host = a_host();
        let scratch = a_directory_of_our_own("no-winget");
        let version = reported_version(&host);
        let (archive, _) = a_release_archive(&host, &scratch, &version);
        let output = scratch.join("manifests");
        succeeded(
            &render(&host, &archive, &output),
            "rendering a manifest before asking what happens without winget",
        );
        let manifests = manifest_directory(&output, "lichman0405.SURE", &version);

        let nothing_on_path = scratch.join("a path with nothing on it");
        std::fs::create_dir_all(&nothing_on_path).expect("the empty directory");
        let manifests_text = manifests.to_string_lossy().into_owned();
        let archive_text = archive.to_string_lossy().into_owned();
        let run = run_script_with_path(
            &host,
            &manifest_script(),
            &[
                OsStr::new("-Phase"),
                OsStr::new("Verify"),
                OsStr::new("-ManifestDirectory"),
                OsStr::new(&manifests_text),
                OsStr::new("-Archive"),
                OsStr::new(&archive_text),
            ],
            &nothing_on_path,
        );

        let text = run.everything();
        assert_eq!(
            run.status, 3,
            "a run that could not validate its result must not answer 0 or 1:\n{text}"
        );
        assert!(
            text.contains("--- NOT CHECKED ---"),
            "the run did not say the validation did not happen:\n{text}"
        );
        assert!(
            !text.contains("OK:"),
            "a run that validated nothing printed OK:\n{text}"
        );
        // Everything before that step still ran, which is what makes this a
        // report about one check rather than a run that did nothing.
        assert!(
            text.contains("Every value, against the archive"),
            "the run stopped before the checks it could make:\n{text}"
        );
    }

    /// `winget validate` accepts what the script renders, on a machine that has
    /// winget.
    ///
    /// The render test above already fails if the script exits non-zero, and
    /// the script exits 3 when winget is missing — so on a machine without
    /// winget that test would fail rather than pass quietly, and this one says
    /// what to install. When winget *is* present, the unrendered template must
    /// also fail validation: that is what makes a placeholder that survived
    /// impossible to publish by accident.
    #[test]
    fn winget_validate_accepts_the_rendered_manifest_and_refuses_the_template() {
        if !winget_on_path() {
            panic!(
                "winget is not on PATH on this machine, so `winget validate` could not be run \
                 against the rendered manifest or against the unrendered template. Neither is a \
                 pass: install App Installer (https://aka.ms/getwinget) and run this again, or \
                 read `docs/development/INSTALL_WINGET.md`, which records what was and was not \
                 measured."
            );
        }
        let host = a_host();
        let scratch = a_directory_of_our_own("winget-validate");
        let version = reported_version(&host);
        let (archive, _) = a_release_archive(&host, &scratch, &version);
        let output = scratch.join("manifests");
        let run = render(&host, &archive, &output);
        succeeded(&run, "rendering a manifest with winget on PATH");
        // Winget's own success sentence is localized — measured on a zh-CN
        // machine, which prints `清单验证成功。` — so the script's own OK line is
        // the locale-independent verdict marker. `succeeded` has already
        // checked the exit status, which is the other half.
        assert!(
            run.stdout.contains("accepted by winget validate"),
            "the run did not report winget's verdict:\n{}",
            run.everything()
        );

        // The template as committed: a placeholder in `PackageVersion` and one
        // in `InstallerSha256`. Copied to a scratch directory first, because
        // `winget validate` is not being asked about the repository.
        let unrendered = scratch.join("unrendered-template");
        std::fs::create_dir_all(&unrendered).expect("the scratch directory");
        for name in super::template_files() {
            let from = template_directory().join(name);
            std::fs::copy(&from, unrendered.join(name))
                .unwrap_or_else(|error| panic!("cannot copy {}: {error}", from.display()));
        }
        let winget = std::env::var_os("PATH")
            .and_then(|path| {
                std::env::split_paths(&path)
                    .map(|directory| directory.join("winget.exe"))
                    .find(|candidate| candidate.is_file())
            })
            .expect("winget was found on PATH a moment ago");
        let outcome = {
            let _one_at_a_time = one_winget_at_a_time();
            Command::new(&winget)
                .arg("validate")
                .arg("--manifest")
                .arg(&unrendered)
                .output()
                .unwrap_or_else(|error| panic!("cannot run {}: {error}", winget.display()))
        };
        let text = Run::of(outcome);
        assert_ne!(
            text.status,
            0,
            "winget validate accepted the unrendered template, so a placeholder could be \
             published by accident:\n{}",
            text.everything()
        );
        assert!(
            text.everything().contains("InstallerSha256"),
            "the refusal does not name the digest field:\n{}",
            text.everything()
        );
    }

    /// Which of the launchers' three resolution steps finds a winget-installed
    /// SURE. The answer is the second one, and this is the experiment.
    ///
    /// The eight launchers resolve `sure.exe` as `$env:SURE_BIN`, then `sure` on
    /// `PATH`, then `%LOCALAPPDATA%\SURE\bin\sure.exe`. A WinGet package
    /// installs into a WinGet-managed directory and surfaces the command through
    /// its own `Links` directory, which WinGet puts on `PATH` — so the third
    /// step, the per-user install directory `scripts/Install-Sure.ps1` writes,
    /// stays empty, and the second step is the one that answers.
    ///
    /// **What is measured here and what is not.** What is measured is the
    /// launcher: given a `Links` directory holding `sure.exe` on `PATH`, and an
    /// empty `%LOCALAPPDATA%\SURE\bin`, it starts the server, and when the
    /// `Links` entry is removed it fails closed. What is *not* measured is
    /// WinGet doing the installing: `winget install` changes the machine and
    /// this repository's rules forbid a test from running it. The claim about
    /// WinGet's layout is read from WinGet's own source (`PortableInstaller.cpp`
    /// and `Workflows/PortableFlow.cpp`, which extract the archive under
    /// `%LOCALAPPDATA%\Microsoft\WinGet\Packages\<id>_<source>_<hash>\` and write
    /// the alias into `%LOCALAPPDATA%\Microsoft\WinGet\Links`), and from this
    /// machine's own `Links` directory being on its user `PATH`.
    /// `docs/development/INSTALL_WINGET.md` states that split where a reader
    /// meets the conclusion, rather than only here.
    #[test]
    fn the_second_resolution_step_is_the_one_a_winget_install_fills() {
        let host = a_host();
        let scratch = a_directory_of_our_own("launcher-step");
        let links = scratch.join("Links");
        std::fs::create_dir_all(&links).expect("the Links directory");
        let linked = links.join("sure.exe");
        // This is the copy the launcher is then asked to start, so it is the one
        // site in this file where the copied file is executed: the bytes land on
        // a temporary name in `Links`, are closed there and are renamed onto
        // `sure.exe`, which is the name the launcher resolves. The executable bit
        // and every other permission bit come across with the copy.
        sure_testkit::copy_program(Path::new(SURE), &linked).expect("the alias can be planted");

        // What a WinGet install leaves in the per-user directory: nothing. It is
        // not created, so `Test-Path` on the third step's candidate has nothing
        // to find — which is what the assertion below is about.
        let per_user = scratch.join("SURE").join("bin").join("sure.exe");
        assert!(
            !per_user.exists(),
            "the third resolution step would answer, so this test would not be measuring the \
             second"
        );

        let launcher = repository_root()
            .join("integrations")
            .join("claude-code")
            .join("scripts")
            .join("sure-mcp.ps1");
        let stream = format!(
            "{}\n{}\n",
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "winget_manifest.rs", "version": "0"},
                },
            }),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        );

        let started = run_launcher(&host, &launcher, &scratch, &links, &stream);
        let answers = format!("{}{}", started.stdout, started.stderr);
        assert_eq!(
            started.status, 0,
            "the launcher did not reach the binary on PATH:\n{answers}"
        );
        assert!(
            started.stdout.contains("\"id\":1") && started.stdout.contains("\"id\":2"),
            "the session did not answer both requests, so nothing proves the server started:\n{answers}"
        );

        // The falsifier: with the alias gone, the same run with the same `PATH`
        // must fail closed rather than find something else.
        std::fs::remove_file(&linked).expect("the planted alias");
        let without = run_launcher(&host, &launcher, &scratch, &links, &stream);
        assert_ne!(
            without.status, 0,
            "the launcher still started after the PATH entry was removed, so the run above was \
             not measuring it:\n{}{}",
            without.stdout, without.stderr
        );
        assert!(
            without.stderr.contains("no SURE binary was found"),
            "the launcher failed for some other reason:\n{}",
            without.stderr
        );
    }

    /// Drive the Claude Code MCP launcher with a stream on its standard input.
    ///
    /// `SURE_BIN` removed, `PATH` holding one directory the caller chose, and
    /// `LOCALAPPDATA` pointing at the scratch root: nothing else in the
    /// launcher's three-step resolution can answer, so what it starts is what
    /// the caller put there. The same shape as `install_flow.rs`'s
    /// `run_launcher`, which uses it to prove the *third* step answers after a
    /// real install; the two together are what says the steps are distinguishable.
    fn run_launcher(
        host: &Path,
        launcher: &Path,
        localdata: &Path,
        path: &Path,
        stream: &str,
    ) -> Run {
        let mut child = Command::new(host)
            .arg("-NoProfile")
            .arg("-File")
            .arg(launcher)
            .env_remove("SURE_BIN")
            .env("LOCALAPPDATA", localdata)
            .env("PATH", path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("could not start {}: {error}", launcher.display()));
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(stream.as_bytes())
            .expect("the caller can write");
        child
            .wait_with_output()
            .map(Run::of)
            .expect("the launcher exits")
    }
}
