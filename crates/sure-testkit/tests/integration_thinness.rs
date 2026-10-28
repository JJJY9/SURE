//! Harness packages contain no duplicated check engine.
//!
//! P1-T001 acceptance: "Harness packages contain no duplicated check engine."
//!
//! ADR 0004 states the rule; these assertions are what makes it survive. Each
//! one is paired with a case that must fail, so a checker that always returned
//! "thin" would not pass.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use sure_testkit::ThinnessFinding;
use sure_testkit::integrations::{self, IntegrationFile};

fn root() -> PathBuf {
    sure_testkit::repository_root().join("integrations")
}

fn loaded() -> Vec<IntegrationFile> {
    integrations::load(&root()).expect("integrations directory must be readable")
}

/// The core-owned user-facing wording, taken from the core rather than copied.
///
/// A copy here would drift from the constant it is supposed to guard, which is
/// the failure this whole check exists to catch.
fn frozen_sentences() -> Vec<&'static str> {
    vec![sure_domain::status::NO_TRUSTED_INTENT_LIMITATION]
}

#[test]
fn harness_packages_are_thin() {
    let files = loaded();
    assert!(
        !files.is_empty(),
        "no integration files were read, so this check proves nothing"
    );
    let mut findings = integrations::findings(&files, &frozen_sentences());
    findings.extend(integrations::manifest_reference_findings(&root(), &files));
    assert!(
        findings.is_empty(),
        "integration packages stopped being thin:\n{}",
        findings
            .iter()
            .map(|f| format!("  - {f}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn the_real_launchers_are_found_and_are_launchers() {
    // If the loader silently returned no launchers, the check above would pass
    // for the wrong reason.
    let files = loaded();
    let launchers: Vec<&IntegrationFile> = files.iter().filter(|f| f.is_launcher()).collect();
    assert!(
        launchers.len() >= 4,
        "expected the claude-code and cursor hook launchers, found {:?}",
        launchers.iter().map(|f| &f.relative).collect::<Vec<_>>()
    );
    for launcher in &launchers {
        assert!(
            integrations::reaches_core(&launcher.text),
            "{} does not reach the core, yet the tree is expected to be thin",
            launcher.relative
        );
    }
}

// --- the checker itself -------------------------------------------------

fn file(relative: &str, text: &str) -> IntegrationFile {
    IntegrationFile {
        relative: relative.to_owned(),
        path: PathBuf::from(relative),
        text: text.to_owned(),
    }
}

#[test]
fn a_launcher_that_never_reaches_the_core_is_reported() {
    let files = [file("h/scripts/decide.ps1", "Write-Output '{}'\n")];
    let findings = integrations::findings(&files, &frozen_sentences());
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, ThinnessFinding::LauncherDoesNotReachCore { file } if file.ends_with("decide.ps1"))),
        "a launcher that never calls the core must be reported: {findings:?}"
    );
}

#[test]
fn a_launcher_that_grew_into_a_program_is_reported() {
    let mut text = String::from("$bin = $env:SURE_BIN\n");
    while text.lines().count() <= integrations::MAX_LAUNCHER_LINES {
        text.push_str("$x = 1\n");
    }
    let files = [file("h/scripts/big.ps1", &text)];
    let findings = integrations::findings(&files, &frozen_sentences());
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, ThinnessFinding::LauncherTooLarge { .. })),
        "an oversized launcher must be reported: {findings:?}"
    );
}

#[test]
fn a_copied_frozen_sentence_is_reported() {
    let sentence = sure_domain::status::NO_TRUSTED_INTENT_LIMITATION;
    let files = [file(
        "h/scripts/talk.sh",
        &format!("SURE_BIN=sure\necho \"{sentence}\"\n"),
    )];
    let findings = integrations::findings(&files, &frozen_sentences());
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, ThinnessFinding::LauncherEmbedsFrozenWording { .. })),
        "a restated verdict sentence must be reported: {findings:?}"
    );
}

#[test]
fn a_check_engine_shipped_as_source_is_reported() {
    let files = [file("h/src/engine.rs", "fn check() {}\n")];
    let findings = integrations::findings(&files, &frozen_sentences());
    assert!(
        findings.iter().any(
            |f| matches!(f, ThinnessFinding::EngineArtefact { extension, .. } if extension == "rs")
        ),
        "Rust source inside an integration package must be reported: {findings:?}"
    );
}

#[test]
fn a_hook_manifest_pointing_at_a_missing_script_is_reported() {
    // A name that no other run can compute, for the reason `scan/mod.rs`'s
    // missing-directory fixture already records: `%TEMP%` is shared, and a
    // fixture a test did not create is one something else can take away.
    //
    // This test was one of five whose scratch directory carried a name every run
    // reused, and it was seen to fail with `Os { code: 3, kind: NotFound }` on the
    // write below — a write into a directory `create_dir_all` had just made.
    // **What takes the directory away is not known.** The obvious explanation, a
    // deletion by the previous run still finishing when this one starts, did not
    // survive a probe: 3000 rounds of exactly this shape — fixed name, create,
    // write, remove, repeat — failed zero times, and so did 3000 with a unique
    // name. What is established is narrower and is what this change acts on: all
    // five failures were on paths that every run shared, and a path no other
    // process can compute is a path no other process can remove. The five are
    // listed in `progress/HANDOFF.md`, with which of them were proven and which
    // were not.
    let dir = std::env::temp_dir().join(format!(
        "sure-testkit-thinness-missing-{}",
        std::process::id()
    ));
    let hooks = dir.join("hooks");
    std::fs::create_dir_all(&hooks).expect("temp dir");
    let manifest = hooks.join("hooks.json");
    std::fs::write(
        &manifest,
        r#"{"hooks":{"Stop":[{"command":"powershell -File .\\scripts\\gone.ps1 stop"}]}}"#,
    )
    .expect("write manifest");

    let files = [IntegrationFile {
        relative: "h/hooks/hooks.json".to_owned(),
        path: manifest,
        text: std::fs::read_to_string(hooks.join("hooks.json")).expect("read back"),
    }];
    let findings = integrations::manifest_reference_findings(&dir, &files);
    assert!(
        findings.iter().any(|f| matches!(
            f,
            ThinnessFinding::ManifestReferencesMissingFile { referenced, .. }
            if referenced.contains("gone.ps1")
        )),
        "a hook wired to a missing script must be reported: {findings:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_mcp_manifest_pointing_at_a_missing_script_is_reported() {
    // The same defect as a hook pointing at a missing launcher, on the newer
    // surface: the harness starts nothing, says nothing, and the session has no
    // tools. An MCP manifest sits at the package root, so this is also the case
    // that says the check resolves its references there rather than one
    // directory up.
    let dir = std::env::temp_dir().join(format!(
        "sure-testkit-thinness-mcp-missing-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let manifest = dir.join("mcp.json");
    std::fs::write(
        &manifest,
        r#"{"mcpServers":{"sure":{"command":"powershell","args":["-File","${CLAUDE_PLUGIN_ROOT}/scripts/gone.ps1"]}}}"#,
    )
    .expect("write manifest");

    let files = [IntegrationFile {
        relative: "h/mcp.json".to_owned(),
        path: manifest,
        text: std::fs::read_to_string(dir.join("mcp.json")).expect("read back"),
    }];
    let findings = integrations::manifest_reference_findings(&dir, &files);
    assert!(
        findings.iter().any(|f| matches!(
            f,
            ThinnessFinding::ManifestReferencesMissingFile { referenced, .. }
            if referenced.contains("gone.ps1")
        )),
        "an MCP server wired to a missing launcher must be reported: {findings:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cursor_synthetic_fixtures_are_valid_json_with_expected_shape() {
    let fixtures = sure_testkit::repository_root()
        .join("integrations")
        .join("cursor")
        .join("fixtures");
    assert!(
        fixtures.is_dir(),
        "cursor synthetic fixtures directory must exist"
    );

    let entries = std::fs::read_dir(&fixtures).expect("fixtures directory is readable");
    let mut count = 0;
    for entry in entries {
        let entry = entry.expect("fixture entry readable");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        count += 1;
        let text = std::fs::read_to_string(&path).expect("fixture file readable");
        let value: serde_json::Value =
            serde_json::from_str(&text).expect("fixture must be valid JSON");
        let object = value.as_object().expect("fixture must be a JSON object");
        for key in ["event", "harness_session_id", "source"] {
            assert!(
                object.contains_key(key),
                "{} must contain '{key}'",
                path.display()
            );
        }
        assert_eq!(
            object.get("source").and_then(|v| v.as_str()),
            Some("cursor"),
            "{} must declare source as 'cursor'",
            path.display()
        );
    }
    assert!(
        count >= 6,
        "expected at least six cursor synthetic fixtures, found {count}"
    );
}

#[test]
fn claude_code_synthetic_fixtures_are_valid_json_with_expected_shape() {
    let fixtures = sure_testkit::repository_root()
        .join("integrations")
        .join("claude-code")
        .join("fixtures");
    assert!(
        fixtures.is_dir(),
        "claude-code synthetic fixtures directory must exist"
    );

    let entries = std::fs::read_dir(&fixtures).expect("fixtures directory is readable");
    let mut count = 0;
    for entry in entries {
        let entry = entry.expect("fixture entry readable");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        count += 1;
        let text = std::fs::read_to_string(&path).expect("fixture file readable");
        let value: serde_json::Value =
            serde_json::from_str(&text).expect("fixture must be valid JSON");
        let object = value.as_object().expect("fixture must be a JSON object");
        for key in ["event", "harness_session_id", "source"] {
            assert!(
                object.contains_key(key),
                "{} must contain '{key}'",
                path.display()
            );
        }
        assert_eq!(
            object.get("source").and_then(|v| v.as_str()),
            Some("claude-code"),
            "{} must declare source as 'claude-code'",
            path.display()
        );
    }
    assert!(
        count >= 4,
        "expected at least four claude-code synthetic fixtures, found {count}"
    );
}

#[test]
fn miqi_synthetic_fixtures_are_valid_json_with_expected_shape() {
    let fixtures = sure_testkit::repository_root()
        .join("integrations")
        .join("miqi")
        .join("fixtures");
    assert!(
        fixtures.is_dir(),
        "miqi synthetic fixtures directory must exist"
    );

    let entries = std::fs::read_dir(&fixtures).expect("fixtures directory is readable");
    let mut count = 0;
    for entry in entries {
        let entry = entry.expect("fixture entry readable");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        count += 1;
        let text = std::fs::read_to_string(&path).expect("fixture file readable");
        let value: serde_json::Value =
            serde_json::from_str(&text).expect("fixture must be valid JSON");
        let object = value.as_object().expect("fixture must be a JSON object");
        for key in ["event", "harness_session_id", "source"] {
            assert!(
                object.contains_key(key),
                "{} must contain '{key}'",
                path.display()
            );
        }
        assert_eq!(
            object.get("source").and_then(|v| v.as_str()),
            Some("miqi"),
            "{} must declare source as 'miqi'",
            path.display()
        );
    }
    assert!(
        count >= 4,
        "expected at least four miqi synthetic fixtures, found {count}"
    );
}

#[test]
fn cursor_launcher_contract_fixtures_are_valid_json() {
    let launcher = sure_testkit::repository_root()
        .join("integrations")
        .join("cursor")
        .join("fixtures")
        .join("launcher");
    assert!(
        launcher.is_dir(),
        "cursor launcher fixtures directory must exist"
    );

    let entries = std::fs::read_dir(&launcher).expect("launcher fixtures directory is readable");
    let mut count = 0;
    for entry in entries {
        let entry = entry.expect("launcher fixture entry readable");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        count += 1;
        let text = std::fs::read_to_string(&path).expect("launcher fixture file readable");
        let _: serde_json::Value =
            serde_json::from_str(&text).expect("launcher fixture must be valid JSON");
    }
    assert!(
        count >= 3,
        "expected at least three cursor launcher contract fixtures, found {count}"
    );

    // The launcher script must resolve SURE from the override, PATH, and the
    // per-user install location, and must not fabricate evidence when missing.
    let script = sure_testkit::repository_root()
        .join("integrations")
        .join("cursor")
        .join("scripts")
        .join("sure-hook.ps1");
    let text = std::fs::read_to_string(&script).expect("cursor launcher script readable");
    assert!(
        text.contains("SURE_BIN"),
        "cursor launcher must honour SURE_BIN override"
    );
    assert!(
        text.contains("Get-Command sure"),
        "cursor launcher must look for sure on PATH"
    );
    assert!(
        text.contains("LOCALAPPDATA"),
        "cursor launcher must fall back to per-user install location"
    );
    assert!(
        text.contains("SURE binary not found"),
        "cursor launcher must fail safely when SURE is missing"
    );
    assert!(
        text.contains("hook ingest --source cursor"),
        "cursor launcher must forward to the SURE core"
    );
}

#[test]
fn claude_code_launcher_contract_fixtures_are_valid_json() {
    let launcher = sure_testkit::repository_root()
        .join("integrations")
        .join("claude-code")
        .join("fixtures")
        .join("launcher");
    assert!(
        launcher.is_dir(),
        "claude-code launcher fixtures directory must exist"
    );

    let entries = std::fs::read_dir(&launcher).expect("launcher fixtures directory is readable");
    let mut count = 0;
    for entry in entries {
        let entry = entry.expect("launcher fixture entry readable");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        count += 1;
        let text = std::fs::read_to_string(&path).expect("launcher fixture file readable");
        let _: serde_json::Value =
            serde_json::from_str(&text).expect("launcher fixture must be valid JSON");
    }
    assert!(
        count >= 3,
        "expected at least three claude-code launcher contract fixtures, found {count}"
    );

    // The launcher script must resolve SURE from the override, PATH, and the
    // per-user install location, and must not fabricate evidence when missing.
    let script = sure_testkit::repository_root()
        .join("integrations")
        .join("claude-code")
        .join("scripts")
        .join("sure-hook.ps1");
    let text = std::fs::read_to_string(&script).expect("claude-code launcher script readable");
    assert!(
        text.contains("SURE_BIN"),
        "claude-code launcher must honour SURE_BIN override"
    );
    assert!(
        text.contains("Get-Command sure"),
        "claude-code launcher must look for sure on PATH"
    );
    assert!(
        text.contains("LOCALAPPDATA"),
        "claude-code launcher must fall back to per-user install location"
    );
    assert!(
        text.contains("SURE binary not found"),
        "claude-code launcher must fail safely when SURE is missing"
    );
    assert!(
        text.contains("hook ingest --source claude-code"),
        "claude-code launcher must forward to the SURE core"
    );
}

// --- the MCP launcher, which fails closed where the hooks fail open --------

// **Everything below this line that runs a launcher is Windows-only, and so is
// the apparatus it runs on.** The launcher is `sure-mcp.ps1`, the stand-ins are
// `.cmd` files that answer with `exit /b`, and the interpreter is the one the
// package ships against — none of which exists on a Unix runner. The tests are
// gated to Windows for that reason and not to make a job quieter; the helpers
// are gated with them, because a helper used only by a Windows-gated test is
// dead code everywhere else and `-D warnings` in CI fails the ubuntu and macos
// jobs on it. That is what happened: this file was the only thing stopping the
// Unix jobs from reaching their test step from `752489c` until `P15-T016`.

/// The PowerShell to run a launcher with.
///
/// Named by absolute path when it can be, because one of these tests empties
/// `PATH` on purpose — that is how it makes `sure` unfindable — and a test that
/// could not find its own interpreter would fail for the wrong reason.
#[cfg(windows)]
fn powershell() -> PathBuf {
    if let Some(root) = std::env::var_os("SystemRoot") {
        let candidate = PathBuf::from(root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from("powershell")
}

/// An empty scratch directory of this test's own, as the install tests use.
#[cfg(windows)]
fn launcher_scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sure-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// The MCP launcher's path, so each test names the same file.
fn claude_code_mcp_launcher() -> PathBuf {
    sure_testkit::repository_root()
        .join("integrations")
        .join("claude-code")
        .join("scripts")
        .join("sure-mcp.ps1")
}

/// Write a `.cmd` that stands in for a SURE build, and return its path.
///
/// A `.cmd` rather than an `.exe` because these tests are about what the
/// launcher does with the status and the streams of whatever it resolved, and
/// building a binary to be wrong would test the compiler.
#[cfg(windows)]
fn stub_binary(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    let text = format!("@echo off\r\n{body}");
    // The launcher resolves this path and starts it, so it is a program and is
    // put at its path by the door for programs: written beside its name, closed
    // there, renamed onto it. See `sure_testkit::program`.
    sure_testkit::write_program(&path, text.as_bytes(), 0o755).expect("write stub binary");
    path
}

#[cfg(windows)]
#[test]
fn the_claude_code_mcp_launcher_says_where_to_put_sure_when_it_cannot_find_it() {
    // The failure this task exists for: a harness that cannot start SURE must be
    // told what to do, and must not be handed anything it could read as a result
    // — not an empty tool list, and not a session that answers nothing.
    let script = claude_code_mcp_launcher();
    let scratch = launcher_scratch("mcp-launcher-missing");
    let empty_path = scratch.join("empty-path");
    let local = scratch.join("localappdata");
    std::fs::create_dir_all(&empty_path).expect("empty PATH directory");
    std::fs::create_dir_all(&local).expect("per-user directory");

    let output = std::process::Command::new(powershell())
        .args(["-NoProfile", "-File", &script.to_string_lossy()])
        .env_remove("SURE_BIN")
        .env("LOCALAPPDATA", &local)
        .env("PATH", &empty_path)
        .output()
        .expect("spawn sure-mcp.ps1");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(3),
        "the launcher must refuse to start a session it cannot serve: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "the launcher wrote to the protocol stream: {stdout}"
    );
    // Actionable means it names the three places SURE could have been and what
    // to do, in SURE's own words rather than the operating system's.
    for place in ["SURE_BIN", "PATH", "LOCALAPPDATA"] {
        assert!(
            stderr.contains(place),
            "the refusal does not say where SURE was looked for ({place}): {stderr}"
        );
    }
    assert!(
        stderr.contains("sure.exe"),
        "the refusal does not name the binary: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&scratch);
}

#[cfg(windows)]
#[test]
fn the_claude_code_mcp_launcher_refuses_a_binary_that_does_not_carry_the_bridge() {
    // The other half of "missing or incompatible": a build older than the
    // bridge answers `sure mcp serve --help` with a usage error and exit 2. The
    // launcher must not hand the session to it and let the caller's first
    // message be the thing that discovers it.
    let script = claude_code_mcp_launcher();
    let scratch = launcher_scratch("mcp-launcher-old");
    let old = stub_binary(
        &scratch,
        "sure-old.cmd",
        "echo error: unrecognized subcommand 'mcp' 1>&2\r\nexit /b 2\r\n",
    );

    let output = std::process::Command::new(powershell())
        .args(["-NoProfile", "-File", &script.to_string_lossy()])
        .env("SURE_BIN", &old)
        .output()
        .expect("spawn sure-mcp.ps1");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(3),
        "an incompatible build must be refused, not started: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "the refusal leaked onto the protocol stream: {stdout}"
    );
    assert!(
        stderr.contains(&old.to_string_lossy().to_string()),
        "the refusal does not say which binary is too old: {stderr}"
    );
    assert!(
        stderr.contains("status 2"),
        "the refusal does not pass on the status the binary answered with: {stderr}"
    );
    assert!(
        stderr.contains("2025-11-25"),
        "the refusal does not say which MCP revision this package needs: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&scratch);
}

#[cfg(windows)]
#[test]
fn the_claude_code_mcp_launcher_does_not_invent_a_status_it_was_not_given() {
    // The third way a binary can be wrong: the path exists and holds something
    // the operating system will not start, so there is no status to quote. The
    // refusal has to say that. A sentence with the status left blank would be
    // the same fault this package exists to avoid, one level down.
    let script = claude_code_mcp_launcher();
    let scratch = launcher_scratch("mcp-launcher-unrunnable");
    let broken = scratch.join("sure-broken.exe");
    // Named `.exe` and handed to the launcher as `SURE_BIN`, so it is a path the
    // launcher tries to start — which is the whole test. It is written through
    // the program door for that reason; the bytes being `@echo off` rather than
    // an image is the fixture's point, not a reason to write them another way.
    sure_testkit::write_program(&broken, b"@echo off\r\nexit /b 2\r\n", 0o755)
        .expect("write a file that is not a program");

    let output = std::process::Command::new(powershell())
        .args(["-NoProfile", "-File", &script.to_string_lossy()])
        .env("SURE_BIN", &broken)
        .output()
        .expect("spawn sure-mcp.ps1");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(3),
        "a binary that cannot be started must be refused, not handed the session: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "the refusal leaked onto the protocol stream: {stdout}"
    );
    assert!(
        stderr.contains(&broken.to_string_lossy().to_string()),
        "the refusal does not say which path it tried: {stderr}"
    );
    assert!(
        stderr.contains("2025-11-25"),
        "the refusal does not say which MCP revision this package needs: {stderr}"
    );
    assert!(
        stderr.contains("could not be run"),
        "the refusal does not say the binary could not be started: {stderr}"
    );
    assert!(
        !stderr.contains("status )") && !stderr.contains("status ,"),
        "the refusal printed a status it never received: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&scratch);
}

#[cfg(windows)]
#[test]
fn the_claude_code_mcp_launcher_hands_the_protocol_stream_over_untouched() {
    // What the launcher may not do to a session that can start: add a line, drop
    // a line, or lose the status. The stub answers the launcher's own probe with
    // nothing and then speaks one message, so the probe's silence is part of
    // what is being checked.
    let script = claude_code_mcp_launcher();
    let scratch = launcher_scratch("mcp-launcher-handover");
    let message = r#"{"jsonrpc":"2.0","id":1,"method":"x"}"#;
    let stand_in = stub_binary(
        &scratch,
        "sure-stand-in.cmd",
        &format!("if \"%*\"==\"mcp serve --help\" exit /b 0\r\necho {message}\r\nexit /b 7\r\n"),
    );

    let output = std::process::Command::new(powershell())
        .args(["-NoProfile", "-File", &script.to_string_lossy()])
        .env("SURE_BIN", &stand_in)
        .output()
        .expect("spawn sure-mcp.ps1");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(7),
        "the server's own status must be the one the caller sees: {stderr}"
    );
    assert_eq!(
        stdout.trim_end(),
        message,
        "the protocol stream must carry the server's messages and nothing else: {stdout:?}"
    );

    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn claude_code_mcp_manifest_names_a_launcher_that_is_there_and_is_a_launcher() {
    // The manifest is the contract with Claude Code, and the launcher is what
    // resolves the binary. A manifest naming a file that is not there is the
    // quiet failure: Claude Code starts nothing and the session has no tools,
    // so the two halves are checked together.
    let mcp = sure_testkit::repository_root()
        .join("integrations")
        .join("claude-code")
        .join(".mcp.json");
    let text = std::fs::read_to_string(&mcp).expect(".mcp.json readable");
    let manifest: serde_json::Value =
        serde_json::from_str(&text).expect(".mcp.json must be valid JSON");
    let sure = manifest
        .get("mcpServers")
        .and_then(|v| v.get("sure"))
        .expect(".mcp.json must declare the sure server");
    let args: Vec<String> = sure
        .get("args")
        .and_then(|v| v.as_array())
        .expect("the sure server must list args")
        .iter()
        .filter_map(|v| v.as_str())
        .map(str::to_owned)
        .collect();

    // `--format json` here would be a defect: the packages launch `sure mcp
    // serve` and nothing else, and no flag of the launcher's may reach the
    // session's stream.
    assert!(
        !args.iter().any(|a| a == "--format"),
        "the manifest must not pass output flags into the session: {args:?}"
    );
    assert!(
        args.iter().any(|a| a.contains("sure-mcp.ps1")),
        "the manifest must name the launcher that resolves the binary: {args:?}"
    );

    let script = claude_code_mcp_launcher();
    assert!(
        script.is_file(),
        "the manifest names {}, which does not exist",
        script.display()
    );

    let launcher = std::fs::read_to_string(&script).expect("launcher readable");
    assert!(
        integrations::reaches_core(&launcher),
        "the MCP launcher must reach the core"
    );
    assert!(
        launcher.lines().count() <= integrations::MAX_LAUNCHER_LINES,
        "the MCP launcher is {} lines, over the {} -line bound",
        launcher.lines().count(),
        integrations::MAX_LAUNCHER_LINES
    );
    for part in ["SURE_BIN", "Get-Command sure", "LOCALAPPDATA"] {
        assert!(
            launcher.contains(part),
            "the MCP launcher must resolve the binary the way the hooks do ({part}): {launcher}"
        );
    }
}

#[test]
fn claude_code_check_command_exists_and_is_thin() {
    let check_md = sure_testkit::repository_root()
        .join("integrations")
        .join("claude-code")
        .join("commands")
        .join("check.md");

    assert!(
        check_md.is_file(),
        "claude-code check.md command file must exist"
    );

    let text = std::fs::read_to_string(&check_md).expect("check.md readable");

    // It must reference the local SURE invocation path or concept.
    let reaches_core =
        text.contains("SURE_BIN") || text.contains("sure.exe") || text.contains("sure check");
    assert!(
        reaches_core,
        "check.md must reference local SURE invocation (SURE_BIN, sure.exe, or sure check)"
    );

    // It must not copy the frozen no-trusted-intent limitation sentence.
    let normalised = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let frozen = sure_domain::status::NO_TRUSTED_INTENT_LIMITATION;
    let frozen_normalised = frozen.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        !normalised.contains(&frozen_normalised),
        "check.md must not copy the frozen no-trusted-intent limitation sentence; the core owns that wording"
    );
}

#[test]
fn claude_code_repair_handoff_references_repair_and_recheck() {
    let fix_md = sure_testkit::repository_root()
        .join("integrations")
        .join("claude-code")
        .join("commands")
        .join("fix.md");

    assert!(fix_md.is_file(), "claude-code fix.md must exist");

    let text = std::fs::read_to_string(&fix_md).expect("fix.md readable");

    assert!(
        text.contains("sure repair"),
        "claude-code fix.md must reference `sure repair` so the handoff can obtain the contract"
    );
    assert!(
        text.contains("sure recheck"),
        "claude-code fix.md must reference `sure recheck` so the handoff can close with evidence"
    );

    let normalised = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let frozen = sure_domain::status::NO_TRUSTED_INTENT_LIMITATION;
    let frozen_normalised = frozen.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        !normalised.contains(&frozen_normalised),
        "claude-code fix.md must not copy the frozen no-trusted-intent limitation sentence"
    );
}

#[test]
fn cursor_repair_handoff_references_repair_and_recheck() {
    let fix_md = sure_testkit::repository_root()
        .join("integrations")
        .join("cursor")
        .join("commands")
        .join("fix.md");

    assert!(fix_md.is_file(), "cursor fix.md must exist");

    let text = std::fs::read_to_string(&fix_md).expect("fix.md readable");

    assert!(
        text.contains("sure repair"),
        "cursor fix.md must reference `sure repair` so the handoff can obtain the contract"
    );
    assert!(
        text.contains("sure recheck"),
        "cursor fix.md must reference `sure recheck` so the handoff can close with evidence"
    );

    let normalised = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let frozen = sure_domain::status::NO_TRUSTED_INTENT_LIMITATION;
    let frozen_normalised = frozen.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        !normalised.contains(&frozen_normalised),
        "cursor fix.md must not copy the frozen no-trusted-intent limitation sentence"
    );
}

#[test]
fn cursor_command_files_exist_and_are_thin() {
    let commands_dir = sure_testkit::repository_root()
        .join("integrations")
        .join("cursor")
        .join("commands");

    let expected = ["check.md", "status.md", "fix.md", "recheck.md"];
    for name in &expected {
        let path = commands_dir.join(name);
        assert!(path.is_file(), "cursor command file {name} must exist");

        let text = std::fs::read_to_string(&path).expect("command file readable");

        // Each command must reference the local SURE invocation path or concept.
        let reaches_core = text.contains("SURE_BIN")
            || text.contains("sure.exe")
            || text.contains("sure check")
            || text.contains("sure history")
            || text.contains("sure recheck")
            || text.contains("sure repair");
        assert!(
            reaches_core,
            "{name} must reference local SURE invocation (SURE_BIN, sure.exe, or sure <subcommand>)"
        );

        // No command file may copy the frozen no-trusted-intent limitation sentence.
        let normalised = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let frozen = sure_domain::status::NO_TRUSTED_INTENT_LIMITATION;
        let frozen_normalised = frozen.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            !normalised.contains(&frozen_normalised),
            "{name} must not copy the frozen no-trusted-intent limitation sentence; the core owns that wording"
        );
    }
}

#[test]
fn cursor_install_script_exists_and_has_required_contract() {
    let script = sure_testkit::repository_root()
        .join("integrations")
        .join("cursor")
        .join("scripts")
        .join("install.ps1");

    assert!(script.is_file(), "cursor install.ps1 must exist");

    let text = std::fs::read_to_string(&script).expect("install.ps1 readable");

    assert!(
        text.contains("SURE_BIN"),
        "cursor install.ps1 must reference SURE_BIN for binary resolution"
    );
    assert!(
        text.contains("LOCALAPPDATA"),
        "cursor install.ps1 must reference LOCALAPPDATA for per-user fallback"
    );
    assert!(
        text.contains("Copy-Item") || text.to_ascii_lowercase().contains("copy"),
        "cursor install.ps1 must support copy fallback"
    );
    assert!(
        text.contains("ForceCopy")
            || text.contains("{{SURE_BIN}}")
            || text.contains("{{PLUGIN_ROOT}}"),
        "cursor install.ps1 must have a copy/render fallback or force-copy switch"
    );
}

#[test]
fn cursor_uninstall_script_exists() {
    let script = sure_testkit::repository_root()
        .join("integrations")
        .join("cursor")
        .join("scripts")
        .join("uninstall.ps1");

    assert!(script.is_file(), "cursor uninstall.ps1 must exist");

    let text = std::fs::read_to_string(&script).expect("uninstall.ps1 readable");

    assert!(
        text.contains("CURSOR_PLUGIN_DIR") || text.contains("APPDATA"),
        "cursor uninstall.ps1 must know where to remove the plugin from"
    );
}

#[test]
fn cursor_install_script_does_not_require_symlinks_unconditionally() {
    let script = sure_testkit::repository_root()
        .join("integrations")
        .join("cursor")
        .join("scripts")
        .join("install.ps1");

    let text = std::fs::read_to_string(&script).expect("install.ps1 readable");

    // The script must not unconditionally use New-Item -ItemType SymbolicLink;
    // it should have a copy fallback or a ForceCopy switch.
    let has_symlink = text.contains("SymbolicLink");
    let has_fallback = text.contains("ForceCopy") || text.contains("Copy-Item");
    assert!(
        !has_symlink || has_fallback,
        "cursor install.ps1 must not require symlink privileges unconditionally; it needs a copy fallback"
    );
}

#[cfg(windows)]
#[test]
fn cursor_install_script_runs_into_temp_directory() {
    let repo = sure_testkit::repository_root();
    let install_script = repo
        .join("integrations")
        .join("cursor")
        .join("scripts")
        .join("install.ps1");

    let temp =
        std::env::temp_dir().join(format!("sure-cursor-install-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).expect("temp dir");

    let plugin_dir = temp.join("cursor-plugins");
    let sure_bin = temp.join("sure.exe");
    std::fs::write(&sure_bin, "dummy").expect("write dummy sure.exe");

    let output = std::process::Command::new("powershell")
        .args([
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &install_script.to_string_lossy(),
        ])
        .env("CURSOR_PLUGIN_DIR", &plugin_dir)
        .env("SURE_BIN", &sure_bin)
        .output()
        .expect("spawn install.ps1");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "install.ps1 failed: stdout={stdout}, stderr={stderr}"
    );

    let installed = plugin_dir.join("sure");
    assert!(
        installed.is_dir(),
        "plugin directory should be created at {installed:?}"
    );
    assert!(
        installed.join("hooks").join("hooks.json").is_file(),
        "hooks.json should be present in installed plugin"
    );
    assert!(
        installed
            .join(".cursor-plugin")
            .join("plugin.json")
            .is_file(),
        "plugin.json should be present in installed plugin"
    );

    // Verify that placeholders were rendered in copied files.
    // (If Developer Mode created a symlink, placeholders are not rendered;
    // this assertion only matters for the copy path.)
    if !installed.is_symlink() {
        let hook = std::fs::read_to_string(installed.join("scripts").join("sure-hook.ps1"))
            .expect("read installed hook");
        // The original contains the literal placeholder; a rendered copy would
        // have it replaced. Since the dummy sure_bin path does not contain the
        // placeholder string, we can check it was processed by looking for the
        // original placeholder absence in any file that had it. In practice none
        // of the current files contain placeholders, so we just verify the copy
        // succeeded and the directory structure is intact.
        assert!(
            hook.contains("hook ingest --source cursor"),
            "installed hook should still forward to the SURE core"
        );
    }

    let _ = std::fs::remove_dir_all(&temp);
}

#[cfg(windows)]
#[test]
fn cursor_uninstall_script_removes_installed_plugin() {
    let repo = sure_testkit::repository_root();
    let uninstall_script = repo
        .join("integrations")
        .join("cursor")
        .join("scripts")
        .join("uninstall.ps1");

    let temp =
        std::env::temp_dir().join(format!("sure-cursor-uninstall-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).expect("temp dir");

    let plugin_dir = temp.join("cursor-plugins");
    let installed = plugin_dir.join("sure");
    std::fs::create_dir_all(&installed).expect("create fake plugin dir");
    std::fs::write(installed.join("dummy.txt"), "hello").expect("write dummy file");

    let output = std::process::Command::new("powershell")
        .args([
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &uninstall_script.to_string_lossy(),
        ])
        .env("CURSOR_PLUGIN_DIR", &plugin_dir)
        .output()
        .expect("spawn uninstall.ps1");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "uninstall.ps1 failed: stdout={stdout}"
    );
    assert!(
        stdout.contains("Uninstalled"),
        "uninstall.ps1 should report removal when plugin was present: {stdout}"
    );
    assert!(
        !installed.exists(),
        "plugin directory should be removed after uninstall"
    );

    // Run again against empty directory; should report not present.
    let output = std::process::Command::new("powershell")
        .args([
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &uninstall_script.to_string_lossy(),
        ])
        .env("CURSOR_PLUGIN_DIR", &plugin_dir)
        .output()
        .expect("spawn uninstall.ps1 again");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("not installed"),
        "uninstall.ps1 should report not-installed when plugin is absent: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&temp);
}

#[test]
fn agent_plugin_manifest_is_valid_json_with_expected_shape() {
    let plugin = sure_testkit::repository_root()
        .join("integrations")
        .join("agent-plugin")
        .join("plugin.json");

    assert!(plugin.is_file(), "agent-plugin plugin.json must exist");

    let text = std::fs::read_to_string(&plugin).expect("plugin.json readable");
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("agent-plugin plugin.json must be valid JSON");
    let object = value
        .as_object()
        .expect("plugin.json must be a JSON object");

    for key in ["name", "description", "version", "author"] {
        assert!(object.contains_key(key), "plugin.json must contain '{key}'");
    }
    assert_eq!(
        object.get("name").and_then(|v| v.as_str()),
        Some("sure"),
        "plugin.json name must be 'sure'"
    );
    assert_eq!(
        object.get("license").and_then(|v| v.as_str()),
        Some("Apache-2.0"),
        "plugin.json license must be Apache-2.0"
    );
}

#[test]
fn agent_plugin_mcp_manifest_references_sure_mcp_serve() {
    let mcp = sure_testkit::repository_root()
        .join("integrations")
        .join("agent-plugin")
        .join("mcp.json");

    assert!(mcp.is_file(), "agent-plugin mcp.json must exist");

    let text = std::fs::read_to_string(&mcp).expect("mcp.json readable");
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("agent-plugin mcp.json must be valid JSON");
    let object = value.as_object().expect("mcp.json must be a JSON object");
    let servers = object
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .expect("mcp.json must contain an mcpServers object");
    let sure = servers
        .get("sure")
        .and_then(|v| v.as_object())
        .expect("mcp.json must contain a 'sure' server");
    let command = sure
        .get("command")
        .and_then(|v| v.as_str())
        .expect("sure server must name a command");
    let args = sure
        .get("args")
        .and_then(|v| v.as_array())
        .expect("sure server must list args");

    assert_eq!(command, "sure", "sure server command must be 'sure'");
    let args: Vec<String> = args
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_owned())
        .collect();
    assert_eq!(
        args,
        vec!["mcp".to_owned(), "serve".to_owned()],
        "sure server args must be ['mcp', 'serve']"
    );
}

#[test]
fn agent_plugin_skill_exists_and_is_thin() {
    let skill = sure_testkit::repository_root()
        .join("integrations")
        .join("agent-plugin")
        .join("skills")
        .join("sure-check")
        .join("SKILL.md");

    assert!(
        skill.is_file(),
        "agent-plugin sure-check SKILL.md must exist"
    );

    let text = std::fs::read_to_string(&skill).expect("SKILL.md readable");

    // It must reference the local SURE invocation path or concept.
    let reaches_core = text.contains("SURE_BIN")
        || text.contains("sure.exe")
        || text.contains("sure check")
        || text.contains("sure repair")
        || text.contains("sure recheck");
    assert!(
        reaches_core,
        "SKILL.md must reference local SURE invocation (SURE_BIN, sure.exe, or sure <subcommand>)"
    );

    // It must preserve honest uncertainty rather than restating the frozen
    // after-the-fact limitation sentence.
    let normalised = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let frozen = sure_domain::status::NO_TRUSTED_INTENT_LIMITATION;
    let frozen_normalised = frozen.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        !normalised.contains(&frozen_normalised),
        "SKILL.md must not copy the frozen no-trusted-intent limitation sentence; the core owns that wording"
    );
}

#[test]
fn agent_plugin_install_script_exists_and_has_required_contract() {
    let script = sure_testkit::repository_root()
        .join("integrations")
        .join("agent-plugin")
        .join("scripts")
        .join("install.ps1");

    assert!(script.is_file(), "agent-plugin install.ps1 must exist");

    let text = std::fs::read_to_string(&script).expect("install.ps1 readable");

    assert!(
        text.contains("SURE_BIN"),
        "agent-plugin install.ps1 must reference SURE_BIN for binary resolution"
    );
    assert!(
        text.contains("AGENT_PLUGIN_DIR"),
        "agent-plugin install.ps1 must reference AGENT_PLUGIN_DIR for install location"
    );
    assert!(
        text.contains("Copy-Item") || text.to_ascii_lowercase().contains("copy"),
        "agent-plugin install.ps1 must support copy fallback"
    );
    assert!(
        text.contains("ForceCopy")
            || text.contains("{{SURE_BIN}}")
            || text.contains("{{PLUGIN_ROOT}}"),
        "agent-plugin install.ps1 must have a copy/render fallback or force-copy switch"
    );
}

#[test]
fn agent_plugin_uninstall_script_exists() {
    let script = sure_testkit::repository_root()
        .join("integrations")
        .join("agent-plugin")
        .join("scripts")
        .join("uninstall.ps1");

    assert!(script.is_file(), "agent-plugin uninstall.ps1 must exist");

    let text = std::fs::read_to_string(&script).expect("uninstall.ps1 readable");

    assert!(
        text.contains("AGENT_PLUGIN_DIR") || text.contains("LOCALAPPDATA"),
        "agent-plugin uninstall.ps1 must know where to remove the plugin from"
    );
}

#[test]
fn agent_plugin_install_script_does_not_require_symlinks_unconditionally() {
    let script = sure_testkit::repository_root()
        .join("integrations")
        .join("agent-plugin")
        .join("scripts")
        .join("install.ps1");

    let text = std::fs::read_to_string(&script).expect("install.ps1 readable");

    // The script must not unconditionally use New-Item -ItemType SymbolicLink;
    // it should have a copy fallback or a ForceCopy switch.
    let has_symlink = text.contains("SymbolicLink");
    let has_fallback = text.contains("ForceCopy") || text.contains("Copy-Item");
    assert!(
        !has_symlink || has_fallback,
        "agent-plugin install.ps1 must not require symlink privileges unconditionally; it needs a copy fallback"
    );
}

#[cfg(windows)]
#[test]
fn agent_plugin_install_script_runs_into_temp_directory() {
    let repo = sure_testkit::repository_root();
    let install_script = repo
        .join("integrations")
        .join("agent-plugin")
        .join("scripts")
        .join("install.ps1");

    let temp = std::env::temp_dir().join(format!("sure-agent-install-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).expect("temp dir");

    let plugin_dir = temp.join("agent-plugins");
    let sure_bin = temp.join("sure.exe");
    std::fs::write(&sure_bin, "dummy").expect("write dummy sure.exe");

    let output = std::process::Command::new("powershell")
        .args([
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &install_script.to_string_lossy(),
        ])
        .env("AGENT_PLUGIN_DIR", &plugin_dir)
        .env("SURE_BIN", &sure_bin)
        .output()
        .expect("spawn install.ps1");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "install.ps1 failed: stdout={stdout}, stderr={stderr}"
    );

    let installed = plugin_dir.join("sure");
    assert!(
        installed.is_dir(),
        "plugin directory should be created at {installed:?}"
    );
    assert!(
        installed.join("plugin.json").is_file(),
        "plugin.json should be present in installed plugin"
    );
    assert!(
        installed.join("mcp.json").is_file(),
        "mcp.json should be present in installed plugin"
    );
    assert!(
        installed
            .join("skills")
            .join("sure-check")
            .join("SKILL.md")
            .is_file(),
        "SKILL.md should be present in installed plugin"
    );

    let _ = std::fs::remove_dir_all(&temp);
}

#[cfg(windows)]
#[test]
fn the_cursor_and_agent_plugin_installers_say_what_their_mcp_manifest_needs() {
    // Both packages declare their MCP server as `command: "sure"`, which starts
    // only where `sure` resolves on PATH — the documented requirement in each
    // package's README. The installer is the one place SURE can be actionable
    // about it, so when the binary it resolved is not what PATH would find it
    // must say so and name the path, rather than installing a manifest that
    // starts nothing and never says why.
    for (package, dir_variable) in [
        ("cursor", "CURSOR_PLUGIN_DIR"),
        ("agent-plugin", "AGENT_PLUGIN_DIR"),
    ] {
        let script = sure_testkit::repository_root()
            .join("integrations")
            .join(package)
            .join("scripts")
            .join("install.ps1");
        let scratch = launcher_scratch(&format!("mcp-path-{package}"));
        let plugin_dir = scratch.join("plugins");
        let empty_path = scratch.join("empty-path");
        std::fs::create_dir_all(&empty_path).expect("empty PATH directory");
        let sure_bin = stub_binary(&scratch, "sure-not-on-path.cmd", "exit /b 0\r\n");

        let output = std::process::Command::new(powershell())
            .args([
                "-NoProfile",
                "-File",
                &script.to_string_lossy(),
                "-ForceCopy",
            ])
            .env(dir_variable, &plugin_dir)
            .env("SURE_BIN", &sure_bin)
            .env("PATH", &empty_path)
            .output()
            .unwrap_or_else(|error| panic!("spawn {package} install.ps1: {error}"));

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{package} install.ps1 failed: stdout={stdout}, stderr={stderr}"
        );
        assert!(
            stdout.contains("PATH") && stdout.contains(&sure_bin.to_string_lossy().to_string()),
            "{package} install.ps1 did not say that its mcp.json starts `sure` from PATH, and \
             where the binary it found is instead: {stdout}"
        );
        // What was installed still names `sure`: the requirement is stated, not
        // silently rewritten by whoever happened to run the installer.
        let installed = std::fs::read_to_string(plugin_dir.join("sure").join("mcp.json"))
            .unwrap_or_else(|error| panic!("{package} mcp.json installed: {error}"));
        assert!(
            installed.contains("\"command\": \"sure\""),
            "{package} mcp.json no longer names `sure`: {installed}"
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }
}

// --- codex --------------------------------------------------------------

fn codex_path(relative: &str) -> PathBuf {
    let mut path = sure_testkit::repository_root()
        .join("integrations")
        .join("codex");
    for part in relative.split('/') {
        path = path.join(part);
    }
    path
}

fn codex_text(relative: &str) -> String {
    let path = codex_path(relative);
    assert!(path.is_file(), "codex {relative} must exist");
    std::fs::read_to_string(&path).expect("codex file readable")
}

/// The frozen sentence is the core's to say.
///
/// An integration that restates it owns a second copy that goes stale the next
/// time the constant changes, which is the failure the thinness check exists to
/// catch. `docs/product/UX_AND_LANGUAGE.md` owns the wording.
fn assert_no_frozen_sentence(label: &str, text: &str) {
    let normalised = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let frozen = sure_domain::status::NO_TRUSTED_INTENT_LIMITATION;
    let frozen_normalised = frozen.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        !normalised.contains(&frozen_normalised),
        "{label} must not copy the frozen no-trusted-intent limitation sentence; the core owns that wording"
    );
}

#[test]
fn codex_skill_files_exist_and_are_thin() {
    for name in ["sure-check", "sure-fix"] {
        let relative = format!("skills/{name}/SKILL.md");
        let text = codex_text(&relative);

        // Codex reads skills from `.agents/skills` and requires both front
        // matter keys; a SKILL.md without them is never offered.
        assert!(
            text.starts_with("---\n"),
            "codex {relative} must open with YAML front matter"
        );
        assert!(
            text.contains("name:") && text.contains("description:"),
            "codex {relative} must carry the `name` and `description` front matter Codex requires"
        );

        let reaches_core = text.contains("SURE_BIN")
            || text.contains("sure.exe")
            || text.contains("sure check")
            || text.contains("sure repair")
            || text.contains("sure recheck");
        assert!(
            reaches_core,
            "codex {relative} must reference local SURE invocation (SURE_BIN, sure.exe, or sure <subcommand>)"
        );

        assert_no_frozen_sentence(&format!("codex {relative}"), &text);
    }
}

#[test]
fn codex_check_prompt_preserves_uncertainty_and_is_thin() {
    let text = codex_text("prompts/check.md");

    let reaches_core =
        text.contains("SURE_BIN") || text.contains("sure.exe") || text.contains("sure check");
    assert!(
        reaches_core,
        "codex prompts/check.md must reference local SURE invocation (SURE_BIN, sure.exe, or sure check)"
    );

    // Honest uncertainty: every not-checked state stays visible and none of
    // them may be turned into a pass. This is named in SURE's own vocabulary
    // rather than by restating the core's frozen user-facing sentence.
    for status in ["unknown", "skipped", "error", "cannot_confirm"] {
        assert!(
            text.contains(status),
            "codex prompts/check.md must name `{status}` among the states not to soften"
        );
    }
    assert!(
        text.contains("into a pass"),
        "codex prompts/check.md must forbid turning a not-checked state into a pass"
    );

    assert_no_frozen_sentence("codex prompts/check.md", &text);
}

#[test]
fn codex_repair_handoff_references_repair_and_recheck() {
    // Both surfaces carry the handoff: the deprecated `/prompts:` file and the
    // current skill. Keeping them in one test is what stops one from drifting.
    for relative in ["prompts/fix.md", "skills/sure-fix/SKILL.md"] {
        let text = codex_text(relative);

        assert!(
            text.contains("sure repair"),
            "codex {relative} must reference `sure repair` so the handoff can obtain the contract"
        );
        assert!(
            text.contains("sure recheck"),
            "codex {relative} must reference `sure recheck` so the handoff can close with evidence"
        );
        assert!(
            text.contains("not evidence"),
            "codex {relative} must say the agent's own completion message is not evidence"
        );

        assert_no_frozen_sentence(&format!("codex {relative}"), &text);
    }
}

#[test]
fn codex_mcp_template_names_sure_mcp_serve() {
    let text = codex_text("mcp.toml");

    assert!(
        text.contains("[mcp_servers.sure]"),
        "codex mcp.toml must declare the server as [mcp_servers.<name>], which is the key Codex reads"
    );
    assert!(
        text.contains("sure mcp serve"),
        "codex mcp.toml must name the `sure mcp serve` invocation"
    );

    // The template and the portable Agent Plugin must declare the same server,
    // or the two packages silently describe two different SURE bridges.
    let mcp_json = sure_testkit::repository_root()
        .join("integrations")
        .join("agent-plugin")
        .join("mcp.json");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&mcp_json).expect("agent-plugin mcp.json readable"),
    )
    .expect("agent-plugin mcp.json must be valid JSON");
    let sure = manifest
        .get("mcpServers")
        .and_then(|v| v.get("sure"))
        .expect("agent-plugin mcp.json must declare a 'sure' server");
    let command = sure
        .get("command")
        .and_then(|v| v.as_str())
        .expect("agent-plugin sure server must name a command");
    let args: Vec<&str> = sure
        .get("args")
        .and_then(|v| v.as_array())
        .expect("agent-plugin sure server must list args")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    assert!(
        text.contains(&format!("command = \"{command}\"")),
        "codex mcp.toml must name the same command the Agent Plugin declares ('{command}')"
    );
    let args_toml = format!(
        "args = [{}]",
        args.iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert!(
        text.contains(&args_toml),
        "codex mcp.toml must carry `{args_toml}`, the same args the Agent Plugin declares"
    );

    assert_no_frozen_sentence("codex mcp.toml", &text);
}

#[test]
fn codex_readme_documents_the_achieved_tier() {
    let text = codex_text("README.md");

    // The achieved tier is stated, and the tier that is deliberately not
    // claimed is stated as unclaimed. A README that only lists ambitions is how
    // a Tier 0 package gets read as a Tier 2 one.
    for tier in ["Tier 0", "Tier 1", "Tier 2"] {
        assert!(
            text.contains(tier),
            "codex README.md must name {tier} so the achieved tier is unambiguous"
        );
    }
    assert!(
        text.contains("not claimed"),
        "codex README.md must say plainly which tier is not claimed"
    );
    assert!(
        text.contains("cannot confirm") || text.contains("cannot say what Codex did"),
        "codex README.md must state the blind spot behind the achieved tier"
    );

    // The documented binary resolution order, and the no-admin promise.
    assert!(
        text.contains("SURE_BIN") && text.contains("LOCALAPPDATA"),
        "codex README.md must document the SURE_BIN / PATH / LOCALAPPDATA resolution order"
    );
    assert!(
        text.to_ascii_lowercase().contains("no administrator")
            || text.to_ascii_lowercase().contains("administrator rights"),
        "codex README.md must state that installation needs no administrator rights"
    );

    // What it deliberately does not do.
    assert!(
        text.to_ascii_lowercase().contains("no checking logic"),
        "codex README.md must state that the package contains no checking logic"
    );

    assert_no_frozen_sentence("codex README.md", &text);
}

#[cfg(windows)]
#[test]
fn agent_plugin_uninstall_script_removes_installed_plugin() {
    let repo = sure_testkit::repository_root();
    let uninstall_script = repo
        .join("integrations")
        .join("agent-plugin")
        .join("scripts")
        .join("uninstall.ps1");

    let temp =
        std::env::temp_dir().join(format!("sure-agent-uninstall-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).expect("temp dir");

    let plugin_dir = temp.join("agent-plugins");
    let installed = plugin_dir.join("sure");
    std::fs::create_dir_all(&installed).expect("create fake plugin dir");
    std::fs::write(installed.join("dummy.txt"), "hello").expect("write dummy file");

    let output = std::process::Command::new("powershell")
        .args([
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &uninstall_script.to_string_lossy(),
        ])
        .env("AGENT_PLUGIN_DIR", &plugin_dir)
        .output()
        .expect("spawn uninstall.ps1");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "uninstall.ps1 failed: stdout={stdout}"
    );
    assert!(
        stdout.contains("Uninstalled"),
        "uninstall.ps1 should report removal when plugin was present: {stdout}"
    );
    assert!(
        !installed.exists(),
        "plugin directory should be removed after uninstall"
    );

    // Run again against empty directory; should report not present.
    let output = std::process::Command::new("powershell")
        .args([
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            &uninstall_script.to_string_lossy(),
        ])
        .env("AGENT_PLUGIN_DIR", &plugin_dir)
        .output()
        .expect("spawn uninstall.ps1 again");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("not installed"),
        "uninstall.ps1 should report not-installed when plugin is absent: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&temp);
}

// --- claude-code install/uninstall: what "install the Claude package" means ---
//
// P15-T009's acceptance is that a Windows user can install and remove the
// Claude and Cursor packages with documented PowerShell commands, and that a
// normal per-user install needs neither symlink privileges nor administrator
// rights. The Cursor half was already here; the Claude package shipped no
// installer of either kind.
//
// **What "install Claude" means is decided here.** This package names its own
// files through `${CLAUDE_PLUGIN_ROOT}`, which is Claude Code's substitution
// (`integrations/claude-code/README.md`), so the package is relocatable by
// design and a per-user copy of it is a valid plugin root. The installer places
// that copy and resolves the binary the way every other installer here does.
// **Loading the plugin is Claude Code's own workflow, and this repository does
// not claim to have watched it** — no plugin was installed into a running
// session, which is the line `integrations/claude-code/README.md` already draws
// for the MCP server. The argument for this option, and against shipping the
// plugin CLI as the thing SURE documents, is in
// `docs/integrations/INSTALLATION_MATRIX.md`, where a reader who is not reading
// this file will look for it.
//
// Every test below runs a script into a scratch directory and sets
// `CLAUDE_PLUGIN_DIR`, so nothing here reaches `%LOCALAPPDATA%\claude-plugins`,
// `%USERPROFILE%\.claude` or any other directory of whoever runs the suite.

/// The Claude Code package's README, which is where the documented commands
/// live: the acceptance asks for *documented* PowerShell commands, so the
/// document and the scripts are asserted against each other.
fn claude_code_readme() -> String {
    let path = sure_testkit::repository_root()
        .join("integrations")
        .join("claude-code")
        .join("README.md");
    assert!(path.is_file(), "claude-code README.md must exist");
    std::fs::read_to_string(&path).expect("claude-code README.md readable")
}

/// A plugin script of the Claude Code package, for the tests that only read it.
fn claude_code_script(name: &str) -> PathBuf {
    sure_testkit::repository_root()
        .join("integrations")
        .join("claude-code")
        .join("scripts")
        .join(name)
}

#[test]
fn claude_code_install_script_exists_and_has_required_contract() {
    let script = claude_code_script("install.ps1");
    assert!(script.is_file(), "claude-code install.ps1 must exist");

    let text = std::fs::read_to_string(&script).expect("install.ps1 readable");

    assert!(
        text.contains("SURE_BIN"),
        "claude-code install.ps1 must reference SURE_BIN for binary resolution"
    );
    assert!(
        text.contains("CLAUDE_PLUGIN_DIR"),
        "claude-code install.ps1 must reference CLAUDE_PLUGIN_DIR for the install location"
    );
    assert!(
        text.contains("LOCALAPPDATA"),
        "claude-code install.ps1 must reference LOCALAPPDATA for the per-user default"
    );
    assert!(
        text.contains("Copy-Item") || text.to_ascii_lowercase().contains("copy"),
        "claude-code install.ps1 must support copy fallback"
    );
    assert!(
        text.contains("ForceCopy")
            || text.contains("{{SURE_BIN}}")
            || text.contains("{{PLUGIN_ROOT}}"),
        "claude-code install.ps1 must have a copy/render fallback or force-copy switch"
    );
}

#[test]
fn claude_code_uninstall_script_exists() {
    let script = claude_code_script("uninstall.ps1");
    assert!(script.is_file(), "claude-code uninstall.ps1 must exist");

    let text = std::fs::read_to_string(&script).expect("uninstall.ps1 readable");

    assert!(
        text.contains("CLAUDE_PLUGIN_DIR") || text.contains("LOCALAPPDATA"),
        "claude-code uninstall.ps1 must know where to remove the plugin from"
    );
}

#[test]
fn claude_code_install_script_does_not_require_symlinks_unconditionally() {
    let script = claude_code_script("install.ps1");
    let text = std::fs::read_to_string(&script).expect("install.ps1 readable");

    // The script must not unconditionally use New-Item -ItemType SymbolicLink;
    // it should have a copy fallback or a ForceCopy switch. Acceptance line 2 is
    // the reason: a per-user install may not need the privilege.
    let has_symlink = text.contains("SymbolicLink");
    let has_fallback = text.contains("ForceCopy") || text.contains("Copy-Item");
    assert!(
        !has_symlink || has_fallback,
        "claude-code install.ps1 must not require symlink privileges unconditionally; \
         it needs a copy fallback"
    );
}

/// The install and the uninstall must agree on the directory they mean.
///
/// Remove is half of the acceptance, and it is the half that fails silently:
/// an uninstaller whose default drifts from the installer's leaves the package
/// in place and reports that it was never installed. The two scripts are
/// asserted against each other rather than against a literal, so that changing
/// the destination in one place only is what this catches. It is a text
/// assertion: the destination is only ever materialised for the person running
/// the installer, not for the suite.
#[test]
fn the_claude_code_install_and_uninstall_scripts_agree_on_where_the_package_goes() {
    let install =
        std::fs::read_to_string(claude_code_script("install.ps1")).expect("install.ps1 readable");
    let uninstall = std::fs::read_to_string(claude_code_script("uninstall.ps1"))
        .expect("uninstall.ps1 readable");

    for (name, text) in [("install.ps1", &install), ("uninstall.ps1", &uninstall)] {
        assert!(
            text.contains("'claude-plugins'"),
            "claude-code {name} does not name the same default plugin directory as its \
             partner script; uninstall would then remove nothing"
        );
        assert!(
            text.contains(r"'sure'"),
            "claude-code {name} must name the package's own folder inside that directory"
        );
    }
}

#[test]
fn the_claude_code_readme_documents_the_install_and_remove_commands() {
    // "Documented PowerShell commands" is half of the acceptance sentence, so
    // the document is asserted against the scripts rather than trusted: a
    // rename that leaves the README naming a file that is not there would
    // otherwise make the acceptance greener the less it was true.
    let readme = claude_code_readme();

    for command in [
        r"integrations\claude-code\scripts\install.ps1",
        r"integrations\claude-code\scripts\uninstall.ps1",
    ] {
        assert!(
            readme.contains(command),
            "claude-code README.md must give the PowerShell command that runs {command}"
        );
    }
    assert!(
        readme.contains("PowerShell"),
        "claude-code README.md must say which shell the install commands are for"
    );
    assert!(
        readme.to_ascii_lowercase().contains("no administrator")
            || readme.to_ascii_lowercase().contains("administrator rights"),
        "claude-code README.md must state that a per-user install needs no administrator rights"
    );
    // The documented destination and the script's default have to be the same
    // string, or the README describes an install nobody gets. The assertion
    // pins the whole backticked path and not the directory name alone: a
    // substring check for `…\claude-plugins\sure` is satisfied by
    // `…\claude-plugins\sure-old` too, which is how a documentation test goes
    // green while describing somewhere the installer never writes.
    assert!(
        readme.contains(r"`%LOCALAPPDATA%\claude-plugins\sure`"),
        "claude-code README.md must name the directory the installer defaults to, in \
         backticks, as the table above it does"
    );
    assert!(
        std::fs::read_to_string(claude_code_script("install.ps1"))
            .expect("install.ps1 readable")
            .contains(r"'claude-plugins'"),
        "claude-code install.ps1 no longer defaults to the directory its README documents"
    );
}

#[cfg(windows)]
#[test]
fn claude_code_install_script_runs_into_temp_directory() {
    let script = claude_code_script("install.ps1");
    let scratch = launcher_scratch("claude-code-install");
    let plugin_dir = scratch.join("claude-plugins");
    let sure_bin = scratch.join("sure.exe");
    std::fs::write(&sure_bin, "dummy").expect("write dummy sure.exe");

    // `run_launcher` asks the PowerShell hosts on this machine in turn and
    // fails with what each answered, rather than passing -ExecutionPolicy
    // Bypass: an override would make the installer pass for a reason that is
    // not the installer.
    let output = run_launcher(
        &script,
        &[],
        "",
        &[
            ("CLAUDE_PLUGIN_DIR", plugin_dir.as_os_str()),
            ("SURE_BIN", sure_bin.as_os_str()),
        ],
        &[],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "claude-code install.ps1 failed: stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stdout.contains("Installed"),
        "install.ps1 should say what it did: {stdout}"
    );

    let installed = plugin_dir.join("sure");
    assert!(
        installed.is_dir(),
        "the package should be installed at {installed:?}"
    );
    for relative in [
        [".claude-plugin", "plugin.json"],
        ["hooks", "hooks.json"],
        ["scripts", "sure-mcp.ps1"],
        ["scripts", "sure-hook.ps1"],
        ["commands", "check.md"],
    ] {
        let path = relative
            .iter()
            .fold(installed.clone(), |path, part| path.join(*part));
        assert!(
            path.is_file(),
            "{} should be present in the installed package",
            path.display()
        );
    }
    assert!(
        installed.join(".mcp.json").is_file(),
        "the dotfile manifest should be copied too, or the installed package is not a plugin"
    );

    // The render step replaces `{{SURE_BIN}}` and `{{PLUGIN_ROOT}}`. This
    // package is relocatable because it names `${CLAUDE_PLUGIN_ROOT}`, which is
    // Claude Code's substitution, so the render step must not touch it — a
    // render map keyed on `PLUGIN_ROOT` instead of `{{PLUGIN_ROOT}}` would
    // rewrite the package's own placeholder and leave a plugin that points at a
    // path nobody substitutes. Read only on the copy path: a symlinked install
    // has no copy to read, and the files it points at are the source ones these
    // assertions are about.
    if !installed
        .symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_symlink())
    {
        let mcp = std::fs::read_to_string(installed.join(".mcp.json"))
            .expect("installed .mcp.json readable");
        assert!(
            mcp.contains("${CLAUDE_PLUGIN_ROOT}"),
            "the installed .mcp.json lost Claude Code's own placeholder: {mcp}"
        );
        let hooks = std::fs::read_to_string(installed.join("hooks").join("hooks.json"))
            .expect("installed hooks.json readable");
        assert!(
            hooks.contains("${CLAUDE_PLUGIN_ROOT}"),
            "the installed hooks.json lost Claude Code's own placeholder: {hooks}"
        );
    }

    let _ = std::fs::remove_dir_all(&scratch);
}

#[cfg(windows)]
#[test]
fn claude_code_install_script_copies_when_a_symlink_is_not_allowed() {
    // Acceptance line 2, exercised rather than read. The installer probes for
    // symlink capability in `%TEMP%`; this points `TEMP` at a directory that
    // does not exist, so the probe cannot succeed whatever the machine allows,
    // and the run that follows is the copy path by construction.
    //
    // What breaks this test: making the symlink unconditional (`$link=$true`),
    // or dropping the copy branch. Both make the install fail with
    // `UnauthorizedAccessException` on a machine without Developer Mode — which
    // is this one — and that was measured rather than assumed: see the
    // hand-back for the run against a deliberately broken copy of the script.
    let script = claude_code_script("install.ps1");
    let scratch = launcher_scratch("claude-code-copy");
    let plugin_dir = scratch.join("claude-plugins");
    let sure_bin = scratch.join("sure.exe");
    std::fs::write(&sure_bin, "dummy").expect("write dummy sure.exe");
    let absent_temp = scratch.join("no-such-temp-directory");

    let output = run_launcher(
        &script,
        &[],
        "",
        &[
            ("CLAUDE_PLUGIN_DIR", plugin_dir.as_os_str()),
            ("SURE_BIN", sure_bin.as_os_str()),
            ("TEMP", absent_temp.as_os_str()),
        ],
        &[],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "claude-code install.ps1 failed when it could not make a symlink: \
         stdout={stdout}, stderr={stderr}"
    );

    let installed = plugin_dir.join("sure");
    let metadata = std::fs::symlink_metadata(&installed)
        .unwrap_or_else(|error| panic!("installed package at {}: {error}", installed.display()));
    assert!(
        metadata.file_type().is_dir(),
        "the fallback did not produce a directory at {}",
        installed.display()
    );
    assert!(
        installed
            .join(".claude-plugin")
            .join("plugin.json")
            .is_file(),
        "the copied package is missing its manifest"
    );

    let _ = std::fs::remove_dir_all(&scratch);
}

#[cfg(windows)]
#[test]
fn claude_code_install_script_refuses_when_sure_is_not_installed() {
    // The other half of the installer contract, and the one the package's own
    // documentation states: `docs/integrations/CLAUDE_CODE.md` requires an
    // install to fail safely when the binary is unavailable. A package placed
    // where nothing can start it, with no word said, is the failure this
    // refusal exists to prevent.
    let script = claude_code_script("install.ps1");
    let scratch = launcher_scratch("claude-code-missing-bin");
    let plugin_dir = scratch.join("claude-plugins");
    let empty_path = scratch.join("empty-path");
    let empty_local = scratch.join("localappdata");
    std::fs::create_dir_all(&empty_path).expect("empty PATH directory");
    std::fs::create_dir_all(&empty_local).expect("per-user directory");

    let output = run_launcher(
        &script,
        &[],
        "",
        &[
            ("CLAUDE_PLUGIN_DIR", plugin_dir.as_os_str()),
            ("LOCALAPPDATA", empty_local.as_os_str()),
            ("PATH", empty_path.as_os_str()),
        ],
        &["SURE_BIN"],
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "install.ps1 succeeded with no SURE binary anywhere: stderr={stderr}"
    );
    assert!(
        stderr.contains("SURE not found"),
        "install.ps1 must say why it refused: {stderr}"
    );
    assert!(
        !plugin_dir.join("sure").exists(),
        "install.ps1 refused but touched the plugin directory anyway"
    );

    let _ = std::fs::remove_dir_all(&scratch);
}

#[cfg(windows)]
#[test]
fn claude_code_uninstall_script_removes_installed_package() {
    let script = claude_code_script("uninstall.ps1");
    let scratch = launcher_scratch("claude-code-uninstall");
    let plugin_dir = scratch.join("claude-plugins");
    let installed = plugin_dir.join("sure");
    std::fs::create_dir_all(&installed).expect("create installed package");
    std::fs::write(installed.join("dummy.txt"), "hello").expect("write dummy file");

    let output = run_launcher(
        &script,
        &[],
        "",
        &[("CLAUDE_PLUGIN_DIR", plugin_dir.as_os_str())],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "claude-code uninstall.ps1 failed: stdout={stdout}"
    );
    assert!(
        stdout.contains("Uninstalled"),
        "uninstall.ps1 should report removal when the package was present: {stdout}"
    );
    assert!(
        !installed.exists(),
        "the package directory should be removed after uninstall"
    );

    // Run again against an empty directory; it must say so rather than fail or
    // claim a removal that did not happen.
    let output = run_launcher(
        &script,
        &[],
        "",
        &[("CLAUDE_PLUGIN_DIR", plugin_dir.as_os_str())],
        &[],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "claude-code uninstall.ps1 failed on a machine where nothing was installed: {stdout}"
    );
    assert!(
        stdout.contains("not installed"),
        "uninstall.ps1 should report not-installed when the package is absent: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&scratch);
}

// --- packaging: the version a package declares, and the launchers a platform
// --- can actually start ---------------------------------------------------
//
// P15-T008's acceptance has two lines, and each one is a claim this file can
// hold: "Installable/local-test packages have version aligned with release" and
// "Windows launchers are tested; secondary platform launchers/configs are
// included as supported".
//
// **What "supported" means is decided here, because until it is decided the
// word asserts nothing.** A package's non-Windows launcher counts as supported
// when all three of these hold, and each is an assertion below rather than a
// sentence in a README:
//
//   1. the launcher is shipped, and it names its own interpreter on its first
//      line, so the only thing between it and starting by path is the mode;
//   2. the repository records that path as executable, in the **git index**;
//   3. a manifest that names the launcher by path is checked beside it, since
//      that manifest's `command` is only startable while (2) holds.
//
// The argument for the index and against naming an interpreter in the manifest
// is in `docs/integrations/INSTALLATION_MATRIX.md`, which is where a reader who
// is not reading this file will look for it.

/// A script inside one integration package.
///
/// Gated with the tests that use it: a helper whose only callers are
/// `#[cfg(windows)]` is dead code everywhere else, and `-D warnings` fails those
/// jobs on it.
#[cfg(windows)]
fn integ_script(package: &str, name: &str) -> PathBuf {
    sure_testkit::repository_root()
        .join("integrations")
        .join(package)
        .join("scripts")
        .join(name)
}

/// Every POSIX launcher an integration package ships.
///
/// Used by a test that runs on every platform as well as by the Unix-gated one
/// below, because a helper that a `#[cfg]`-gated test is the only user of is
/// dead code on the other platforms and `-D warnings` fails those jobs on it.
fn posix_launchers() -> Vec<IntegrationFile> {
    let launchers: Vec<IntegrationFile> = loaded()
        .into_iter()
        .filter(|f| f.extension() == "sh")
        .collect();
    assert!(
        launchers.len() >= 3,
        "expected a POSIX launcher for claude-code, cursor and codex; found {:?}",
        launchers.iter().map(|f| &f.relative).collect::<Vec<_>>()
    );
    launchers
}

/// The mode the repository records for a path under `integrations/`, read out of
/// the git index.
///
/// The index is what a clone materialises, so this is the mode a Unix checkout
/// gets — and it is readable on Windows, where a working tree cannot carry one
/// at all.
fn indexed_mode(relative_to_integrations: &str) -> String {
    let relative = format!("integrations/{relative_to_integrations}");
    let output = std::process::Command::new("git")
        .current_dir(sure_testkit::repository_root())
        .args(["ls-files", "-s", "--", &relative])
        .output()
        .expect(
            "`git` must be runnable to read the index mode this assertion is about; \
             it is absent or not on PATH",
        );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_else(|| panic!("git ls-files -s reported nothing for {relative}: {stdout}"));
    line.split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn every_packaged_manifest_declares_the_release_version() {
    // `sure_domain::VERSION` is the version `sure` reports for itself, and
    // `docs/development/RELEASE_PROCESS.md` names the release archive after the
    // version `sure` reports. Taking it from the core rather than re-parsing
    // `Cargo.toml` here is what keeps this assertion from drifting from the
    // value the release is named after.
    let release = sure_domain::VERSION;
    assert!(
        !release.is_empty(),
        "the core reports an empty version, so nothing here could be aligned with it"
    );

    let files = loaded();
    let mut found: Vec<(String, String)> = Vec::new();
    for file in &files {
        if file.path.file_name().and_then(|n| n.to_str()) != Some("plugin.json") {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(&file.text)
            .unwrap_or_else(|error| panic!("{} must be valid JSON: {error}", file.relative));
        let version = value
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{} must declare a version", file.relative));
        found.push((file.relative.clone(), version.to_owned()));
    }
    found.sort();

    // The set is pinned, not only swept: a package that loses its manifest, or
    // a fourth that ships one with a version nobody aligned, would otherwise
    // make this test greener the less there was to check.
    let expected: Vec<&str> = vec![
        "agent-plugin/plugin.json",
        "claude-code/.claude-plugin/plugin.json",
        "cursor/.cursor-plugin/plugin.json",
    ];
    assert_eq!(
        found
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        expected,
        "the packages that declare a version are not the ones that did"
    );
    for (path, version) in &found {
        assert_eq!(
            version, release,
            "{path} declares version '{version}' and the release is '{release}'"
        );
    }

    // A package with an installer is installable by definition, so it is the
    // one shape that must never be able to lose its version unnoticed.
    let mut installable: Vec<&str> = files
        .iter()
        .filter(|f| f.relative.ends_with("scripts/install.ps1"))
        .filter_map(|f| f.relative.split('/').next())
        .collect();
    installable.sort_unstable();
    installable.dedup();
    assert!(
        !installable.is_empty(),
        "no package ships an installer, so the sweep above proves nothing about \
         installable packages"
    );
    for package in &installable {
        assert!(
            found
                .iter()
                .any(|(path, _)| path.starts_with(&format!("{package}/"))),
            "{package} ships an installer and declares no version at all, so there is \
             nothing of it to align with the release"
        );
    }
}

#[test]
fn the_unix_launchers_carry_the_executable_bit_in_the_index() {
    // The codex hook manifest runs its launcher by path — `command` is
    // `"${PLUGIN_ROOT}/scripts/sure-hook.sh"` — so on the platform that command
    // targets, the exec bit is the difference between the hook running and the
    // kernel answering "Permission denied". A clone with `core.filemode=true`
    // takes this mode from the index; a clone with it false does not, which is
    // stated as the cost of this choice rather than hidden.
    for launcher in posix_launchers() {
        assert_eq!(
            indexed_mode(&launcher.relative),
            "100755",
            "{} is recorded without the executable bit, so a fresh Unix checkout \
             cannot start it by path",
            launcher.relative
        );
        assert!(
            launcher.text.starts_with("#!"),
            "{} must name its interpreter on its first line, or the mode above starts \
             nothing anyway",
            launcher.relative
        );
    }
}

#[cfg(unix)]
#[test]
fn the_unix_launchers_are_executable_where_that_is_observable() {
    // Only a Unix filesystem can answer this, and it is the end-user-visible
    // half of the assertion above: what the checkout actually produced. The
    // index says what a clone should get; this says what one got. Windows jobs
    // compile it out, so the `ubuntu-latest` and `macos-latest` jobs are what
    // hold this property.
    use std::os::unix::fs::PermissionsExt;

    for launcher in posix_launchers() {
        let mode = std::fs::metadata(&launcher.path)
            .unwrap_or_else(|error| panic!("{} readable: {error}", launcher.relative))
            .permissions()
            .mode();
        assert!(
            mode & 0o111 != 0,
            "{} is mode {:o} on this checkout, so naming it by path does not start it",
            launcher.relative,
            mode
        );
    }
}

/// Every `command` / `commandWindows` string in a hook manifest, and where it
/// was found.
fn collect_command_strings(
    prefix: &str,
    value: &serde_json::Value,
    out: &mut Vec<(String, String)>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                let here = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                if (key == "command" || key == "commandWindows")
                    && let Some(text) = item.as_str()
                {
                    out.push((here, text.to_owned()));
                    continue;
                }
                collect_command_strings(&here, item, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_command_strings(&format!("{prefix}[{index}]"), item, out);
            }
        }
        _ => {}
    }
}

#[test]
fn the_codex_manifest_gives_each_platform_a_launcher_that_platform_can_start() {
    // The one manifest in this tree whose Unix `command` is a launcher rather
    // than an interpreter, and therefore the one place the index mode is
    // load-bearing. Both halves are read out of the file, so a change to either
    // is a change this test sees.
    let text = codex_text("hooks/hooks.json");
    let value: serde_json::Value =
        serde_json::from_str(&text).expect("codex hooks.json must be valid JSON");

    let mut commands: Vec<(String, String)> = Vec::new();
    collect_command_strings("", &value, &mut commands);
    assert!(
        commands.len() >= 4,
        "expected a command for each codex hook, found {commands:?}"
    );

    for (found_at, command) in &commands {
        // `commandWindows` is called that because it names the Windows
        // executable; the POSIX one is the plain `command`.
        if found_at.ends_with("commandWindows") {
            assert!(
                command.contains("powershell") && command.contains("-File"),
                "codex {found_at} must name the interpreter that starts it, since the \
                 `.ps1` it points at is not executable by anything: {command}"
            );
            assert!(
                command.contains("sure-hook.ps1"),
                "codex {found_at} names no launcher: {command}"
            );
        } else {
            assert!(
                command.contains("scripts/sure-hook.sh"),
                "codex {found_at} must name the POSIX launcher: {command}"
            );
            // Naming the file rather than an interpreter is the decision this
            // task made; it works only while the file is one the index marks
            // executable, which
            // `the_unix_launchers_carry_the_executable_bit_in_the_index` asserts
            // for every `.sh` in the tree.
            assert!(
                !command.starts_with("sh ") && !command.contains("sh -c"),
                "codex {found_at} names an interpreter, so the packages have stopped \
                 relying on the index mode this repository sets: {command}"
            );
        }
    }
}

// --- the Windows hook launchers, run rather than read ----------------------

/// A program on the parent's `PATH`, resolved before the child's environment is
/// written.
///
/// `std::process::Command` resolves a bare program name against the child's
/// `PATH` where one is set, and these tests set an empty one on purpose — so the
/// host has to be found by absolute path, or the test would fail for a reason
/// that is not the launcher.
#[cfg(windows)]
fn on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// The stand-in for the core: it records the argv it was handed and the payload
/// it was given, and answers 0.
#[cfg(windows)]
fn recording_sure_stub(dir: &std::path::Path) -> PathBuf {
    // `%*` is the argv the launcher handed the core, and `%~dp0` the stub's own
    // directory — the scratch directory this test made. Nothing outside it is
    // written. The payload arrives on the stub's stdin, which is where a harness
    // puts it.
    stub_binary(
        dir,
        "sure.cmd",
        "(echo %*) > \"%~dp0args.txt\"\r\n\
         findstr /r \".\" > \"%~dp0stdin.txt\"\r\n\
         exit /b 0\r\n",
    )
}

/// Run a launcher under a PowerShell host that will start it, and return the run.
///
/// Windows PowerShell 5.1 refuses to start any `.ps1` at all when the machine's
/// execution policy is `Restricted`, which is the default on a Windows client.
/// This test does not pass `-ExecutionPolicy Bypass` to get past that: an
/// override makes a launcher pass for a reason that is not the launcher, and the
/// packages' own manifests deliberately do not carry one. It asks the hosts that
/// will start the file instead, and when none will, it fails with what each host
/// answered — a refusal that is visible, never a run that is quietly skipped.
#[cfg(windows)]
fn run_launcher(
    script: &std::path::Path,
    args: &[&str],
    stdin: &str,
    envs: &[(&str, &std::ffi::OsStr)],
    removals: &[&str],
) -> std::process::Output {
    use std::io::Write;

    let mut hosts: Vec<PathBuf> = Vec::new();
    if let Some(pwsh) = on_path("pwsh.exe").or_else(|| on_path("pwsh")) {
        hosts.push(pwsh);
    }
    hosts.push(powershell());

    let mut refusals: Vec<String> = Vec::new();
    for host in hosts {
        let mut command = std::process::Command::new(&host);
        command.arg("-NoProfile").arg("-File").arg(script);
        for arg in args {
            command.arg(arg);
        }
        for (key, value) in envs {
            command.env(key, value);
        }
        for key in removals {
            command.env_remove(key);
        }
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = match command.spawn() {
            Ok(child) => child,
            // This host is not installed; the next candidate is.
            Err(_) => continue,
        };
        if let Some(mut pipe) = child.stdin.take() {
            let _ = pipe.write_all(stdin.as_bytes());
            // `pipe` is dropped here, which closes it: the launcher reads to EOF.
        }
        let output = child
            .wait_with_output()
            .unwrap_or_else(|error| panic!("{} did not finish: {error}", host.display()));
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Only a refusal by the execution policy moves on to the next host. Any
        // other outcome is the launcher's, and is returned to be asserted on.
        if stderr.contains("about_Execution_Policies") || stderr.contains("UnauthorizedAccess") {
            refusals.push(format!("{}: {}", host.display(), stderr.trim()));
            continue;
        }
        return output;
    }
    panic!(
        "no PowerShell host on this machine will start {}; each answered:\n{}",
        script.display(),
        refusals.join("\n")
    );
}

#[cfg(windows)]
#[test]
fn the_windows_hook_launchers_forward_the_event_and_fail_safe() {
    // Every shipped `.ps1` hook, run as a program with a stand-in for the core.
    // Reading the file proves the text is what it was; this proves the event
    // arrives and the argv is the contract, which is the half of acceptance line
    // 2 that no test did before.
    let event = r#"{"hook_event_name":"SessionStart","session_id":"sure-thinness"}"#;
    // (package, the arguments a harness hands the launcher, the argv the core
    // must be handed). Codex takes no event name: its payload carries
    // `hook_event_name` itself, which is why its launcher forwards no argument.
    let cases: [(&str, &[&str], &[&str]); 4] = [
        (
            "claude-code",
            &["session-start"],
            &["hook", "ingest", "--source", "claude-code", "session-start"],
        ),
        (
            "cursor",
            &["session-start"],
            &[
                "--format",
                "json",
                "hook",
                "ingest",
                "--source",
                "cursor",
                "session-start",
            ],
        ),
        (
            "copilot",
            &["session-start"],
            &[
                "--format",
                "json",
                "hook",
                "ingest",
                "--source",
                "copilot",
                "session-start",
            ],
        ),
        (
            "codex",
            &[],
            &["--format", "json", "hook", "ingest", "--source", "codex"],
        ),
    ];

    for (package, launcher_args, expected_argv) in cases {
        let scratch = launcher_scratch(&format!("hook-{package}"));
        let stub = recording_sure_stub(&scratch);
        let script = integ_script(package, "sure-hook.ps1");

        let output = run_launcher(
            &script,
            launcher_args,
            event,
            &[("SURE_BIN", stub.as_os_str())],
            &[],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{package} launcher failed: stdout={stdout}, stderr={stderr}"
        );

        let forwarded = std::fs::read_to_string(scratch.join("args.txt")).unwrap_or_else(|error| {
            panic!("{package} launcher never started the core it resolved: {error}")
        });
        assert_eq!(
            forwarded.split_whitespace().collect::<Vec<_>>(),
            expected_argv,
            "{package} launcher handed the core a different argv"
        );

        let delivered = std::fs::read_to_string(scratch.join("stdin.txt"))
            .unwrap_or_else(|error| panic!("{package} launcher sent nothing to the core: {error}"));
        assert!(
            delivered.contains("sure-thinness"),
            "{package} launcher did not forward the event it was given: {delivered:?}"
        );

        // The other half: SURE absent. The launcher must not block the session
        // and must not fabricate a result — nothing on the protocol stream, and
        // a sentence naming what was looked for.
        let empty_path = scratch.join("empty-path");
        let empty_local = scratch.join("empty-localappdata");
        std::fs::create_dir_all(&empty_path).expect("empty PATH directory");
        std::fs::create_dir_all(&empty_local).expect("empty per-user directory");
        let output = run_launcher(
            &script,
            launcher_args,
            event,
            &[
                ("LOCALAPPDATA", empty_local.as_os_str()),
                ("PATH", empty_path.as_os_str()),
            ],
            &["SURE_BIN"],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(0),
            "a missing SURE must not block the session: {package}: {stderr}"
        );
        assert!(
            stdout.is_empty(),
            "{package} launcher fabricated a result with no SURE to ask: {stdout:?}"
        );
        assert!(
            stderr.contains("SURE binary not found") && stderr.contains(package),
            "{package} launcher did not say which binary was missing and for whom: {stderr:?}"
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }
}

#[cfg(windows)]
#[test]
fn the_windows_hook_launchers_do_not_bind_the_event_to_a_parameter() {
    // The shape the Codex launcher records a measurement for
    // (`integrations/codex/scripts/sure-hook.ps1:5-12`): a `param` block is
    // bound from a redirected event by PowerShell 5.1 — the host Windows 11 runs
    // by default, and the one every manifest here names — and the event never
    // arrives. The launcher then starts, exits 0 and collects nothing, which is
    // the silent failure this whole file exists to make visible.
    //
    // It is asserted as text because the behaviour is the 5.1 host's, and this
    // repository's development machine cannot run 5.1 at all: its execution
    // policy is `Restricted`, these tests pass no `-ExecutionPolicy` override,
    // and `& 'x.ps1'` under 5.1 was measured to be refused for that reason. So
    // no test here observes 5.1's binding. A string assertion is evidence of the
    // shape; it is not evidence of the host's behaviour, and it is not claimed
    // to be.
    for package in ["claude-code", "cursor", "codex", "copilot"] {
        let text = std::fs::read_to_string(integ_script(package, "sure-hook.ps1"))
            .unwrap_or_else(|error| panic!("{package} hook launcher readable: {error}"));
        assert!(
            !text.contains("param("),
            "{package} declares a param block, which PowerShell 5.1 binds from the \
             redirected event, so the hook runs and the event never arrives"
        );
        assert!(
            text.contains("$input"),
            "{package} does not read `$input`, which is where a redirected payload \
             arrives in both hosts"
        );
        assert!(
            text.contains("[Console]::In.ReadToEnd()"),
            "{package} has no fallback to the console, so a payload that arrives there \
             is read as empty"
        );
    }
}
