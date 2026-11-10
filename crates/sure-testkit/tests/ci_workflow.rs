//! The shape of `.github/workflows/ci.yml`, and what that shape is for.
//!
//! `P15-T010`'s acceptance is one sentence:
//!
//! > *Windows is mandatory primary job; macOS/Linux core jobs mandatory;
//! > fmt/check/clippy/test/evals included appropriately.*
//!
//! That sentence is four claims about a file, and a file is the thing this
//! machine can check. `ci.yml` already carried the substance of all four when
//! this file was written; what it did not carry was anything that would
//! *notice* one of them leaving. This repository has paid for that class of
//! blindness: `scripts/check-non-windows.mjs`'s header records that `ci` was red
//! for **75 consecutive runs** while every local gate was green, and the census
//! is item 99 of `progress/HANDOFF.md`.
//!
//! # What this file proves, and what it cannot
//!
//! It reads the workflow as text and asserts the four properties, each with an
//! edit that must turn it red. It proves **what the file says**. It proves
//! **nothing** about whether the workflow is valid YAML, whether GitHub Actions
//! would accept it, whether any run has happened, or whether a run that happened
//! passed. A file that says the right thing is not a run that did the right
//! thing, and the 75-run streak is exactly those two being confused; the run
//! record lives in `progress/HANDOFF.md`, and the runner is GitHub.
//! `grep -rn '\.github' --include='*.rs' crates/` found no test that read these
//! workflows at all before this one.
//!
//! # The reader, and why it is line-based
//!
//! `crates/sure-cli/tests/winget_manifest.rs` reads its YAML the same way — as
//! lines — for the same reason: a YAML parser would be a new dependency, and the
//! properties here are about text a person edits by hand. What keeps a line
//! reader honest is that it reports what it found. Every rule is written so that
//! a reader that came back empty produces *violations rather than silence*:
//! `a_workflow_that_is_not_there_is_not_a_pass` feeds it nothing and requires it
//! to complain, and `the_reader_sees_the_jobs_that_are_there` fails if the jobs,
//! the runners or the commands were read as absent. The one thing it
//! deliberately cannot read is a `run: |` block; a step that used one is
//! reported as a fault rather than skipped, so a multi-line command cannot hide
//! from these rules.
//!
//! # The rules, and the reading each one freezes
//!
//! 1. **The workflow runs by itself** — triggered by `push` and by
//!    `pull_request`. A job no trigger reaches is not a mandatory job.
//! 2. **Windows is a job of its own** — some job runs on `windows-latest` and
//!    on nothing else. This is the reading "primary job" is taken in:
//!    `docs/adr/0007-windows-primary-development.md` makes Windows the primary
//!    development environment, and the Windows-only checks (the bootstrap
//!    validation, the PowerShell host) are a job rather than a step of a matrix
//!    leg. A reader who disagrees with that reading should change this rule on
//!    purpose, not discover it afterwards.
//! 3. **The core jobs are mandatory on all three platforms** — the job that runs
//!    the workspace's tests runs them on `windows-latest`, `macos-latest` and
//!    `ubuntu-latest`, and none of the three may leave.
//! 4. **No job is conditional and nothing is allowed to fail** — no job-level
//!    `if:`, and no `continue-on-error` at any level. A step-level `if:` is not
//!    this rule's business: `ci.yml` uses one to apply the Linux `sysctl` knob
//!    only on Linux, and that is how a platform-specific step is written.
//! 5. **The four command families are run** — `fmt`, `check`, `clippy` and
//!    `test`, each carrying the fragments that make it a gate rather than a
//!    report, in one command per family.
//! 6. **The evals are reached by that test command** — it is a whole-workspace
//!    `cargo test`, and `crates/sure-core/tests/acceptance_report_runner.rs`
//!    names `evaluation/acceptance-manifest.json`, declares no case with
//!    `#[ignore]`, and the manifest declares cases. The evals are plain
//!    `#[test]`s, so running them *is* what "included appropriately" means here;
//!    the release *metrics* of `docs/product/PRODUCT_EVALS.md` are computed from
//!    that same report by `sure_core::release_gate` and read by
//!    `scripts/Build-Release.*`, which is `P15-T011`'s subject and
//!    `release-dry-run.yml`'s file.
//!
//! # Two things that look like gaps and are not
//!
//! `ci.yml` never runs `scripts/check-non-windows.mjs`, and that is correct
//! rather than an omission: the script cross-compiles clippy for Unix targets
//! *from Windows*, and this workflow's `macos-latest` and `ubuntu-latest` matrix
//! legs compile those `cfg` arms natively. Adding it here would be a redundant
//! job, and `scripts/check-non-windows.mjs` says so in its own header.
//! `release-dry-run.yml` is `workflow_dispatch`-only on purpose — its own header
//! and `docs/development/GITHUB_WORKFLOW.md` say the two workflows answer
//! different questions — so nothing here asserts anything about it.
//!
//! # Why the assertions live in `sure-testkit`
//!
//! This crate already holds the checks that keep the repository's own shape in
//! place (`repository_shape.rs`, `integration_thinness.rs`), it runs on all
//! three platforms — so this check runs in every matrix leg it is about — and
//! nothing in the product depends on it.
//!
//! # The second file: `.github/workflows/release.yml` (`P15-T011`)
//!
//! `P15-T011`'s acceptance is two sentences of different kinds:
//!
//! > *Release workflow can produce artifacts without requiring marketplace
//! > publication.*
//! > *No automatic force/merge behavior.*
//!
//! The first is a capability with a restriction and the second is a
//! prohibition, and a prohibition is the easiest kind of claim to assert
//! **vacuously**. Both are properties of a file, so both are read here, by the
//! same reader and the same rules-shaped function as the rest of this file —
//! `release_violations` over `release.yml` and the `scripts/Assemble-Release.sh`
//! its release job runs. What it proves is what that file says: no run of
//! `release.yml` has happened, because `git tag` returns zero tags on this
//! repository and its only trigger is a dispatch naming a tag. The rules and the
//! reading each one freezes are in the section headed "release.yml" below.
//!
//! Two of the rules are about *order* rather than presence, because presence is
//! where a rule of this kind goes vacuous: the two existence checks have to come
//! **before** `gh release create` in the file (a check after the create is not a
//! gate), and each job's `cargo test --workspace` has to come before the
//! packaging command that refuses without the release gate that test writes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

/// The workflow this file is about.
const WORKFLOW: &str = ".github/workflows/ci.yml";

/// The corpus the evals are read from, and the test target that runs it.
const MANIFEST: &str = "evaluation/acceptance-manifest.json";
const EVAL_RUNNER: &str = "crates/sure-core/tests/acceptance_report_runner.rs";

/// The three platforms the acceptance makes mandatory, as the labels spell them.
const PLATFORMS: [&str; 3] = ["windows-latest", "macos-latest", "ubuntu-latest"];

/// The workflow `P15-T011` added, and the script its `release` job runs.
const RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";
const ASSEMBLER: &str = "scripts/Assemble-Release.sh";

/// The create, as the file spells it — not the bare words "gh release create".
///
/// The narrower anchor is load-bearing rather than fussy, and the first run of
/// the rule below against the real file is what says so. The step that refuses a
/// tag which is not in the checkout carries a message that *mentions*
/// `gh release create` — "without `--verify-tag` would silently make one" — and
/// reading the bare words finds that sentence first, at line 576, ahead of the
/// step that checks whether a release already exists at line 601. The rule then
/// reported the create as happening *after* a check it in fact precedes, which
/// is a red test rather than a quiet misreading, and that is the whole reason
/// this constant exists. An anchor that also matches prose about the anchor is
/// not an anchor.
const CREATE: &str = "gh release create \"$TAG\"";

/// The four artifacts a release publishes, as `sure-$version-<triple>.<ext>`.
///
/// `<version>` is written as the shell variable the create step uses rather than
/// as a number, and that is the point rather than a shortcut: the version a
/// release is named after is the version `sure` itself reports, the tag is the
/// only place it is written down, and a workflow that spelled a version out
/// would be a second place for it to disagree with the artifact beside it.
const RELEASE_ARTIFACTS: [(&str, &str); 4] = [
    ("x86_64-pc-windows-msvc", "zip"),
    ("aarch64-apple-darwin", "tar.gz"),
    ("x86_64-apple-darwin", "tar.gz"),
    ("x86_64-unknown-linux-gnu", "tar.gz"),
];

/// The license-disclosure file every archive carries, and that the release
/// notes say it carries.
///
/// It is generated from `Cargo.lock` by `scripts/Generate-ThirdPartyNotices.mjs`
/// and staged by both `Build-Release.*` scripts, so it is inside each archive
/// rather than one of the nine assets attached to the release. The rule below
/// is therefore about the notes' sentence, which is the only place in
/// `release.yml` where a downloader is told what an archive holds.
const THIRD_PARTY_NOTICES: &str = "THIRD_PARTY_NOTICES.txt";

/// Tokens that would be automatic force or merge behaviour, and the act each is.
///
/// This is the second acceptance clause turned into text a reader can find. It
/// is a *list of acts*, not a list of commands, and the entry for each is the
/// act — `every_act_the_second_clause_forbids_is_one_this_reader_reports`
/// injects each token into the real workflow and requires the rule to name it,
/// so a token whose check had stopped working cannot stay here looking like a
/// check. What no list can carry is the acts nobody thought of; the header of
/// `scripts/git-guard.mjs` states the same two policies for the local case and
/// is where a reader should look for the intent behind this one.
const FORBIDDEN_ACTS: &[(&str, &str)] = &[
    ("git push", "a push, of any ref, to anywhere"),
    ("--force", "a force push, or a `--force-with-lease`"),
    (
        "--clobber",
        "replacing a release's assets rather than refusing a second run",
    ),
    ("git tag", "creating or moving a tag"),
    ("gh release delete", "deleting a release"),
    (
        "gh release edit",
        "editing a release, which is how a draft is published",
    ),
    (
        "gh release upload",
        "adding an asset to a release that already exists",
    ),
    ("--draft=false", "publishing a draft"),
    ("gh pr merge", "merging a pull request"),
    ("git merge", "merging"),
    ("git rebase", "rewriting history"),
    ("git reset", "rewriting history"),
    ("-X DELETE", "deleting through the API"),
    ("--auto", "an automatic action"),
];

/// The publication channels the first acceptance clause is about, and each one.
///
/// A job whose credentials are a marketplace token is a job that needs one, so
/// the clause is checked twice over: no channel's tooling is named, and no
/// `secrets.` reference exists — the one credential any step uses is
/// `${{ github.token }}`, which every run is issued and nothing has to be
/// configured for. Every token here is matched **case-sensitively**, because
/// they are command names: `WinGet` in a sentence inside the create step's
/// release notes is prose about what is *not* published, and `winget` is the
/// submitter.
const PUBLICATION_CHANNELS: &[(&str, &str)] = &[
    (
        "secrets.",
        "a repository secret, so the release would need configuring before it could run",
    ),
    ("vsce", "`vsce`, the Visual Studio Marketplace publisher"),
    ("ovsx", "`ovsx`, the Open VSX publisher"),
    ("npm publish", "the npm registry"),
    ("winget", "the WinGet community repository"),
    ("nuget", "the NuGet registry"),
    ("twine", "the Python package index"),
    ("homebrew", "a Homebrew tap"),
];

/// The credentials a publication channel's tooling reads, by the name it reads.
///
/// A second list rather than a case-insensitive match on the first, and this
/// file is why: the release notes the create step writes say in prose that no
/// WinGet package, no Marketplace extension and no npm package is published from
/// here, and matching case-insensitively would read that sentence as a
/// dependence on WinGet. The opposite mistake is the one that put this list
/// here: a workflow authenticates to the Marketplace with `VSCE_PAT`, which is
/// not spelled `vsce`, so the command-name list alone reported nothing when a
/// `VSCE_PAT` was added to the real workflow. That was found by running the
/// mutation, not by reading the rule. A list of command names is not a list of
/// the ways a credential arrives.
const PUBLICATION_CREDENTIALS: &[(&str, &str)] = &[
    (
        "VSCE_PAT",
        "the Visual Studio Marketplace publisher's personal access token",
    ),
    ("OVSX_PAT", "the Open VSX publisher's personal access token"),
    ("NPM_TOKEN", "the npm registry's token"),
    (
        "NODE_AUTH_TOKEN",
        "the npm registry's token, under the name `actions/setup-node` reads",
    ),
    ("NUGET_API_KEY", "the NuGet registry's key"),
    ("WINGET_TOKEN", "the WinGet submission token"),
    ("TWINE_PASSWORD", "the Python package index's password"),
    ("HOMEBREW_TAP_TOKEN", "a Homebrew tap's token"),
];

/// What each command family has to carry, and why the fragment is not decoration.
///
/// These are the spellings the rest of the repository already uses: the
/// supervisor's gate set runs `cargo clippy --workspace --all-targets
/// --all-features -- -D warnings` and `cargo test --workspace --all-features
/// --no-fail-fast`, and `scripts/check-non-windows.mjs` runs the same clippy
/// command for the other platform. A CI run that selected a different set of
/// features would be a second definition of "the checks" — see the argument in
/// `docs/development/GITHUB_WORKFLOW.md`.
const REQUIRED: &[(&str, &[(&str, &str)])] = &[
    (
        "cargo fmt",
        &[(
            "--check",
            "a `fmt` step without it rewrites the tree instead of failing the run",
        )],
    ),
    (
        "cargo check",
        &[
            (
                "--workspace",
                "so every member is compiled and not only the default member",
            ),
            (
                "--all-targets",
                "so the tests and benches are compiled as well as the libraries",
            ),
        ],
    ),
    (
        "cargo clippy",
        &[
            ("--workspace", "so every member is linted"),
            (
                "--all-targets",
                "so the lint reaches the integration targets, which is where the defect that caused the 75-run streak lived",
            ),
            (
                "--all-features",
                "so a feature-gated path is linted by the same command that lints the rest",
            ),
            (
                "-D warnings",
                "without it clippy reports warnings and the run stays green",
            ),
        ],
    ),
    (
        "cargo test",
        &[
            (
                "--workspace",
                "so every member's test targets run, which is where the evals are",
            ),
            (
                "--all-features",
                "so the tests behind a feature run under the same command",
            ),
            (
                "--no-fail-fast",
                "the first failing target otherwise hides every target after it, and the targets are where the platform-specific tests live",
            ),
        ],
    ),
];

// --- reading --------------------------------------------------------------

fn repository_root() -> PathBuf {
    sure_testkit::repository_root()
}

/// A tracked file of the checkout, with its line endings normalized.
///
/// `.gitattributes` declares `* text=auto eol=lf`, and this machine's checkout is
/// not the only place these files are read, so a comparison written against LF
/// normalizes rather than assumes — the same reason, and the same shape, as
/// `script_text` in `crates/sure-cli/tests/install_flow.rs`.
fn read(relative: &str) -> String {
    let path = repository_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        .replace("\r\n", "\n")
}

/// One significant line: not blank and not a whole-line comment.
struct Line<'a> {
    /// 1-based, so a violation can name the line a reader would open.
    number: usize,
    /// The leading whitespace, in bytes. Indentation here is spaces; a tab would
    /// make this number wrong and the reader would report missing jobs rather
    /// than mis-reading them quietly.
    indent: usize,
    text: &'a str,
}

fn significant_lines(text: &str) -> Vec<Line<'_>> {
    text.lines()
        .enumerate()
        .filter_map(|(index, raw)| {
            let text = raw.trim();
            if text.is_empty() || text.starts_with('#') {
                return None;
            }
            Some(Line {
                number: index + 1,
                indent: raw.len() - raw.trim_start().len(),
                text,
            })
        })
        .collect()
}

/// A `key: value` pair, with a YAML list dash removed and both halves trimmed.
fn key_and_value(text: &str) -> (&str, &str) {
    let text = text.strip_prefix("- ").unwrap_or(text);
    match text.split_once(':') {
        Some((key, value)) => (key.trim(), value.trim()),
        None => (text, ""),
    }
}

/// The bare labels in a value: an inline list, a scalar, or nothing at all.
///
/// A `${{ ... }}` expression yields no labels: the matrix job's
/// `runs-on: ${{ matrix.os }}` says *whatever the matrix says*, and reading it
/// as a label would be inventing one.
fn labels_in(value: &str) -> Vec<String> {
    let value = value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(value);
    value
        .split(',')
        .map(|part| part.trim().trim_matches(|c| c == '\'' || c == '"'))
        .filter(|part| !part.is_empty() && !part.contains("${{"))
        .map(str::to_owned)
        .collect()
}

/// The keys of the workflow's top-level `on:` section.
///
/// Both spellings are read — a block (`on:` then `push:` lines) and an inline
/// list (`on: [push, pull_request]`) — because a formatting change should not
/// turn "the workflow has no triggers" into a true-looking report.
fn triggers(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut inside = false;
    for line in significant_lines(text) {
        if line.indent == 0 {
            inside = line.text.starts_with("on:");
            if inside {
                let (_, value) = key_and_value(line.text);
                if !value.is_empty() {
                    found.extend(labels_in(value));
                }
            }
            continue;
        }
        if inside {
            let (key, _) = key_and_value(line.text);
            if !key.is_empty() && !found.iter().any(|seen| seen == key) {
                found.push(key.to_owned());
            }
        }
    }
    found
}

/// A job, as this file reads it.
struct Job {
    /// The job id, as it is spelled under `jobs:`.
    name: String,
    /// The line the job id is on.
    line: usize,
    /// The literal runner labels: `runs-on:` plus the matrix's `os:` list.
    labels: Vec<String>,
    /// The `runs-on:` value as written, for a violation to quote.
    runs_on: Option<String>,
    /// Every single-line `run:` command, in the order the job declares them.
    commands: Vec<String>,
    /// Why this job is not mandatory, as sentences.
    faults: Vec<String>,
}

impl Job {
    fn new(name: &str, line: usize) -> Self {
        Self {
            name: name.to_owned(),
            line,
            labels: Vec::new(),
            runs_on: None,
            commands: Vec::new(),
            faults: Vec::new(),
        }
    }
}

/// Read every job out of the workflow text.
///
/// The structure it expects is the one the file is written in: job ids at two
/// spaces under a top-level `jobs:`, job keys at four, steps and matrix entries
/// deeper than that. `the_reader_sees_the_jobs_that_are_there` is what stops a
/// shape this reader cannot follow from reading as a clean workflow.
fn jobs(text: &str) -> Vec<Job> {
    let mut found: Vec<Job> = Vec::new();
    let mut job: Option<Job> = None;
    // The indent of the `matrix:` key of the job being read, when it has one.
    let mut matrix: Option<usize> = None;
    // Set while a matrix `os:` list written one label per line is being read.
    let mut collecting_os = false;
    // Only the `jobs:` section holds jobs. Without this, the `on:` section's
    // `push:` and `pull_request:` keys read as two jobs with no runner — which
    // is what this reader did until `the_reader_sees_the_jobs_that_are_there`
    // reported them by name.
    let mut in_jobs = false;

    for line in significant_lines(text) {
        if line.indent == 0 {
            in_jobs = line.text.starts_with("jobs:");
            if !in_jobs {
                found.extend(job.take());
            }
            continue;
        }
        if !in_jobs {
            continue;
        }
        if line.indent == 2 && line.text.ends_with(':') {
            found.extend(job.take());
            let name = line.text.trim_end_matches(':');
            matrix = None;
            collecting_os = false;
            job = Some(Job::new(name, line.number));
            continue;
        }
        let Some(current) = job.as_mut() else {
            continue;
        };

        if collecting_os {
            if let Some(label) = line.text.strip_prefix("- ") {
                current.labels.extend(labels_in(label));
                continue;
            }
            collecting_os = false;
        }

        let (key, value) = key_and_value(line.text);
        if line.indent == 4 {
            // A job-level key. A `run:` here would not be a step, and a
            // job-level `if:` is what makes a job conditional.
            match key {
                "runs-on" => {
                    current.labels.extend(labels_in(value));
                    current.runs_on = Some(value.to_owned());
                }
                "if" => current.faults.push(format!(
                    "the job `{}` (line {}) is conditional (`if: {value}`), so a run in which the \
                     condition is false reports nothing about it",
                    current.name, line.number
                )),
                "continue-on-error" => current.faults.push(format!(
                    "the job `{}` (line {}) carries `continue-on-error: {value}`, so a failing job \
                     would not be a failing run",
                    current.name, line.number
                )),
                _ => {}
            }
            continue;
        }

        // Everything deeper than a job key: steps, and the strategy's matrix.
        match key {
            "matrix" => {
                matrix = Some(line.indent);
                collecting_os = false;
            }
            // A matrix entry, and only a matrix entry: `if: matrix.os ==
            // 'ubuntu-latest'` is not one (it starts with `if:`), and neither is
            // a `- run:` line — which is what keeps this reader from finding
            // `ubuntu-latest` in a step and reporting a platform the matrix no
            // longer carries.
            "os" if matrix.is_some_and(|indent| line.indent == indent + 2) => {
                if value.is_empty() {
                    collecting_os = true;
                } else {
                    current.labels.extend(labels_in(value));
                }
            }
            "run" => {
                if value.is_empty() || value.starts_with('|') || value.starts_with('>') {
                    current.faults.push(format!(
                        "the step at line {} of job `{}` runs a multi-line shell (`run: {value}`), \
                         and this reader reads single-line commands only, so what that step runs is \
                         not covered by any rule here",
                        line.number, current.name
                    ));
                } else {
                    current.commands.push(value.to_owned());
                }
            }
            "continue-on-error" => current.faults.push(format!(
                "the step at line {} of job `{}` carries `continue-on-error: {value}`, so a failing \
                 step in a green job",
                line.number, current.name
            )),
            _ => {}
        }
    }
    found.extend(job.take());
    found
}

/// The jobs, as a phrase a violation can carry.
fn listing(jobs: &[Job]) -> String {
    if jobs.is_empty() {
        return "no job was read at all".to_owned();
    }
    jobs.iter()
        .map(|job| format!("`{}` on {:?}", job.name, job.labels))
        .collect::<Vec<_>>()
        .join(", ")
}

// --- the rules ------------------------------------------------------------

/// Every rule, applied to the workflow text. Empty means this file is content.
fn violations(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    let found_triggers = triggers(text);
    for wanted in ["push", "pull_request"] {
        if !found_triggers.iter().any(|trigger| trigger == wanted) {
            out.push(format!(
                "{WORKFLOW} is not triggered by `{wanted}`, so nothing runs its jobs automatically \
                 and a job no trigger reaches is not a mandatory job; the triggers read are \
                 {found_triggers:?}"
            ));
        }
    }

    let jobs = jobs(text);

    // Rule 2: Windows alone, which is the reading of "primary job" this file
    // takes.
    let windows_only = jobs.iter().any(|job| {
        let windows = job.labels.iter().any(|label| label == "windows-latest");
        let elsewhere = job.labels.iter().any(|label| label != "windows-latest");
        windows && !elsewhere
    });
    if !windows_only {
        out.push(format!(
            "no job runs on Windows and nothing else, so the checks only a Windows machine can make \
             have no job of their own: {}",
            listing(&jobs)
        ));
    }

    // Rule 3: the core jobs are mandatory on all three platforms.
    let core: Vec<&Job> = jobs
        .iter()
        .filter(|job| {
            job.commands
                .iter()
                .any(|command| command.starts_with("cargo test --workspace"))
        })
        .collect();
    if core.is_empty() {
        out.push(format!(
            "no job runs `cargo test --workspace`, so the workspace's tests — including the \
             acceptance corpus's evals — are not run by this workflow: {}",
            listing(&jobs)
        ));
    } else if !core.iter().any(|job| {
        PLATFORMS
            .iter()
            .all(|platform| job.labels.iter().any(|label| label == platform))
    }) {
        for job in &core {
            let missing: Vec<&str> = PLATFORMS
                .iter()
                .copied()
                .filter(|platform| !job.labels.iter().any(|label| label == platform))
                .collect();
            out.push(format!(
                "the job `{}` (line {}) runs the workspace's tests on {:?} and not on {missing:?}, \
                 and the acceptance makes all three platforms mandatory",
                job.name, job.line, job.labels
            ));
        }
    }

    // Rule 4: nothing conditional, nothing tolerant.
    for job in &jobs {
        out.extend(job.faults.iter().cloned());
        if job.labels.is_empty() {
            out.push(format!(
                "the job `{}` (line {}) declares no runner this file can read (`runs-on: {}`), so \
                 where it runs is not something this file says",
                job.name,
                job.line,
                job.runs_on.as_deref().unwrap_or("nothing")
            ));
        }
    }

    // Rule 5: the four families, each in one command carrying every fragment.
    for (family, fragments) in REQUIRED {
        let commands: Vec<&String> = jobs
            .iter()
            .flat_map(|job| job.commands.iter())
            .filter(|command| command.starts_with(family))
            .collect();
        if commands.is_empty() {
            out.push(format!(
                "no job in {WORKFLOW} runs a `{family}` command, and the acceptance lists it among \
                 the checks that have to be there"
            ));
            continue;
        }
        if commands.iter().any(|command| {
            fragments
                .iter()
                .all(|(fragment, _)| command.contains(fragment))
        }) {
            continue;
        }
        for (fragment, why) in fragments.iter() {
            if !commands.iter().any(|command| command.contains(fragment)) {
                out.push(format!(
                    "no `{family}` command carries `{fragment}`, and {why}"
                ));
            }
        }
        // Every fragment is carried by some command of this family and no single
        // command carries all of them: the gate has been split apart, and no one
        // command is the check the acceptance asks for.
        if fragments
            .iter()
            .all(|(fragment, _)| commands.iter().any(|command| command.contains(fragment)))
        {
            out.push(format!(
                "the `{family}` fragments are spread over more than one command and no single \
                 command is the gate: {commands:?}"
            ));
        }
    }

    out.dedup();
    out
}

/// Rule 6, over the two files it is about.
///
/// Taken as text so that the ways this could go false can be fed to it: the
/// `#[ignore]` and the empty manifest below never touch the real files, and the
/// real files are read by the test that calls this.
fn eval_violations(runner: &str, manifest: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if !runner.contains(MANIFEST) {
        out.push(format!(
            "{EVAL_RUNNER} does not name {MANIFEST}, so the target `cargo test --workspace` runs is \
             not the corpus's runner and nothing here says the evals are included"
        ));
    }
    if runner.contains("#[ignore") {
        out.push(format!(
            "{EVAL_RUNNER} carries an `#[ignore]`, so the case behind it is skipped by `cargo test \
             --workspace` while the run stays green: a case a run passes over is the false green \
             this repository refuses"
        ));
    }
    match serde_json::from_str::<serde_json::Value>(manifest) {
        Ok(value) => {
            let cases = value["cases"].as_array().map_or(0, Vec::len);
            if cases == 0 {
                out.push(format!(
                    "{MANIFEST} declares no cases, so `cargo test --workspace` runs no evals"
                ));
            }
        }
        Err(error) => out.push(format!(
            "{MANIFEST} is not JSON this reader can read ({error}), so nothing here can say whether \
             the evals are included"
        )),
    }
    out
}

// --- release.yml: the reader, and the rules -------------------------------

/// The line number of the first significant line carrying a token.
///
/// The first, and that matters: every rule below that asks *where* something is
/// is asking about the first place a reader would arrive, and a second
/// occurrence can only make a gate later rather than earlier.
fn line_carrying(lines: &[Line<'_>], token: &str) -> Option<usize> {
    lines
        .iter()
        .find(|line| line.text.contains(token))
        .map(|line| line.number)
}

/// The job ids of a selection of jobs, as a phrase a violation can carry.
///
/// `listing` reads what each job runs on; this one is for the rules that are
/// about the jobs themselves and would be unreadable if every line repeated the
/// runner.
fn names(jobs: &[&Job]) -> String {
    if jobs.is_empty() {
        return "no job at all".to_owned();
    }
    jobs.iter()
        .map(|job| job.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A fault from the shared reader that `release.yml`'s rules accept on purpose.
///
/// `jobs()` reports every `run: |` block as a fault, because the rules `ci.yml`
/// is held to cannot see inside one. `release.yml` uses multi-line shells for its
/// identity steps, for its two refusal steps and for the create itself — a refusal
/// that prints three lines and exits is not a one-liner — so that one fault is
/// filtered here. The two faults those rules *are* about, a job-level `if:` and a
/// `continue-on-error` at any level, are different faults from the same reader
/// and are not filtered by this predicate; two of the edits in `RELEASE_BREAKS`
/// add one of each and are what says so rather than this comment.
///
/// What is genuinely given up by the filter is stated plainly: a `run: |` block's
/// *body* is not read by `jobs()`, so nothing that lives only inside one is
/// covered by the job/step faults. The rules below are written against the whole
/// text for that reason — `line_carrying` walks every significant line,
/// indentation and all — so a `--clobber` inside a heredoc is found even though
/// no job-level rule would see it.
fn accepted_fault(fault: &str) -> bool {
    fault.contains("runs a multi-line shell")
}

/// Every rule about `release.yml`, over its text and the assembler's.
///
/// Empty means the two acceptance sentences are the file's content. It is a
/// function of both texts so that a way each rule could go false can be fed to
/// it: the edits in `RELEASE_BREAKS` never touch the real files.
fn release_violations(workflow: &str, assembler: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let lines = significant_lines(workflow);

    // --- the first clause: it can produce artifacts, and needs no marketplace

    // Rule R1. A dispatch is the only trigger, and the tag is a required input.
    // Everything below this is about a run a person asked for by name; a `push:`
    // trigger would be a run that started itself.
    let found_triggers = triggers(workflow);
    if !found_triggers
        .iter()
        .any(|found| found == "workflow_dispatch")
    {
        out.push(format!(
            "{RELEASE_WORKFLOW} has no `workflow_dispatch:` trigger, so there is no way for a \
             person to ask for a release at all; the triggers read are {found_triggers:?}"
        ));
    }
    for forbidden in [
        "push",
        "pull_request",
        "schedule",
        "workflow_run",
        "repository_dispatch",
        "release",
        "create",
    ] {
        if found_triggers.iter().any(|found| found == forbidden) {
            out.push(format!(
                "{RELEASE_WORKFLOW} carries a `{forbidden}:` trigger, so a run can start without \
                 anyone asking for it in a named tag — and this file's first outward-facing act is \
                 creating a release"
            ));
        }
    }
    for (indent, wanted, what) in [
        (2, "workflow_dispatch:", "the dispatch trigger"),
        (4, "inputs:", "the dispatch's inputs"),
        (6, "tag:", "the tag input"),
        (
            8,
            "required: true",
            "the input being required, without which a dispatch with no tag starts a run that \
             cannot know what it is releasing",
        ),
    ] {
        if !lines
            .iter()
            .any(|line| line.indent == indent && line.text == wanted)
        {
            out.push(format!(
                "{RELEASE_WORKFLOW} does not carry `{wanted}` at indent {indent} under `on:`, which \
                 is {what}"
            ));
        }
    }

    // Rule R2. Nothing conditional, nothing allowed to fail. This is the same
    // reading `ci.yml`'s rule 4 takes, over this file's jobs.
    let jobs = jobs(workflow);
    if jobs.is_empty() {
        out.push(format!(
            "no job was read out of {RELEASE_WORKFLOW} at all, so every rule below is passing \
             because the reader came back with nothing"
        ));
    }
    for job in &jobs {
        for fault in job.faults.iter().filter(|fault| !accepted_fault(fault)) {
            out.push(fault.clone());
        }
        if job.labels.is_empty() {
            out.push(format!(
                "the job `{}` (line {}) declares no runner this reader can read (`runs-on: {}`), so \
                 where it runs is not something this file says",
                job.name,
                job.line,
                job.runs_on.as_deref().unwrap_or("nothing")
            ));
        }
    }
    for wanted in [
        "package-windows",
        "package-macos",
        "package-macos-intel",
        "package-linux",
        "release",
    ] {
        if !jobs.iter().any(|job| job.name == wanted) {
            out.push(format!(
                "{RELEASE_WORKFLOW} has no job named `{wanted}`; the jobs read are {}",
                listing(&jobs)
            ));
        }
    }

    // Rule R3. Four artifacts, four jobs that package them, and the tests before
    // the packaging in each one — the packaging scripts refuse without the
    // release gate `cargo test -p sure-core --test acceptance_report_runner`
    // writes, so a packaging step that came first would be a packaging step that
    // failed rather than a release built from an unmeasured tree.
    let packaging: Vec<&Job> = jobs
        .iter()
        .filter(|job| {
            job.commands
                .iter()
                .any(|command| command.contains("Build-Release."))
        })
        .collect();
    if packaging.len() != RELEASE_ARTIFACTS.len() {
        out.push(format!(
            "{} job(s) run a `Build-Release.` command and a release carries {} archives, so the \
             jobs and the artifacts do not line up: {}",
            packaging.len(),
            RELEASE_ARTIFACTS.len(),
            names(&packaging)
        ));
    }
    for job in &packaging {
        let Some(build) = job
            .commands
            .iter()
            .position(|command| command.contains("Build-Release."))
        else {
            // `packaging` was filtered on exactly this, so this arm is
            // unreachable; it is written out rather than unwrapped so that a
            // filter that changed shape could not panic the whole file.
            continue;
        };
        match job
            .commands
            .iter()
            .position(|command| command.starts_with("cargo test --workspace"))
        {
            None => out.push(format!(
                "the job `{}` (line {}) packages without running `cargo test --workspace` first, \
                 and `scripts/Build-Release.*` refuse to package without the release gate that test \
                 writes: {:?}",
                job.name, job.line, job.commands
            )),
            Some(tests) if tests > build => out.push(format!(
                "the job `{}` (line {}) runs `cargo test --workspace` at position {tests} of its \
                 commands and packages at position {build}, so the packaging happens before the \
                 tests that write the release gate it is supposed to be gated on",
                job.name, job.line
            )),
            Some(_) => {}
        }
    }
    for &(triple, _) in RELEASE_ARTIFACTS
        .iter()
        .filter(|(triple, _)| *triple != "x86_64-pc-windows-msvc")
    {
        let found = packaging.iter().any(|job| {
            job.commands
                .iter()
                .any(|command| command.contains("Build-Release.sh") && command.contains(triple))
        });
        if !found {
            out.push(format!(
                "no job packages for `{triple}`: no `Build-Release.sh` command in \
                 {RELEASE_WORKFLOW} names that target, so the release would be missing \
                 `sure-$version-{triple}.tar.gz`"
            ));
        }
    }
    // The Windows artifact's command names no triple — the PowerShell script
    // builds for its own host — so the job that runs it is required to be on
    // Windows, and the triple it stands for is the one the uploads and the asset
    // list spell out (rule R4).
    let windows = packaging.iter().any(|job| {
        job.labels.iter().any(|label| label == "windows-latest")
            && job
                .commands
                .iter()
                .any(|command| command.contains("Build-Release.ps1"))
    });
    if !windows {
        out.push(format!(
            "the PowerShell build (`Build-Release.ps1`) is not run by a job on `windows-latest`, so \
             the Windows artifact — the platform \
             `docs/adr/0007-windows-primary-development.md` makes primary — is not what this file \
             produces: {}",
            names(&packaging)
        ));
    }

    // Rule R4. Every archive, its checksum, and the one aggregate.
    //
    // Read from the **code lines** rather than from the whole text, and that is
    // not fastidiousness: this file's own header names `SHA256SUMS.txt`,
    // `scripts/Assemble-Release.sh` and `${{ github.token }}` in prose, and a
    // `contains` over the whole text is satisfied by a sentence about the thing.
    // The mutation that deleted the step running the assembler is what found
    // that: the rule stayed green on the comment eleven lines from the top. A
    // rule about what the file *does* has to read what the file does.
    for (triple, extension) in RELEASE_ARTIFACTS.iter() {
        let archive = format!("sure-$version-{triple}.{extension}");
        if line_carrying(&lines, &archive).is_none() {
            out.push(format!(
                "{RELEASE_WORKFLOW} does not name `{archive}` on any line it runs, so the release \
                 would not carry it"
            ));
        }
        let checksum = format!("{archive}.sha256");
        if line_carrying(&lines, &checksum).is_none() {
            out.push(format!(
                "{RELEASE_WORKFLOW} does not name `{checksum}` on any line it runs, so a download of \
                 {archive} could not be checked against anything"
            ));
        }
    }
    if line_carrying(&lines, "sure-$version-release-checksums.txt").is_none() {
        out.push(format!(
            "{RELEASE_WORKFLOW} does not name `sure-$version-release-checksums.txt` on any line it \
             runs, so the release would not carry the one file a downloader needs to check all four \
             archives at once"
        ));
    }
    // The checksum trap, held in the same place. `SHA256SUMS.txt` is a curated
    // manifest over the source tree and is not a release artifact; attaching or
    // writing one under that name is the mistake
    // `scripts/Build-Release.ps1`'s header calls the trap in this task.
    if let Some(at) = line_carrying(&lines, "SHA256SUMS.txt") {
        out.push(format!(
            "line {at} of {RELEASE_WORKFLOW} names `SHA256SUMS.txt`, which is a curated manifest \
             over the source tree and not a release artifact"
        ));
    }
    if line_carrying(&lines, ASSEMBLER).is_none() {
        out.push(format!(
            "{RELEASE_WORKFLOW} does not run `{ASSEMBLER}` in any step, so nothing recomputes the \
             four digests from the bytes that came back through the upload and the download"
        ));
    }
    // Every `--output-dir` this file passes is quoted and absolute, and this
    // rule is the supervisor's rather than the worker's: the first version of
    // this file passed `--output-dir target/tmp/release` to the assembler, which
    // refuses a relative path and exits 1 with
    // `FAILED: --output-dir must be an absolute path: target/tmp/release`. It
    // was found by running the script with the argument the file gave it, and
    // not by reading — the flag was correct, the *value* was not, which is the
    // shape a rule about presence cannot see. The three `Build-Release.sh`
    // commands happened to be right, so the file was inconsistent with itself.
    for line in lines
        .iter()
        .filter(|line| line.text.contains("--output-dir"))
    {
        let Some(rest) = line.text.split("--output-dir ").nth(1) else {
            continue;
        };
        let quoted = rest.starts_with('"');
        let after_quote = rest.trim_start_matches('"');
        let absolute =
            after_quote.starts_with("$GITHUB_WORKSPACE/") || after_quote.starts_with('/');
        if !quoted || !absolute {
            out.push(format!(
                "line {} of {RELEASE_WORKFLOW} passes `--output-dir {}`, which is not a quoted \
                 absolute path; `{ASSEMBLER}` and `scripts/Build-Release.sh` both refuse a relative \
                 output directory, so this step fails on the runner rather than checking anything",
                line.number,
                rest.split_whitespace().next().unwrap_or("")
            ));
        }
    }
    // The assembler's half of the same two properties, read from its code lines:
    // the file it writes is a name of its own, and the four archives it verifies
    // are the four this workflow publishes.
    let assembler_lines = significant_lines(assembler);
    let named = assembler_lines.iter().any(|line| {
        line.text.starts_with("CHECKSUMS_NAME=")
            && line.text.contains("release-checksums")
            && !line.text.contains("SHA256SUMS")
    });
    if !named {
        out.push(format!(
            "{ASSEMBLER} does not assign `CHECKSUMS_NAME` a name holding `release-checksums` and not \
             `SHA256SUMS`, so what it writes is not the object the release attaches and is named \
             like"
        ));
    }
    for (triple, extension) in RELEASE_ARTIFACTS.iter() {
        let entry = format!("{triple}:{extension}");
        if line_carrying(&assembler_lines, &entry).is_none() {
            out.push(format!(
                "{ASSEMBLER} does not carry `{entry}` in its list of artifacts, so the four archives \
                 it verifies are not the four {RELEASE_WORKFLOW} publishes"
            ));
        }
    }

    // Rule R5. The release notes say what every archive holds, and the file
    // inside each archive that says which third-party licenses the binary is
    // built from is one of them. This rule reads the whole text on purpose:
    // the notes are prose the workflow writes into the release, so the
    // sentence itself is the object being policed, and nothing in a `run:`
    // command would say the same thing.
    if line_carrying(&lines, THIRD_PARTY_NOTICES).is_none() {
        out.push(format!(
            "the release notes in {RELEASE_WORKFLOW} do not name `{THIRD_PARTY_NOTICES}` among the \
             files an archive holds, so a downloader is not told the archive carries the \
             third-party license texts of the crates compiled into the binary"
        ));
    }

    // --- the second clause: no automatic force, and no merge

    for &(token, act) in FORBIDDEN_ACTS {
        if let Some(at) = line_carrying(&lines, token) {
            out.push(format!(
                "line {at} of {RELEASE_WORKFLOW} carries `{token}`, which is {act}; the second \
                 acceptance clause is that this workflow does none of it"
            ));
        }
    }
    // The create happens once, as a draft, and only after both existence checks.
    // Order is the property here and not presence: a check written *after* the
    // create is not a gate on it, and a rule that only asked whether the tokens
    // appear somewhere would go green on exactly that file.
    match line_carrying(&lines, CREATE) {
        None => out.push(format!(
            "nothing in {RELEASE_WORKFLOW} runs `{CREATE}`, so no release is created and the four \
             artifacts stay workflow artifacts that expire"
        )),
        Some(create) => {
            for (token, what) in [
                ("refs/tags/", "the tag being released exists"),
                (
                    "releases/tags/",
                    "no release for that tag exists already, which is what makes a second run a \
                     refusal rather than a replacement of the first one's assets",
                ),
            ] {
                match line_carrying(&lines, token) {
                    None => out.push(format!(
                        "nothing in {RELEASE_WORKFLOW} reads `{token}`, so the create is not gated on \
                         whether {what}"
                    )),
                    Some(guard) if guard > create => out.push(format!(
                        "`{token}` is read at line {guard} of {RELEASE_WORKFLOW} and `{CREATE}` \
                         is at line {create}, so the create happens before the check that {what}"
                    )),
                    Some(_) => {}
                }
            }
        }
    }
    let draft = lines
        .iter()
        .any(|line| line.text.starts_with("--draft") && !line.text.contains('='));
    if !draft {
        out.push(format!(
            "{RELEASE_WORKFLOW} never calls `gh release create` with `--draft`, so a run would \
             publish a release rather than leave one for a person to publish — and a release that \
             has been public has been public"
        ));
    }
    // The tag is read from the typed input, which is what makes the tag *this
    // run's* tag rather than whatever the payload happened to carry, and what
    // the `required: true` above applies to.
    if line_carrying(&lines, "${{ inputs.tag }}").is_none() {
        out.push(format!(
            "{RELEASE_WORKFLOW} does not read the tag it was dispatched with as `${{{{ \
             inputs.tag }}}}` on any line it runs, so the tag it releases is not the one it was \
             asked for"
        ));
    }
    // `--verify-tag` as a flag on its own line, and not merely present: the
    // refusal step's own message mentions the flag by name, so `contains` would
    // be satisfied by a file whose create no longer passes it. The last clause
    // of that message is measured — this is the shape that keeps the check from
    // passing on the sentence describing the check.
    let verify_tag = lines
        .iter()
        .any(|line| line.text.starts_with("--verify-tag") && !line.text.contains('='));
    if !verify_tag {
        out.push(format!(
            "{RELEASE_WORKFLOW} never calls `gh release create` with `--verify-tag` as a flag of \
             its own, and without it `gh` creates the tag itself when it is missing — a tag made by \
             a workflow rather than by a person, which is the act the second acceptance clause is \
             about"
        ));
    }
    let writes = lines
        .iter()
        .filter(|line| line.text == "contents: write")
        .count();
    if writes != 1 {
        out.push(format!(
            "`contents: write` appears {writes} time(s) in {RELEASE_WORKFLOW} and has to appear \
             exactly once, on the one job that creates the release: a scope a packaging job does \
             not need is a scope it can use"
        ));
    }
    if lines
        .iter()
        .any(|line| line.indent == 0 && line.text.starts_with("permissions:"))
    {
        out.push(format!(
            "{RELEASE_WORKFLOW} carries a workflow-level `permissions:` block, which replaces the \
             default its four packaging jobs inherit from `release-dry-run.yml`'s measured \
             configuration, and what `actions/upload-artifact` does under a narrower scope is not \
             something this repository has measured"
        ));
    }
    // A release of three artifacts because one job's name drifted out of `needs:`
    // is exactly the quiet failure the explicit asset list is there to prevent.
    let needs = "needs: [package-windows, package-macos, package-macos-intel, package-linux]";
    if line_carrying(&lines, needs).is_none() {
        out.push(format!(
            "{RELEASE_WORKFLOW} does not declare `{needs}`, so the job that creates the release is \
             not gated on all four artifacts being built"
        ));
    }

    // --- the first clause again: it needs no marketplace to run

    for &(token, channel) in PUBLICATION_CHANNELS
        .iter()
        .chain(PUBLICATION_CREDENTIALS.iter())
    {
        if let Some(at) = line_carrying(&lines, token) {
            out.push(format!(
                "line {at} of {RELEASE_WORKFLOW} carries `{token}`, which is {channel}; the first \
                 acceptance clause is that this release is produced without any of them"
            ));
        }
    }
    if line_carrying(&lines, "${{ github.token }}").is_none() {
        out.push(format!(
            "{RELEASE_WORKFLOW} does not use `${{{{ github.token }}}}` on any line it runs, the \
             token every run is issued and nothing has to be configured for, so whatever credential \
             it does use is one the repository would have to carry"
        ));
    }

    out.dedup();
    out
}

// --- the repository, against every rule -----------------------------------

#[test]
fn the_ci_workflow_satisfies_every_rule() {
    let text = read(WORKFLOW);
    let found = violations(&text);
    assert!(
        found.is_empty(),
        "{WORKFLOW} no longer carries what the acceptance asks of it:\n{}",
        found
            .iter()
            .map(|violation| format!("  - {violation}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn the_evals_are_reached_by_the_command_ci_runs() {
    let found = eval_violations(&read(EVAL_RUNNER), &read(MANIFEST));
    assert!(
        found.is_empty(),
        "the acceptance corpus is not included the way this file has to be able to say:\n{}",
        found
            .iter()
            .map(|violation| format!("  - {violation}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// --- and the reader and the rules, against edits that break them ----------

/// The reader found jobs, runners and commands, rather than an empty file.
///
/// Without this, a reader that returned nothing would make every "no job does
/// X" rule pass and every "no job is conditional" rule pass vacuously — the
/// failure mode of a checker that is green because it is blind.
#[test]
fn the_reader_sees_the_jobs_that_are_there() {
    let text = read(WORKFLOW);
    let jobs = jobs(&text);
    let names: Vec<&str> = jobs.iter().map(|job| job.name.as_str()).collect();
    for expected in ["bootstrap-validate-windows", "rust", "shellcheck-secondary"] {
        assert!(
            names.contains(&expected),
            "the reader did not find the job `{expected}`, and it read {names:?}"
        );
    }
    for job in &jobs {
        assert!(
            !job.labels.is_empty(),
            "the job `{}` (line {}) was read with no runner at all",
            job.name,
            job.line
        );
        assert!(
            !job.commands.is_empty(),
            "the job `{}` (line {}) was read with no commands at all",
            job.name,
            job.line
        );
    }
    let rust = jobs
        .iter()
        .find(|job| job.name == "rust")
        .expect("the core job is one of the jobs the loop above required");
    for platform in PLATFORMS {
        assert!(
            rust.labels.iter().any(|label| label == platform),
            "the reader did not read `{platform}` out of the matrix, and it read {:?}",
            rust.labels
        );
    }
    assert!(
        rust.commands
            .iter()
            .any(|command| command.starts_with("cargo test")),
        "the core job's commands were read as {:?}",
        rust.commands
    );
}

/// An empty workflow is not a pass, and neither is a job with no runner.
#[test]
fn a_workflow_that_is_not_there_is_not_a_pass() {
    let found = violations("");
    assert!(
        !found.is_empty(),
        "an empty file satisfied every rule, so the rules below prove nothing about a file that is \
         there"
    );
    // The same for a file that has the jobs and none of the runners: the
    // platform rules have to complain rather than read a platform out of
    // nothing.
    let no_runners = violations(
        "name: ci\non:\n  push:\njobs:\n  rust:\n    steps:\n      - run: cargo test --workspace\n",
    );
    assert!(
        no_runners
            .iter()
            .any(|violation| violation.contains("declares no runner")),
        "a job with no runner was read as a job with a runner: {no_runners:#?}"
    );
}

/// An edit to the real workflow that must turn exactly one rule red.
struct Break {
    /// What the edit is, in a sentence.
    what: &'static str,
    /// Text taken out of the workflow as it stands.
    from: &'static str,
    /// What goes in its place.
    to: &'static str,
    /// Text the resulting violation has to carry.
    wanted: &'static str,
}

/// Every rule, broken the way it would really be broken.
///
/// The edits are taken from the file's own bytes rather than written as
/// fixtures: a fixture proves the checker reacts to a workflow nobody has, and
/// an edit proves it reacts to this one. `replace` that found nothing is a
/// failure rather than a pass — a stale edit must redden rather than quietly
/// mutate nothing, which is the way this kind of table rots.
const BREAKS: &[Break] = &[
    Break {
        what: "the workflow stops running on pull requests",
        from: "  pull_request:",
        to: "  # pull_request:",
        wanted: "pull_request",
    },
    Break {
        what: "the Windows-only job is moved off Windows",
        from: "    runs-on: windows-latest",
        to: "    runs-on: ubuntu-latest",
        wanted: "on Windows and nothing else",
    },
    Break {
        what: "Windows leaves the matrix",
        from: "os: [windows-latest, macos-latest, ubuntu-latest]",
        to: "os: [macos-latest, ubuntu-latest]",
        wanted: "windows-latest",
    },
    Break {
        what: "macOS leaves the matrix",
        from: "os: [windows-latest, macos-latest, ubuntu-latest]",
        to: "os: [windows-latest, ubuntu-latest]",
        wanted: "macos-latest",
    },
    Break {
        what: "Linux leaves the matrix",
        from: "os: [windows-latest, macos-latest, ubuntu-latest]",
        to: "os: [windows-latest, macos-latest]",
        wanted: "ubuntu-latest",
    },
    Break {
        what: "a job is allowed to fail",
        from: "  rust:\n    strategy:",
        to: "  rust:\n    continue-on-error: true\n    strategy:",
        wanted: "continue-on-error",
    },
    Break {
        what: "a step is allowed to fail",
        from: "      - run: cargo fmt --all -- --check",
        to: "      - run: cargo fmt --all -- --check\n        continue-on-error: true",
        wanted: "continue-on-error",
    },
    Break {
        what: "a job becomes conditional",
        from: "  rust:\n    strategy:",
        to: "  rust:\n    if: github.event_name == 'push'\n    strategy:",
        wanted: "conditional",
    },
    Break {
        what: "the format check stops being run",
        from: "      - run: cargo fmt --all -- --check\n",
        to: "",
        wanted: "cargo fmt",
    },
    Break {
        what: "the compile check stops being run",
        from: "      - run: cargo check --workspace --all-targets\n",
        to: "",
        wanted: "cargo check",
    },
    Break {
        what: "clippy stops failing the run on warnings",
        from: "cargo clippy --workspace --all-targets --all-features -- -D warnings",
        to: "cargo clippy --workspace --all-targets --all-features",
        wanted: "-D warnings",
    },
    Break {
        what: "the test step stops disabling fail-fast",
        from: "cargo test --workspace --all-features --no-fail-fast",
        to: "cargo test --workspace --all-features",
        wanted: "--no-fail-fast",
    },
    Break {
        what: "the test step selects a different feature set from the gate",
        from: "cargo test --workspace --all-features --no-fail-fast",
        to: "cargo test --workspace --no-fail-fast",
        wanted: "--all-features",
    },
    Break {
        what: "the test step stops running the whole workspace",
        from: "cargo test --workspace --all-features --no-fail-fast",
        to: "cargo test -p sure-core --lib --all-features --no-fail-fast",
        wanted: "cargo test --workspace",
    },
    Break {
        what: "a step is written as a multi-line shell, where no rule here can see it",
        from: "      - run: cargo fmt --all -- --check",
        to: "      - run: |\n          cargo fmt --all -- --check",
        wanted: "multi-line shell",
    },
];

#[test]
fn every_rule_is_turned_red_by_an_edit_that_breaks_it() {
    let text = read(WORKFLOW);
    assert!(
        violations(&text).is_empty(),
        "the workflow is already failing a rule, so no edit below can be said to have broken it"
    );
    for edit in BREAKS {
        let broken = text.replace(edit.from, edit.to);
        assert_ne!(
            broken, text,
            "\"{}\" edits text that is not in {WORKFLOW} any more ({}), so it would have mutated \
             nothing and passed for that reason instead. The table has to be re-pointed at what the \
             file says now.",
            edit.what, edit.from
        );
        let found = violations(&broken);
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

#[test]
fn the_eval_rule_is_turned_red_by_the_three_ways_it_could_be_false() {
    let runner = read(EVAL_RUNNER);
    let manifest = read(MANIFEST);

    // The real files pass, which is the only reason the negatives below mean
    // anything.
    assert!(eval_violations(&runner, &manifest).is_empty());

    // A case marked `#[ignore]` is a case `cargo test --workspace` skips.
    let ignored = format!("#[test]\n#[ignore = \"flaky\"]\nfn a_case() {{}}\n{runner}");
    assert!(
        eval_violations(&ignored, &manifest)
            .iter()
            .any(|violation| violation.contains("#[ignore]")),
        "an ignored case was not reported"
    );

    // A runner that stopped naming the corpus.
    let renamed = runner.replace(MANIFEST, "evaluation/somewhere-else.json");
    assert_ne!(renamed, runner, "the runner does not name {MANIFEST}");
    assert!(
        eval_violations(&renamed, &manifest)
            .iter()
            .any(|violation| violation.contains(MANIFEST)),
        "a runner that names no corpus was not reported"
    );

    // A manifest with no cases, and one that is not JSON at all.
    for empty in ["{\"schema_version\": 1, \"cases\": []}", "not json"] {
        assert!(
            !eval_violations(&runner, empty).is_empty(),
            "a corpus of {empty:?} was read as a corpus with cases in it"
        );
    }
}

// --- release.yml, and the reader and the rules, against edits -------------

#[test]
fn the_release_workflow_satisfies_every_rule() {
    let found = release_violations(&read(RELEASE_WORKFLOW), &read(ASSEMBLER));
    assert!(
        found.is_empty(),
        "{RELEASE_WORKFLOW} no longer carries what the two acceptance sentences ask of it:\n{}",
        found
            .iter()
            .map(|violation| format!("  - {violation}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The reader found this workflow's jobs, runners and commands.
///
/// The same guard `the_reader_sees_the_jobs_that_are_there` is for `ci.yml`, and
/// it is load-bearing in a second way here: three of the rules below are "no job
/// does X" or "no job packages for Y", and a reader that came back empty would
/// satisfy the first kind and violate the second — which is a red test, so the
/// pair of them is what keeps the result a reading rather than a silence.
#[test]
fn the_release_reader_sees_the_jobs_that_are_there() {
    let workflow = read(RELEASE_WORKFLOW);
    let jobs = jobs(&workflow);
    let names: Vec<&str> = jobs.iter().map(|job| job.name.as_str()).collect();
    for expected in [
        "package-windows",
        "package-macos",
        "package-macos-intel",
        "package-linux",
        "release",
    ] {
        assert!(
            names.contains(&expected),
            "the reader did not find the job `{expected}`, and it read {names:?}"
        );
    }
    for job in &jobs {
        assert!(
            !job.labels.is_empty(),
            "the job `{}` (line {}) was read with no runner at all",
            job.name,
            job.line
        );
        assert!(
            !job.commands.is_empty(),
            "the job `{}` (line {}) was read with no single-line command at all, and every rule \
             about a command would pass on it for that reason",
            job.name,
            job.line
        );
    }
    let packaging: Vec<&str> = jobs
        .iter()
        .filter(|job| {
            job.commands
                .iter()
                .any(|command| command.contains("Build-Release."))
        })
        .map(|job| job.name.as_str())
        .collect();
    assert_eq!(
        packaging,
        vec![
            "package-windows",
            "package-macos",
            "package-macos-intel",
            "package-linux"
        ],
        "the jobs the reader reads as packaging jobs are {packaging:?}"
    );
    let found_triggers = triggers(&workflow);
    assert!(
        found_triggers
            .iter()
            .any(|found| found == "workflow_dispatch"),
        "the reader did not read `workflow_dispatch` out of `on:`, and it read {found_triggers:?}"
    );
}

/// An empty workflow is not a pass, and neither is a workflow with the right
/// jobs and no dispatch.
#[test]
fn a_release_workflow_that_is_not_there_is_not_a_pass() {
    let found = release_violations("", "");
    assert!(
        !found.is_empty(),
        "an empty pair of files satisfied every rule, so the rules prove nothing about the files \
         that are there"
    );
    for wanted in ["workflow_dispatch", "no job was read", "gh release create"] {
        assert!(
            found.iter().any(|violation| violation.contains(wanted)),
            "an empty file produced no violation carrying {wanted:?}: {found:#?}"
        );
    }
    // A file with a `release` job and no dispatch: the trigger rules have to
    // complain rather than read a trigger out of nothing.
    let no_trigger = release_violations(
        "name: release\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      \
         - run: cargo test --workspace\n",
        "",
    );
    assert!(
        no_trigger
            .iter()
            .any(|violation| violation.contains("workflow_dispatch")),
        "a workflow with no trigger was read as one with a trigger: {no_trigger:#?}"
    );
}

/// The token lists are lists of things this reader actually reports.
///
/// This is the test that keeps them from being decoration. Each token is
/// injected into the real workflow as a real `run:` line and the rules are
/// required to name it, so a token whose check had stopped working — a typo in
/// the token, a rule that returned early, a list that grew an entry the rule
/// never reads — is a red test rather than a line in a table that looks like a
/// check. It proves the *detector* works for every token here. It cannot prove
/// the list is complete, and that is the part a reader has to weigh.
#[test]
fn every_forbidden_and_every_publication_token_is_one_this_reader_reports() {
    let workflow = read(RELEASE_WORKFLOW);
    let assembler = read(ASSEMBLER);
    assert!(
        release_violations(&workflow, &assembler).is_empty(),
        "the workflow is already failing a rule, so nothing injected below could be said to have \
         caused it"
    );

    let anchor = "      - uses: actions/checkout@v4";
    for &(token, act) in FORBIDDEN_ACTS
        .iter()
        .chain(PUBLICATION_CHANNELS.iter())
        .chain(PUBLICATION_CREDENTIALS.iter())
    {
        let broken = workflow.replace(anchor, &format!("{anchor}\n      - run: {token}"));
        assert_ne!(
            broken, workflow,
            "the anchor {anchor:?} is not in the workflow"
        );
        let found = release_violations(&broken, &assembler);
        assert!(
            found.iter().any(|violation| violation.contains(token)),
            "injecting `{token}` ({act}) into {RELEASE_WORKFLOW} produced no violation naming it \
             — so the entry is a line in a list rather than a check:\n{found:#?}"
        );
    }
}

/// An edit to one of the two real files that must turn a rule red.
struct ReleaseBreak {
    /// What the edit is, in a sentence.
    what: &'static str,
    /// Which file the edit is made to.
    file: ReleaseFile,
    /// Text taken out of that file as it stands.
    from: &'static str,
    /// What goes in its place.
    to: &'static str,
    /// Text the resulting violation has to carry.
    wanted: &'static str,
}

/// The two files the release rules are about.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReleaseFile {
    Workflow,
    Assembler,
}

/// Every release rule, broken the way it would really be broken.
///
/// Same discipline as `BREAKS`: the edits are taken from the files' own bytes
/// rather than written as fixtures, so each one proves the checker reacts to
/// *these* files; and a `replace` that found nothing is a failure rather than a
/// pass, because that is the way this kind of table rots into decoration.
///
/// The list is deliberately longer than the rule list, because the second
/// acceptance clause is a prohibition: a prohibition is satisfied by a file that
/// says nothing, so each clause rule is broken once per way it could be broken
/// rather than once per rule. The edits a supervisor would think of that are
/// *not* here are the reason
/// `every_forbidden_and_every_publication_token_is_one_this_reader_reports`
/// exists: that one is generated from the token lists, so it cannot fall behind
/// them.
const RELEASE_BREAKS: &[ReleaseBreak] = &[
    ReleaseBreak {
        what: "the workflow starts running on a tag push",
        file: ReleaseFile::Workflow,
        from: "on:\n  workflow_dispatch:",
        to: "on:\n  push:\n    tags: ['v*']\n  workflow_dispatch:",
        wanted: "a `push:` trigger",
    },
    ReleaseBreak {
        what: "the tag input stops being required",
        file: ReleaseFile::Workflow,
        from: "        required: true",
        to: "        required: false",
        wanted: "`required: true`",
    },
    ReleaseBreak {
        what: "the release stops being a draft",
        file: ReleaseFile::Workflow,
        from: "            --draft \\",
        to: "",
        wanted: "`--draft`",
    },
    ReleaseBreak {
        what: "a draft is published from the workflow",
        file: ReleaseFile::Workflow,
        from: "            --draft \\",
        to: "            --draft=false \\",
        wanted: "`--draft=false`",
    },
    ReleaseBreak {
        what: "the create would make the tag itself",
        file: ReleaseFile::Workflow,
        from: "            --verify-tag \\",
        to: "",
        wanted: "`--verify-tag`",
    },
    ReleaseBreak {
        what: "assets would be replaced instead of a second run refusing",
        file: ReleaseFile::Workflow,
        from: "            --verify-tag \\",
        to: "            --verify-tag --clobber \\",
        wanted: "`--clobber`",
    },
    ReleaseBreak {
        what: "a job is allowed to fail",
        file: ReleaseFile::Workflow,
        from: "  release:\n    name: Attach the four artifacts to a draft release",
        to: "  release:\n    continue-on-error: true\n    name: Attach the four artifacts to a draft release",
        wanted: "continue-on-error",
    },
    ReleaseBreak {
        what: "a step is allowed to fail",
        file: ReleaseFile::Workflow,
        from: "      - name: Refuse to touch a release that already exists",
        to: "      - name: Refuse to touch a release that already exists\n        continue-on-error: true",
        wanted: "continue-on-error",
    },
    ReleaseBreak {
        what: "the job that creates the release becomes conditional",
        file: ReleaseFile::Workflow,
        from: "  release:\n    name: Attach the four artifacts to a draft release",
        to: "  release:\n    if: github.event_name == 'workflow_dispatch'\n    name: Attach the four artifacts to a draft release",
        wanted: "conditional",
    },
    ReleaseBreak {
        what: "a repository secret is used, where a run-issued token was",
        file: ReleaseFile::Workflow,
        from: "          GH_TOKEN: ${{ github.token }}",
        to: "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
        wanted: "`secrets.`",
    },
    ReleaseBreak {
        what: "a marketplace publisher's token appears",
        file: ReleaseFile::Workflow,
        from: "          GH_TOKEN: ${{ github.token }}",
        to: "          VSCE_PAT: ${{ secrets.VSCE_PAT }}",
        wanted: "`VSCE_PAT`",
    },
    ReleaseBreak {
        what: "the create stops passing the tag it was given",
        file: ReleaseFile::Workflow,
        from: "          TAG: ${{ inputs.tag }}",
        to: "          TAG: latest",
        wanted: "`${{ inputs.tag }}`",
    },
    ReleaseBreak {
        what: "the Windows artifact is packaged off Windows",
        file: ReleaseFile::Workflow,
        from: "  package-windows:\n    name: Windows x64 artifact (x86_64-pc-windows-msvc)\n    runs-on: windows-latest",
        to: "  package-windows:\n    name: Windows x64 artifact (x86_64-pc-windows-msvc)\n    runs-on: ubuntu-latest",
        wanted: "is not run by a job on `windows-latest`",
    },
    ReleaseBreak {
        what: "a packaging job stops naming its target",
        file: ReleaseFile::Workflow,
        from: "sh scripts/Build-Release.sh --phase all --target x86_64-apple-darwin",
        to: "sh scripts/Build-Release.sh --phase all",
        wanted: "no job packages for `x86_64-apple-darwin`",
    },
    ReleaseBreak {
        what: "the tests stop coming before the packaging",
        file: ReleaseFile::Workflow,
        from: "      - name: The workspace's tests, on this runner\n        shell: pwsh\n        run: cargo test --workspace --no-fail-fast\n",
        to: "",
        wanted: "packages without running `cargo test --workspace` first",
    },
    ReleaseBreak {
        what: "the Intel archive leaves the release's asset list",
        file: ReleaseFile::Workflow,
        from: "sure-$version-x86_64-apple-darwin.tar.gz",
        to: "sure-$version-x86_64-apple-darwin-absent.tar.gz",
        wanted: "`sure-$version-x86_64-apple-darwin.tar.gz`",
    },
    ReleaseBreak {
        what: "the aggregate checksum file stops being named",
        file: ReleaseFile::Workflow,
        from: "sure-$version-release-checksums.txt",
        to: "sure-$version-checksums.txt",
        wanted: "does not name `sure-$version-release-checksums.txt`",
    },
    ReleaseBreak {
        what: "the release notes stop saying an archive carries the third-party notices",
        file: ReleaseFile::Workflow,
        from: "\\`THIRD_PARTY_NOTICES.txt\\`",
        to: "\\`THIRD_PARTY_NOTICES-absent.txt\\`",
        wanted: "THIRD_PARTY_NOTICES.txt",
    },
    ReleaseBreak {
        what: "the source-tree manifest is attached as a release asset",
        file: ReleaseFile::Workflow,
        from: "            --notes-file \"$notes\" \\",
        to: "            --notes-file \"$notes\" \\\n            SHA256SUMS.txt \\",
        wanted: "names `SHA256SUMS.txt`",
    },
    ReleaseBreak {
        what: "the assembly script stops being run",
        file: ReleaseFile::Workflow,
        from: "        run: sh scripts/Assemble-Release.sh --version \"${TAG#v}\" --output-dir \"$GITHUB_WORKSPACE/target/tmp/release\"",
        to: "        run: echo nothing to assemble",
        wanted: "does not run `scripts/Assemble-Release.sh`",
    },
    ReleaseBreak {
        what: "the assembly script is given a relative output directory, which it refuses",
        file: ReleaseFile::Workflow,
        from: "        run: sh scripts/Assemble-Release.sh --version \"${TAG#v}\" --output-dir \"$GITHUB_WORKSPACE/target/tmp/release\"",
        to: "        run: sh scripts/Assemble-Release.sh --version \"${TAG#v}\" --output-dir target/tmp/release",
        wanted: "not a quoted absolute path",
    },
    ReleaseBreak {
        what: "the check that the tag exists stops reading the tag",
        file: ReleaseFile::Workflow,
        from: "git rev-parse --verify \"refs/tags/${TAG}^{commit}\"",
        to: "git rev-parse --verify HEAD",
        wanted: "reads `refs/tags/`",
    },
    ReleaseBreak {
        what: "the check that no release exists stops asking about the release",
        file: ReleaseFile::Workflow,
        from: "repos/$GITHUB_REPOSITORY/releases/tags/$TAG",
        to: "repos/$GITHUB_REPOSITORY",
        wanted: "reads `releases/tags/`",
    },
    ReleaseBreak {
        what: "the release job stops waiting for all four artifacts",
        file: ReleaseFile::Workflow,
        from: "    needs: [package-windows, package-macos, package-macos-intel, package-linux]",
        to: "    needs: [package-windows, package-macos-intel, package-linux]",
        wanted: "is not gated on all four artifacts",
    },
    ReleaseBreak {
        what: "a packaging job is handed write scope it does not need",
        file: ReleaseFile::Workflow,
        from: "  package-linux:\n    name: Linux x64 artifact (x86_64-unknown-linux-gnu)\n    runs-on: ubuntu-latest",
        to: "  package-linux:\n    name: Linux x64 artifact (x86_64-unknown-linux-gnu)\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write",
        wanted: "appears 2 time(s)",
    },
    ReleaseBreak {
        what: "a workflow-level permissions block narrows every job at once",
        file: ReleaseFile::Workflow,
        from: "jobs:\n",
        to: "permissions:\n  contents: read\n\njobs:\n",
        wanted: "workflow-level `permissions:`",
    },
    ReleaseBreak {
        what: "a job loses its runner",
        file: ReleaseFile::Workflow,
        from: "    runs-on: macos-26-intel",
        to: "    runs-on: ${{ matrix.os }}",
        wanted: "declares no runner",
    },
    ReleaseBreak {
        what: "the assembly script writes the source-tree manifest's name",
        file: ReleaseFile::Assembler,
        from: "CHECKSUMS_NAME=\"sure-$VERSION-release-checksums.txt\"",
        to: "CHECKSUMS_NAME=\"SHA256SUMS.txt\"",
        wanted: "does not assign `CHECKSUMS_NAME`",
    },
    ReleaseBreak {
        what: "the assembly script verifies a different set of archives",
        file: ReleaseFile::Assembler,
        from: "x86_64-pc-windows-msvc:zip",
        to: "x86_64-pc-windows-msvc:tar.gz",
        wanted: "`x86_64-pc-windows-msvc:zip`",
    },
];

#[test]
fn every_release_rule_is_turned_red_by_an_edit_that_breaks_it() {
    let workflow = read(RELEASE_WORKFLOW);
    let assembler = read(ASSEMBLER);
    assert!(
        release_violations(&workflow, &assembler).is_empty(),
        "the files are already failing a rule, so no edit below can be said to have broken it"
    );
    for edit in RELEASE_BREAKS {
        let (before, other) = match edit.file {
            ReleaseFile::Workflow => (&workflow, &assembler),
            ReleaseFile::Assembler => (&assembler, &workflow),
        };
        let after = before.replace(edit.from, edit.to);
        assert_ne!(
            after,
            *before,
            "\"{}\" edits text that is not in {} any more ({}), so it would have mutated nothing \
             and passed for that reason instead. The table has to be re-pointed at what the file \
             says now.",
            edit.what,
            match edit.file {
                ReleaseFile::Workflow => RELEASE_WORKFLOW,
                ReleaseFile::Assembler => ASSEMBLER,
            },
            edit.from
        );
        let found = match edit.file {
            ReleaseFile::Workflow => release_violations(&after, other),
            ReleaseFile::Assembler => release_violations(other, &after),
        };
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
