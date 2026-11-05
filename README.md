# SURE

**Software Understanding & Reality Evaluation**

> **AI says it's done. Be SURE.**

[English](README.md) · [中文](README.zh-CN.md)

SURE checks software that was built with AI coding tools, and tells you what is
actually true about it — in plain language, with evidence behind every claim.

It answers three questions:

1. **Can this project actually work?**
2. **Is anything clearly broken, unsafe, fake or incomplete?**
3. **Can the AI's claims about what it completed be confirmed?**

When SURE finds a real problem, it explains the consequence, writes a bounded
repair contract you can hand back to your coding agent, and checks again after
the repair. When it cannot confirm something, it says "cannot confirm" instead
of guessing. **A false "all clear" is treated as more serious than a visible
error.**

SURE works beside the tool you already use. Claude Code users keep using Claude
Code. Cursor users keep using Cursor. Codex users keep using Codex.

## Install on Windows

**There is no published download yet.** SURE is a developer-preview build: the
archive is built from this checkout. If you do not have the toolchain below,
that is the reason — not something you did wrong.

You need two things on the machine that builds SURE:

- **Rust** — install [rustup](https://rustup.rs); the repository's
  `rust-toolchain.toml` pins the version, so rustup installs the right one for
  you.
- **Visual Studio Build Tools** with the "Desktop development with C++"
  workload.

Then, from the root of this repository, in PowerShell:

```powershell
# 1. The release gate — SURE's own acceptance tests. Takes a few minutes.
cargo test -p sure-core --test acceptance_report_runner

# 2. Build and package the archive. Also a few minutes.
& .\scripts\Build-Release.ps1 -Phase All

# 3. Install for your user account. No administrator, no PATH change.
& .\scripts\Install-Sure.ps1 -Archive .\target\tmp\release\sure-0.1.3-x86_64-pc-windows-msvc.zip

# 4. Check that it works.
& "$env:LOCALAPPDATA\SURE\bin\sure.exe" version
```

The program lands at `%LOCALAPPDATA%\SURE\bin\sure.exe`. To remove it later:
`& .\scripts\Uninstall-Sure.ps1` — it never deletes `sure.db`, the file where
your check history lives.

The full walk is `docs/development/QUICKSTART_WINDOWS.md`; the installer
reference is `docs/development/INSTALL_WINDOWS.md`.

## Install on macOS and Linux

Build from source:

```sh
cargo install --path crates/sure-cli   # installs `sure` into ~/.cargo/bin
```

That is also where the Unix launcher scripts look for it. The Rust core is
portable and CI-tested on both platforms; `docs/development/MACOS.md` and
`docs/development/LINUX.md` state the support boundaries.

## Use it

Is SURE itself set up correctly on this machine?

```powershell
& "$env:LOCALAPPDATA\SURE\bin\sure.exe" doctor
```

Check a project. The path must be absolute:

```powershell
& "$env:LOCALAPPDATA\SURE\bin\sure.exe" check "C:\demo\hello"
```

### What a run looks like

This is a real `sure check` run against a small project holding a
`package.json` and one JavaScript file — the output of SURE 0.1.3, cut to its
own headings. The project's path was replaced with `C:\demo\hello`, and a line
holding `...` is where text was left out:

```text
SURE checked C:\demo\hello.

Not enough could be checked to say whether this is ready.
This project is not ready to hand off.
...
No unresolved findings from the checks that ran.

What the run did, stage by stage
  1/12. Find the project's parts: node (level B); all of it was read. Support reaches level B.
  ...
  8/12. Ask a model to assess the project: No analysis provider is configured, so SURE assessed nothing with a model. ... (NOT CHECKED)
  9/12. Check what was claimed against the evidence: SURE has no recorded history for this machine, so there are no agent claims to check against evidence. (NOT CHECKED)
  ...

2 of the 12 stages did not run, and each is marked NOT CHECKED above. A run with
a stage that did not run is never reported as clean.

SURE exited with status 1. That is what it returns when it checked the project
and did not find it clean — not 3, which would mean this build cannot check a
project at all.
```

Read the exit status as the answer:

| status | meaning |
| --- | --- |
| `0` | clean — every check that ran passed, and nothing was skipped |
| `1` | checked, and not clean — findings, or not enough could be checked |
| `5` | the run did not finish — bad path, unreadable project |
| `2` | the command line itself was wrong |

**Expect `1` on your first runs.** With no AI model configured — the default —
SURE runs its deterministic checks but marks the model-assessment stage "not
checked", and a run with any stage not checked is never reported as clean. That
is the tool being honest, not your project failing. Stage 9 needs history from
the plugin below, so a machine that has never used SURE has two stages marked.

Other commands worth knowing:

- `sure config set execution.mode host_confirmed` — let SURE run your project's
  own commands (tests, build), not only read its files
- `sure repair` — turn findings into a bounded repair contract you can hand to
  your coding agent
- `sure recheck` — check again after the repair, and compare with last time
- `sure history` — see (and delete) what SURE has recorded on this machine
- add `--format json` to any command for one JSON object on one line, for
  scripts to read

A first check writes nothing to your machine: SURE opens your history only if
one already exists.

## Connect it to your AI coding tool

SURE can also record a coding session (only with your consent) and compare the
AI's "done" claims against what actually happened. That needs the plugin for
your harness:

```powershell
# Claude Code — copies the plugin to %LOCALAPPDATA%\claude-plugins\sure
& .\integrations\claude-code\scripts\install.ps1 -ForceCopy
```

Loading the plugin into Claude Code is Claude Code's own step;
`integrations/claude-code/README.md` explains it. Cursor and Codex packages
follow the same layout — see `docs/integrations/INSTALLATION_MATRIX.md`. The
Copilot package is a template today; nothing installs it.

No plugin? The CLI still checks projects. Claim-checking then reports "cannot
confirm", which is the honest answer rather than a missing feature.

## Where SURE keeps things

`%LOCALAPPDATA%\SURE\` on Windows — the program, and `sure.db`, your evidence
history. SURE is local-first: everything stays on your machine and nothing is
sent anywhere.

## Read more

- `ROADMAP.md` — where the project stands and what comes next
- `FINAL_REPORT.md` — what this v0.1 is and is not, with measurements
- `docs/` — architecture, security, integrations, development
- `START_HERE.md` — if you want to work on SURE itself

## License

Apache-2.0. See `LICENSE`.
