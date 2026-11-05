# Windows quickstart: from nothing to a first verdict

`docs/development/INSTALL_WINDOWS.md` is the reference for the installer — where
it puts files, every switch it takes, how `PATH` is treated, and how to take it
out again. This document is the walk: from a bare Windows 11 machine to one
`sure check` that answered. Every command below is one line you can paste into
PowerShell, and the whole of it is per-user — no administrator, no elevation
prompt, no service, no `PATH` change.

**This is not the quickstart in the repository root.** `WINDOWS_QUICKSTART.md`
bootstraps this repository's own autonomous-development loop and is a developer's
document about working *on* SURE. This one is about installing the SURE program.

## 1. There is no SURE to download today

Read this before the first command, because the first step of a quickstart is
normally "fetch the archive", and in this project that step does not exist.

Measured on 2026-09-21 in this repository, with the command beside the answer:

| asked | what it answered |
| --- | --- |
| `gh release list` | nothing |
| `gh api repos/lichman0405/SURE/releases` | `[]` |
| `gh api repos/lichman0405/SURE/tags` | `[]` |
| `git tag` | nothing |
| `gh workflow list` | `ci`, `release-dry-run`, `Dependabot Updates` — no `release` |

So there is **no published archive**. Nothing is on a releases page, and a link
to one would be a link to nothing. Three facts about this tree are why, and each
is held by a rule in `crates/sure-cli/tests/quickstart_flow.rs` rather than by
this paragraph:

* **`.github/workflows/release.yml` creates a draft and cannot publish one.** The
  line it runs is `gh release create "$TAG" … --draft`, and no line it runs
  carries `--draft=false`, `gh release edit` or `gh release delete`. A draft is
  not a download.
* **That file is not on the default branch, so it cannot be dispatched from this
  repository at all.** `git ls-tree --name-only origin/main .github/workflows/`
  lists `ci.yml` and `release-dry-run.yml`; `gh workflow list` offers `ci`,
  `release-dry-run` and `Dependabot Updates`; and no run of a workflow named
  `release` appears in `gh run list`. It takes exactly one `workflow_dispatch`
  input, a required `tag`, so a run of it has to name the tag it is releasing —
  and no workflow named `release` is offered for dispatch here at all.
* **No workflow that can run today packages a Windows archive.** `ci` builds and
  tests on a `windows-latest` runner and uploads no artifact at all;
  `release-dry-run.yml`'s jobs are `validate`, `package-macos`,
  `package-macos-intel` and `package-linux`, and `x86_64-pc-windows-msvc` appears
  on no line it runs. The one job in this tree that builds a Windows archive is
  `release.yml`'s `package-windows` — the file in the bullet above, which the
  workflow's own header describes as *"the artifact nothing in CI has ever
  produced"*.

**This is the gap, stated rather than papered over.** A nontechnical Windows user
cannot install SURE today: the step between a bare machine and an archive in your
hand runs through a Rust toolchain. Section 2 is that step, and it is honestly a
developer's step rather than a step this document dresses up.

## 2. Get an archive — the one path that works today

The only way to hold a SURE archive today is to build one. Two things have to be
on the machine doing the building, and `CLAUDE.md` names both as this
repository's primary development environment:

* **Rust 1.98.1.** `rust-toolchain.toml` pins `channel = "1.98.1"`, so `rustup`
  reads it out of the checkout and installs the right one; you do not have to
  remember the number.
* **Visual Studio Build Tools with the Desktop development with C++ workload**,
  and the Windows SDK that comes with it — that is what the
  `x86_64-pc-windows-msvc` target links against.

If they are not on the machine, section 1 is why, and it is not something you
did wrong.

From the root of a SURE checkout, in PowerShell:

```powershell
# The release gate. The packager refuses to build without it, and writing it runs
# the acceptance corpus, so give it minutes rather than seconds.
cargo test -p sure-core --test acceptance_report_runner

# Build, package, checksum and check the artifact. Also minutes.
& .\scripts\Build-Release.ps1 -Phase All
```

That leaves two files in `target\tmp\release\` — the archive and the checksum
the installer will require beside it:

```text
sure-0.1.3-x86_64-pc-windows-msvc.zip
sure-0.1.3-x86_64-pc-windows-msvc.zip.sha256
```

The name is `sure-<version>-x86_64-pc-windows-msvc.zip`, where `<version>` is
what `sure version` prints — `0.1.3` in this build.
`docs/development/RELEASE_PROCESS.md` is the specification for the layout: one
top-level directory named after the archive, holding `sure.exe`, `LICENSE` and
`RELEASE.txt`.

**Do not use `-Phase Verify` to check a download.** It reads
`target/tmp/release-gate.json` out of the checkout it is run from, so a person
holding only an archive cannot run it at all, and it writes `logs\` and
`scratch\` into the directory holding that archive.
`docs/development/INSTALL_WINDOWS.md` has the measurement. What a person
downloading an archive actually needs is the checksum check, and the installer
does that itself.

## 3. Install the CLI

Still in the root of the checkout, with the archive where section 2 left it:

```powershell
& .\scripts\Install-Sure.ps1 -Archive .\target\tmp\release\sure-0.1.3-x86_64-pc-windows-msvc.zip
```

That is the whole install. It verifies the archive against the `.sha256` before
it extracts anything — there is no switch to skip that check, and a check that
can be turned off is not a check — and then it writes exactly four paths:

```text
%LOCALAPPDATA%\SURE\
    bin\sure.exe            the program
    bin\LICENSE
    bin\RELEASE.txt         the archive's own record of what was built
    install-manifest.json   what this install wrote, with each file's digest
```

`%LOCALAPPDATA%\SURE` is also the directory SURE keeps your evidence in
(`sure.db`, the history a verdict is read from). The two live side by side on a
machine that has been used, which is why `docs/development/INSTALL_WINDOWS.md`
calls it the user's data directory that happens to hold an install rather than
"the install directory", and why the uninstaller is built so that it cannot
touch `sure.db`.

**No `PATH` entry is written, machine or user.** The installer prints the one
line that would add one for your own account, and does not run it. You can reach
the program without any `PATH` change — including from the integration you
install in section 4 — by its full path:

```powershell
& "$env:LOCALAPPDATA\SURE\bin\sure.exe" version
```

```text
SURE 0.1.3
```

Exit status `0` means installed. Status `2` means it stopped, with the reason
printed and nothing installed or replaced.

**The build carries no Authenticode signature, and this document does not
promise you anything about what Windows does with it.** The installer reads the
`signature` line out of the archive's own `RELEASE.txt` — the answer the machine
that built the archive took from Windows itself — and reports that rather than
making a claim of its own. When it says `not-signed`, Windows may show a
SmartScreen or "unknown publisher" prompt the first time you run the program.
Whether a particular machine shows it is not measurable from here, and
`## The build is unsigned, and how that is known` in
`docs/development/INSTALL_WINDOWS.md` is where the boundary is written down.

## 4. Install one harness integration

One is enough to start, and the one this document walks through is **Claude
Code**, because it is the integration this repository's own install tests drive.

```powershell
& .\integrations\claude-code\scripts\install.ps1 -ForceCopy
```

It resolves `sure.exe` in the same order the launchers do — `$env:SURE_BIN`,
then `sure` on `PATH`, then `%LOCALAPPDATA%\SURE\bin\sure.exe`, which is what
section 3 just wrote. If none of the three is there it stops before touching
anything, with `SURE not found. Install SURE or set SURE_BIN.` and exit 1,
because a package placed where nothing can start it is worse than no package.

It then puts a copy of `integrations\claude-code\` at:

```text
%LOCALAPPDATA%\claude-plugins\sure
```

`-ForceCopy` asks for the copy explicitly. Without it the script first tries a
directory symlink, which Windows refuses unless Developer Mode or administrator
rights are in force; the copy is the path that always works, and this install is
meant to need neither privilege.

**Loading the plugin into Claude Code is Claude Code's own workflow, not this
script's.** The script places the package and says where it went; no plugin from
this repository has been loaded into a running session here.
`integrations/claude-code/README.md` records the three loading mechanisms Claude
Code documents, and which of them this package can and cannot stand in for.

To take it out again:

```powershell
& .\integrations\claude-code\scripts\uninstall.ps1
```

`docs/integrations/INSTALLATION_MATRIX.md` covers the other packages — Cursor and
Codex — the CLI-only fallback for a person who installs no harness package, and
what installing the Claude Code package means. It has no Copilot section because
there is no Copilot install to describe: `integrations/copilot/README.md` opens
by saying the package is a template that nothing installs.

## 5. Run your first check

```powershell
& "$env:LOCALAPPDATA\SURE\bin\sure.exe" check "C:\path\to\your\project"
```

**The path has to be absolute.** A relative one is refused with status 5, on
purpose: a relative path resolves against whatever directory SURE happened to be
started in, and whether it was inside the project would then depend on that.

What follows is a real run of that command, against a project holding a
`package.json` and one JavaScript file, cut to its own headings. A line holding
three dots is where text was left out.

**It is a run of a machine that has never used SURE**, which is the machine this
walk is written for: nothing has been recorded for it, so stage 9 has no history
to read and is one of the two stages marked as not checked below. If your machine
has already been used with SURE, that is the one line that changes — stage 9
reads what your history holds and is marked as run, so the summary underneath
reads one lower. A machine with no analysis provider configured is the other half
of the count, and section 5's status table says why stage 8 is always marked.

```text
SURE checked C:\path\to\your\project.

Not enough could be checked to say whether this is ready.
...
No unresolved findings from the checks that ran.

What the run did, stage by stage
  1/12. Find the project's parts: node (level B); all of it was read. Support reaches level B.
  ...
  8/12. Ask a model to assess the project: No analysis provider is configured, so SURE assessed nothing with a model. This is a scope limit and not a failure: the deterministic checks are unaffected. (NOT CHECKED)
  ...
  9/12. Check what was claimed against the evidence: SURE has no recorded history for this machine, so there are no agent claims to check against evidence. (NOT CHECKED)
  ...

2 of the 12 stages did not run, and each is marked NOT CHECKED above. A run with
a stage that did not run is never reported as clean.

SURE exited with status 1. That is what it returns when it checked the project
and did not find it clean — not 3, which would mean this build cannot check a
project at all.
```

**Read the status as the answer:**

| status | what it means |
| --- | --- |
| `0` | the run was clean. On a machine where no analysis provider is configured — which is what SURE does when no settings file asks for one — nothing reaches it: stage 8 is then always recorded as not run, and a run with a stage that did not run is never reported as clean |
| `1` | the project was checked and is not clean. **This is what `sure check` returns for every project it can read in this configuration**, and it is not a finding: it says SURE could not establish enough to call the project clean |
| `5` | the command tried and did not finish — an unreadable project, a relative path, a store it could not read |
| `3` | the command exists and this build cannot carry it out, whose remedy is a newer build. `check` never returns it |
| `2` | the command line was wrong |

The distinction between `1` and `3` is the one that matters most: "this project
has problems" and "SURE cannot do that here" need opposite responses, and one
status for both is how a broken tool gets read as a clean project.

**A check writes nothing.** It opens your history only when there is one already
and creates no store, so a first check on a machine that has never used SURE
leaves no file behind. `docs/architecture/CLI.md` is the contract for every
command, and the statuses above are its table.

## 6. Where you are

```text
%LOCALAPPDATA%\SURE\bin\sure.exe          the CLI, installed
%LOCALAPPDATA%\claude-plugins\sure        the Claude Code package, copied
```

You have run one whole check and read its verdict. The commands worth knowing
next are all in `docs/architecture/CLI.md`:

* `sure doctor` — where SURE keeps its files on this machine, what is at each of
  them, and **what it did not check**. Exits `0` when it found nothing wrong and
  `1` when it did, so `sure doctor || fix it` works.
* `sure config set execution.mode host_confirmed` — allow SURE to run the
  project's own commands (tests, build) instead of only reading its files. The
  default is `inspect_only`.
* `sure repair` — turns what a check found into a bounded contract an agent can
  act on.
* `sure recheck` — checks again and says what the earlier run left open. Unlike
  `check`, these two record, so a second run has something to compare against.
* `sure history` — what SURE has recorded on this machine, and how to delete it.

## What would close the gap in section 1

Named, so that the next person can tell whether they are looking at the gap or
past it. Three things, and none of them is a code change:

1. **A person with write access creates a release tag and dispatches
   `.github/workflows/release.yml`.** The tag has to name the commit the run is
   dispatched from, and the workflow refuses anything else. It also has to be on
   the branch GitHub offers for dispatch — today the file is not on the default
   branch, which is why `gh workflow list` does not offer it.
2. **A person publishes the draft, by hand, on the release page.** Nothing in
   the workflow does this and nothing should: publishing is outward-facing and
   hard to reverse, which is the whole reason the create is a draft.
3. **Then, and only then, could this section be replaced by a single line
   pointing a reader at where to get the archive** without that line being false.

A package manager would be a second route rather than a substitute.
`scripts/New-WingetManifest.ps1` renders a WinGet manifest, and submitting one is
a pull request against `microsoft/winget-pkgs`, a repository this project does
not own; the release workflow invokes no publication channel at all.

What does *not* change when the gap closes: the build still carries no
Authenticode signature and the archive still carries no Apple Developer ID
signature or notarization ticket, so a downloader meets the prompt described in
section 3 and `docs/development/MACOS.md` respectively. Those are external
credentials this project does not hold, and publishing does not supply them.

## How "documented and tested" is satisfied here

The same standard `docs/development/INSTALL_WINDOWS.md` records for the installer,
applied to this walk. Every claim above is named to the thing that measures it,
and that thing is `crates/sure-cli/tests/quickstart_flow.rs`.

Every name in the right-hand column is a name you can find in that file: either a
`#[test]` function, or the function that carries the rule the test runs. The
quickstart's own rules about the workflow files are not tests of their own — they
are `release_workflow_violations` and `dry_run_violations`, and
`the_windows_quickstart_satisfies_every_rule` is the test that runs them against
the real files. Each rule's own doc comment in that file says what it is about.

| claim in this document | what measures it |
| --- | --- |
| Sections 3, 4 and 5 are a journey a person can actually make: install this archive, install this integration, and get a verdict from `sure check` | `the_whole_documented_journey_installs_the_cli_an_integration_and_answers_a_check` — stages a real archive, runs `scripts/Install-Sure.ps1` into a scratch root, runs `integrations/claude-code/scripts/install.ps1 -ForceCopy` with `SURE_BIN` removed and nothing on `PATH`, runs `sure check` with the **installed** binary, and requires the verdict |
| Section 4's claim that the installer resolves the binary section 3 wrote, and stops when it is not there | `the_integration_installer_finds_the_cli_this_document_installed` — the same run, then the installed `bin\sure.exe` is removed and the same command is required to fail with `SURE not found`, so the passing run cannot have been measuring something else |
| Section 5's claim that a check writes nothing | `a_check_leaves_the_store_of_the_person_running_it_byte_identical` — the digest of this machine's own per-user store, taken across a real run |
| Section 5's status table, and that a check of a readable project is `1` and never `3` | `the_whole_documented_journey_installs_the_cli_an_integration_and_answers_a_check`, on the exit status of the real run |
| Section 5's quoted run: the number it prints of the stages that did not run | `the_windows_quickstart_satisfies_every_rule`, through the rule `quoted_run_violations`, and `the_whole_documented_journey_installs_the_cli_an_integration_and_answers_a_check` — the number in the run's own summary sentence is required to equal the number of lines in the same run carrying the `(NOT CHECKED)` marker, in the transcript below and in the live run alike. The number itself belongs to the machine — 2 on a machine with no history and 1 on a machine with a store — so what the rule holds is that the sentence counts its own lines, on whichever machine it was made |
| Section 1: there is no published archive, and the release workflow cannot publish one | `the_windows_quickstart_satisfies_every_rule`, through the rule `release_workflow_violations` — reads the lines `release.yml` runs and requires the invocation `gh release create "$TAG"` with `--draft`, no `--draft=false`, `gh release edit` or `gh release delete`, and a read of the workflow's own `workflow_dispatch` input list, which is required to be exactly `tag` |
| Section 1: no workflow packages a Windows archive | `the_windows_quickstart_satisfies_every_rule`, through the rule `dry_run_violations` — requires the Windows target triple and the `.zip` extension to appear on no line `release-dry-run.yml` runs, and the job list to be the four jobs named above |
| Section 1 does not send the reader to a download that does not exist | `the_windows_quickstart_satisfies_every_rule`, through `forbidden_in` over `DOWNLOAD_PROMISES` — four families of phrasing, each one a sentence a quickstart would really carry |
| The staging fixture is the one `install_flow.rs` already uses rather than a second invention | `the_two_stagers_are_one_stager` — reads `install_flow.rs`'s own `STAGE_AND_PACK` literal out of its bytes and requires this file's copy to be character for character the same |
| The rules read files that are there, and the reader is not blind to what they say | `a_file_that_is_not_there_is_not_a_pass` — an empty corpus, and a corpus with one file missing and one file empty, are required to fail rather than satisfy the rules; and `the_reader_sees_the_mechanism_that_is_there`, which requires the real document to carry the anchors a reader would look for and the real workflows to carry the structure the rules look for |
| Every rule fails when the thing it names is removed | `every_rule_is_turned_red_by_an_edit_that_breaks_it`, over edits taken from these files' own bytes — a `from` that matches nothing is a failure, not a pass |
| Every phrase in the forbidden list is one the reader actually finds | `every_forbidden_phrase_is_one_this_reader_reports` — each phrase is injected into the real document as a real sentence, and the rule is required to name it |

## What is not covered

Named as limits rather than left to be assumed.

* **Section 2 is not tested, and cannot be here.** `scripts/Build-Release.ps1
  -Phase All` refuses to package without the release gate and takes a full
  release build; the journey test stages the documented archive layout around
  the binary cargo just compiled, exactly as
  `crates/sure-cli/tests/install_flow.rs` does and for the same reason. What the
  installer reads is a real ZIP with real bytes; what it is not is a
  `Build-Release.ps1` artifact, and `P15-T002`'s verification of that artifact is
  a separate thing.
* **Nothing here observes a run of `.github/workflows/release.yml`.**
  `git tag` returns nothing on this repository, so it has never been given a tag
  to release. The rules above are about what the file says, and they prove
  nothing about whether GitHub would accept it.
* **The SmartScreen prompt is not exercised.** No test runs an unsigned binary
  through a download-marked file and watches. What this document says is limited
  to what the archive's own `RELEASE.txt` records, and to the fact that Windows
  may warn — see `docs/development/INSTALL_WINDOWS.md`, `## What is not covered`.
* **Claude Code loading the plugin is not observed.** The installer places the
  files; no plugin from this repository has been loaded into a running session
  here, and `integrations/claude-code/README.md` says so in the same words.
* **Both PowerShell hosts are driven only where this machine has them.** The
  journey runs under Windows PowerShell, which is always installed, and under
  PowerShell 7 when `pwsh.exe` is found, because `CLAUDE.md` names PowerShell 7+
  for this repository's scripts and a claim about that host that nothing ran is
  an unmeasured claim.
