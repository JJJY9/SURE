# Dogfooding: SURE checking SURE

This page is the record `P16-T007` asks for: the built checker pointed at its own
repository, under a documented execution mode, with what it actually said written
down and every one of its findings judged. It is the artefact clause 3 of the
task ("Dogfood result is saved for FINAL_REPORT") names, and it is written to be
read against the run it quotes rather than as a claim about SURE in general.

The interesting result is not the exit code. It is that **SURE's own repository
is the hardest project SURE will ever be pointed at**, because it is the one
project that contains both SURE's detection patterns as source text and SURE's
deliberate false-completion fixtures. This page reports which of the run's
findings survive being checked by hand, and it reports the three defects the run
turned up that no test did.

Everything below is a command that was run and output that was produced. Where a
result is a limit rather than a pass, it says so. Nothing here was repaired: the
lane for `P16-T007` is this page and `target/tmp/dogfood/`, and every defect
below is in someone else's files.

## 1. The run

### The binary

| | |
| --- | --- |
| Binary | `C:\Users\lishi\code\SURE\target\debug\sure.exe` |
| Size / SHA-256 | 18 484 736 bytes, `ad3fc3d69893f080235d2447a24b27a4487f2c47ff7fc01c2afc00494ad57314` |
| Built | `2026-09-21 11:38:50 +08:00` |
| `sure version` prints | `SURE 0.0.0-bootstrap` |

The prebuilt debug binary was used rather than a fresh build. It is newer than
every shipped source file in the tree: `find crates -path '*/src/*.rs' -newer
target/debug/sure.exe` returns nothing, so no file under `crates/*/src/` is
newer than the binary that ran. The files newer than it are tests
(`crates/sure-core/tests/acceptance_report_runner.rs`,
`crates/sure-cli/tests/quickstart_flow.rs`) and do not ship. The last commit
before the run, `169098d`, touched only
`crates/sure-cli/tests/quickstart_flow.rs` and
`docs/development/INSTALL_WINGET.md`. So the checker is current with respect to
the shipped tree as of `169098d`; it is not a build of HEAD, because HEAD moved
during the run (see §9).

### The mode, and why it is the documented one

The run is under **`inspect_only`**, and that needs no flag:

* `docs/architecture/EXECUTION_SAFETY.md` names `inspect_only` "the **default**,
  and … the answer whenever anything short of a deliberate arrangement is in
  effect".
* It is the mode the run itself reports: `Execution mode: inspect_only — SURE
  will read your project's files only. Nothing in your project will be run.`
* No user settings file exists on this machine (`C:\Users\lishi\AppData\Roaming\SURE\`
  is absent), so nothing could have moved the mode in either direction, and
  `sure doctor` reports `"settings_location": "platform"`, `"presence":
  "absent"`.
* At `169098d` it was also the only mode this build acted on:
  `EXECUTION_SAFETY.md` then read *"**Nothing does.** … no check drives on that
  road yet"*, and that quoted sentence is gone from the tree — `P18-T007` wired
  the pipeline to the runner and rewrote it. What has not changed is the run:
  a run still starts in `inspect_only`, the mode a project's own file cannot
  move, and under it no command that starts a process is admitted.
  `EXECUTION_SAFETY.md` now says that, and `support::CEILING` is still
  `InspectOnly` for the platform reason rather than the old one.

No `--settings-file` was passed and no setting was changed at any scope. Nothing
was installed, and no execution policy was weakened anywhere.

### Where the store was pointed, and why that mattered

The real store was never touched. `--store-dir` is the documented mechanism
(`docs/architecture/STORAGE_AND_DATA_PATHS.md`, "A store location the caller
names"; `docs/architecture/CLI.md`, "`--store-dir DIR`"), and it takes an
absolute directory that must be outside the project being checked. The scratch
location was:

```text
C:\Users\lishi\AppData\Local\Temp\sure-dogfood-P16-T007\
```

The lane for this task (`target/tmp/dogfood/**`) could **not** be used as the
store: it is inside the project, and `Paths::ensure_outside` refuses that. That
refusal, and the one state in which `check` does not ask for it, is measured in
§7.3.

### The exact commands

Run from `C:\Users\lishi\code\SURE`, in this order, in PowerShell (the `--store-dir`
value quoted as a Windows path; each was also run through Git Bash for the
captured logs, which makes no difference to SURE):

```powershell
# 1. Which location does this run see, and did the redirect take effect?
target/debug/sure.exe doctor --store-dir 'C:\Users\lishi\AppData\Local\Temp\sure-dogfood-P16-T007\store' --format json
#    -> exit 0.  "store_location":"caller", "store_file":{...,"presence":"absent"}, "store":{"state":"not_created"}

# 2. The dogfood check itself, human form.
target/debug/sure.exe check 'C:\Users\lishi\code\SURE' --store-dir 'C:\Users\lishi\AppData\Local\Temp\sure-dogfood-P16-T007\store' > target/tmp/dogfood/check-human.txt
#    -> exit 1, 3 seconds, stdout 18 903 bytes, stderr 0 bytes

# 3. The same run, machine form.
target/debug/sure.exe check 'C:\Users\lishi\code\SURE' --store-dir 'C:\Users\lishi\AppData\Local\Temp\sure-dogfood-P16-T007\store' --format json > target/tmp/dogfood/check-json.json
#    -> exit 1, 23 051 bytes

# 4. The repair loop, which is the half of the surface that writes.
target/debug/sure.exe recheck 'C:\Users\lishi\code\SURE' --store-dir 'C:\Users\lishi\AppData\Local\Temp\sure-dogfood-P16-T007\store' > target/tmp/dogfood/recheck-human.txt
#    -> exit 1, 33 339 bytes

# 5. The same command again, now that an earlier run is in the store.
target/debug/sure.exe recheck 'C:\Users\lishi\code\SURE' --store-dir 'C:\Users\lishi\AppData\Local\Temp\sure-dogfood-P16-T007\store' > target/tmp/dogfood/recheck2-human.txt
#    -> exit 1.  Stage 12: "18 earlier finding(s) stayed open, 0 resolved."
```

`target/debug/sure.exe check` (no `PATH` argument) checks the current directory
and gives the same answer as the explicit path; both forms were run. Every
output quoted below is from the files named above, all of which are under
`target/tmp/dogfood/` and are gitignored.

### The store, before and after

| Reading | Size | SHA-256 |
| --- | --- | --- |
| Before the first `sure` process | 348 160 | `d171755690549d3a59f1949e85c124b1f06b5cc7f84b8e395f176a8031d67853` |
| After the last one | 348 160 | `d171755690549d3a59f1949e85c124b1f06b5cc7f84b8e395f176a8031d67853` |

Identical, and identical to the digest the task named. The file's mtime is still
`2026-09-18 23:12`. One artifact of the runs exists in the scratch location:
`…\Temp\sure-dogfood-P16-T007\store\sure.db`, 94 208 bytes, written by the
`recheck` runs because they are the commands that record. `sure check` created
nothing anywhere: pointing it at a directory that did not exist
(`…\sure-dogfood-P16-T007\never-created`) left that directory uncreated, which is
the documented behaviour ("`sure check` reports and remembers nothing: it opens a
store only when one is already there and creates nothing, before or after").

Nothing was written into the repository by any run. `find . -name .sure -not
-path './target/*'` returns nothing; `git status --porcelain` after all runs
lists only files this task never opened (`docs/testing/ADVERSARIAL_FIXTURES.md`,
the four `integrations/*/scripts/sure-hook.ps1`, `progress/HANDOFF.md`,
`progress/state.json`), which belong to the workers running alongside this one.

## 2. What the run said

The first four lines of `check-human.txt`, verbatim:

```text
SURE checked C:\Users\lishi\code\SURE.

Not enough could be checked to say whether this is ready.

Not enough could be checked to say whether this is ready.
This project is not ready to hand off.
```

and the counts:

```text
Unresolved findings: 5 Must fix, 5 Should fix first, 5 Can fix later, 3 Note.
18 check(s) could not run or were skipped. 1 of them are critical. (run the tests)
```

and the scope statement, which is the sentence that matters most for reading
everything that follows:

```text
Could not check
---------------
SURE checked 0 of 18 checks. 4 checks were skipped and 14 checks could not run.
```

```text
  10/12. Work out the verdict: Not enough could be checked to say whether this is ready. 0 check(s) produced a result, 18 did not run.
```

```text
No check in this run produced a result about the project, so the status above is not a finding: it says SURE could not establish enough to call the project clean.
```

The run exited **1**, not 0 and not 3; the report says both what 1 means and that
it is not a finding here.

**Zero checks produced a result.** Every one of the 18 entries in the `Findings`
section has `Status: Cannot confirm`, and each carries the same sentence in its
`What:` line: *"SURE planned this check and did not run it, so it has no answer
for it."* The two reasons behind that, from stages 5 and 6:

```text
  5/12. Read the project and check it: 14 of the planned checks read your project's files and run nothing. This build has no runner for a planned check, so none of them reported a result and each is recorded as unknown rather than passed. (NOT CHECKED)
  6/12. Run the project's own checks: 4 check(s) would run your project's code. 4 of them were stopped by the execution mode and are recorded as not checked: run the tests, look for probable mistakes, check that it compiles, check that the source is formatted. (NOT CHECKED)
```

The two stage lines above are **this run's output at `169098d`**, quoted as it
was printed. Stage 5's sentence is not what today's build says — `P18-T007`
wired `pipeline.rs` to the runner and both stage descriptions were rewritten
with it. This run is unaffected: it was under `inspect_only`, its 4 dynamic
checks are still unrun, and the numbers below are the numbers it printed. What
stage 5 says instead, measured rather than described: the same command over this
repository, an empty store and `inspect_only` named in a settings file outside
the project, on the working tree while `P18-T007` was being written (so the
counts are that tree's and not this chapter's):

```text
  5/12. Read the project and check it: 14 of the planned checks read your project's files and run nothing. Each of them has a result: 0 were stopped by the execution mode and are recorded as not checked rather than passed, and the rest are the runner's answer — a detector's own observation where the check carries one, and its command's outcome where the plan holds a command.
  6/12. Run the project's own checks: 4 check(s) would run your project's code and the execution mode stopped every one of them, so none was carried out and each is recorded as not checked rather than passed: run the tests, look for probable mistakes, check that it compiles, check that the source is formatted. (NOT CHECKED)
```

The 14 static checks produce their results now, which is the whole difference
`P18-T007` made to a run under `inspect_only`; the 4 that would run still do not,
and the verdict is still `not_green` — the run above exited 1 with 14 of 18
checks reporting.

So the honest headline is **not** "SURE found five must-fix problems in its own
repository". It is: SURE planned eighteen checks, ran none of them, located
fourteen places worth looking at, and refused to call the project clean.

## 3. The fourteen places it pointed at, and whether each is true

Stage 7 is the one stage that did work on the project's content:

```text
  7/12. Look for unfinished work: 12 candidate(s) worth acting on, 2 that are style noise, 0 dropped as duplicates. A candidate is something to look at, not a defect SURE has established.
```

Fourteen candidates, twelve of them material. Fourteen of the eighteen findings
carry one of them as their evidence anchor; the other four are the declared
commands. The table is the run's own list, with the line it names read back out
of the tree. **Every anchor is literally true** — the file really does contain
that text on that line. None of them is a defect, and the judgement is in the
last column.

| # | Severity | Anchor (file:line) | What is on the line | Judgement |
| --- | --- | --- | --- | --- |
| 1 | Must fix | `crates/sure-core/src/documents.rs:1818` | `"[mail](mailto:someone@example.com)\n",` | **False as a defect.** It is one entry of a test's list of markdown links, inside the file's own `#[cfg(test)] mod tests` (which begins at `documents.rs:1344`). |
| 2 | Must fix | `crates/sure-core/src/false_completion_aggregator.rs:438` | `let reason = candidate_reason("src/pay.rs", 7, "tok_visa");` | **False as a defect.** A `#[test]` case using a fake token as a fixture; the file's test module begins at line 233. |
| 3 | Must fix | `crates/sure-core/src/noop_heuristics.rs:208` | `trimmed.contains(".status(200)")` | **False as a defect.** It is the detector's own pattern table — the definition of "hard-coded success", not an instance of one. |
| 4 | Must fix | `crates/sure-cli/src/check.rs:645` | `return Ok(());` | **False as a defect.** An early-return guard at the top of `fn repairs(...)`; the function's body continues with a `writeln!` that prints the repair section. It is not a function that always succeeds. |
| 5 | Must fix | `Cargo.toml` | the command `cargo test` | **True, and honest.** See §4. |
| 6 | Should fix first | `crates/sure-core/src/demo_data_heuristics.rs:9` | `//! - Demo analytics values (ga('create', 'UA-XXXXX-Y') …` | **False as a defect.** A module doc comment describing what the detector looks for. |
| 7 | Should fix first | `crates/sure-core/src/demo_data_heuristics.rs:13` | `//! - Placeholder user/content IDs in production paths (user_123, demo_user,` | **False as a defect.** Same: documentation of the pattern set. |
| 8 | Should fix first | `crates/sure-core/src/demo_data_heuristics.rs:181` | `lower.contains("demodata = [")` | **False as a defect.** The pattern table itself. |
| 9 | Should fix first | `crates/sure-core/src/demo_data_heuristics.rs:239` | `lower.contains("lorem ipsum")` | **False as a defect.** The pattern table itself. |
| 10 | Should fix first | `Cargo.toml` | the command `cargo clippy --all-targets` | **True, and honest.** See §4. |
| 11 | Can fix later | `crates/sure-core/src/candidate_context.rs:19` | `/// Found in a mock, stub, or fixture file/directory.` | **False as a defect.** A doc comment on an enum variant, matched because it contains the words it is defining. |
| 12 | Can fix later | `crates/sure-cli/src/report.rs:1920` | `fn a_check_that_recorded_no_goal_answers_with_null_and_not_a_placeholder() {` | **False as a defect.** A test function's *name*, inside `#[cfg(test)] mod tests` (begins at `report.rs:1261`). |
| 13 | Can fix later | `crates/sure-cli/src/commands.rs:12` | `//! command ship as a stub that nobody chose to make a stub, and …` | **False as a defect.** A module doc comment using the word "stub" in prose. |
| 14 | Can fix later | `crates/sure-core/src/candidate_scanner.rs:1` | `//! Candidate scanner for TODO/mock/stub/placeholder patterns.` | **False as a defect.** The module doc of the scanner itself, matched on the word "TODO". |
| 15 | Note | `fixtures/adversarial/dead-button/public/app.js:38` | `buyButton.addEventListener('click', handleBuyClick);` | **True, and expected.** This is SURE's own adversarial fixture; containing that line is its purpose. |
| 16 | Note | `fixtures/adversarial/route-mismatch/src/frontend/api.js:17` | `return fetch('/api/orders').then(function (response) {` | **True, and expected.** SURE's own route-mismatch fixture. |
| 17 | Can fix later | `Cargo.toml` | the command `cargo check --all-targets` | **True, and honest.** See §4. |
| 18 | Note | `Cargo.toml` | the command `cargo fmt --check` | **True, and honest.** See §4. |

Twelve of the fourteen are false as defects, and they are false for reasons that
are worth separating, because they are not one bug:

* **Eight are SURE reading its own pattern library as if it were a project.**
  Rows 3, 6, 7, 8, 9, 11, 13 and 14 are the detection patterns and the prose that
  documents them. `demo_data_heuristics.rs:239` is `lower.contains("lorem
  ipsum")`: the line SURE flags as "hard-coded demo or chart values" is the line
  that *defines* what a hard-coded demo value is. There is no rule that excludes
  the detector modules from the scan, and the run's own framing ("A candidate is
  something to look at, not a defect SURE has established") is what keeps that
  honest rather than wrong.
* **Three are in-file Rust test modules, read as production code.**
  `candidate_context::classify_path` classifies a **path** and nothing else
  (`candidate_context.rs`, "Heuristics are conservative … When uncertain,
  `CandidateContext::Product` is returned"). `crates/sure-core/src/documents.rs`
  carries no `tests/` component and no `test`/`spec`/`mock`/`stub` filename
  segment, so it is `Product` — even though line 1818 sits 474 lines inside the
  file's own `#[cfg(test)] mod tests`. The same is true of rows 2 and 12. This is
  the documented conservative direction rather than a hidden failure, and it is
  the one direction that costs: the *severity* is computed from `Reach`, so a
  test fixture in a `src/` file is graded with production gravity.
* **Two are fixtures behaving exactly as designed**, and both are correctly held
  at `Note` because `classify_path` *does* see `fixtures/` and returns
  `MockFixture` → `NotProduction` → `note`. Rows 15 and 16 are the context
  filter working.
* **Row 4 is a line-level pattern match that is simply too wide.**
  `noop_heuristics.rs:192` is `trimmed.contains("return Ok(());")`, which matches
  any line containing that text wherever it appears. In `check.rs:645` it is the
  first statement of a function that goes on to do work.

None of these is a false green. A false green would be *stating* a defect that is
not there; this run states the opposite — it states that it cannot confirm any of
them, and the verdict is "not enough could be checked". What the fourteen do
produce is **noise at a severity label**: an entry reading `Severity: Must fix`
over a line that is a doc comment. §5 takes that up.

## 4. The four command checks

The other four findings are the project's declared commands, and they are the
cleanest part of the output. All four are real commands for this repository, all
four are stopped by `inspect_only` with a sentence saying so, and the next action
is the command itself:

```text
run the tests
  Severity: Must fix
  Status:   Cannot confirm
  Action:   Run `cargo test` and let SURE re-check it, or allow SURE to run it.
  Where to look:
    - command at Cargo.toml (cargo test)
```

Judgement: **true**. `run the tests` is marked `[critical]`, which is what makes
`has_critical_gaps: true`, and the run is explicit that the gap is SURE's, not
the project's.

One imprecision, and it is small: the anchor reads `command at Cargo.toml`. None
of the four commands is declared in `Cargo.toml` — `grep -n 'cargo test\|clippy\|
cargo check\|fmt' Cargo.toml` returns only `[workspace.lints.clippy]`. The four
are derived from the Rust stack (`docs/architecture/ECOSYSTEM_DISCOVERY.md`: the
four `CommandRole`s, with `format_command` appending `--check`), and `Cargo.toml`
is the manifest that makes the stack Rust. A reader who takes "command at
Cargo.toml" to mean "declared in Cargo.toml" would look for a declaration that is
not there. The sentence is defensible; it is one word away from being exact.

## 5. The one reading that can go wrong

The counts line says `Unresolved findings: 5 Must fix, 5 Should fix first, 5 Can fix
later, 3 Note.` Every one of those eighteen is `Cannot confirm`. The severities
are the *checks'* own — `findings_from_checks.rs` states the rule ("A check the
plan called `must_fix` produces a `must_fix` finding") — and the same eighteen
are counted as `open_findings` in the JSON frame's `report.totals`, so the
number is not wrong.

What it is, is available to be misread. `5 Must fix` on the fourth line of a
report reads as five established must-fix defects, and nothing on that line says
they are eighteen checks that did not run. The correction is one line below
(`18 check(s) could not run or were skipped`) and every entry repeats `Status:
Cannot confirm`, so a reader who reads the report rather than the line is fine.
A reader who skims — or a script that parses `Unresolved findings` and stops — is not.

I judge this an honest but poorly-labelled count, not a false green: it errs
toward alarm, the verdict is not-green either way, and the run never claims a
check passed. It is recorded here as a wording risk rather than as a defect,
because the machine frame keeps the two lists apart and names them
(`report.totals` is `{"checked": 0, "could_not_run": 14, "skipped": 4,
"open_findings": 18}`), so a caller that wants the distinction can have it.

## 6. What the run did not check, and whether it said so

This section is the one `CLAUDE.md`'s "a false green is more serious than a
visible error" is about, so it is measured rather than asserted.

**Visible, and honestly so.** Every one of these is a line in the report that a
reader cannot miss:

| Not checked | Where the run says so |
| --- | --- |
| All 14 static detector checks (at `169098d`, because this build had no runner for a planned check) | Stage 5, `(NOT CHECKED)`, plus a `Could not check` entry per check |
| The 4 project commands, stopped by the mode | Stage 6, `(NOT CHECKED)`, each named, with the mode's own sentence |
| Model-backed assessment | Stage 8, `(NOT CHECKED)`, "no analysis provider is configured" |
| Claim checking against recorded events | Stage 9, `(NOT CHECKED)` for `check`; for `recheck`, "the history holds no claims about this project" |
| Repair contracts and the comparison with the last run | Stages 11 and 12, `(not part of this run)` for `check` |
| The verdict itself | "SURE checked 0 of 18 checks", the closing paragraph, and the status sentence |

There is no place in this run where a check that did not run was rendered as a
pass. `checked_count` is 0, `green` is false, `has_critical_gaps` is true, and
the machine frame says `"outcome": "not_green"` with `"exit_code": 1`.

**Silent, and worth naming.**

1. **The discovery skip set does not appear in the output.** Stage 1 says `Find
   the project's parts: node (level B), rust (level B); all of it was read.` The
   repository contains a large `target/` build tree — described as roughly 82 GB
   by this repository's own working notes, and deliberately not measured here —
   that no line of the report mentions. `docs/architecture/PROJECT_DISCOVERY.md`
   lists the declared skips (`.git`, `node_modules`, `target/`, caches) and says
   the rule is that SURE "does nothing about `.gitignore`" on purpose, so the
   behaviour is designed and documented — but a reader of the run alone cannot
   see it. The measurement that says the skip happened is the run's own duration:
   the whole `check` took **3 seconds** over a workspace of 607 tracked files
   plus that `target/` tree, which is not a walk of it. `all of it was read` is
   true of the components SURE found, and reads as a stronger claim than it is.
2. **Nothing says the anchors are SURE's own source.** The report uses the word
   *candidate* and defines it in stage 7 ("A candidate is something to look at,
   not a defect SURE has established"), which is the honest framing — but it
   does not distinguish "this line contains a pattern" from "this line *is* a
   pattern definition", and on this particular project that is the whole
   difference.

Both are absences of explanation rather than absences of a warning, and neither
can produce a false green: the run's verdict is not-green and its per-finding
status is `Cannot confirm` in all eighteen cases.

## 7. Three defects the run found that the tests did not

None of these is in the `P16-T007` lane. All three were left alone by that task,
as it requires, and reported with the file and line so whoever owns them could
decide. None is a false green.

**All three were then repaired in `b55a675`**, each reddened by mutation before it
was trusted. The sections below are the observations exactly as this run recorded
them and are left as they were written, because they are the evidence for the
repairs — so the file and line numbers in them are those of the tree this run was
made against, not of the tree that carries the fix.

### 7.1 The verdict sentence is printed twice

Observed at the top of `check-human.txt`, lines 3–6:

```text
Not enough could be checked to say whether this is ready.

Not enough could be checked to say whether this is ready.
This project is not ready to hand off.
```

The mechanism is visible in the code: `crates/sure-cli/src/human_report.rs:44`
writes `verdict.aggregate.headline`, then a blank line, then
`render_summary(verdict)` at `:49`, and
`crates/sure-core/src/project_verdict.rs:70` is the first line of that function:

```rust
parts.push(verdict.aggregate.headline.clone());
```

For the `not_enough_checked` verdict the headline and the summary's first
sentence are the same frozen string (`sure-domain/src/status.rs:494`), so the
sentence appears twice with nothing between the two copies but a blank line. It
affects the markdown and HTML forms too (`crates/sure-cli/src/portable_report.rs:47`
and `:177`). Cosmetic, and squarely in the middle of the surface a user reads
first.

### 7.2 A first `recheck` reports a comparison that did not happen

`recheck` on a store that has never seen this project prints:

```text
Against the earlier run: 0 finding(s) still open, 0 closed.
```

while stage 12 of the *same report* says:

```text
  12/12. Compare with what the last run found: no earlier run left anything open for this project.
```

Measured twice, on two independent virgin stores
(`target/tmp/dogfood/recheck-first-human.txt` and `recheck-first-json.json`):
exit 1, the summary line present, stage 12 saying there was no earlier run. The
function's own doc comment states the intent it does not implement —
`crates/sure-cli/src/check.rs:689-694`: *"Silent unless there was one. A run with
no history, or one that is not comparing, has already said so in its stages"* —
and the condition at `check.rs:696` is `run.lifecycle`, which
`crates/sure-core/src/pipeline.rs:885-886` sets for every `recheck` that read the
store successfully. The emptiness that distinguishes the cases is computed at
`pipeline.rs:1187` (`if previous.is_empty()`) and used only for stage 12's
detail, never for the summary line or for `details.lifecycle`, which is
`{"closed": [], "still_open": []}` in both cases.

So a reader of a first re-check is told a comparison against an earlier run found
nothing open, when there was no earlier run. Stage 12 contradicts it 14 lines
later and the verdict is not-green either way, so it is a wording defect and not
a false green — but "0 findings open against the earlier run" is exactly the
sentence a person would quote, and on a first run it is not a fact about
anything.

### 7.3 `sure check` does not refuse a store inside the project unless a store is already there

`docs/architecture/CLI.md`, "`--store-dir DIR`", says:

> **A location inside the project being checked is refused**, by the same
> `Paths::ensure_outside` rule the `--goal` path already used, and in the same
> shape: status 5, a message that says what it did and did not do, and no store
> directory created. **The check refuses before it opens the store**, so the
> refusal leaves the machine as it found it.

Measured, with three variants of the same command line:

```powershell
# (a) directory does not exist
target/debug/sure.exe check 'C:\Users\lishi\code\SURE' --store-dir 'C:\Users\lishi\code\SURE\target\tmp\dogfood\store-inside'
#     -> exit 1, a full report, no refusal, nothing created

# (b) directory exists and is empty
mkdir target/tmp/dogfood/store-inside
target/debug/sure.exe check 'C:\Users\lishi\code\SURE' --store-dir 'C:\Users\lishi\code\SURE\target\tmp\dogfood\store-inside'
#     -> exit 1, a full report, no refusal, directory still empty

# (c) a `sure.db` is present in it
target/debug/sure.exe check 'C:\Users\lishi\code\SURE' --store-dir 'C:\Users\lishi\code\SURE\target\tmp\dogfood\store-inside'
#     -> exit 5: "sure check could not finish. … SURE keeps authoritative evidence in
#        C:\Users\lishi\code\SURE\target\tmp\dogfood\store-inside, and that is inside
#        C:\Users\lishi\code\SURE. … SURE stopped rather than treat it as authoritative."
```

and, for contrast, the command that writes refuses in state (b) — the state in
which `check` runs happily:

```powershell
target/debug/sure.exe recheck 'C:\Users\lishi\code\SURE' --store-dir 'C:\Users\lishi\code\SURE\target\tmp\dogfood\store-inside'
#     -> exit 5, the same refusal, nothing created
```

The refusal lives at store-open time, and `check` opens the store only when one
is already there — so for `check` the refusal is real but state-dependent. The
security property itself holds: in (a) and (b) nothing was read and nothing was
written (the directory was still empty afterwards, and `check`'s stage 9 said
`SURE has no recorded history for this machine`), and in (c) the run stopped
with status 5. What does not hold is the documented promise, which is
unconditional, and the design principle stated two sections earlier in the same
file: *"finding that out only when a command happens to write would make the
same mistake a usage error in one invocation and a silent success in another."*
Here the same command line is a silent success in one state and a refusal in
another, and the user is told nothing in the first.

Related, and I judge it correct as it stands: `sure doctor --store-dir
<inside the project>` exits 0 and reports the location
(`"store_location": "caller"`, the path inside the project). `doctor` takes no
project argument, so it has nothing to ask `ensure_outside` about; it reports
where the store is rather than ruling on it, which is the job its own
documentation gives it.

## 8. A control, and what it says about reading this run

A dogfood result on a repository that is *supposed* to be sound is worth little
without something to compare it to. A scratch project was created under
`target/tmp/dogfood/control/` — a two-file Rust crate with a `return Ok(());`
no-op, a `tok_visa` literal, a `.status(200)` literal, a `demoData = [...]`
literal, a `lorem ipsum` literal, a `TODO` comment, and a JS click handler that
does nothing — and the same command was run against it:

```powershell
target/debug/sure.exe check 'C:\Users\lishi\code\SURE\target\tmp\dogfood\control' --store-dir 'C:\Users\lishi\AppData\Local\Temp\sure-dogfood-P16-T007\store'
```

Result (`target/tmp/dogfood/control-check.txt`): exit 1, `10 check(s)`, `SURE
checked 0 of 10 checks`, `8 candidate(s) worth acting on, 0 that are style
noise`, and the verdict `Not enough could be checked to say whether this is
ready.` — the same verdict shape as the run against SURE itself, with the
planted patterns located exactly (`TODO` at `src/lib.rs:4`, `tok_visa` at
`:10`, `.status(200)` at `:13`, `return Ok(());` at `:6`, `demoData` at `:16`,
`lorem ipsum` at `:19`, the click handler at `public/app.js:1`).

Two things follow, and both belong in `FINAL_REPORT`:

* **The candidate scanner localises accurately.** Every planted pattern was found
  at the right line. The false positives on SURE's own tree are not the scanner
  failing to find things; they are the scanner finding exactly what it was built
  to find, in a repository that contains the vocabulary of the thing it looks
  for.
* **This build's verdict does not distinguish the two projects.** A repository
  holding SURE's deliberate adversarial fixtures and a scratch crate full of
  planted false-completion patterns both come back "not enough could be
  checked", because no check runs against either. The *difference* between them
  lives entirely in the candidate list. A reader must not take the shared
  verdict as evidence that SURE's repository is either sound or unsound: the run
  establishes neither.

## 9. Reproducing this run

From a checkout of this branch on Windows, with `target/debug/sure.exe` present
(or rebuilt — `cargo build -p sure-cli` writes the same path; this record did not
rebuild):

```powershell
# 1. Scratch store, outside the project. Any absolute path outside the checkout will do.
New-Item -ItemType Directory -Force "$env:TEMP\sure-dogfood\store"

# 2. The check.
target\debug\sure.exe check 'C:\Users\lishi\code\SURE' --store-dir "$env:TEMP\sure-dogfood\store"

# 3. The same, as a frame.
target\debug\sure.exe check 'C:\Users\lishi\code\SURE' --store-dir "$env:TEMP\sure-dogfood\store" --format json

# 4. The repair loop, twice: the first run records, the second compares.
target\debug\sure.exe recheck 'C:\Users\lishi\code\SURE' --store-dir "$env:TEMP\sure-dogfood\store"
target\debug\sure.exe recheck 'C:\Users\lishi\code\SURE' --store-dir "$env:TEMP\sure-dogfood\store"
```

What a reader should expect to match exactly: the **shape** of the answer — exit
1, `checked 0 of N`, every finding `Cannot confirm`, the mode `inspect_only`, the
store location `caller`, and nothing written outside the scratch store.

What will **not** match exactly, and why:

* **The fingerprints.** Every run of the day produced a different one, because
  the tree moved: commit `58ea68c` landed at 11:45:05, `169098d` at 11:42:27,
  and tracked files including `progress/state.json` and `progress/HANDOFF.md`
  were rewritten during the same window by other workers. The fingerprint is
  documented as the working tree relative to `HEAD`, so a commit alone moves it
  (`docs/architecture/FINGERPRINTING.md`). The fingerprints in this record are
  564c7e3b… (`check` at 11:43), 11dd3298… (`recheck` at 11:45), 8b9c0d4c… and
  4b4da886… (two `check`s at 11:46). Three consecutive runs with the tree
  verified byte-identical before and after each produced one fingerprint,
  4b4da886…, so the instrument is stable over a fixed tree; the variation was the
  tree, not the tool. `target/` is outside the fingerprint, measured: writing a
  file under `target/tmp/dogfood/` left the fingerprint unchanged.
* **The line numbers** in the fourteen anchors. They are pinned to
  `crates/**` and `fixtures/**`, which other workers are holding.
* **The candidate count**, if the tree's own source changes: the anchors that
  come from SURE's pattern tables move only when those tables move.

The findings this record judges are the ones from the run whose fingerprint was
`564c7e3bb87ecbca0a5a280d96ffd66b3727939ad41e5f1d9742d559fc0f4d1e`, and the
quoted output is preserved in `target/tmp/dogfood/` as:

| File | What it is |
| --- | --- |
| `check-human.txt` | the run's human report, 18 903 bytes |
| `check-json.json` | the same run as one JSON frame, 23 051 bytes |
| `recheck-human.txt` | the first re-check, 33 339 bytes |
| `recheck2-human.txt` | the second re-check, with the comparison at stage 12 |
| `recheck-first-human.txt`, `recheck-first-json.json` | a first re-check on a virgin store, the evidence for §7.2 |
| `control-check.txt` | the control project's run |
| `inside-empty-check.txt`, `inside-with-store-check.txt`, `inside-recheck.txt` | the three store states of §7.3 |

`target/` is gitignored, so these logs are scratch: what survives is this page.

## 10. Cannot confirm

* **Whether SURE behaves the same under a mode that runs project code.** Every
  run here is `inspect_only`, which is this build's only acting mode. Nothing in
  this record is a measurement of `host_confirmed` or `container`.
* **Whether the intended repair loop closes a finding.** The store holds
  eighteen `Cannot confirm` findings; no check can pass in this build, so
  `recheck`'s stage 12 has only ever had "stayed open" to report. The closing
  path is asserted by tests, not observed here.
* **`sure repair`'s own output.** Not run. Its stage was exercised through
  `recheck` (18 repair contracts, one per finding) but the command itself was not
  invoked, so no claim is made about its rendering.
* **Anything about `--goal`.** No goal was passed. Stage 2's
  `0 statement(s) the project documents about itself` is the no-goal path only.
* **The contents of the scratch store.** The `.db` was never opened; the counts
  quoted from `recheck` are SURE's own report of what it wrote.
* **The exact cause of one pair of fingerprints.** Two runs seconds apart at
  ~11:46 gave `8b9c0d4c…` and `4b4da886…`. The newest tracked-file mtime I
  recorded at 11:46:36 was 11:45:52, so I cannot point at the file that moved
  between them, and I did not reproduce it: three later runs over a
  byte-identical tree gave one fingerprint. The likely explanation — a
  concurrent commit or edit by another worker — is a hypothesis, not a
  measurement, and is recorded as unresolved.
* **The `target/` tree was never enumerated.** It is gitignored and the task's
  own rules forbid walking it. The claim that SURE skipped it rests on the
  documented skip set and on a 3-second run time, not on an instrument.
* **The purity of `sure check` on platforms other than this one.** The
  "creates nothing" reading in §1 is one run on Windows 11 against one
  filesystem.
* **Whether the twelve anchors judged false are considered acceptable by the
  project.** I judge each one; I did not find a written acceptance for the
  detector-matches-its-own-pattern-table case, and
  `crates/sure-core/tests/benign_fixture_e2e.rs` was not read. If a rule exists
  that says these are expected, this page has not found it.
