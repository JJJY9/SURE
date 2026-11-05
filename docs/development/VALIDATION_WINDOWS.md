# Validating SURE on native Windows

This page is the record of one validation run of the whole Windows flow —
environment, build, install, `doctor`, `check`, and both harness plugins — on a
native Windows 11 x64 machine, followed by the same flow again from a checkout
whose path contains **both spaces and non-ASCII characters**. It is the page
`FINAL_REPORT.md` cites for "native Windows status", and it is written to be
read against the machine it was taken on rather than as a claim about Windows in
general.

Everything below is a command that was actually run and output that was actually
produced. Where a result is a limit rather than a pass, it says so.

## What was and was not validated

| # | What the brief asked for | Status |
| --- | --- | --- |
| `[0]` | Environment → install → doctor → check → Claude/Cursor plugin flow recorded on native Windows 11 x64 | **Validated.** Steps A–G below, exit codes and output quoted. |
| `[1]` | A repository path with spaces and Unicode | **Validated.** Step H: a second clone at a path carrying both, built, gated, packaged, installed, doctored, checked and wired into both plugins from there. |

Three things bound that:

* **The tree moved during the run.** The artifact this record is about names
  commit `eab162e3af51270a5187083003d81511e48da43d`, read out of the archive's
  own `RELEASE.txt` rather than remembered. `P16-T002` landed
  (`69e1d4692c8e72f789d788bd8b5610987908bea0`, `2026-09-21T11:09:45+08:00`) while
  the hostile-path step was still running, so the harness's `HEAD` is now one
  commit past what was built. `eab162e` is an ancestor of it. Nothing in this
  record was re-run against the newer commit.
* **It is one machine, one user, and one working copy.** The user's own
  per-user directories were measured before and after rather than assumed, and
  the numbers are in `## What the run did not touch` below.
* **The plugins were driven, not loaded by an editor.** See
  `## Not validated here`.

## The machine

Measured during step A, not transcribed from a specification:

| | |
| --- | --- |
| OS | Native Windows 11, `10.0.26200.0` (build 26200) |
| PowerShell | 7.6.6 |
| Rust | `rustc 1.98.1 (48a229cea 2026-09-01)`, host `x86_64-pc-windows-msvc` |
| Cargo | `cargo 1.98.1 (797e8a9bc 2026-08-05)` |
| Node | v25.8.1, npm 11.11.0 |
| Git | `2.55.0.windows.3` |
| Long paths | `LongPathsEnabled = 0`; `git config --get core.longpaths` unset (exit 1) |
| Console code page | a console started fresh reports `936`, which is this machine's registry `ACP`/`OEMCP`; `[Console]::InputEncoding` and `[Console]::OutputEncoding` are both `gb2312` there |
| Execution policy | `LocalMachine RemoteSigned`; machine, user and current-user scopes `Undefined` |
| Main repository | `C:\Users\lishi\code\SURE` (24 characters) |
| Second checkout | `C:\Users\lishi\code\SURE\target\tmp\windows-validation\路径 with spaces 校验\sure repo` (82 characters) |

Long paths are the reason the last two rows are here. With `LongPathsEnabled` at
`0` and no `core.longpaths`, `CreateProcess` is capped at `MAX_PATH`, so the
hostile path's depth is a real constraint and not a stylistic one. The deepest
path this run produced under the hostile tree was **221 characters** — inside the
cap, and therefore **not** a test of what happens past it. 5,125 paths were
created under that tree.

## How the run was driven

* Every install target was redirected. `-InstallRoot` pointed at scratch, and
  `$env:CLAUDE_PLUGIN_DIR` and `$env:CURSOR_PLUGIN_DIR` pointed at scratch, so
  neither plugin installer could reach `%APPDATA%\Cursor\`, `%APPDATA%\Code\`,
  `%LOCALAPPDATA%\claude-plugins\` or `%LOCALAPPDATA%\agent-plugins\`.
* `$env:SURE_BIN` was set to the installed binary before any launcher ran. All
  three resolvers — the two hook launchers and both installers — use the order
  `$env:SURE_BIN` → `PATH` → `%LOCALAPPDATA%\SURE\bin\sure.exe`, so setting it is
  what keeps the third candidate out of the picture.
* Every `sure check`, `sure doctor`, `sure history` and `sure repair` was given
  `--store-dir` naming a directory under scratch. No SURE command was run whose
  store could default to the user's real one.
* All scratch lives under `C:\Users\lishi\code\SURE\target\tmp\windows-validation\`,
  which is gitignored, and the hostile step added
  `...\windows-validation\路径 with spaces 校验\`.
* The execution policy was not weakened at any scope: no `Set-ExecutionPolicy`,
  no `-ExecutionPolicy` argument, no environment preference. Scripts were
  invoked as `pwsh -NoProfile -File <path>`. One of those invocations was
  refused, and the refusal is a finding rather than something worked around —
  see `## What the run found`, item 4.
* `pwsh -NoProfile -File scripts/gates.ps1` was not run.
* `sure` was not on `PATH` before the run and is not on it after.

Two things about the driving are worth writing down because they cost time and
would cost a reader the same:

* **`Start-Process -ArgumentList` does not quote.** It joins the elements with
  spaces, so a path containing a space splits into separate arguments. The first
  attempt at step H died with
  `run-hostile.ps1: 找不到接受自变量 'with' 的位置参数。` — PowerShell saying it
  had no parameter to bind `with` to — because the clone path had been split.
  Passing one pre-quoted string, or letting PowerShell itself start the child,
  fixes it. This is a fact about driving Windows tooling and not about SURE.
* **`cmd`-style capture mangles non-ASCII.** SURE writes UTF-8. A capture that
  decodes its output with this machine's console code page (`gb2312`) stores
  mojibake. Measured both ways in the same session: with `& $command 1> $file`
  the file held `路径` intact, and with the command captured into a string the
  string did not contain it. Some logs quoted below therefore show
  `璺緞 with spaces 鏍￠獙` where the path on disk is `路径 with spaces 校验`. That
  is the capture, not SURE, and the same run's JSON read back through a
  redirection that preserves bytes shows the path intact.

## A. Environment (exit 0)

```powershell
Start-Process -FilePath 'pwsh' `
  -ArgumentList '-NoProfile','-File','C:\Users\lishi\code\SURE\scripts\Test-SureEnvironment.ps1' `
  -NoNewWindow -Wait -PassThru `
  -RedirectStandardOutput "$s\logs\A-env.out.txt" -RedirectStandardError "$s\logs\A-env.err.txt"
```

Exit code `0`. The script exits `2` only when `$coreReady` is false, and it
printed `CORE_READY: True`; it has no other exit path.

```text
=== SURE Windows Environment Check ===
[PASS] Windows - Native Windows 10.0.26200.0
[PASS] PowerShell - 7.6.6
[PASS] Git - git version 2.55.0.windows.3
[WARN] Git long paths - Not enabled globally
[PASS] rustup - rustup 1.29.0 (28d1352db 2026-03-05)
[... 4 lines elided ...]
[PASS] rustc - rustc 1.98.1 (48a229cea 2026-09-01)
[PASS] cargo - cargo 1.98.1 (797e8a9bc 2026-08-05)
[PASS] Rust MSVC host - x86_64-pc-windows-msvc
[PASS] Pinned Rust - Rust 1.98.1
[PASS] rustfmt - installed
[PASS] clippy - installed
[PASS] Rust compile/link smoke - Native MSVC executable built
[PASS] Git path/worktree smoke - Passed with spaces + Unicode
[PASS] Node.js - v25.8.1
[PASS] npm - 11.11.0
[PASS] Claude Code - 2.1.276 (Claude Code)
[PASS] Claude doctor - Claude Code doctor |  | Running: npm-global (2.1.276) | Commit: bc0a4292e047 | Platform: win32-x64 | ... [line truncated]
[SKIP] Claude online probe - Use -OnlineClaudeProbe for a real authenticated call
[PASS] GitHub CLI - gh version 2.88.1 (2026-03-12)
[PASS] ripgrep - ripgrep 15.1.0 (rev af60c2de9d)
[WARN] Cursor - not detected
[PASS] Codex CLI - codex-cli 0.155.0
[WARN] Docker - not found; container execution tests will be limited
[PASS] Repository location - C:\Users\lishi\code\SURE
[PASS] Free disk - 422 GB free

CORE_READY: True
FULL_DEV_READY: True
Report: C:\Users\lishi\code\SURE\diagnostics\sure-env-report.md
```

**What this means.** The pinned toolchain is present and a native MSVC
compile/link smoke test built an executable. The `[WARN]` lines are the script's
own warnings about optional tooling, and none of them is a `core` failure.

**What it does not mean.** `[PASS] Git path/worktree smoke - Passed with spaces +
Unicode` is the script's own self-test of a Git worktree at a nasty path; it is
not a statement about the repository *this* run was executed from, whose own path
contains neither. `[WARN] Cursor - not detected` says the Cursor *editor* is not
installed on this machine, so nothing here exercises Cursor's own loading of a
plugin; step G drives the plugin's launcher by hand for exactly that reason.

The script writes `diagnostics\sure-env-report.md` and `.json` inside the working
tree. `.gitignore` line 4 (`/diagnostics/*.md`) covers the Markdown; `git status
--porcelain` was not changed by this step.

## B. Build, package and verify (exit 0)

```powershell
Start-Process -FilePath 'pwsh' `
  -ArgumentList '-NoProfile','-File','C:\Users\lishi\code\SURE\scripts\Build-Release.ps1','-OutputDirectory',"$s\release" `
  -NoNewWindow -PassThru `
  -RedirectStandardOutput "$s\logs\B-build.out.txt" -RedirectStandardError "$s\logs\B-build.err.txt"
```

Started `2026-09-21T03:05:47.1606290Z`, exit `0`, log last written
`2026-09-21T03:06:09.4150539Z`. The release gate was already present at
`target\tmp\release-gate.json`; the packaging build itself was incremental and
cargo reported it:

```text
== Build
   cargo build --workspace --release --locked --target x86_64-pc-windows-msvc
   Compiling sure-testkit v0.0.0-bootstrap (C:\Users\lishi\code\SURE\crates\sure-testkit)
   Compiling sure-core v0.0.0-bootstrap (C:\Users\lishi\code\SURE\crates\sure-core)
   Compiling sure-cli v0.0.0-bootstrap (C:\Users\lishi\code\SURE\crates\sure-cli)
   Finished `release` profile [optimized] target(s) in 19.76s
   exit        0

== Stage
   sure.exe    9483264 bytes
[... 46 lines elided: signature, package, checksum, extract, second signature reading ...]
== Run the extracted binary
   invoked     ...\release\scratch\extracted\sure-0.0.0-bootstrap-x86_64-pc-windows-msvc\sure.exe doctor --format json
   exit        0
   version     0.0.0-bootstrap
   outcome     ok
   os/arch     windows x86_64
   target_env  msvc
[... 6 lines elided ...]
RESULT
  artifact    ...\manual-validation\release\sure-0.0.0-bootstrap-x86_64-pc-windows-msvc.zip
  size        4194987 bytes
  sha256      7410b4f2c9b8cefe9376a51690251ee29c466bbcdda7a13b743b041a2edfea4f
  verified    the archive matches the checksum file, re-read from disk
  signature   not-signed - Get-AuthenticodeSignature reported NotSigned, with no signer certificate and no signature type
  OK          the bytes that are checksummed are the bytes that were run
```

The archive's own `RELEASE.txt`, as installed later by step C, states:

```text
  target        x86_64-pc-windows-msvc
  built from    eab162e3af51270a5187083003d81511e48da43d
  worktree      clean
  built at      2026-09-21T03:06:08.4744543Z
  built with    rustc 1.98.1 (48a229cea 2026-09-01)
  release gate  permitted; 13 of 20 cases release-blocking, 13 observed
  sure.exe      SHA-256 314ac21f96998b6851cc61b7f165808885e2ff79813df28b55201e5fc99338de
                9483264 bytes
  signature     not-signed
```

**What this means.** The packaging script ran the gate, built, staged, asked
Windows about the signature, packaged, wrote a `.sha256`, re-read it, verified,
extracted into a fresh directory, ran the extracted binary from there and
compared the `running_from` it reported against that directory. All of that is
one exit code here, and it was `0`.

**What it does not mean.** `signature not-signed` is a reading of these bytes,
not a statement about SmartScreen. Whether a given machine shows a prompt is not
measurable from here and nothing in this record claims otherwise.

### The packaging step reaches the user's store, by design

`scripts/Build-Release.ps1` lines 1190–1195:

```powershell
    # By absolute path, and `--store-dir` is deliberately not passed: a user
    # runs `sure doctor` against their own store, so that is what is run here.
    # `sure doctor` opens the store read-only and creates nothing.
    $doctorCode = Invoke-Captured -Program $extractedExe -Arguments @(
        'doctor', '--format', 'json'
    ) -OutPath $stdoutPath -ErrPath $stderrPath
```

**That comment's second sentence was true here, and it was verified rather than
taken on trust.** `crates/sure-core/src/paths/mod.rs` holds no environment
variable a caller could set to redirect the store, so the packaging run cannot be
told to keep away from it. Before running the build, `doctor --store-dir` was
pointed at a byte-identical copy of the real store at a scratch path: the copy's
size, mtime and SHA-256 were unchanged afterwards and no `-wal` or `-shm` appeared
beside it. The real store was then measured before and after the build, and is
identical (the numbers are in `## What the run did not touch`). `sure doctor` on
a *named* store that does not exist also created nothing: its frame reported
`"store":{"state":"not_created"}` and `sure history` immediately afterwards
reported `"store_present":false`.

**So:** the packaging step is not store-free, and anyone packaging a release on
their own machine is opening their own history database with it. What was
established is that opening it does not change it — on this machine, for this
command, which is a narrower statement than "it is safe to run anywhere".

## C. Install (exit 0)

```powershell
Start-Process -FilePath 'pwsh' `
  -ArgumentList '-NoProfile','-File','C:\Users\lishi\code\SURE\scripts\Install-Sure.ps1','-Archive',$zip,'-InstallRoot',"$s\installed" `
  -NoNewWindow -Wait -PassThru `
  -RedirectStandardOutput "$s\logs\C-install.out.txt" -RedirectStandardError "$s\logs\C-install.err.txt"
```

Exit `0`. `-InstallRoot` pointed at scratch, so `%LOCALAPPDATA%\SURE\bin\sure.exe`
was never a destination.

```text
== SURE installer (per-user, Windows)
   archive      ...\windows-validation\release\sure-0.0.0-bootstrap-x86_64-pc-windows-msvc.zip
   checksum     ...\sure-0.0.0-bootstrap-x86_64-pc-windows-msvc.zip.sha256
   install to   ...\windows-validation\installed\bin

== Checksum
   sha256       7410b4f2c9b8cefe9376a51690251ee29c466bbcdda7a13b743b041a2edfea4f
   result       the archive is the file this checksum was written for

== Unpack
   unpacking to C:\Users\lishi\AppData\Local\Temp\sure-install-a967cc099dbd460eb1d1aceee70537e3\unpacked
   top-level    sure-0.0.0-bootstrap-x86_64-pc-windows-msvc
   payload      sure.exe (9483264 bytes)
   payload      LICENSE (11358 bytes)
   payload      RELEASE.txt (3210 bytes)
[... 8 lines elided ...]
== Install
   created      ...\windows-validation\installed
   installed    ...\installed\bin\sure.exe (9483264 bytes, sha256 314ac21f96998b6851cc61b7f165808885e2ff79813df28b55201e5fc99338de)
   installed    ...\installed\bin\LICENSE (11358 bytes, sha256 cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30)
   installed    ...\installed\bin\RELEASE.txt (3210 bytes, sha256 7611192fb99633f4893ec195fb3bc2823821c38e4e2dd9724a46ec2b56fb08fc)
   manifest     ...\installed\install-manifest.json
[... 18 lines elided: the PATH paragraph, and the signature/SmartScreen paragraph ...]
== Done
   program      ...\windows-validation\installed\bin\sure.exe
   signature    not-signed, read from the archive's own RELEASE.txt and copied to
                ...\installed\bin\RELEASE.txt
```

**What this means.** The installer checked the digest before unpacking anything,
wrote exactly `bin\sure.exe`, `bin\LICENSE`, `bin\RELEASE.txt` and
`install-manifest.json`, and reported the signature it copied rather than one of
its own. The installed `sure.exe` digest matches the one the archive's
`RELEASE.txt` states, so the bytes that were packaged are the bytes that landed.

**One deviation, stated.** `-ScratchDirectory` was not passed, so the unpack
directory was the installer's own default under
`%TEMP%\sure-install-<32 hex digits>\unpacked` rather than something under
`target\`. That is a directory outside the scratch root this run otherwise kept
to; it is the installer's documented default and the installer removes it, and it
was not redirected because redirecting it would have tested a path a user does
not take.

## D. Doctor (exit 0, twice)

```powershell
Start-Process -FilePath $exe -ArgumentList 'doctor','--store-dir',"$s\store" ...
Start-Process -FilePath $exe -ArgumentList 'doctor','--format','json','--store-dir',"$s\store" ...
```

Both exit `0`. From the human report, the lines that matter here:

```text
Where SURE keeps things on this machine
  evidence and history ...\windows-validation\store
  settings             C:\Users\lishi\AppData\Roaming\SURE
  settings file        C:\Users\lishi\AppData\Roaming\SURE\sure.yaml
  settings location    the platform's own location for this user
  record store         ...\windows-validation\store\sure.db
  store location       named for this run, not the platform's own
  per-user install     C:\Users\lishi\AppData\Local\SURE\bin\sure.exe (nothing there)

What SURE found there
  evidence and history not created yet
  settings             not created yet
  settings file        not created yet
  record store         not created yet, so nothing is recorded
[... 30 lines elided: toolchain, container, providers, integrations, limits ...]
SURE found nothing wrong with its own files.
```

and from the JSON frame:

```json
{"command":"doctor","exit_code":0,"outcome":"ok",
 "details":{"build":{"running_from":"...\\windows-validation\\installed\\bin\\sure.exe",
                     "os":"windows","arch":"x86_64","target_env":"msvc","version":"0.0.0-bootstrap"},
            "places":{"data_dir":{"path":"...\\windows-validation\\store","presence":"absent"},
                      "install_file":{"path":"C:\\Users\\lishi\\AppData\\Local\\SURE\\bin\\sure.exe","presence":"absent"},
                      "config_dir":{"path":"C:\\Users\\lishi\\AppData\\Roaming\\SURE","presence":"absent"},
                      "store_location":"caller"},
            "store":{"state":"not_created"}}}
```

**What this means.** The installed binary, run from where the installer put it,
resolves its own store to the directory it was told to use, reports the
per-user install location as *absent*, and creates nothing. The line
`per-user install ... (nothing there)` is the run's own evidence that the
forbidden location was untouched, taken by SURE rather than asserted by me.

## E. Check, repair and history

```powershell
Start-Process -FilePath $exe -ArgumentList 'check','--store-dir',"$s\store","$s\project" ...
Start-Process -FilePath $exe -ArgumentList '--format','json','check','--store-dir',"$s\store","$s\project" ...
```

Both **exit `1`** — `outcome: not_green` in the JSON frame. The project under
check is a three-file Rust project written into scratch with a `Cargo.toml` and
one test:

```text
SURE checked ...\windows-validation\project.

Not enough could be checked to say whether this is ready.

This project is not ready to hand off.
I can check whether the current project runs and whether anything obviously looks incomplete. I cannot confirm that it matches your original request because that request was not provided to SURE.
SURE can look at the project as it is now. It cannot see what the AI did while it worked. (capability tier 0, snapshot)
Unresolved findings: 1 Must fix, 1 Can fix later.
2 check(s) could not run or were skipped. 1 of them are critical. (run the tests)

Findings
--------
run the tests
  Severity: Must fix
  Status:   Cannot confirm
  What:     SURE planned this check and did not run it, so it has no answer for it. Checking this would have meant running your project's code, and you have not allowed that.
  Impact:   Nothing here is known to be broken, and nothing here is confirmed to work either. Until this check runs and passes, SURE cannot confirm this part of the project.
  Action:   Run `cargo test` and let SURE re-check it, or allow SURE to run it.
  Where to look:
    - command at Cargo.toml (cargo test)
[... 28 lines elided: the second finding, the stage-by-stage list of all 12 stages ...]
SURE exited with status 1. That is what it returns when it checked the project and did not find it clean — not 3, which would mean this build cannot check a project at all.
No check in this run produced a result about the project, so the status above is not a finding: it says SURE could not establish enough to call the project clean.
```

The JSON frame agrees field for field:

```json
{"command":"check","exit_code":1,"outcome":"not_green",
 "details":{"report":{"aggregate":{"headline":"Not enough could be checked to say whether this is ready.",
                                   "is_green":false,"severity":"not_enough_checked"},
                     "totals":{"checked":0,"could_not_run":0,"open_findings":2,"skipped":2},
                     "capability":{"tier":0,"blind_spots":["no_session_visibility","no_pre_action_control"]}},
            "grants":{"execution_mode":"inspect_only","permissions":["inspect"],
                      "settings_file":"C:\\Users\\lishi\\AppData\\Roaming\\SURE\\sure.yaml",
                      "settings_file_read":false},
            "stages":[ ... 12 stages ... ]}}
```

**What this means.** In the default `inspect_only` mode, a project whose only
planned checks are commands to run produces `not_enough_checked` and exit `1`,
with every stage's outcome and reason printed. The report says which stage did
not run and why, and it says that a run with a stage that did not run is never
reported as clean.

**What it does not mean.** Exit `1` here is **not** a failure of the check. It is
what `docs/architecture/CLI.md` says `check` returns for every project it can
read. It is not evidence that the scratch project is broken, and it is not
evidence that SURE works on a real project either — the project checked is three
files written by this run.

`sure check` created nothing. `sure history` immediately after it:

```json
{"command":"history","details":{"removed":false,"sessions":[],
 "store":"...\\windows-validation\\store\\sure.db","store_present":false,"total":0},
 "exit_code":0,"outcome":"ok"}
```

`sure repair` is the command that creates the store:

```powershell
Start-Process -FilePath $exe -ArgumentList 'repair','--store-dir',$st,$proj ...
```

Exit `1`, 7135 bytes on stdout, 0 bytes on stderr, `sure.db` created — measured
twice, into two fresh store directories, with the same result both times.

A relative `--store-dir` is refused rather than resolved:

```text
error: invalid value 'diag-repair-store' for '--store-dir <DIR>': The store directory was given as "diag-repair-store", which is not an absolute path.

A relative path would be resolved against the current directory, so whether it is inside the project would depend on where SURE happened to be started.

SURE stopped rather than check it and report the answer as if it meant something.
```

That refusal took exit `2` and created nothing.

## F. The Claude Code plugin

```powershell
$env:CLAUDE_PLUGIN_DIR = "$s\plugins\claude"
$env:SURE_BIN          = "$s\installed\bin\sure.exe"
Start-Process -FilePath 'pwsh' -ArgumentList '-NoProfile','-File','C:\Users\lishi\code\SURE\integrations\claude-code\scripts\install.ps1' ...
```

Exit `0`:

```text
Installed (copy): C:\Users\lishi\code\SURE\target\tmp\windows-validation\plugins\claude\sure
Package installed at ...\plugins\claude\sure. Loading a plugin is Claude Code's own workflow, not this script's; the commands and the limit are in README.md.
```

`Installed (copy)` is the installer's own word for which branch it took: no
symlink privilege was detected, so it copied the tree. Both `{{SURE_BIN}}` and
`{{PLUGIN_ROOT}}` were substituted — scanning every file of both installed
plugin trees for `{{` finds none — and the installed tree holds `.mcp.json`,
`.claude-plugin\plugin.json`, `hooks\hooks.json`, four commands, the fixtures and
four scripts.

The wired events are the ones `integrations/claude-code/hooks/hooks.json` names:
`SessionStart`, `PreToolUse` (matcher `Bash|Read|Write|Edit`), `PostToolUse`,
`Stop`, each invoking `& "${CLAUDE_PLUGIN_ROOT}\scripts\sure-hook.ps1" <event>`.

The launcher was then driven by hand, with the payload on its stdin:

```powershell
$out = $event | & pwsh -NoProfile -File $hook pre-tool-use --store-dir "$s\store"
```

| what was sent | exit | stdout |
| --- | --- | --- |
| `SessionStart`, with `project_root` | `0` | `SURE allows this tool request.` |
| `PreToolUse`, the shipped fixture's shape (no `project_root`) | `1` | block, plus the "could not record" paragraph |
| `PreToolUse`, with `project_root` | `1` | block only |
| `PreToolUse` straight into the binary, `--format json` | `1` | the JSON frame below |

```json
{"command":"hook","decision":"block","exit_code":1,"outcome":"not_green","protocol_version":1,
 "reason":"The current execution mode does not permit this action.",
 "sure_version":"0.0.0-bootstrap"}
```

**What this means.** The block is SURE's, and it is reported on stdout in both
renderings: prose for the human reading a hook log, a JSON frame for the harness.
The exit code is `1`, which is the code this project documents for a block.

**What it does not mean.** `exit 1` is **not** what stops a tool call in Claude
Code. `docs/integrations/HOOK_FAILURE_SEMANTICS.md` §1.1 records that Claude Code
treats a non-zero hook exit without valid JSON on stdout as non-blocking, so on
this harness the block is a decision SURE reports and not, by itself, a
prevention. That is a documented property of the integration and this run
confirms the behaviour on the SURE side only — it did not observe an editor's
reaction, because no editor was driving these hooks.

### The store rows

After step F and step G, read with `sqlite3 -readonly` against the flow's own
store:

| table | rows |
| --- | --- |
| `records` | 12 — `check-result` 2, `decision` 3, `event` 5, `finding` 2 |
| `sessions` | 2 |
| `session_events` | 5 — `session.started` 2, `tool.requested` 3 |

`sure history` reports the same thing through its own interface:

```json
{"command":"history","details":{"sessions":[{"harness":"claude-code",
 "harness_session_id":"p16t001-claude-session",
 "project_root":"...\\windows-validation\\project","row_id":1,
 "sure_session_id":"ses_89pf5ykd2s7h6744j6r0","started_at":"2026-09-21T03:09:00Z"}],
 "store_present":true,"total":1},"exit_code":0}
```

**What this means.** An event that arrives through the shipped launcher is
recorded, and `sure history` and `sure history show` can read it back, with the
session's harness, project root and start time intact.

**What it does not mean.** One of the three decisions in this store is a
`decision` row that could not be written, and the paragraph SURE prints when that
happens is quoted below; the count above is what landed, not what was attempted.

## G. The Cursor plugin

```powershell
$env:CURSOR_PLUGIN_DIR = "$s\plugins\cursor"
Start-Process -FilePath 'pwsh' -ArgumentList '-NoProfile','-File','C:\Users\lishi\code\SURE\integrations\cursor\scripts\install.ps1' ...
```

Exit `0`:

```text
Installed (copy): ...\windows-validation\plugins\cursor\sure
MCP: mcp.json starts 'sure' from PATH; this SURE is at ...\installed\bin\sure.exe. Add that directory to PATH, or set the server's command in ...\plugins\cursor\sure\mcp.json to that path.
```

The wired events are `sessionStart`, `preToolUse` (matcher
`Shell|Read|Write|Delete`), `postToolUse`, `postToolUseFailure`, `afterFileEdit`
and `stop`. The installer's `MCP:` line is correct and is worth keeping: the
Cursor package's `mcp.json` starts `sure` from `PATH`, and `sure` is not on
`PATH` on this machine, so the MCP server of that package would not start here
without the edit the installer names. The hooks do not depend on `PATH`, because
their launcher resolves `$env:SURE_BIN` first.

| what was sent | exit | stdout |
| --- | --- | --- |
| `sessionStart`, with `project_root` | `0` | `{"command":"hook","decision":"allow","exit_code":0,"outcome":"ok",...}` |
| `preToolUse`, the shipped fixture's shape | `1` | `"decision":"block"` plus the "could not record" paragraph |
| `preToolUse`, with `project_root` | `1` | `"decision":"block"` only |

The Cursor launcher passes `--format json` itself
(`& $bin --format json hook ingest --source cursor @args`), which is why both
rows here are frames where the Claude Code rows were prose.

## H. The same flow from a path with spaces and non-ASCII

```powershell
$clone  = 'C:\Users\lishi\code\SURE\target\tmp\windows-validation\路径 with spaces 校验\sure repo'
$hs     = 'C:\Users\lishi\code\SURE\target\tmp\windows-validation\路径 with spaces 校验\scratch'
git clone --local --quiet 'C:\Users\lishi\code\SURE' "$clone"
```

Exit `0`, in under a second, `HEAD` at `eab162e3af51270a5187083003d81511e48da43d`,
working tree clean, no `target` directory of its own, path length 82. The whole
flow was then run from there, with `CARGO_TARGET_DIR` set to a `target`
**inside the clone** so that nothing this step produced landed outside the hostile
tree, and with the store, the install root and both plugin roots under
`$hs`.

| step | command | exit |
| --- | --- | --- |
| H1 gate | `cargo test -p sure-core --test acceptance_report_runner --manifest-path <clone>\Cargo.toml` | `0` |
| H2 build | `pwsh -NoProfile -File <clone>\scripts\Build-Release.ps1 -OutputDirectory $hs\release` | `0` |
| H3 install | `pwsh -NoProfile -File <clone>\scripts\Install-Sure.ps1 -Archive <zip> -InstallRoot $hs\installed` | `0` |
| H4 environment | `pwsh -NoProfile -File <clone>\scripts\Test-SureEnvironment.ps1` | `0` |
| H5 doctor | `sure --store-dir $hs\store doctor --format json` | `0` |
| H6 check | `sure --store-dir $hs\store --format json check <clone>` | `1` |
| H7 Claude Code | `install.ps1` / `sure-hook.ps1 session-start` / `sure-hook.ps1 pre-tool-use` / `sure history` | `0` / `0` / `1` / `0` |
| H8 Cursor | `install.ps1` / `sure-hook.ps1 session-start` / `sure-hook.ps1 pre-tool-use` | `0` / `0` / `1` |

Wall clock, from the timestamps each step wrote:

| from | to | what |
| --- | --- | --- |
| `03:11:36.6431191Z` | `03:12:13.0238412Z` | gate: cold `cargo test` build (`Finished `test` profile ... in 34.55s`) and 13 tests in 1.25s |
| `03:12:13.0238412Z` | `03:13:04.5069239Z` | packaging: cold `cargo build --release --locked` for the whole workspace, plus stage, zip, checksum, extract and run |
| `03:13:04.5069239Z` | `03:13:06.1113913Z` | install |
| `03:13:06Z` | `03:14:01.9544892Z` | H4–H8: environment check, doctor, check, both plugin installs, both hook flows |

**Every step passed at the hostile path.** About 90 seconds of wall clock covered
a cold gate build, a cold release build of the whole workspace, packaging and the
install; the flow after that took another 56 seconds. The cold-build budget this
task set was roughly 25 minutes and it was not approached, so nothing had to be
stopped and no part of H was left unmeasured for time.

The gate output, from the clone:

```text
running 13 tests
test an_escalation_does_not_read_met ... ok
test no_observed_row_copies_the_requirement_it_is_graded_against ... ok
[... 9 lines elided ...]
test two_runs_are_byte_identical ... ok
test no_machine_path_appears_in_the_document ... ok
test the_report_matches_the_schema_it_ships_with ... ok
test the_cannot_confirm_rows_are_the_named_ones_with_their_reasons ... ok

test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.25s
```

and the archive the clone built and installed:

```text
== Release gate
   decision    permitted
   gate file   ...\路径 with spaces 校验\sure repo\target\tmp\release-gate.json
== Package
   archive     ...\路径 with spaces 校验\scratch\release\sure-0.0.0-bootstrap-x86_64-pc-windows-msvc.zip
   sha256      b3f41c19a8d4d3f911540137089ff2c972fb5ebd11d86994a942359ad9805b16
== Install
   installed   ...\路径 with spaces 校验\scratch\installed\bin\sure.exe (9483264 bytes, sha256 6bdc574acdd2aed9d7817756f79c3bb0b66870a0ff5213f49964bd3be07c4641)
```

The environment check from the hostile clone reports the repository it is
standing in, and its own path smoke test with both hazards:

```text
[PASS] Git path/worktree smoke - Passed with spaces + Unicode
[... 6 lines elided ...]
[PASS] Repository location - C:\Users\lishi\code\SURE\target\tmp\windows-validation\路径 with spaces 校验\sure repo
[PASS] Free disk - 420.6 GB free

CORE_READY: True
FULL_DEV_READY: True
```

`sure check` against the clone itself — the whole SURE repository, 5,125 paths
under a tree whose name has a space and a non-ASCII character in it:

```json
{"command":"check","exit_code":1,"outcome":"not_green",
 "details":{"project":"C:/Users/lishi/code/SURE/target/tmp/windows-validation/\u8def\u5f84 with spaces \u6821\u9a8c/sure repo",
            "report":{"aggregate":{"headline":"Not enough could be checked to say whether this is ready."},
                      "totals":{"checked":0,"could_not_run":14,"open_findings":18,"skipped":4},
                      "project_fingerprint":"fp_2qv46bzyfe1vsee55v17"},
            "support":{"letter":"C","level":"inspect_only"}}}
```

Note the shape of that string: the project is reported with forward slashes and
the non-ASCII is intact **in the file this was read from**. The mojibake seen in
parts of this record is the capture, described in `## How the run was driven`.

**What this means.** Nothing in the flow above — gate, packaging, install,
doctor, check, both plugin installers, both hook launchers — failed because of
the path. A checkout at a path with a space and a non-ASCII character in it can be
built, packaged, installed and wired up on this machine, and SURE's own store
keys the project by the path it was given.

**What it does not mean.** This is not a test of long paths: at 221 characters
the deepest path here is inside `MAX_PATH`. See
`## What the run found`, item 5, for what the two builds' binaries do and do not
share.

## What the run found

Findings 1 and 5 are properties of the tree as it stands. Finding 4 is a property
of this machine. Findings 2 and 5 are the two a user would actually meet. **None
of them was repaired**: this task owns one file, and a validation run that
silently fixes what it finds is not a validation run.

### 1. The packaging script opens the user's own store

`scripts/Build-Release.ps1` runs the extracted binary as
`doctor --format json` with no `--store-dir`, deliberately, for the reason its
comment gives. There is no environment variable that could redirect it —
`crates/sure-core/src/paths/mod.rs` says the store location is the platform's own
and that there is "deliberately no environment variable either". So a release
build opens the packager's own history database. It was measured not to change
it (see `## B`), and that is the whole of what is established; the boundary is
stated here because "running the release build" and "not touching the user's
data" are not the same statement.

### 2. The Windows hook launchers decode their input with the console code page

`integrations/claude-code/scripts/sure-hook.ps1` lines 8–9:

```powershell
$inputJson=($input -join "`n")
if([string]::IsNullOrWhiteSpace($inputJson)){$inputJson=[Console]::In.ReadToEnd()}
```

A probe that reads its stdin the same way, with a byte-for-byte copy of a hook
payload redirected into it as stdin, stored this:

```text
{"event":"SessionStart",...,"project_root":"C:/Users/lishi/code/SURE/target/tmp/windows-validation/璺緞 with spaces 鏍￠獙/sure repo","source":"claude-code"}
--read via: pipeline $input
--[Console]::InputEncoding: gb2312
--[Console]::OutputEncoding: gb2312
```

The payload on disk, read as bytes, holds
`"project_root":"...windows-validation/路径 with spaces 校验/sure repo"`. The
bytes are UTF-8 and the process decoded them as `gb2312`, because that is what
`[Console]::InputEncoding` is on this machine. `$OutputEncoding` is set to UTF-8
further down the same file, which protects what is written *to* SURE and does not
protect what is read *from* the harness.

The consequence, isolated by an A/B on the same payload bytes:

| through the installed launcher | rows written |
| --- | --- |
| `project_root` with non-ASCII | **0 sessions, 0 events** |
| the same payload with an ASCII `project_root` | 1 session, 1 event |

and the same payload sent straight into the binary, with no launcher in between,
records the right path — read back out of the store as
`...windows-validation/路径 with spaces 校验/sure repo`. The binary is not the
problem; the launcher's stdin decode is.

The Cursor launcher (`integrations/cursor/scripts/sure-hook.ps1`) is the same
code with a different `--source`, so the same applies to it, and the `.sh`
launchers beside them read from a pipe whose encoding is not this one.

### 3. An event whose project root does not resolve is dropped without a word

Two ways to reach it, both measured, both silent:

* the path is corrupt, as in finding 2;
* the path is a real-looking ASCII path that is not there — a `project_root` of
  `C:/Users/lishi/code/SURE/target/tmp/windows-validation/no-such-project-here`
  through the launcher gave exit `0`, `SURE allows this tool request.` on stdout,
  **0 bytes on stderr, and no store row at all**.

And one way that is documented rather than silent-in-principle: when the payload
carries no `project_root` (the shape of both shipped fixtures), the project
defaults to the process's working directory, and if the named store sits inside
that tree the store is refused — `Paths::ensure_outside` — so nothing is
recorded. Measured with one payload and one store, changing only the working
directory:

| working directory | store relative to the project root | rows |
| --- | --- | --- |
| `C:\Users\lishi\code\SURE` | inside it | 0 sessions |
| `C:\Users\lishi\code\SURE` | inside it (*the same case: everything under `target\` is inside the repository*) | 0 sessions |
| `...\windows-validation\project` | outside it | 1 session |
| `...\路径 with spaces 校验\sure repo` | outside it | 1 session |

The **decision** path is not silent — it prints
`SURE could not record this decision in the local history: the event it belongs
to was not stored, and a decision with nothing to hang from would be outside
``sure history`` and outside ``sure history delete``. The decision above stands.`
— and that paragraph is where this run's first sight of the behaviour came from.
The **event-only** path, which is what `SessionStart` is, prints nothing on either
stream and exits `0`. So a harness that wires only `SessionStart` and whose
payload has no `project_root` records nothing and says nothing, and `sure history`
answers `"store_present":true,"total":0` — a store that exists and is empty looks
exactly like one where nothing has happened yet.

### 4. One of the repository's own scripts carries mark-of-the-web

`scripts\Test-SureEnvironment.ps1` has a `Zone.Identifier` alternate data stream
with `ZoneId=3`; `scripts\Build-Release.ps1`, `scripts\Install-Sure.ps1` and
`integrations\claude-code\scripts\install.ps1` have no alternate data streams at
all. With `LocalMachine = RemoteSigned` and the `Process` scope unset, that file
is refused from any shell whose process-scope policy is not `Bypass`:

```text
SecurityError: 无法加载文件 C:\Users\lishi\code\SURE\scripts\Test-SureEnvironment.ps1。
文件 C:\Users\lishi\code\SURE\scripts\Test-SureEnvironment.ps1 未进行数字签名。无法在当前系统上运行此脚本。
有关运行脚本和设置执行策略的详细信息，请参阅 https://go.microsoft.com/fwlink/?LinkID=135170
处的 about_Execution_Policies。
```

Exit `1`. The message is RemoteSigned's *unsigned-file* one and not Restricted's
"running scripts is disabled on this system" — the two are different policies and
quoting the wrong one would describe a machine this is not. The message links
`about_Execution_Policies`.

This is the one command in this record that was refused, and the refusal is
recorded rather than worked around: weakening the policy at any scope was
explicitly out of bounds for this task, and it would have been the wrong fix in
any case — the file is unsigned, and the difference between it and its
neighbours is the zone stamp, not the code. The same script from the step-H clone
runs and exits `0`, because `git clone` does not copy alternate data streams.
Step A's run succeeded because the session that started it carried
`PSExecutionPolicyPreference=Bypass`: that variable is **inherited**, and a child
`pwsh` takes it as its own `Process` scope, so the child ran the file — while the
same child given `-ExecutionPolicy RemoteSigned` refuses it. The scope belongs to
the environment a shell was started in and not to the machine, which is why one
command answers differently in two sessions on one computer. **A new clone is not
affected; the working copy on this machine is.**

### 5. The two archives do not carry the same `sure.exe`

Built from the same commit on the same machine, at two paths:

| | main tree | hostile path |
| --- | --- | --- |
| archive `sha256` | `7410b4f2c9b8cefe9376a51690251ee29c466bbcdda7a13b743b041a2edfea4f` | `b3f41c19a8d4d3f911540137089ff2c972fb5ebd11d86994a942359ad9805b16` |
| archive size | 4,194,987 bytes | 4,195,044 bytes |
| `sure.exe` size | 9,483,264 bytes | 9,483,264 bytes |
| `sure.exe` `sha256` | `314ac21f96998b6851cc61b7f165808885e2ff79813df28b55201e5fc99338de` | `6bdc574acdd2aed9d7817756f79c3bb0b66870a0ff5213f49964bd3be07c4641` |

The two binaries differ in **24 bytes out of 9,483,264**, and both carry the
CodeView `RSDS` signature at the same offset — `8340580` — with the 16-byte run
that differs sitting immediately after it, which is where the linker's per-build
debug identifier lives. The remaining eight differing bytes are in five other
places, two of them in the PE header. Neither binary contains the string
`windows-validation`, so no build-directory path is embedded in either.

The archive's own `RELEASE.txt` says the ZIP is not byte-for-byte reproducible
because a ZIP records a timestamp per entry. That explains the archive digests;
it does not by itself explain the binary, and the binary is as far as this run
took it. **What this does not mean:** it is not evidence of a defect, and it is
not evidence against one either. The `.sha256` beside each archive is an
integrity check over the bytes that were shipped, which is what it was used for
here, and it was verified in both builds.

## What the run did not touch

The user's own per-user directories, measured **before** the run started and
**after** every step in this record finished:

| | before | after |
| --- | --- | --- |
| `%LOCALAPPDATA%\SURE\sure.db` size | 348160 | **348160** |
| `%LOCALAPPDATA%\SURE\sure.db` mtime (UTC) | `2026-09-18T15:12:15.0354647Z` | **`2026-09-18T15:12:15.0354647Z`** |
| `%LOCALAPPDATA%\SURE\sure.db` SHA-256 | `d171755690549d3a59f1949e85c124b1f06b5cc7f84b8e395f176a8031d67853` | **`d171755690549d3a59f1949e85c124b1f06b5cc7f84b8e395f176a8031d67853`** |
| `%LOCALAPPDATA%\SURE\` contents | `sure.db` | `sure.db` |
| `%LOCALAPPDATA%\SURE\bin\` | absent | **absent** |
| `%APPDATA%\SURE\` | absent | **absent** |

The store's size, mtime and digest are unchanged, so nothing in this run wrote to
it. `%LOCALAPPDATA%\SURE\bin\` did not exist before the run and does not exist
after it; nothing installed a binary there. `sure` is not on `PATH` and was not
put there.

The one command that is *designed* to reach that store is the `doctor` invocation
inside `Build-Release.ps1` — finding 1 — and the digests above are the reading
that it did not change it.

## Not validated here

Named as limits rather than left to be assumed:

* **macOS and Linux.** Nothing in this record was taken anywhere but native
  Windows 11 x64. `scripts/Test-SureEnvironment.ps1` is a Windows script, both
  installers are Windows installers, and the hostile-path step re-ran the
  Windows flow. No portability claim follows from any of it.
* **A real editor loading a plugin.** No Claude Code process and no Cursor
  process loaded either plugin. `[WARN] Cursor - not detected` in step A is the
  same fact from the environment check. The hooks were driven by hand with the
  shipped launcher scripts and payloads of the shape the repository's own tests
  use; what an editor does with SURE's exit codes and stdout was not observed,
  and `docs/integrations/HOOK_FAILURE_SEMANTICS.md` is the source for how Claude
  Code treats them.
* **`MCP`.** Neither `.mcp.json` nor `mcp.json` was started. The Cursor
  installer's `MCP:` line (step G) names what would have to change for its
  server to start on this machine, and that line is as far as this run went.
* **Windows past `MAX_PATH`.** `LongPathsEnabled` is `0` and `core.longpaths` is
  unset, and the deepest path this run created was 221 characters. Nothing here
  says what happens at 261.
* **The six repository gates and `scripts/gates.ps1`.** Deliberately not run.
* **CI, and `release.yml`.** Read, not run. Nothing here is a statement about
  GitHub Actions or about the `package-windows` job.
* **SmartScreen, antivirus, and code signing.** `not-signed` is a reading of the
  bytes taken by `Get-AuthenticodeSignature`; whether a machine warns is not
  measurable from here and was not measured.
* **Elevation, services, scheduled tasks, machine-wide state.** None used, so
  none exercised.
* **The other three integration packages** — `agent-plugin`, `codex`, `copilot` —
  were not installed or driven. `INSTALL_WINDOWS.md` counts the launcher scripts
  that resolve the per-user install path; this run drove two of them.
* **A second `sure` on `PATH`.** The three-way resolver order was exercised in
  its first branch (`$env:SURE_BIN`) only; no run had a `sure` on `PATH` and none
  had a binary at the per-user install location.
* **`-Phase Verify` of `Build-Release.ps1`.** The packaging run was `-Phase All`,
  which covers the verify steps internally; the separate `-Phase Verify` entry
  point on a downloaded archive was not run.

## Where the evidence is

Everything this record quotes is under
`C:\Users\lishi\code\SURE\target\tmp\windows-validation\` — gitignored, and not
part of the commit that adds this page. The main tree's logs are in `logs\`, and
the hostile step's are in `路径 with spaces 校验\scratch\logs\`, with one file per
command: `<step>.out.txt`, `<step>.err.txt` and, where exit codes were written to
disk, `<step>.exit.txt`. The two drives of the hostile step are
`run-hostile.ps1` and `run-hostile2.ps1` in the same directory.

`docs/development/WINDOWS.md` is the page that lists what the six gates and the
Windows test targets cover; this page is the record of the flow those gates
describe, run once, by hand, on the machine above.
