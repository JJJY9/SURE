# Installing SURE on Windows

Per-user. No administrator, no elevation prompt, no service, no `PATH` edit, no
registry key, and no driver. Everything below is one PowerShell script that
copies files and one that removes them.

```powershell
& .\scripts\Install-Sure.ps1 -Archive <path>\sure-<version>-x86_64-pc-windows-msvc.zip
& .\scripts\Uninstall-Sure.ps1
```

This page is the reference for those two commands. If you are starting from nothing,
`docs/development/QUICKSTART_WINDOWS.md` is the walk: where an archive can and cannot
come from today, the install above, one harness integration, and the first check
afterwards.

## Where it installs

```text
%LOCALAPPDATA%\SURE\
    bin\sure.exe                  what the install writes
    bin\LICENSE
    bin\RELEASE.txt
    bin\THIRD_PARTY_NOTICES.txt
    install-manifest.json         what the install wrote, with each file's SHA-256

    sure.db                       the user's evidence, which the install never writes
```

`%LOCALAPPDATA%\SURE\bin\sure.exe` is not a preference chosen here. Eight
launcher scripts, across five integration packages, already resolve exactly that
path, and a different destination would be a binary those integrations cannot
find. `Grep` over `integrations/` for `LOCALAPPDATA` returns these among its
results, and every other hit is a Markdown file (a README, a command, a prompt or
a skill) or one of the two uninstall scripts (the `.sh` launchers beside them
resolve `$SURE_BIN` and `PATH` instead, which is correct for Unix):

| file | line | what it does |
| --- | --- | --- |
| `integrations/agent-plugin/scripts/install.ps1` | 7 | `Join-Path $env:LOCALAPPDATA 'SURE\bin\sure.exe'`, third in the order `$env:SURE_BIN` → `Get-Command sure` → here |
| `integrations/claude-code/scripts/install.ps1` | 7 | the same candidate |
| `integrations/claude-code/scripts/sure-hook.ps1` | 26 | the same candidate, third in the same order |
| `integrations/claude-code/scripts/sure-mcp.ps1` | 16 | the same path, with `[Environment]::GetFolderPath('LocalApplicationData')` as a fallback when `%LOCALAPPDATA%` is unset |
| `integrations/codex/scripts/sure-hook.ps1` | 26 | the same candidate |
| `integrations/copilot/scripts/sure-hook.ps1` | 26 | the same candidate |
| `integrations/cursor/scripts/install.ps1` | 7 | the same candidate |
| `integrations/cursor/scripts/sure-hook.ps1` | 26 | the same candidate |

Eight rather than three is worth stating because the brief that dispatched this
task named three, and five packages rather than six because the first correction
of that number still did not count them: the search is what is authoritative, it
returns eight files and five directories, and it is what a change to the install
location would have to satisfy.

`crates/sure-cli/tests/install_flow.rs` drives the fourth of them end to end
against a real install.

The known-folder lookup is not hand-rolled. `crates/sure-core/src/paths/mod.rs`
records why: a bare read of `%LOCALAPPDATA%` "would quietly produce a *relative*
path whenever that variable is unset". Both scripts read the variable first and
ask the platform (`[Environment]::GetFolderPath('LocalApplicationData')`) second,
which is the same two steps `sure-mcp.ps1:16` takes, and a test compares the two
scripts' text so that a fix to one is a fix to both.

## The directory is also the data directory

`crates/sure-core/src/paths/mod.rs` puts the user's durable evidence — the
`sure.db` history a verdict is read from — at `<per-user data>\SURE`, which on
Windows is the same directory the program is installed into. So on a machine
where SURE has been used, the two live side by side. This is the fact that
shapes the uninstaller, and it is why nothing here is described as "the install
directory": it is the user's data directory that happens to hold an install.

## The archive

`scripts/Build-Release.ps1` produces it and `docs/development/RELEASE_PROCESS.md`
specifies it: `sure-<version>-x86_64-pc-windows-msvc.zip`, one top-level
directory of the same name holding `sure.exe`, `LICENSE`, `RELEASE.txt` and
`THIRD_PARTY_NOTICES.txt`, with a `<archive>.sha256` beside it in `sha256sum`
format.

The installer **requires** both files. It checks the checksum before it extracts
anything, and there is no switch to skip that check — a check that can be turned
off is not a check. It also refuses a `.sha256` that is missing, empty, has more
than one line, carries a CR, starts with a BOM, or names a different file, and it
refuses an archive whose entries would extract outside the scratch directory.

### Verifying a download

The `.sha256` is an integrity check over the bytes that were shipped: it shows
they arrived unchanged. It is **not** a signature and it does not establish who
built them — see `## Signing` in `RELEASE_PROCESS.md`.

`scripts/Build-Release.ps1 -Phase Verify` does **not** verify a download. It
needs `target/tmp/release-gate.json` in the checkout it is run from, because the
gate path is derived from the script's own location, so a person holding only a
downloaded archive cannot run that phase at all. It also writes `logs\` and
`scratch\` into the directory holding the archive — that is the run's own
evidence and is by design, but it means that directory is not left undisturbed.
Do not use `-Phase Verify` to check a download, and do not describe it as leaving
a directory as it found it.

The installer checks the checksum itself, which is what a person downloading an
archive actually needs.

## The build is unsigned, and how that is known

Authenticode credentials are external to this project and it does not hold one,
so the Windows build carries no Authenticode signature. **That is read from the
binary rather than assumed about it**: `scripts/Build-Release.ps1` asks Windows
its own question — `Get-AuthenticodeSignature` — about the `sure.exe` it is about
to zip, and writes the answer into the archive's `RELEASE.txt` as a `signature`
line. `scripts/Install-Sure.ps1` copies that file to `bin\RELEASE.txt` and
**reports what it says** rather than making a claim of its own, so the line the
installer prints when it finishes is the one the machine that built the archive
measured.

Three answers are possible, and the archive tells you which one it holds:

* `not-signed` — the binary carries no signature and that was read. Windows may
  show a SmartScreen or "unknown publisher" prompt the first time the program
  runs. That is the consequence of the state above, not a fault in the archive or
  in the install, and it is a prompt a person may meet rather than a neutral
  detail.
* `cannot-confirm` — the reading could not be taken. The cmdlet that answers it
  lives in the PowerShell module `Microsoft.PowerShell.Security`, which does not
  load in every host or on every image, so there are machines where the question
  cannot be asked at all. The archive then says the state was **not read** and
  names why, and nothing here claims either way. **A reading that did not happen
  is not an observation that there is no signature**, and this project does not
  report an absence it did not observe.
* `signed` — a signature was read. `scripts/Build-Release.ps1` refuses to package
  in that case, because this document, the installer's output, the release notes
  and `RELEASE_PROCESS.md` all tell a user the binary has none.

`RELEASE_PROCESS.md`'s `## Signing` is where the reason, the boundary and the
phrasings that must not be written are kept. The short form of the boundary:
whether a particular person meets a SmartScreen prompt is **not measurable from
here** — SmartScreen is a Microsoft service driven by download telemetry this
project does not hold — and nothing in this repository promises that SmartScreen
comes to treat this binary any differently over time. `## What is not covered`
below says the same thing about the tests.

## Options

| switch | default | what it does |
| --- | --- | --- |
| `-Archive` | required | the `.zip` to install |
| `-Checksum` | `<archive>.sha256` | the checksum file to check it against |
| `-InstallRoot` | `%LOCALAPPDATA%\SURE` | where to install; must be absolute |
| `-ScratchDirectory` | a fresh directory under `%TEMP%` | where the archive is unpacked |
| `-Force` | off | replace files at the destinations that this install did not write, naming each one before it does |

`-ScratchDirectory` is used with care: a directory the installer created is
removed whole at the end, but one the caller named is only ever touched at its
`unpacked` child. `-ScratchDirectory C:\` is a value a person can type.

Exit codes: `0` installed, `2` stopped — with the reason printed, and nothing
installed or replaced.

## PATH

**The installer writes no `PATH` entry, machine or user.** Neither does the
uninstaller remove one. This is checked rather than claimed: a test reads the
shipped text of both scripts and fails if any line calls
`SetEnvironmentVariable` outside a line that only prints it.

The program is reachable three ways without any `PATH` entry:

1. by its full path, `%LOCALAPPDATA%\SURE\bin\sure.exe`;
2. by `$env:SURE_BIN`, if you set it;
3. by the eight launcher scripts above, which resolve the per-user path directly.

If you want `sure` on `PATH` for your own shells, that is a change to your user
environment and it is yours to make. The installer prints the line and does not
run it:

```powershell
[Environment]::SetEnvironmentVariable(
  'Path',
  ([Environment]::GetEnvironmentVariable('Path', 'User') + ';' + "$env:LOCALAPPDATA\SURE\bin"),
  'User')
```

Open a new shell afterwards. This is per-user, not machine-wide, and needs no
administrator.

### How "documented and tested" is satisfied here

The `PATH` behavior above is not a paragraph standing on its own. What is
measured, in `crates/sure-cli/tests/install_flow.rs`, is:

* `the_claude_code_mcp_launcher_starts_the_installed_binary_with_no_path_entry`
  installs a real archive, then runs `integrations/claude-code/scripts/sure-mcp.ps1`
  with `SURE_BIN` removed and `PATH` set to a directory with nothing in it, and
  requires a successful MCP `initialize` and `tools/list` — then removes the
  installed `bin\sure.exe` and requires the same run to fail, so that the passing
  run cannot have been measuring something else.
* `the_install_flow_never_reaches_for_a_service_an_administrator_or_the_machine`
  reads both scripts' shipped code and fails on `New-Service`,
  `Register-ScheduledTask`, `HKLM:`, `HKEY_LOCAL_MACHINE`, `-Verb RunAs`, a
  `'Machine'` scope, or a `SetEnvironmentVariable` that is not inside a line that
  prints it.

## Uninstalling

```powershell
& .\scripts\Uninstall-Sure.ps1                       # the program; your history is kept
& .\scripts\Uninstall-Sure.ps1 -RemoveUserData       # the history too
& .\scripts\Uninstall-Sure.ps1 -WhatIf               # print the removals, make none
```

### It is structurally incapable of removing your evidence

Removing `%LOCALAPPDATA%\SURE` recursively would delete `sure.db` — the record
SURE exists to keep — while appearing to be tidying up. The uninstaller is built
so that it cannot:

1. **There is no recursive delete in the file.** A directory is removed only when
   it is already empty, so the filesystem refuses when anything the install did
   not write is inside it. The test reads the file and fails if the word
   `-Recurse` appears in it.
2. **A file is removed only when the install's own manifest records it *and* its
   digest still matches what the install wrote.** A file whose bytes changed
   since — a newer binary, something you replaced — is reported and left.
3. **`sure.db` is not in the manifest**, because the install never writes it, so
   the removal in (2) cannot reach it whatever it contains. The only path that
   can remove it is `-RemoveUserData`, which names it and defaults to off.
4. **With no manifest, it removes nothing at all** and exits `2`.

`-RemoveUserData` removes exactly `sure.db`, `sure.db-wal` and `sure.db-shm`, by
name, inside the install root. The names are `sure_core::paths::STORE_FILE` plus
SQLite's two WAL sidecars, and a test compares the list in the script against
that constant, so a rename on either side reddens rather than silently missing.

### When the directory holds files the install never wrote

This is the real case, and the one with no manifest to consult. The uninstaller
lists what it found, says that which files the install created cannot be
established, removes nothing, and exits `2`:

```text
== What this install created
   manifest     none found, so which files the install created cannot be established

   Files under ...\SURE, all of them left alone:
     bin\
     sure.db

   There is a program at ...\SURE\bin\sure.exe and no manifest that says this
   install put it there. It may have come from somewhere else.

   Nothing was removed. Removing files here would mean deleting by guesswork,
   in a directory that also holds the history SURE exists to keep. If the
   program is one you want gone, remove the files named above yourself.
```

`Cannot confirm` is a result, and it is not a yes.

### What it leaves behind

* The settings file `%APPDATA%\SURE\sure.yaml` is outside the install root and is
  never removed. The uninstaller names it and tells you to delete it yourself.
* `%LOCALAPPDATA%\SURE` itself is left in place even when it is empty: it is the
  per-user data directory for this application, and SURE will use it again.
* No `PATH` entry is removed, because none was added.

### `-WhatIf`

`-WhatIf` prints every removal it would make and makes none. The sentences
differ for the three outcomes — `removed`, `would remove … (-WhatIf: nothing was
removed)`, `not removed … (the removal was not confirmed)` — so a dry run cannot
end with "SURE is uninstalled". PowerShell's own "What if:" lines that precede
each one come from `ShouldProcess` and are localized by the system; the
surrounding sentences are this script's.

## What is not covered

Named as limits rather than left to be assumed:

* **The tests install two archives: a staged one, and the build's own.** Most of
  `install_flow.rs` stages the documented layout around the binary cargo just
  compiled, because `Build-Release.ps1` refuses to package without the release
  gate and takes minutes to run a release build. A fixture written beside the
  installer cannot disagree with it, so `P15-T031` added
  `the_installer_installs_the_archive_the_build_produced`: it installs
  `target/tmp/release/sure-*-x86_64-pc-windows-msvc.zip` — or whatever
  `SURE_RELEASE_ARCHIVE` names — and holds the installer's own records against
  the build's. What it reads is the `.sha256` line's format, the archive's single
  top-level directory, the payload names and their bytes, the digest, byte count
  and target the archive's own `RELEASE.txt` states for `sure.exe`, the digests
  and sizes the manifest records,
  and the version, target and running-from the installed program reports. **It is
  `#[ignore]`d, and `release.yml`'s `package-windows` job is what runs it**, by
  name and with `--ignored`, in a step immediately after the
  `Build-Release.ps1 -Phase All` whose output it installs. That label is the
  decision and not an oversight: `ci.yml` packages a Windows archive nowhere, and
  each packaging job in `release.yml` runs `cargo test --workspace` *before* it
  packages, so a default-run test that needs an artifact and reports its absence
  by failing would be a permanent red in two workflows that cannot do anything
  differently — and the six gates would redden on exactly the fresh checkout they
  are run on. Run it by hand with
  `cargo test -p sure-cli --test install_flow -- --ignored`; point
  `SURE_RELEASE_ARCHIVE` at an archive the build produced elsewhere and it reads
  that instead. It costs about 1.5 seconds when the archive is there, and **when
  it is run with no archive present it fails rather than skips:** a checkout that
  has never run `& .\scripts\Build-Release.ps1 -Phase All` gets one red test
  whose message names that command and the variable. Read from
  `.github/workflows/` rather than run: that is why the check is in the
  packaging job and not in `ci.yml`. **What is still not covered:** no test runs
  the packager itself, and the staged archive the other tests use is still not a
  `Build-Release.ps1` artifact.
* **The SmartScreen warning is not exercised.** No test runs an unsigned binary
  through a download-marked file and observes the prompt. The claim is limited
  to: the build carries no Authenticode signature — which
  `scripts/Build-Release.ps1` reads off the binary and the archive's `RELEASE.txt`
  records, see `## The build is unsigned, and how that is known` above — and
  Windows may warn. **What a given machine does with that binary is not
  measurable from here**, and no test asserts it either way.
* **No test asserts what an antivirus or an endpoint agent does** with the
  installed binary.
* **`Get-FileHash` is deliberately not used** by either script, and the reason is
  measured rather than imagined. It is a *script function* from
  `Microsoft.PowerShell.Utility`, so it only exists in a host that brings that
  module up — and the host these tests spawn does not. That host is Windows
  PowerShell 5.1 started from a PowerShell 7 session, which is what a launcher, a
  hook or a build script does, and the child inherits the 7 session's
  `PSModulePath` verbatim, a PowerShell 7 `Modules` directory included:
  `Get-FileHash` answers `ABSENT` there while every other command either script
  uses still resolves as a *cmdlet*. The failure lands on the integrity check and
  reads like a typo. The shadowing step itself was not isolated — a Windows
  PowerShell 5.1 started by hand from a 7 session did bring the function up — so
  the module resolution is written here as the consistent explanation rather than
  as a proven cause. Both scripts use `[System.Security.Cryptography.SHA256]`,
  which is the same algorithm from the same place and depends on no module being
  findable. The measurement, with the child's own output, is in `Get-Sha256`'s
  comment in `scripts/Install-Sure.ps1`.
* **Both hosts are driven, but only the ones this machine has.** The suite runs
  the whole flow under Windows PowerShell, which is always installed, and under
  PowerShell 7 when it can find `pwsh.exe` on `PATH` or at its standard install
  location. A machine without PowerShell 7 only tests the first.
* **`sure --store-dir` is not part of this flow.** The install always lands in
  the per-user location; a store elsewhere is a `sure` option and is documented
  with the CLI.
