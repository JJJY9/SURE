# Installing SURE with WinGet

**This package is not published.** `packaging/winget/template/` holds a template
for a WinGet manifest and `scripts/New-WingetManifest.ps1` renders it from a
release archive; the manifest it renders names a GitHub release asset that does
not exist yet. No package has been submitted to `microsoft/winget-pkgs`, no
review has been opened, and **`winget install` does not install SURE today**.
Publication is external and optional — that is this task's acceptance, and
`## What is not covered` at the end says what that leaves unmeasured.

What the template does have to be is *true*: every value it carries is one the
renderer derives from real bytes, and a value it cannot derive is a refusal
rather than a guess. That is what the rest of this document is about.

If you want SURE on a Windows machine now, `docs/development/INSTALL_WINDOWS.md`
is the flow that exists: a per-user install with no administrator, no service and
no `PATH` edit.

## What the template is

Three files, because a WinGet manifest is three files:

| file | `ManifestType` | what it carries |
| --- | --- | --- |
| `packaging/winget/template/lichman0405.SURE.yaml` | `version` | the identifier, the version, the default locale |
| `packaging/winget/template/lichman0405.SURE.installer.yaml` | `installer` | what to download, what it contains, and its SHA-256 |
| `packaging/winget/template/lichman0405.SURE.locale.en-US.yaml` | `defaultLocale` | who publishes it, under what license, and what it does |

Each opens with a `# yaml-language-server: $schema=https://aka.ms/winget-manifest.<type>.<version>.schema.json`
comment so an editor can validate it while it is being read, and then a block of
notes fenced by two lines:

```text
# >>> template notes: removed when this file is rendered
...
# <<< end of template notes
```

Everything between those lines is written for a reader of *this repository* and
is removed before the manifest is published: a published manifest must not open
with "THIS IS A TEMPLATE", and a note saying "no digest is written down here"
must not ship next to a digest. The renderer requires both lines exactly once
each, so a template that lost its fence is refused rather than rendered with its
notes still in it.

The two placeholders the templates are allowed to carry are `<version>` and
`<sha256-of-the-archive>`, and they are the only two strings the renderer
substitutes. Anything else in angle brackets that survives rendering is a
refusal, because a manifest published with a placeholder in a field is worse than
one that was never written.

## What the package installs

```yaml
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
  - RelativeFilePath: sure-<version>-x86_64-pc-windows-msvc/sure.exe
    PortableCommandAlias: sure
```

The release archive is a ZIP holding one top-level directory with `sure.exe`,
`LICENSE`, `RELEASE.txt` and `THIRD_PARTY_NOTICES.txt` in it
(`docs/development/RELEASE_PROCESS.md:20-26`).
WinGet extracts that archive and puts the one executable where it wants it, so
the manifest describes *what is in the archive* rather than running
`scripts/Install-Sure.ps1`.

That choice is the reason an uninstall is exact. `Install-Sure.ps1` writes a
`bin\` directory holding `sure.exe`, `LICENSE`, `RELEASE.txt` and
`THIRD_PARTY_NOTICES.txt`, and writes an
`install-manifest.json` beside it — all inside `%LOCALAPPDATA%\SURE`, a directory
that also holds `sure.db`, the user's evidence. A package whose install ran that
script would own files WinGet has no record of, and WinGet's uninstall would
either miss them or remove a directory it should not have touched. A `portable`
package owns one directory and one link.

WinGet installs it **per user, under `%LOCALAPPDATA%`**, and needs no
administrator. That is not a setting in the manifest: `portable` is a per-user
installer type, and the `Scope` key is deliberately absent. Measured, by adding
`Scope: user` to the rendered installer manifest and running `winget validate`
over it:

```text
Manifest validation succeeded with warnings.
Manifest Warning: Scope is not supported for InstallerType portable.
```

It exits `-1978335192`, and in this repository a warning is not a pass.

### Where the files land

```text
%LOCALAPPDATA%\Microsoft\WinGet\Packages\lichman0405.SURE_Microsoft.Winget.Source_8wekyb3d8bbwe\
    sure-<version>-x86_64-pc-windows-msvc\
        sure.exe
        LICENSE
        RELEASE.txt

%LOCALAPPDATA%\Microsoft\WinGet\Links\
    sure.exe          -> the sure.exe above
```

`Links` is on the user `PATH`, and that is what makes the alias `sure` work. On
this machine it exists, it holds 18 entries and every one of them is a link into
a `Packages` directory:

```text
real WinGet Links directory: C:\Users\lishi\AppData\Local\Microsoft\WinGet\Links
exists: True
on the user PATH: True
entries in it: 18
of which links: 18
   bat.exe     -> ...\Packages\sharkdp.bat_Microsoft.Winget.Source_8wekyb3d8bbwe\bat-v0.26.1-x86_64-pc-windows-msvc\bat.exe
   delta.exe   -> ...\Packages\dandavison.delta_Microsoft.Winget.Source_8wekyb3d8bbwe\delta-0.19.1-x86_64-pc-windows-msvc\delta.exe
   eza.exe     -> ...\Packages\eza-community.eza_Microsoft.Winget.Source_8wekyb3d8bbwe\eza.exe
   fd.exe      -> ...\Packages\sharkdp.fd_Microsoft.Winget.Source_8wekyb3d8bbwe\fd-v10.4.2-x86_64-pc-windows-msvc\fd.exe
   ffmpeg.exe  -> ...\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-8.1.1-full_build\bin\ffmpeg.exe
```

**This is measured, not assumed.** `winget install` changes the machine and
nothing in this repository runs it, so what is measured here is the *launcher*
half, with a WinGet-shaped install planted by hand — a `Links\sure.exe` on `PATH`
and no `%LOCALAPPDATA%\SURE\bin\sure.exe`:

```text
=== The three steps, with a winget-shaped install planted and nothing else
step 1  $env:SURE_BIN                        -> ''
step 2  Get-Command sure                     -> '...\launcher-step\Links\sure.exe'
step 3  $env:LOCALAPPDATA\SURE\bin\sure.exe  -> 'False'

=== The launcher itself, through that PATH, answering an MCP handshake
launcher status: 0
answers both requests: True

=== The falsifier: the same run with the link removed
launcher status: 3
SURE MCP server cannot start: no SURE binary was found. It looked for the environment
variable SURE_BIN, then for `sure` on PATH, then at %LOCALAPPDATA%\SURE\bin\sure.exe.
```

The claim about WinGet's own layout — the `Packages\<id>_<source>_<hash>` and
`Links` shape above — is read from the observed `Packages` and `Links`
directories on this machine, and from WinGet's own source
(`PortableInstaller.cpp`, `Workflows/PortableFlow.cpp`), not from running an
install.

## Which of the launchers' three steps finds this install

Eight launcher scripts across five integration packages resolve `sure.exe` in
this order (`docs/development/INSTALL_WINDOWS.md` lists them by file and line):

1. `$env:SURE_BIN`, if it is set to a path that exists;
2. `Get-Command sure` — that is, `sure` on `PATH`;
3. `%LOCALAPPDATA%\SURE\bin\sure.exe`, the per-user install.

**A WinGet install is found by step 2.** Step 1 is unset unless the user set it.
Step 3 stays empty: this package does not write `%LOCALAPPDATA%\SURE\bin`, and a
machine that has never run `Install-Sure.ps1` has no `bin\` there at all. What
answers is the `sure.exe` link WinGet put in `Links`, which is on `PATH`.

That is the whole reason the experiment above is worth its space: the three steps
are not interchangeable, and "the launchers will find it" is only true because
`Links` is on `PATH`. On a machine where `Links` was removed from `PATH` — or in
a process that inherited a `PATH` without it, which is what a service or an
editor started before WinGet ran would have — the launchers would find nothing
and would say so rather than fall back to something else.

`crates/sure-cli/tests/winget_manifest.rs::the_second_resolution_step_is_the_one_a_winget_install_fills`
is that experiment, with the falsifier in the same test. It drives one of the
eight — `integrations/claude-code/scripts/sure-mcp.ps1`, the same one
`install_flow.rs` drives for step 3. That the other six resolve the same
candidates in the same order is read from their text, which
`docs/development/INSTALL_WINDOWS.md` lists by file and line, rather than
measured by starting each of them; that document already records the same split
for the install path.

## Every value, and what checks it

`scripts/New-WingetManifest.ps1` renders the three files from one archive and
then **re-derives every value from the archive again** and compares. Nothing in a
rendered manifest is carried over from the template on trust.

| value | where it comes from | what checks it |
| --- | --- | --- |
| `PackageIdentifier: lichman0405.SURE` | the template, and `Cargo.toml`'s `repository` owner | `Cargo.toml:16` is `repository = "https://github.com/lichman0405/SURE"`; the renderer refuses unless the identifier's prefix is that URL's owner, so a fork fails here rather than publishing under someone else's name |
| `PackageVersion` | the version in the archive's file name | the renderer runs the `sure.exe` **inside the extracted archive** as `sure version --format json` and requires `sure_version` to be the same string, naming both when they differ |
| `InstallerUrl` | the archive's file name and the repository URL | rebuilt as `<repository>/releases/download/v<version>/<archive name>` and compared with what was written; **this is the one value no check can confirm exists**, because no release does |
| `InstallerSha256` | the archive's bytes | the `.sha256` beside it is parsed as one `sha256sum` line (ASCII, no BOM, no CR, one trailing LF, naming the same file) and the digest is recomputed from the bytes and must equal it. `crates/sure-cli/tests/winget_manifest.rs` checks the result again with `certutil -hashfile … SHA256`, a different implementation, so two copies of one bug cannot agree |
| `InstallerType: zip` | `RELEASE_PROCESS.md:20-26` | the renderer extracts the archive and refuses a layout that is not one top-level directory holding `sure.exe`; the extraction path is refused at `MAX_PATH`, where `CreateProcess` fails with a message that does not mention length |
| `NestedInstallerType: portable` | the binary is self-contained: no installer, no service | `docs/development/INSTALL_WINDOWS.md` — nothing in this repository registers a service, a scheduled task or a machine-wide key |
| `RelativeFilePath` | the archive's own top-level directory, listed rather than built from the name | the renderer lists what the ZIP extracted to, refuses anything but exactly one directory, and requires `sure.exe` inside it |
| `PortableCommandAlias: sure` | the command a user types | consistent with the launchers' step 2 and with `Moniker: sure` |
| `Architecture: x64` | `P15-T002`'s artifact is `x86_64-pc-windows-msvc`, and it is the only one that exists | `scripts/Build-Release.ps1`'s `$Target` has one member; the renderer refuses an archive whose name does not carry that target |
| `Publisher: lichman0405` | the owner of the repository URL | the same `Cargo.toml` check as the identifier |
| `PublisherUrl`, `PackageUrl` | `Cargo.toml:16` | compared with the repository URL read from `Cargo.toml` |
| `License: Apache-2.0` | `Cargo.toml:15` | compared with the `license` field, and `LICENSE` is at the repository root |
| `LicenseUrl` | the template, spelling out the repository URL plus `/blob/main/LICENSE` | **no check.** The renderer compares `License`, `PackageUrl` and `PublisherUrl` with `Cargo.toml` and does not read this field; it is not fetched either, so nothing confirms the path resolves |
| `ManifestVersion: 1.4.0` | the schema version the renderer writes — the **oldest** whose published schema carries every field in this table | the templates and the script's `$SchemaVersion` are compared by a test, so a bump on one side reddens rather than producing files the script then refuses |
| `ShortDescription`, `Description`, `Moniker`, `Tags` | written for a reader of `winget show` | no check; `Description` is where a `winget show` reader is told what this package does **not** do, because a `zip` package that copies one executable has nowhere else to say it |

`PublisherSupportUrl` is deliberately absent: this repository has no support
channel anyone verified exists, and an issue tracker URL that 404s is a worse
answer than no URL.

### The version must agree with the binary

`PackageVersion` and the version `sure` reports are the same string or the
manifest is describing a different program. It is kept true by construction
rather than by convention: the renderer does not read a version from anywhere
else, it reads the archive's name for the version and then **runs the binary out
of the extracted archive** and refuses if the two disagree:

```text
the archive is named for one version and holds another:

  archive     sure-0.0.0-bootstrap-x86_64-pc-windows-msvc.zip
  sure.exe    reports 0.0.0-bootstrap
```

`P15-T002` already made `Build-Release.ps1` name the archive after the version
`sure` reports, so the renderer's refusal is a second reader of the same rule
rather than a new one.

### What a fork has to change

A fork cannot inherit this identity by accident, and the renderer refuses to
render until the templates agree with the fork's own `Cargo.toml`:

1. `repository` and `license` in `Cargo.toml` — or the templates revert to what
   `Cargo.toml` says;
2. `PackageIdentifier` in all three templates, whose prefix must be the new
   repository URL's owner;
3. `Publisher`, `PublisherUrl`, `PackageUrl`, `LicenseUrl` in the locale
   template;
4. the `Moniker` and `PortableCommandAlias`, if the fork is not called `sure`;
5. the release asset layout, if the fork does not publish
   `sure-<version>-x86_64-pc-windows-msvc.zip` under a `v<version>` tag.

Only the first two are enforced; the rest are named here because a fork that
skips them publishes a manifest that is wrong in ways no check in this
repository would see.

## The update process, and what is manual

Rendering a manifest for a new release is one command:

```powershell
& .\scripts\New-WingetManifest.ps1 -Archive target\tmp\release\sure-<version>-x86_64-pc-windows-msvc.zip
```

It writes the three rendered files to
`target\tmp\winget\lichman0405.SURE\<version>\`, runs `winget validate
--manifest` on them, and exits `0` when every value matches the archive and
WinGet accepted the result. `-Phase Verify -ManifestDirectory <dir> -Archive
<archive>` re-derives every value from an already-rendered directory, writes
nothing, and is what a reviewer or a CI job should run.

What that command does **not** do, and what is therefore manual:

1. **It does not create a release, and it does not upload an archive.** Nothing
   in this repository creates a GitHub release. `InstallerUrl` is a claim about
   an asset that a person has to publish, and no check in this repository can
   confirm it exists — `winget validate` reads the manifest's *schema* and
   downloads nothing.
2. **It does not submit anything to `microsoft/winget-pkgs`.** Publication is
   external and optional. It is a pull request to a repository this project does
   not own, and it is a person's decision when and whether to open one.
3. **It does not re-render an existing package version in place.** WinGet's
   convention is a new version directory per release; the renderer writes the
   directory the archive names and fixes nothing else.
4. **It does not check that the archive it is given was built from the commit
   being released.** `Build-Release.ps1` records that inside `RELEASE.txt`, and
   `RELEASE_PROCESS.md` is where that check belongs.
5. **It does not sign anything.** See below.

### Signing

There is none, and the manifest says nothing about one. `RELEASE_PROCESS.md`,
under `## Signing`, says not to fake signing, so there is no `SignatureSha256`
and no signature field: writing one would be a claim about bytes that were never
signed. The build is unsigned and Windows may warn the first time `sure.exe` runs
(`docs/development/INSTALL_WINDOWS.md` says the same, and says what the warning
is a consequence of), and the locale manifest's `Description` tells a
`winget show` reader that before they install rather than after.

## Uninstalling

`winget uninstall lichman0405.SURE` removes:

* the `sure.exe` link in `%LOCALAPPDATA%\Microsoft\WinGet\Links`;
* the package directory under `%LOCALAPPDATA%\Microsoft\WinGet\Packages\`.

It leaves:

* **`%LOCALAPPDATA%\SURE`**, the whole directory — including `sure.db`, the
  user's evidence, the thing SURE exists to keep. This package never writes
  there, so WinGet has no record of it and no business removing it. A machine
  that also ran `scripts/Install-Sure.ps1` keeps that install's `bin\` too, and
  `docs/development/INSTALL_WINDOWS.md` is where *that* flow's uninstaller is
  described — including the fact that it removes a file only when its own
  manifest records it and its digest still matches.
* `%APPDATA%\SURE\sure.yaml`, the settings file, which is outside both install
  roots and is never removed by anything.

**Where the user is told.** In the manifest itself, in the locale file's
`Description`, which is what `winget show lichman0405.SURE` would print once a
package existed, and what a reader would see before installing:

```text
SURE's own data is not part of this package. Its evidence store lives under
%LOCALAPPDATA%\SURE, beside any per-user install made by
scripts\Install-Sure.ps1, and uninstalling this package does not remove it.
See docs/development/INSTALL_WINGET.md in the repository for what an uninstall
removes, what it leaves, and how to delete what is left.
```

That sentence is in the manifest rather than only in this document because it is
the last place a reader is guaranteed to meet it: a `zip` package that copies one
executable has nothing else to say at uninstall time.

**How this was established, and what was not.** The `Packages` and `Links` shape
above is observed on this machine; SURE's own directory names under it come from
the manifest — `Packages\<identifier>_<source>_<hash>\` plus the archive's
top-level directory from `RelativeFilePath`. The removal is what WinGet does for
a `portable` package whose install is one directory and one link, and it is
**not measured here**: `winget uninstall` changes the machine, and this
repository's rules for `P15-T004` forbid running it. To delete what is left by
hand:

```powershell
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\SURE"   # the install, and your history
Remove-Item "$env:APPDATA\SURE\sure.yaml"              # your settings
```

## What is not covered

Named as limits rather than left to be assumed:

* **No package is published, and no install was ever run.** `winget install`,
  `winget uninstall` and `winget upgrade` were not run on this machine or any
  other: they change the machine, and the rules this task was given forbid it.
  So "WinGet installs this correctly" is not measured anywhere in this
  repository. What is measured is the manifest's values against real bytes, its
  acceptance by `winget validate`, and the launcher half against a planted
  `Links` entry.
* **`winget validate` reads a schema and downloads nothing.** It cannot tell you
  that `InstallerUrl` resolves, that the asset exists, or that the digest in the
  manifest is the digest of what a download would return. The digest checks in
  the renderer are what tie the manifest to bytes; the URL is tied to nothing.
* **`winget` is optional, and a run without it says so.** It is treated the way
  the tree treats `pwsh`: the renderer exits `3` with `--- NOT CHECKED ---` and
  prints no OK when it cannot find `winget` on `PATH`, and the tests fail rather
  than pass when they cannot run it. A skipped dynamic check is not a pass.
* **The template cannot pass `winget validate` as committed**, and that is
  deliberate: the renderer's output can, and a placeholder that survived into a
  manifest cannot. Measured with `winget validate --manifest packaging/winget/template`,
  which reports the `PackageVersion` and `InstallerSha256` patterns and exits
  non-zero.
* **The tests render from a staged archive, not a release build.** They build the
  documented layout around the binary cargo just compiled, for the same reason
  `install_flow.rs` does: `Build-Release.ps1` refuses to package without the
  release gate and takes minutes. The script reads a real ZIP with real bytes; a
  `Build-Release.ps1` artifact specifically is `P15-T002`'s verification, not
  this one's.
* **No test drives PowerShell 7.** `install_flow.rs` runs the whole install flow
  under both hosts, adding PowerShell 7 when it can find it; this file drives
  Windows PowerShell only, because what is being tested here is a text
  transformation and a schema check rather than a second host's idea of them. The
  scripts are written for both — .NET hashing rather than `Get-FileHash`, typed
  arguments rather than a command line — and that is reasoning, not a
  measurement.
* **`ManifestVersion: 1.4.0`, and the version is a compatibility choice rather
  than a preference.** It is the oldest schema that can express this manifest:
  `https://aka.ms/winget-manifest.installer.1.4.0.schema.json`, fetched and
  searched on 2026-09-20, carries `InstallerType: zip`, `NestedInstallerType:
  portable`, `NestedInstallerFiles` and `PortableCommandAlias`, and `1.0.0`'s does
  not — it answers a manifest that uses them with `Unknown field.
  [NestedInstallerType]`. Nothing here needs anything newer, so the oldest schema
  that can say it is the one the widest range of `winget` builds accept.

  That last clause is measured, and it is why this is `1.4.0` rather than the
  `1.12.0` it was. `winget` recognises a fixed set of schema versions, and which
  set is *that build's*: measured against `v1.29.290` on 2026-09-20, changing only
  this value in the rendered files:

  | `ManifestVersion` | what `winget validate` said | exit |
  | --- | --- | --- |
  | `1.4.0`, `1.5.0`, `1.6.0`, `1.7.0`, `1.9.0`, `1.10.0`, `1.12.0` | `Manifest validation succeeded.` | `0` |
  | `1.8.0`, `1.11.0`, `1.13.0`, `1.14.0` | `succeeded with warnings`: `The schema header URL does not match the expected pattern` | `-1978335192` |

  The warning is drawn by the `ManifestVersion` **property**, not by the version
  written in the header URL. Measured one change at a time on the rendered files,
  with the other two files left agreeing:

  | header URL | `ManifestVersion` | what `winget validate` said |
  | --- | --- | --- |
  | `1.4.0` | `1.4.0` | `Manifest validation succeeded.` |
  | `1.13.0` | `1.4.0` | `Manifest validation succeeded.` — the header URL alone is inert |
  | `1.13.0` | `1.13.0` | the pattern warning |
  | `1.4.0` | `1.13.0` | the pattern warning, and `The manifest version in the schema header does not match the ManifestVersion property value in the manifest. Value: 1.4.0` |

  So lowering the header URL alone would have changed nothing, and a version that
  is merely newer is not more correct — only more fragile. **These measurements
  come from one `winget` on one machine, and CI showed that machine was the
  permissive one**: the `windows-2025-vs2026` runner image's older `winget`
  answered `1.12.0` with that same warning, and `rust (windows-latest)` went red
  on the commit that carried it. A warning is not a pass here — the same rule that
  keeps `Scope: user` out of the installer manifest (`## What the package
  installs`). The three files must also agree with one another: one file's
  `ManifestVersion` moved on its own is refused outright as `The multi file
  manifest has inconsistent field values`, exit `-1978335191`, an error rather
  than a warning. What this repository can state is that the three templates and
  the script's `$SchemaVersion` carry one value and a test compares them, so a
  bump on one side reddens rather than producing files that then fail for a
  reason nobody expected.
