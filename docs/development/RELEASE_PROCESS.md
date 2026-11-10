# Release process

Initial line: `0.1.x`.

Suggested prerelease progression:
- `v0.1.0-alpha.1`
- `v0.1.0-beta.1`
- `v0.1.0`

## Primary artifact

- Windows x64 (`x86_64-pc-windows-msvc`) CLI/core archive/package
- SHA-256 checksum
- PowerShell per-user install/uninstall flow

### What that archive is, concretely

Decided by `P15-T002` and produced by `scripts/Build-Release.ps1`:

| | |
| --- | --- |
| name | `sure-<version>-x86_64-pc-windows-msvc.zip`, where `<version>` is the version `sure` itself reports |
| layout | one top-level directory of the same name, holding `sure.exe`, `LICENSE`, `RELEASE.txt` and `THIRD_PARTY_NOTICES.txt` |
| checksum | `<archive>.sha256` beside it: one `sha256sum`-format line, `<64 lowercase hex><two spaces><file name>`, ASCII, no BOM |
| where | `target/tmp/release/` by default. `target/` is gitignored, so no binary is committed |
| signature | read rather than assumed, and recorded in the archive's own `RELEASE.txt` as a `signature` line: `not-signed`, `signed` (which fails the run) or `cannot-confirm`. See `## Signing` below |

`RELEASE.txt` travels inside the archive and carries the commit it was built
from, whether the worktree was clean at the time, the `rustc` that built it, the
SHA-256 of `sure.exe`, the signature state read off that `sure.exe`, and the
release gate's decision.

`THIRD_PARTY_NOTICES.txt` travels beside it and is generated, not written by
hand. `scripts/Generate-ThirdPartyNotices.mjs` reads this checkout's `Cargo.lock`
through `cargo metadata --locked`, lists every third-party crate with its SPDX
expression and source URL, and prints each distinct license text once, deduped
by SHA-256. For an MPL-2.0 crate it also prints the source-code pointer the
license asks for. The generator exits non-zero, and the packaging run with it,
when a crate declares no license information at all or when a must-have license
text (MPL-2.0, ISC, BSD-3-Clause, Zlib, Unicode-3.0, CDLA-Permissive-2.0, MIT,
Apache-2.0) that is present in `Cargo.lock` cannot be produced; a canonical SPDX
text embedded in the generator stands in when the crate sources carry none, and
the file marks which texts came from there. `node
scripts/Generate-ThirdPartyNotices.mjs --check <file>` exits 0 only when a file
still carries every crate line and every distinct text, so an archive's copy can
be held against the lockfile it was built from. Both `scripts/Build-Release.*`
run the generator before staging and require the result in the archive's layout.

The checksum is **over the artifact**. It is deliberately not an entry in
`SHA256SUMS.txt`: that file is a curated manifest over a subset of the source
tree, it names no `target/` path and no `sure.exe`, and nothing in this
repository generates or verifies it, so an artifact digest placed there would
look like assurance and would not be.

The archive is **not byte-for-byte reproducible**. A ZIP records a timestamp per
entry, so two builds of the same commit produce two different archives with two
different digests; measured 2026-09-19 over one unchanged checkout, every run
produced a digest no earlier run had. The `.sha256` is an integrity check over
the bytes that were shipped — that they arrived unchanged — and it is not a
claim that a rebuild would produce them again.

`scripts/Build-Release.ps1` will not package this checkout unless
`target/tmp/release-gate.json` exists and reads `permitted`; that document's own
`contract` field is the rule. It then extracts the archive to a fresh directory
and runs the extracted `sure.exe` from there, checking the `running_from` the
binary reports against the directory it extracted to, so that "the artifact was
tested" means the bytes in the archive were run rather than a debug build that
happened to be on `PATH`.

`P15-T003` installs this archive, per user and without administrator rights, and
`docs/development/INSTALL_WINDOWS.md` is where that flow is written down: the
install location, the checksum, the unsigned-build warning, what is and is not
put on `PATH`, and what the uninstaller does with the user's evidence. `P15-T004`
references it.

`P15-T031` closes the loop between this script and that flow, because until it
landed the install tests staged their own archive in the layout they already
believed in — a fixture that cannot disagree with the installer it was written
beside. `crates/sure-cli/tests/install_flow.rs`'s
`the_installer_installs_the_archive_the_build_produced` now installs the
`sure-*-x86_64-pc-windows-msvc.zip` in `target/tmp/release/` (or the one
`SURE_RELEASE_ARCHIVE` names) and holds the installer's records against this
script's output: the `.sha256` line's format, the archive's single top-level
directory, the four payload names, the `sure.exe SHA-256` line this script
writes into `RELEASE.txt`, the manifest's digests and byte counts, and the
version and `running_from` the installed program reports. **It is `#[ignore]`d,
and `release.yml`'s `package-windows` job is what runs it**, by name and with
`--ignored`, in a step immediately after `Build-Release.ps1 -Phase All` — the
step whose output it installs. The label is the decision rather than an
oversight: `ci.yml` packages a Windows archive nowhere, and each packaging job
here runs `cargo test --workspace` *before* it packages, so a test that needs an
artifact and reports its absence by failing would be a permanent red in two
workflows that cannot do anything differently — and the six gates would redden on
exactly the fresh checkout they are run on. Locally,
`cargo test -p sure-cli --test install_flow -- --ignored` runs it. **When it runs
and there is no such archive it fails rather than skips**, naming
`& .\scripts\Build-Release.ps1 -Phase All` in the failure. Cost: about 1.5
seconds when the archive is there.

A future user-friendly installer may use MSIX/WiX or another appropriate Windows packaging system after CLI behavior stabilizes. Do not add installer complexity before core acceptance.

## Cross-platform artifacts

Also produce/document:
- macOS Apple Silicon CLI archive — see `### What the macOS Apple Silicon archive is, concretely`, below;
- macOS Intel CLI archive — **produced and run, not published.** See
  `### What the macOS Intel archive is, concretely` below for the run that does
  it, the exact boundary of what is therefore true, and how to reproduce it;
- Linux x64 CLI archive — **produced and run, not published.** See
  `### What the Linux x64 archive is, concretely` below for the run that does
  it, the glibc floor the artifact carries, the exact boundary of what is
  therefore true, and how to reproduce it;
- SHA-256 checksums;
- Claude Code plugin package/instructions;
- Cursor Plugin package/instructions;
- Agent Plugin/Codex package/instructions.

### What the macOS Apple Silicon archive is, concretely

Decided by `P15-T005` and produced by `scripts/Build-Release.sh`. That script is
a POSIX shell script rather than a second PowerShell script because the artifact
is built on macOS and Linux runners, where `scripts/Build-Release.ps1` cannot
run at all: it is `ZipFile::CreateFromDirectory`, `%LOCALAPPDATA%`, a `sure.exe`
and a MAX_PATH guard. The workflow invokes it as `sh scripts/Build-Release.sh`
and not by path: this file's mode in the git index is 100644, and the workflow
starts it through `sh`, so the bit is not load-bearing for it. Two corrections
to what this sentence said before `P15-T008` read the modes across the
repository. It is no longer true that every `.sh` here is 100644: the three
integration launchers are 100755 on purpose, and
`docs/integrations/INSTALLATION_MATRIX.md` records that decision. And "Git on
Windows does not record the executable bit" says too much — `git update-index
--chmod=+x` records one on Windows. What Windows does not do is read a mode back
off the filesystem, because `core.filemode` is `false` in a normal Git for
Windows checkout, so a mode changed in the working tree is invisible until it is
set in the index deliberately.

| | |
| --- | --- |
| name | `sure-<version>-aarch64-apple-darwin.tar.gz`, where `<version>` is the version `sure` itself reports |
| layout | one top-level directory of the same name, holding `sure`, `LICENSE`, `RELEASE.txt` and `THIRD_PARTY_NOTICES.txt` |
| checksum | `<archive>.sha256` beside it: one `sha256sum`-format line, `<64 lowercase hex><two spaces><file name>`, ASCII, no BOM |
| where | `target/tmp/release/` by default. `target/` is gitignored, so no binary is committed |
| mode | `sure` is recorded as mode 755. A tar records the mode as a field of the format, which is why this artifact is not a ZIP |
| signature | none. See `## Signing` below |
| produced by | `.github/workflows/release-dry-run.yml`, job `package-macos`, on a `macos-latest` runner |

The two platforms' archives do not have to be the same shape: a Windows user
expects a ZIP and `[System.IO.Compression.ZipFile]` writes one, and a macOS user
expects a tarball. What is the same is the naming, the single top-level
directory, the four files inside it, and the `.sha256` beside it.

**The architecture is read from the artifact and never from the runner's name.**
`macos-latest` is believed to be an arm64 image; the label's meaning has changed
before and will change again, and a belief is not a measurement. So the build
names its target explicitly (`--target aarch64-apple-darwin`), and the script
then reads the extracted binary's **first eight bytes** — the 4-byte Mach-O
magic and the 4-byte `cputype` — prints them as hex, and requires exactly the
pair the named target calls for: `cf fa ed fe` / `0c 00 00 01` for this artifact.
A Mach-O of the other architecture, a universal ("fat") binary and a PE or ELF
image are each refused by name, and the refusal prints the bytes it found against
the bytes it required. `/usr/bin/file` is asked the same question as a second
reader where it exists; its absence is reported rather than passed over, and a
disagreement fails the run. The runner's own `uname -m` is printed too, so a
reader can see whether "and it ran" was possible on that machine at all.

`P15-T006` extended the same script to a second target, `x86_64-apple-darwin`,
so the pair above is the arm64 row of a two-row table rather than a constant.
**That extension produces its own artifact**, built, checksummed and run by
`.github/workflows/release-dry-run.yml`'s `package-macos-intel` job — see
`### What the macOS Intel archive is, concretely`, which is also where the
four-direction measurement of this check is written down. Both macOS archives
are `actions/upload-artifact` workflow artifacts and **neither is published**;
that section says what that does and does not mean. A fourth archive — the
Windows ZIP — and a second workflow that attaches all four to a **draft** release
are `## The release workflow` below; a draft is not a publication either, and
that section says why, and records that the workflow has never run and that the
Windows archive has never been built on a runner.

**What "builds/tests" means here is two things.** The workspace's tests are
`cargo test --workspace --no-fail-fast` in the workflow's own step, on the same
runner. The artifact is separately exercised: the script extracts the archive to
a fresh directory and runs the extracted `sure` **from there**, by absolute
path, requiring it to report `running from` **its own path** — that line is the
path of the running executable, not of the directory holding it — and to
describe itself as built for `macos aarch64`. The property that makes it
falsifiable is the one the Windows script states — *the bytes that are
checksummed are the bytes that were run* — and it is established by the order of
the steps, not by a claim.

The release gate applies here exactly as it does on Windows. The document is
`target/tmp/release-gate.json`, written by
`cargo test -p sure-core --test acceptance_report_runner`; on a CI runner
`target/` does not exist until the job creates it, so a `permitted` gate there
is evidence that the acceptance corpus ran **on that runner**.

The macOS artifact is **not byte-for-byte reproducible** for the same reason the
Windows one is not, by a different mechanism: a gzip stream records a
modification time in its header and a tar records one per entry. The `.sha256`
is an integrity check over the bytes that were shipped and is not a claim that a
rebuild would produce them again.

**This artifact has not been signed, notarized, published or downloaded by
anyone.** `scripts/Build-Release.sh` has no signing step and reads the binary's
signature with `codesign -d`, failing only if a signature *chain* appears while
`RELEASE.txt` says there is none; an ad-hoc signature, which an arm64 binary can
carry so the kernel will load it, is not a certificate and does not contradict
that. Nothing in this repository has observed what Gatekeeper does with the
result on a Mac, and `RELEASE.txt` inside the archive says so rather than
guessing.

### What the macOS Intel archive is, concretely

Decided by `P15-T006`, and produced and run by `.github/workflows/release-dry-run.yml`'s
`package-macos-intel` job. The short form is the one a reader should leave with:

> **This project produces and runs a `x86_64-apple-darwin` macOS artifact, on a
> native Intel host, whenever that job runs. It is not published, signed or
> notarized. No release carries it, and the same is true of the Apple Silicon
> artifact.**

The rest of this section is what that sentence rests on, and what it does not.

**What was measured, and where.** Run `35514769749`, dispatched
2026-09-20T13:52:17Z against head SHA
`a009f57afcb23522afd594a86690bf46763fc4aa`, concluded `success` with all five jobs
green. The job that builds this artifact is `106088732392`. Its *"What this
runner is"* step prints the runner's identity rather than leaving the label to be
believed:

| reading | value |
| --- | --- |
| `uname -s` | `Darwin` |
| `uname -m` | **`x86_64`** |
| `RUNNER_ARCH` | **`X64`** |
| `rustc host` | **`x86_64-apple-darwin`** |
| `rustc release` | `1.98.1` |
| `targets installed` | `x86_64-apple-darwin` |
| `cc` | **`/usr/bin/cc`** |
| `clang` | `/usr/bin/clang` |
| runner image | `macos-26`, version `20260824.0517.1`; macOS 26.6.1 (25G76) |

This is a **native Intel host**. It is not an arm64 runner, and nothing here ran
under Rosetta. Note `cc` in particular: that is the exact tool whose absence
stopped the local Windows-host attempt recorded below.

**What was built, and what was run.** `cargo build --workspace --release --locked
--target x86_64-apple-darwin` exited 0 with `Finished release profile [optimized]
target(s) in 2m 41s`. The staged binary was 10443320 bytes, SHA-256
`c6da9be42e232fd56146b4dfd33e840d63db7c318daafb1f3c2e076ed304e7ed`. The archive
`sure-0.0.0-bootstrap-x86_64-apple-darwin.tar.gz` was 4307011 bytes, and its
`.sha256` was 114 bytes (expected 114), 1 LF, 0 CR, digest
`5b6c6ecc30840c2a0d807ff3e9b6d533e3cf336e4ee26732d48a0ac04ee00ec5`. The layout
was 4 entries, exactly the promised set. Verification read `expected` == `actual`,
`shasum -a 256 -c` agreed, and the archive on disk was the archive the checksum
file names. Extraction produced `same as the sure cargo built`. The extracted
binary's header bytes were `cffaedfe07000001`, which the reader returned as
`Mach-O 64-bit, x86_64`, and `/usr/bin/file` said `Mach-O 64-bit executable
x86_64`. The job then invoked `<extracted>/sure doctor`, which exited 0,
reporting `SURE 0.0.0-bootstrap (harness protocol 1), built for macos x86_64, C
library none`, and reporting `from` its own extracted path. The gate read
`permitted`. The verdict line was:

```
OK  the bytes that are checksummed are the bytes that were run
```

The Apple Silicon job in the same run, `106088732521`, also succeeded and also
printed that verdict line.

**Produced and run — not published.** The job uploads the archive and its
`.sha256` with `actions/upload-artifact@v4` as the workflow artifact
`sure-x86_64-apple-darwin`, retained for 14 days. That is what both macOS
archives are: retained by GitHub, downloadable from the run page by someone with
access to this repository, attached to no release and reachable by no public URL.
`gh release list` on this repository returns nothing and
`gh api repos/lichman0405/SURE/releases --jq length` returns 0, so this repository
has no GitHub Releases. Neither macOS archive has been signed, notarized,
published or downloaded by anyone, and nothing here should be read as saying
otherwise.

**The signature boundary is the same as the Apple Silicon artifact's.** The job's
*Signature* step read `code object is not signed at all` from `codesign -d`, exit
1, authority `none`. The archive is not signed and not notarized, and nothing in
this repository has observed what Gatekeeper does with it on a Mac. That is the
boundary `## Signing` records, and the same one the Apple Silicon section above
states.

**Why the Apple Silicon artifact does not cover Intel Macs.** They are different
architectures and that artifact is a thin `aarch64` binary; an Apple Silicon
translation layer runs x86_64 code on arm64 hardware, not the reverse. That is
the shape of the two architectures rather than a measurement of one Mac, and it
is why the Intel target is a separate job producing a separate archive rather
than a reason to expect the arm64 one to be usable on an Intel host. What an
Intel Mac can use is the artifact this section describes, subject to the
publication, signature and Gatekeeper boundaries it records.

**What was measured here, and what that does and does not buy.** The build was
attempted on the machine that wrote this — Windows 11, native Rust MSVC — with
the target installed:

```
$ cargo build --workspace --release --locked --target x86_64-apple-darwin
error: failed to run custom build command for `ring v0.17.14`
cargo:warning=Compiler family detection failed due to error:
  ToolNotFound: failed to find tool "cc": program not found
error occurred in cc-rs: failed to find tool "cc": program not found
$ echo $?
101
$ ls target/x86_64-apple-darwin/release/sure
ls: cannot access '...': No such file or directory
```

That is an excerpt of a 74-line log, which is at
`target/tmp/p15t006/local-x86_64-apple-darwin-build.txt` on the machine that
wrote this and is not committed. The first line is the log's line 23 — the line
that says *which* crate failed — `Compiling ring v0.17.14` is its line 18, and
the two `cc-rs` lines are its lines 52 and 70 (line 65 repeats line 52; one of
the two is shown), given here without the two-space indent they carry in the log.
The line numbers are named because the omission of line 23 from this excerpt is
what let the wrong crate be named underneath it.

The `x86_64-apple-darwin` `std` **is** installed there, so the run got past the
target's own absence and stopped at the C dependency: a crate's build script
compiles C for this target through `cc-rs`, and a Windows host has no C compiler
that emits x86_64 Mach-O objects. The crate this log names is `ring v0.17.14`.
The workspace does carry the other C a reader of this section may be thinking of
— `rusqlite`'s `bundled` feature compiles SQLite from its own C source through
`libsqlite3-sys` — but `cargo` stops at `ring`'s build script and never compiles
`libsqlite3-sys`. The sentence here used to name that crate, which this log does
not mention. **This was always a fact about the host, not about the target**, and
the CI log is what settles it: job `106088732392` found `/usr/bin/cc`, and the
same build there exited 0. It is the same fact
`docs/development/GITHUB_WORKFLOW.md` records about cross-target `clippy` — not
evidence that the artifact cannot be built, only that it could not be built
*here*.

**The architecture check discriminates, in four directions, over real Mach-O
bytes.** The check in `scripts/Build-Release.sh` was extended to serve both macOS
targets and refuses a wrong reading by name:

| archive name | `sure`'s first eight bytes | Architecture step |
| --- | --- | --- |
| `...-aarch64-apple-darwin.tar.gz` | `cffaedfe0c000001` | accepted, `Mach-O 64-bit, arm64` |
| `...-x86_64-apple-darwin.tar.gz` | `cffaedfe07000001` | accepted, `Mach-O 64-bit, x86_64` |
| `...-x86_64-apple-darwin.tar.gz` | `cffaedfe0c000001` | refused, *not* `Mach-O 64-bit, x86_64` |
| `...-aarch64-apple-darwin.tar.gz` | `cffaedfe07000001` | refused, *not* `Mach-O 64-bit, arm64` |

**Both accepted rows are now read off archives this project's own workflow
built.** The arm64 bytes are the ones `P15-T005`'s CI run built and uploaded; the x86_64
bytes are the ones job `106088732392` read off a real linker-produced binary. An
x86_64 little-endian Mach-O beginning `cffaedfe07000001` was believed but not yet
measured when `P15-T006` was first briefed; that is no longer a belief — the job
printed exactly those bytes from the artifact it had just built, so this constant
is read off real bytes in the same way the arm64 one is. The arm64 path was also
compared against itself before and after the Intel target was added, over the
artifact CI actually uploaded, and the two outputs are byte-identical.

**The Intel archive is not byte-for-byte reproducible** either, by the mechanism
the Apple Silicon archive has rather than the Windows ZIP's: a gzip stream
records a modification time in its header and a tar records one per entry. The
`.sha256` is an integrity check over the bytes that were built and uploaded and is
not a claim that a rebuild would produce them again. One Intel build has been measured,
so for this artifact that follows from the format rather than from a second
observation of it.

**What is still not measured, stated plainly.**

- **Whether a second build of the same commit produces the same archive.** One
  Intel build has been measured; the reproducibility statement above rests on the
  archive format's mechanism, not on a repeat.
- **Whether the uploaded workflow artifact survives a download intact.** The job
  built, checksummed and ran the archive on its own runner, and then uploaded it.
  Nobody has downloaded that artifact and re-checked it against its `.sha256`, so
  that round trip is unmeasured — and a 14-day retention window is not a
  distribution channel.
- **What Gatekeeper does with it on a Mac.** The job's own `codesign` reading says
  the binary is unsigned. No launch through Gatekeeper has been observed here; a
  CI runner executing a binary from its own scratch directory is not that
  observation.
- **Whether this artifact behaves the same on an Intel Mac that is not this
  runner image.** The machine was hosted image `macos-26`, version
  `20260824.0517.1`. Nothing here has run the artifact on any other Intel Mac.

**How to reproduce this.** The workflow is still `workflow_dispatch`-only, so the
measurement is reproduced by dispatching it and reading the `package-macos-intel`
job's log:

```
gh workflow run release-dry-run.yml --ref claude/v0.1-autonomous
```

That job's *"What this runner is"* step prints `uname -m`, `RUNNER_ARCH` and
`rustc -vV`'s host, so the log says which machine actually ran rather than leaving
the label to be believed; it prints `command -v cc`, the specific tool whose
absence stopped the local attempt above; and `scripts/Build-Release.sh --target
x86_64-apple-darwin` runs the extracted binary **from the directory it was
extracted into** and compares the `running from` it reports. If a future dispatch
lands on an arm64 host instead, `uname -m` says so, and the log distinguishes a
native run from a Rosetta one rather than the reader having to assume.

### What the Linux x64 archive is, concretely

Decided and written by `P15-T007`, and produced and run by
`.github/workflows/release-dry-run.yml`'s `package-linux` job. The short form is
the one a reader should leave with:

> **This project produces and runs a `x86_64-unknown-linux-gnu` Linux artifact,
> on a native x86_64 Linux host, whenever that job runs. It is not published,
> signed or notarized. No release carries it.**

The rest of this section is what that sentence rests on, and what it does not.

It is produced by the same `scripts/Build-Release.sh` as the two macOS archives —
one script, three targets, because the version read, the stage, the four files
inside the archive, the `.sha256` format, the extraction and the run of the
extracted binary are the same for all three and two scripts holding one archive
contract are two places for it to drift — and by a third job in the same workflow,
`package-linux`, on an `ubuntu-latest` runner.

**What was measured, and where.** Run `35526723850`, attempt 1, on commit
`f727d5f`, concluded `success` with all six jobs green: `validate` on ubuntu,
windows and macos, and the three artifact jobs. `package-linux` is job
`106120068667`. Its *"What this runner is"* step prints the runner's identity
rather than leaving the label to be believed:

| reading | value |
| --- | --- |
| `uname -s` | `Linux` |
| `uname -m` | **`x86_64`** |
| `RUNNER_ARCH` | **`X64`** |
| `rustc host` | **`x86_64-unknown-linux-gnu`** |
| `rustc release` | `1.98.1` |
| `targets installed` | `x86_64-unknown-linux-gnu` |
| `cc` | **`/usr/bin/cc`** |
| `sh` | **`/usr/bin/sh -> /usr/bin/dash`**, version `0.5.12-6ubuntu5` |
| `objdump` | `/usr/bin/objdump` |
| runner image | `Ubuntu 24.04.5 LTS` (`24.04.5 LTS (Noble Numbat)`), `ldd (Ubuntu GLIBC 2.39-0ubuntu8.8) 2.39` |

This is a **native x86_64 Linux host**, which is what the artifact's architecture
requires; and `cc` is present, which is the exact tool whose absence stopped the
local Windows-host attempt recorded below.

**What was built, and what was run.** `cargo build --workspace --release --locked
--target x86_64-unknown-linux-gnu` exited 0 with `Finished release profile
[optimized] target(s) in 1m 35s`. The staged binary was 12025344 bytes, SHA-256
`5db5bf085f8a45aa039af0943134036dc70b792945921dbe579a4f4ea3281144`. The archive
`sure-0.0.0-bootstrap-x86_64-unknown-linux-gnu.tar.gz` was 4599814 bytes, and its
`.sha256` was 119 bytes (expected 119), 1 LF, 0 CR, digest
`44cd8357478cd2dbafaead10d71a4e56ff10ec86620cb9c8c26650e491c9bb2a`. The layout
was 4 entries, exactly the promised set. Verification read `expected` == `actual`,
the second tool agreed, and the archive on disk was the archive the checksum file
names. Extraction produced `same as the sure cargo built`. The extracted binary's
header bytes were `7f454c4602010100000000000000000003003e00`, which the reader
returned as `ELF 64-bit, little-endian, x86_64`, and `/usr/bin/file` said `ELF
64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0,
BuildID[sha1]=4bf7a014c7f016887cf6cf67aa9d873ef64b56f1, not stripped`. The job
then invoked `<extracted>/sure doctor`, which exited 0, reporting `SURE
0.0.0-bootstrap (harness protocol 1), built for linux x86_64, C library gnu`, and
reporting `from` its own extracted path. The gate read `permitted`. The platform's
own `sha256sum -c` was asked the same question from the directory the file was
written into and answered `OK`, and the same command was required to refuse a copy
modified after it was written, which it did. The verdict line was:

```
OK  the bytes that are checksummed are the bytes that were run
```

**The signature step reports `not read`, and that stays as it is.** Its reason is
that an ELF carries no signature field and no step of this build applies one, so
the run measured nothing about whether the binary is signed. That is a measurement
that did not happen and not a pass, and nothing here should be read as saying the
artifact is signed.

**The job's first attempt failed, and that record stays.** Run `35524124026`,
attempt 1, on commit `70ef6dd`, reached this job and died before the release gate
was read and before anything was staged, built or written, with

```
scripts/Build-Release.sh: 530: set: Illegal option -o pipefail
##[error]Process completed with exit code 2.
```

The step's shell is `/usr/bin/bash`, where the option is legal; the thing that
refused it is the `sh` the step handed the script to, which on that runner does
not implement `pipefail`. The fix is `f727d5f`, the run above is its measurement,
and `.github/workflows/release-dry-run.yml`'s `package-linux` header keeps the
whole account, including that both the `set` line and the shebang, as `70ef6dd`
carried them, are `c522699`'s and had been correct on every machine that had run
the file before, because no earlier target ran this script on a machine where
`sh` is not bash.

| | |
| --- | --- |
| name | `sure-<version>-x86_64-unknown-linux-gnu.tar.gz`, where `<version>` is the version `sure` itself reports |
| layout | one top-level directory of the same name, holding `sure`, `LICENSE`, `RELEASE.txt` and `THIRD_PARTY_NOTICES.txt` |
| checksum | `<archive>.sha256` beside it: one `sha256sum`-format line, `<64 lowercase hex><two spaces><file name>`, ASCII, no BOM |
| where | `target/tmp/release/` by default. `target/` is gitignored, so no binary is committed |
| mode | `sure` is recorded as mode 755, as in the macOS archives |
| signature | none, and there is no signing step and no reading to take: Linux has no `codesign` and an ELF has no field a signature lives in. See `## Signing` below |
| produced by | `.github/workflows/release-dry-run.yml`, job `package-linux`, on an `ubuntu-latest` runner |
| `aarch64-unknown-linux-gnu` | refused by name, exit 2. This repository commits to an x86_64 Linux artifact only, and the script will not produce a file named after a platform nothing here builds |

**The architecture is read from the artifact and never from the runner's name.**
`ubuntu-latest` being x86_64 is a belief about a label, and a belief is not a
measurement — the same rule the macOS rows are held to. The Linux reader is where
that rule is easiest to get wrong, so it is worth stating exactly:

| offset | field | x86_64 value | aarch64 value |
| --- | --- | --- | --- |
| 0–3 | magic | `7f 45 4c 46` | `7f 45 4c 46` |
| 4 | `EI_CLASS` | `02` (`ELFCLASS64`) | `02` |
| 5 | `EI_DATA` | `01` (`ELFDATA2LSB`) | `01` |
| 18–19 | `e_machine`, little-endian | `3e00` (`EM_X86_64`) | `b700` (`EM_AARCH64`) |

**The first eight bytes of an ELF are `7f454c4602010100` for an x86_64 image and
for an aarch64 one alike.** A check built by analogy with the macOS eight-byte
read — magic plus a field that names the machine — would accept an arm64 ELF under
a name that says x86_64 and report that it had checked. That is the false green
this reader exists to avoid, and it is why the `e_machine` field at offset 18 is
what the check compares: the script reads **twenty bytes**, prints them as hex,
and compares the four discriminating fields one at a time (`magic`, `EI_CLASS`,
`EI_DATA`, `e_machine`), refusing a mismatch by name and printing found against
required. Offsets 16–17 (`e_type`) are deliberately **not** compared: `0300` is a
PIE and `0200` is not, which is a property of the linker invocation rather than a
promise this repository has made, and a fixed twenty-byte prefix would refuse a
legitimate artifact for a reason that has nothing to do with architecture.
`/usr/bin/file` is asked the same question as a second reader where it exists,
and a disagreement fails the run.

**The machine's glibc is part of the artifact's contract, and the archive says
so.** An ELF built on a CI runner image links that image's GNU C library, so the
oldest distribution it runs on is set by the glibc of the machine that built it —
not by this repository, and not by anything a reader can assume. The
`RELEASE.txt` inside the Linux archive carries a paragraph on this rather than a
version number: it names the mechanism (a dynamically linked `x86_64-unknown-linux-gnu`
binary, not static and not musl, so not Alpine), states that the requirement is
readable **from the binary** as `GLIBC_x.yy` lines among its undefined symbols,
and points at the two readings that give it — `objdump -p` on the extracted
`sure`, and `ldd --version` on the reader's own machine. The `package-linux`
job prints the runner's own `ldd --version` and `/etc/os-release` in its
*"What this runner is"* step, and reads the `GLIBC_` versions off the packaged
binary in a later step, so the log carries both ends of that number.

**The floor is now measured, and it is a real restriction on who can run this.**
The `GLIBC_` symbol versions the packaged binary requires, highest last, are
`GLIBC_2.30`, `GLIBC_2.32`, `GLIBC_2.33`, `GLIBC_2.34`, `GLIBC_2.39`, read in the
job's *"What this archive asks of its glibc, read off the binary"* step. The
highest of them is the oldest glibc that can run the binary, so **this artifact
requires glibc 2.39 or newer**. That is the runner's own libc — `Ubuntu 24.04.5
LTS` carrying `ldd (Ubuntu GLIBC 2.39-0ubuntu8.8) 2.39` — because the build ran on
that image; it is the mechanism above and not a choice this repository made.
**So this artifact does not run on Ubuntu 22.04 (glibc 2.35) or on Debian 12
(glibc 2.36)**, nor on any other distribution whose glibc is older than 2.39. It
does run on the image that built it: the extracted binary was run there and exited
0. The floor belongs to the artifact rather than to the target, so a future
dispatch on a different image would carry that image's floor and the step above
would print it. **Lowering the floor is a follow-up that is owed and not done**: it
means building inside a container older than the runner image, and no step of this
build does that today. Until one does, 2.39 is what this artifact asks for.

**What has been verified, and where.** The build path cannot be finished on the
machine that wrote it — Windows 11, native Rust MSVC — for the reason the Intel
section above records for `x86_64-apple-darwin` and a second one of its own: this
host has the `x86_64-unknown-linux-gnu` `std` installed, so the local build gets
past the target's absence, and then stops in `cc-rs` with

```
error: failed to run custom build command for `ring v0.17.14`
  cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "x86_64-linux-gnu-gcc": program not found (see https://… for help)
  error occurred in cc-rs: failed to find tool "x86_64-linux-gnu-gcc": program not found (see https://… for help)
$ echo $?
101
```

(An excerpt of a 75-line log, at `target/tmp/p15t007/local-linux-build.txt` on
the machine that wrote this and not committed. The `https://…` is the log's own
`docs.rs/cc` link, elided here for width, and the two-space indent is the log's
own. The first line is the log's line 26, which is the line that says *which*
crate failed; `Compiling ring v0.17.14` is its line 17, and the two `cc-rs` lines
are its lines 56 and 72, with line 67 repeating line 56. Those numbers are named
for the reason the Intel excerpt above names its own.)

That is a fact about the host and not about the target: `package-linux`'s runner
has that compiler, and run `35526723850` settles it — job `106120068667`'s identity
step printed `/usr/bin/cc` on its `cc` line and the same build there exited 0.
What **was** verified locally is the half that does not need a Linux compiler —
the reader, against real ELF bytes rather than invented ones:

| archive name | `sure`'s first twenty bytes | Architecture step | bytes |
| --- | --- | --- | --- |
| `...-x86_64-unknown-linux-gnu.tar.gz` | `7f454c4602010100…03003e00` | accepted, `ELF 64-bit, little-endian, x86_64` | **real** — `/bin/ls` copied out of WSL |
| `...-x86_64-unknown-linux-gnu.tar.gz` | `7f454c4602010100…0300b700` | refused, *not* x86_64 | **constructed** — the same file with bytes 18–19 changed `3e00`→`b700`, nothing else touched |
| `...-x86_64-unknown-linux-gnu.tar.gz` | `7f454c4601010161…02002800` | refused, `ELF 32-bit, little-endian, ARM` | **real** — Qualcomm WLAN firmware from a Windows driver store |
| `...-x86_64-unknown-linux-gnu.tar.gz` | `7f454c4601010100…02000300` | refused, `ELF 32-bit, little-endian, i386` | **real** — the same driver store's `m3.bin` |
| `...-x86_64-unknown-linux-gnu.tar.gz` | `cffaedfe07000001…` | refused, `a Mach-O image` | **real** — `P15-T006`'s x86_64 Mach-O |
| `...-x86_64-unknown-linux-gnu.tar.gz` | `4d5a9000…` | refused, `a PE image` | **real** — a PE from `C:\Windows\System32` |

**The arm64 refusal is exercised against constructed bytes and is labelled as
such.** WSL hands out linker-produced x86_64 ELF images and no aarch64 one, and no
package may be installed to obtain one, so two bytes of a real ELF are the
refusal fixture rather than an invented file: the file is otherwise byte-for-byte
`/bin/ls`, `file(1)` calls the result `ARM aarch64`, and the two bytes changed are
exactly the two the check compares. The acceptance direction is exercised against
real bytes, and the two other-machine refusals (`EM_ARM`, `EM_386`) are real
objects that were shipped by someone else.

**What the local runs cannot reach, stated plainly.** The Windows host cannot make
an extracted file executable, so the mode check stops every local run of the
script and the steps after it are unreachable *here*: the *Signature* step, the
*Run the extracted binary* step and the final verdict line. That is a boundary of
this host and not of the artifact. Run `35526723850` reached all of them: the mode
check passed, which is the first time the `755` mode this archive records has been
checked against a real extraction on a Linux filesystem for a Linux target; the
*Signature* step reported `not read` and measured nothing, as it must; the
extracted `sure doctor` ran from its extracted directory and exited 0; and the
verdict line was printed. So "the extracted `sure` runs on Linux and reports
itself built for Linux" is no longer unmeasured, and the claim at the top of this
section is earned by the log above rather than asserted.

**How to reproduce this.** Dispatch the workflow and read the `package-linux`
job's log:

```
gh workflow run release-dry-run.yml --ref claude/v0.1-autonomous
```

Run `35526723850` is that dispatch, so its job log is the worked example of the
paragraph above. The job's *"What this runner is"* step prints `uname -m`,
`RUNNER_ARCH`, `rustc -vV`'s host, the image's `/etc/os-release` and its
`ldd --version`, so the log says which machine and which C library produced the
artifact rather than leaving the label to be believed; a later step reads the
`GLIBC_` versions out of the packaged binary; and `scripts/Build-Release.sh
--target x86_64-unknown-linux-gnu` extracts the archive to a fresh directory and
runs the extracted `sure` **from the directory it was extracted into**, comparing
the `running from` it reports with its own path — so *the bytes that are
checksummed are the bytes that were run* is established by the order of the steps
and not asserted. The job uploads the archive and its `.sha256` as the workflow
artifact `sure-x86_64-unknown-linux-gnu`, retained for 14 days, like the two macOS
ones: **not published, attached to no release and reachable by no public URL.**

**The upload has been downloaded back, once, and it agreed.** After run
`35526723850`, the uploaded artifact was downloaded from the run page and checked
by hand: the digest recomputed from the downloaded bytes matched the one above on
both of two independent hashes, `sha256sum -c` against the `.sha256` downloaded
beside it returned `OK`, the entry list was the four entries above, and the twenty
header bytes read out of the downloaded copy were the ones the job printed. That
is the upload-download-rehash round trip the macOS Intel section above reports as
not measured *for its own artifact*: it is now measured for this one, once, on one
machine. That entry stands unchanged for both macOS archives, and a 14-day
`actions/upload-artifact` artifact is still not a distribution channel.

## The release workflow

Every section above ends by saying that its artifact is not published, and that
remains true of every artifact this project has produced. `P15-T011` adds
`.github/workflows/release.yml`, a second `workflow_dispatch`-only workflow and
the only file here that attaches an artifact to anything outward-facing. The
boundary between it and `release-dry-run.yml` is one row:

| | `release-dry-run.yml` | `release.yml` |
| --- | --- | --- |
| what it builds | three archives (macOS arm64, macOS x64, Linux x64) | four, adding `x86_64-pc-windows-msvc` |
| where the output goes | `actions/upload-artifact`, 14 days, no public URL | the same upload, and then `gh release create` |
| the outward-facing object | none | one GitHub Release, **draft** |
| has it run | yes, several times | **never** |

**No run of `release.yml` has happened, and the file says so.** This repository
has zero tag refs, so the workflow has never been given a tag to
release. Everything in this section is what the file says, read back by
`crates/sure-testkit/tests/ci_workflow.rs`; nothing here is a measurement of a
run, and no reader should upgrade a "would" to a "did". The one dispatch-shaped
gap that is named as a gap is the Windows packaging path: it has only ever been
run on the machine `P15-T002` was written on, and a `windows-latest` runner is
not that machine.

**Trigger and input.** `workflow_dispatch` only, with one input, `tag`, typed
and `required: true`. There is no `push`, no tag pattern, no `schedule`, no
`workflow_run` and no `pull_request`. A `push: tags: ['v*']` trigger is the
conventional shape and was considered: pushing a tag is already a deliberate act.
It is not here because it removes the last chance to stop — a tag arrives and the
outward-facing act begins — and this repository has never had a tag at all. The
dispatch keeps the two acts separate: the tag says which commit is a release, the
dispatch says to go.

**Four refusals, in order, before anything is created.** The tag must be `v`
followed by a digit and must contain only characters a version in a file name may
carry; `refs/tags/<tag>` must already resolve in the checkout (`fetch-depth: 0`,
because `actions/checkout`'s default has no tags in it); the commit the tag names
must equal the commit the run is building; and `gh api
repos/$GITHUB_REPOSITORY/releases/tags/<tag>` must answer **404**. The last one is
three-way on purpose — a 401, a 403 or a network failure is refused as "cannot
tell", not read as "nothing is there", because a release this run cannot see is
not a release that is absent. This is the step that makes a second run for the
same tag a red run rather than a quiet replacement of the first one's assets.
Order matters and is asserted: a check written after the act it guards is not a
gate.

**The release is created as a draft and nothing here can publish it.** `gh
release create "$TAG" --repo … --draft --verify-tag --title … --notes-file …`
with nine assets named one file at a time — the four archives, each `.sha256`,
and the release checksum file. `--verify-tag` is what stops `gh` from silently
creating a tag when one is missing. `--draft=false`, `gh release edit`, `gh
release upload`, `gh release delete`, `--clobber`, `git tag`, `git push`,
`--force`, `gh pr merge` and `--auto` appear nowhere in the file's code, so no
step in it can publish, replace, edit, delete or force anything. A draft is
reversible; a release that has been public has been public. Publishing is a
decision a person makes on the release page.

**The checksum file a downloader gets is not `SHA256SUMS.txt`.**
`scripts/Assemble-Release.sh` recomputes every digest **from the bytes
downloaded from the four jobs**, requires each to equal the `.sha256` the build
wrote on the machine that built it, and writes
`sure-<version>-release-checksums.txt` — four lines, `<64 lowercase hex><two
spaces><name>`, ASCII, no BOM — then reads it back with `sha256sum -c`. The
repository root's `SHA256SUMS.txt` is a curated manifest over the source tree, is
no part of a release, and does not appear in the workflow's code or in the asset
list.

**The credential is the run's own token.** `${{ github.token }}`, as `GH_TOKEN`
for `gh`, in the steps that talk to the API. `secrets.` does not occur outside a
comment saying that it does not occur. No `vsce`, `ovsx`, `npm publish`, WinGet,
NuGet, Homebrew or twine command is invoked, so `## Package managers` and
`## Signing` above stay the last word on those channels, and the release does not
require any of them to exist.

**What the test proves, and what it cannot.** `crates/sure-testkit/tests/ci_workflow.rs`
reads both `release.yml` and `scripts/Assemble-Release.sh` as text and fails if
one of the refusals stops coming before the create, if `--draft` or
`--verify-tag` leaves, if a job loses its runner or gains an `if:` or
`continue-on-error`, if a packaging job stops running the workspace's tests
before it packages, if one of the four archives, its `.sha256`, the aggregate or
one of the nine asset paths leaves, if the release notes stop saying an archive
carries `THIRD_PARTY_NOTICES.txt`, if `contents: write` appears more than once,
or if any word from the forbidden-act and publication-channel lists appears in
the code of either file. Each of those rules is turned red by an edit that breaks
it; the edits are in the test. It proves
**what the files say**. It cannot prove that GitHub accepts the workflow, that
`macos-26-intel` is obtainable, that `windows-latest` can package, or that any
run passes — none of which this repository has observed, and none of which a
file about a workflow can observe.

### Before publishing a draft

A draft release is reversible, and publishing it is a person's decision. That
person's checklist, in the order the release was produced:

- the four packaging jobs are green, including each one's
  `cargo test --workspace` and the checks each `Build-Release.*` run prints;
- every archive verified against its `.sha256`, and
  `sure-<version>-release-checksums.txt` verified with `sha256sum -c`;
- `THIRD_PARTY_NOTICES.txt` sits inside each archive beside `sure.exe`,
  `LICENSE` and `RELEASE.txt`. The build generated it from that run's
  `Cargo.lock`; to re-read it rather than trust the build, extract the archive
  and run
  `node scripts/Generate-ThirdPartyNotices.mjs --check <extracted>/THIRD_PARTY_NOTICES.txt`
  from the same commit;
- **license review.** Read the crate list and any note that a text came from
  the generator's embedded canonical copies. The generator is a disclosure
  gate, not a policy: it fails a build whose dependency declares no license at
  all or whose must-have license text cannot be produced, and it does not judge
  whether a license is acceptable for this project. No deny/compatibility
  configuration exists — `docs/security/SUPPLY_CHAIN.md` records that — and a
  person is the review step that the configuration would otherwise be;
- the release notes' own statement — unsigned and unnotarized — is still what
  `## Signing` above says may be written.

## Package managers

A WinGet manifest/template is useful after the release artifact is stable. Homebrew formula support is secondary.

`P15-T004` writes that template: `packaging/winget/template/` holds the three
files, `scripts/New-WingetManifest.ps1` renders them from a release archive and
refuses any value it cannot derive from those bytes, and
`docs/development/INSTALL_WINGET.md` records what the package would install,
where each value comes from, which parts of the update process are manual, and
what none of it covers. **Nothing is published**: submitting a manifest to
`microsoft/winget-pkgs` is a pull request against a repository this project does
not own, and no package exists there.

## Signing

**This section is the authoritative statement of the signing limitation.** The
other four places that say the Windows build is unsigned — `RELEASE.txt` inside
the archive, `scripts/Install-Sure.ps1`'s output,
`docs/development/INSTALL_WINDOWS.md` and `.github/workflows/release.yml`'s
release notes — each restate it for the moment a reader meets it, and each points
here for the reason. Nothing in this section is a policy a script could have
guessed: every claim in it about the Windows binary is either read off the bytes
or named as unmeasurable.

Authenticode/code-signing credentials are external. If unavailable, document the
unsigned state and expected Windows warnings. Do not fake signing.

### Windows: the state is read, not asserted

`scripts/Build-Release.ps1` asks Windows its own question about the `sure.exe` it
is about to put in the archive — `Get-AuthenticodeSignature`, the cmdlet Windows
provides for exactly this — and writes the answer into the archive's
`RELEASE.txt` as a `signature` line in the header block. The sentence in that
file is **selected by the reading**, so the archive's own text cannot say
something the run did not read. Three states exist, and there is no fourth:

| `signature` | what was read | what happens |
| --- | --- | --- |
| `not-signed` | the cmdlet answered `Status` = `NotSigned`, with no signer certificate and no signature type | the archive is packaged; `RELEASE.txt` says the binary carries no Authenticode signature, and says that this was read |
| `signed` | a signer certificate or a signature type came back | **the run fails, before anything is packaged**, naming the four files this repository would otherwise be contradicting |
| `cannot-confirm` | the cmdlet was not available in the host, threw, or answered something that is neither | the archive is packaged; `RELEASE.txt` says the state **was not read** and names why, and the result block prints that this is not a pass |

**`cannot-confirm` does not fail the packaging step, and that is deliberate.**
`Get-AuthenticodeSignature` ships in the module `Microsoft.PowerShell.Security`,
which does not load in a constrained host, on a stripped image, or from a
`PSModulePath` that cannot find it, so a host exists in which the question cannot
be asked at all. A missing credential is an *external* limitation — the whole of
what this task's acceptance asks to be marked — and a packaging step that refused
here would make the Windows artifact unbuildable on a legitimate machine. A check
that makes a build impossible is a check somebody deletes. So it is recorded in
three places rather than enforced in one: the run's output, the archive's
`RELEASE.txt`, and the result block. It is a stated limitation beside a
successful packaging run. It is never a pass.

That reading also produced a measurement worth recording, because it argues
against a simpler design this could have had: **the cmdlet does not answer
uniformly about bytes that are not an image.** On 2026-09-21, on one machine, a
plain `.txt` file answered `UnknownError` and a `.ps1` file answered `NotSigned`.
So `not-signed` cannot be inferred from "the cmdlet did not complain", which is
why the third state exists rather than a two-way branch, and why the reader only
reports `not-signed` when the status is exactly that. The file this script asks
about is a PE it has just built, and the reading is trusted for that file because
the answer was measured for that file.

**A signature appearing fails the run.** That looks like the opposite of
honesty and is the same thing. Four files in this repository are written on the
footing that this binary carries no signature — the installer's own output,
`INSTALL_WINDOWS.md`, this section and the release notes — so a signed binary
would contradict every one of them at the moment a user read it, with nothing
else in the tree to notice. Three of the four state it outright. The fourth,
`scripts/Install-Sure.ps1`, reports the state the archive carries rather than a
state of its own, and declares a signed archive one this project does not build;
it is in the list because that is what a signed binary would make it change. The
failure prints each file and stops before anything is packaged.
`scripts/Build-Release.sh` has the same rule for macOS, keyed on an `Authority=`
line, and gives the same reason: an archive whose own text contradicts its own
bytes is the shape this repository exists to refuse.

**The reading is taken twice.** Once on the staged `sure.exe`, before
`RELEASE.txt` is written, so the sentence is a function of the reading. Once
again on the extracted `sure.exe` after extraction, in both phases, and compared
against the `signature` line the archive carries. The second is why
`-Phase Verify` reports a signature state at all: that phase stages nothing, so
without it the whole claim on a verified archive would be the archive's own
sentence about itself. A claim *weaker* than the reading — an archive recording
`cannot-confirm` whose binary is in fact unsigned — is printed as a note rather
than failed, because the failure mode being guarded here is a claim stronger
than the reading, not a claim weaker than it.

### What is measured, and what is not

`There is no Authenticode signature on this file` is a fact about bytes. It is
measured on the machine that built them, and it is the only thing about signing
this project can state.

**SmartScreen is not measurable here at all.** It is a Microsoft service driven
by download telemetry this project does not hold and cannot observe. Nothing in
this repository has ever seen the prompt: no test runs an unsigned binary through
a download-marked file and observes what Windows does, and
`docs/development/INSTALL_WINDOWS.md`'s `## What is not covered` says so in the
same words. What can be said is that the binary is unsigned and that Windows
**may** warn. Which of those two a particular person meets depends on the
Mark-of-the-Web on their copy, their SmartScreen settings and their
organisation's policy, none of which this repository can see.

### What must not be written

The acceptance is *"Do not fake signing or claim SmartScreen reputation."* That
rules out, specifically and not as a general principle:

* **Any statement that a reader will not meet a warning.** *No SmartScreen
  prompt*, *you will not be warned*, *nothing will appear*, *this avoids the
  SmartScreen warning*. Nothing here can observe what their machine does.
* **Reputation as a promise about this binary.** *Reputation builds over time*,
  *once it has been downloaded enough the warning stops*, *SmartScreen will trust
  it*. Reputation is a Microsoft service driven by telemetry this project does
  not have; a promise about it is a promise about somebody else's system.
* **Signing presented as free, instant, or already done.** *Signing is free*,
  *the certificate is configured*, *signed by SURE*. No certificate is held, none
  is configured, and the cost of one is not this project's to quote.
* **The absence presented as a neutral fact.** *No signature is required*, *the
  signature state is informational*, *this does not affect anything*. A person
  who runs the program may meet a prompt, and the sentence has to leave them
  expecting that rather than surprised by it.
* **A definite prompt, in the other direction.** *Windows will warn* over-commits
  for the same reason *Windows will not warn* does: the outcome belongs to a
  service this project cannot observe. The honest form is **may**.

`crates/sure-testkit/tests/signing_status.rs` holds the bullets above as **four**
families of strings it fails on, over the three files that make the claim to a
reader. The count is four rather than five because the first two bullets are one
family: a claim about SmartScreen reputation covers both the promise that it
accrues over time and the assertion that a reader meets no warning, which are the
same claim about somebody else's service written in opposite directions. The
remaining three bullets are the other three families. That test's own header says
what it cannot do: a list of phrases cannot contain the phrasing nobody thought
of, and no test can prove what a user will not see.

**One site is known to break the last bullet today, and it is named rather than
left to be found.** `packaging/winget/template/lichman0405.SURE.locale.en-US.yaml`
tells a `winget show` reader that "Windows SmartScreen will warn the first time it
runs", which is the definite form this section rules out — the honest word there
is *may*. That file is `P15-T004`'s artifact rather than this task's, so
`P15-T012` reported it instead of editing it, and the phrasing rule above does not
scan it: adding it to the scanned set would fail the build with no fix available
inside this task. Whichever task next opens that file should correct the sentence
and add it to `SCANNED_FOR_PHRASING` in the same change. The same paragraph
appears in `docs/development/INSTALL_WINGET.md`, where it correctly says **may**,
so the document and the manifest it describes currently disagree.

### macOS: no Developer ID, no notarization and no staple

**This is the authoritative statement of the macOS half.** The Windows half is
`### Windows: the state is read, not asserted` above, and the two are different
facts: a signature and a notarization are produced by different tools, read by
different tools, and this project has neither. `scripts/Build-Release.sh` reads
the macOS artifact's signature with `codesign -d` and reports it, which is the
standard the Windows half above was brought up to; the notarization half is
what `P15-T013` was handed and what this section answers.

**What is missing.** Three things, and none of them is a property of the bytes
in either archive:

* a **Developer ID Application certificate**, issued by Apple to an Apple
  Developer Program member, which is what `codesign --sign` applies;
* a **notarization credential** — an App Store Connect API key, or an Apple ID
  with an app-specific password — which is what `xcrun notarytool submit` uses;
* the **Apple Developer Program membership** both of those belong to, which is
  an individual or an organisation with an Apple account and a paid enrolment.

**Every other credential this project needs is configured somewhere; this one
cannot be, because there is no step that would use it.** That is the whole of
what "unavailable" means here, and it is stated as a property of the code
rather than of intent: no file of the build path — `scripts/Build-Release.sh`,
`scripts/Build-Release.ps1`, `scripts/Assemble-Release.sh` and the three files
in `.github/workflows/` — names a notarization tool or an Apple credential, and
`crates/sure-testkit/tests/notarization_status.rs` is the check that fails the
moment one appears. It is stated as a property rather than as a count for the
reason `.github/workflows/release.yml`'s own header gives about `secrets.`.

**Who would have to provide it.** An Apple Developer Program member with an
Apple account — a person or an organisation, and the enrolment is paid. Neither
the membership nor the certificate can be produced by anything in this
repository, substituted for, or scheduled: `MASTER_PROMPT.md` names Apple
signing/notarization credentials in its own list of genuine external blockers,
and this section is the macOS half of that list. Until a member provides them,
the honest report is this one.

**What the consequence is, for a person who downloads one.** Both macOS
archives are unsigned, unnotarized and unstapled, and
a person who downloads one meets Gatekeeper rather than an Apple-vouched
artifact. A browser download carries the `com.apple.quarantine` attribute;
Gatekeeper consults the signature and the notarization ticket, and an artifact
that has neither is one Apple's software has to make a decision about on that
person's machine. **Nothing in this repository asks anyone to turn Gatekeeper
off**, and the paragraph inside the archive says the same thing to the person
holding it.

**Signing is not notarization, and the one reading this project takes is a
signing reading.** `codesign -d --verbose=2` answers a question about a
signature: the field it prints is `Authority=`, and `Authority=` is what a
certificate produces. **It is not a notarization field**, and there is no
notarization field in a Mach-O for it to print — what notarization produces is
a ticket Apple holds and a staple that `xcrun stapler` attaches, neither of
which is a line `codesign` can be asked for. **Notarization is not read by that
step at all**, and it could not be: the notarization sentence rests on there
being no notarization step in this build — which is what the rule above
measures — and **not** on the `codesign` reading. An archive this project has
never notarized has no staple, which is why the third clause in this section's
title is as load-bearing as the first two: *unnotarized* and *unstapled* are
one state reported twice.

**What has been observed, and what has not.** Neither macOS archive has been
downloaded by a person and launched on a Mac, so what Gatekeeper does with
either is unobserved here and stays unobserved. The *Signature* step's
`codesign` reading is a reading of the binary's signature on a CI runner, and a
runner executing a binary out of its own scratch directory is not a launch
through Gatekeeper. `### What the macOS Intel archive is, concretely` above
records the same boundary for the Intel artifact.

### What must not be claimed about macOS

The acceptance is *"Do not fake signing/notarization."* The macOS half rules
out, specifically and not as a general principle:

* **A signature described as a notarization.** *The archive is notarized*,
  *notarized by Apple*, *Apple has vetted it*, *notarization succeeded*. There
  is no notarization step, no credential for one and no ticket, so a sentence
  saying one happened describes a step that does not exist — and it is the
  specific lie this half of the acceptance is about.
* **The artifact presented as stapled.** *The ticket is stapled*, *the staple
  validates*, *the ticket is attached*. A staple is what `xcrun stapler`
  attaches to something Apple has already notarized, so a stapled archive is an
  archive a notarization has already happened to. Neither is true here.
* **A promised Gatekeeper outcome.** *Opens without a warning*, *passes
  Gatekeeper*, *Gatekeeper will allow it*, *no Gatekeeper prompt*. What a
  downloader meets is a fact about their machine, their browser, their
  administrator and a check Apple's software performs, and this project can see
  none of those.
* **The absence presented as a neutral fact.** *Notarization is not required*,
  *an unnotarized build is normal*, *notarization does not affect anything*. A
  person who runs the program may meet a refusal or a prompt, and the sentence
  has to leave them expecting that rather than surprised by it.

`crates/sure-testkit/tests/notarization_status.rs` holds the bullets above as
**four** families of strings it fails on, over the four files that make the
claim to a reader — `scripts/Build-Release.sh`, `docs/development/MACOS.md`,
`.github/workflows/release.yml` and `.github/workflows/release-dry-run.yml`.
This section is exempt from its phrase rules for the same reason its Windows
counterpart is: a file that lists these phrasings in order to forbid them
cannot be scanned for them by substring. What guards it instead is a presence
rule, and the same limit applies as above — a list of strings cannot contain
the phrasing nobody thought of, and no test can prove what a person's Mac will
do with a download.

### The other platforms

For Linux there is no field to sign into and none to read: a signature over an
ELF is a detached file beside it, never a field inside the image. So
`package-linux`'s *Signature* step reports `not read` and gives that as its
reason rather than letting the absence of a value read as a pass. That is the
same rule as the Windows `cannot-confirm` row above, and it is where the rule
came from.
