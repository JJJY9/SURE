#!/bin/sh
# shellcheck disable=SC3043
# SURE - build, package and check a release artifact for one of the three
# non-Windows targets: macOS Apple Silicon (aarch64-apple-darwin), macOS Intel
# (x86_64-apple-darwin) or Linux x64 (x86_64-unknown-linux-gnu).
#
#   sh scripts/Build-Release.sh --phase all
#   sh scripts/Build-Release.sh --phase all --target x86_64-apple-darwin
#   sh scripts/Build-Release.sh --phase all --target x86_64-unknown-linux-gnu
#   sh scripts/Build-Release.sh --phase verify --output-dir <dir>
#
# Run from anywhere; every path is derived from this file's own location.
#
# =============================================================================
# Why this file is a shell script and not a second PowerShell script
# =============================================================================
#
# `scripts/Build-Release.ps1` is the Windows artifact's build, and it is
# PowerShell and Windows-only by construction: `ZipFile::CreateFromDirectory`,
# `%LOCALAPPDATA%`, a `sure.exe` and a MAX_PATH guard. `CLAUDE.md` requires the
# Rust core to stay portable to macOS and Linux, and `P15-T005`'s acceptance is
# an aarch64 macOS artifact produced **in CI/release environment**, which means
# on a macOS runner — so the macOS build path cannot be a script that assumes
# Windows, and it cannot be a Windows-only wrapper around one either. A POSIX
# shell script is what runs there: `/bin/sh` on macOS, `sh` on a Linux runner.
# `P15-T007` adds Linux x64 to this script rather than to a sibling one, because
# it is built on the same kind of runner and by the same shape of job as the two
# macOS targets: the version read, the stage, the four files inside the
# archive, the `.sha256` format, the extraction and the run of the extracted
# binary are identical, and two scripts holding the same archive contract are
# two places for it to drift.
# It is written to run under `sh` as well as under `bash` — no arrays, no
# `[[ ]]`, no `mapfile`, no process substitution, no `${var,,}`, and no `${x//y}`
# — because macOS's `/bin/sh` is bash 3.2 in POSIX mode and a Linux runner's
# `/bin/sh` can be `dash`, and a script that needs bash 4 is a script that runs
# on the machine it was written on. **That paragraph was true and the file
# contradicted it**: the shebang said `#!/usr/bin/env bash` and the `set` line
# said `pipefail`, which is bash-only, so the first Linux run of this script
# exited 2 before it built anything (`P15-T007`, run `35524124026` — the whole
# account is at the `set` line). The shebang now says `#!/bin/sh`, which is the
# claim every invocation actually makes, and the one line where this file is not
# POSIX on purpose — `local`, which bash-as-sh and dash both implement — carries
# its own `SC3043` directive at the top so that the linter, which now reads this
# file as `sh`, still reads the rest of it as `sh` without a false report. The workflow
# invokes it as `sh scripts/Build-Release.sh` rather than by path, for the reason
# `crates/sure-testkit/tests/hook_failure_semantics.rs` gives about the `.sh`
# hook launchers: Git on Windows does not carry the executable bit, so a script
# invoked by path is a script that works on the machine it was written on and
# fails with "Permission denied" on the runner.
#
# =============================================================================
# What a release artifact is, decided here and recorded in RELEASE_PROCESS.md
# =============================================================================
#
# `docs/development/RELEASE_PROCESS.md` states the Windows artifact concretely
# and lists the macOS one as "macOS Apple Silicon CLI archive" with no format,
# no naming and no layout. This script decides those, and the same decision is
# written into that document so a reader has it in a document rather than in a
# script's source:
#
#   artifact   sure-<version>-<target>.tar.gz
#   checksum   sure-<version>-<target>.tar.gz.sha256, one sha256sum-format line
#   layout     one top-level directory, sure-<version>-<target>/, holding
#              sure, LICENSE, RELEASE.txt and THIRD_PARTY_NOTICES.txt
#   location   target/tmp/release/ by default
#
# `target/` is gitignored, so nothing binary is committed.
#
# **`tar.gz` rather than `zip`, and the reason is not taste.** A ZIP records a
# file's mode in an "external file attributes" field that is a per-entry
# extension: a writer that does not set it produces an archive whose extracted
# `sure` is not executable, and the extraction is then a file the platform
# refuses to run for a reason that has nothing to do with the build. `tar`
# records the mode as a field of the format, on every writer, and this script
# asserts the extracted file is executable below. The Windows artifact is a ZIP
# because that is what a Windows user expects and what
# `[System.IO.Compression.ZipFile]` writes; the two do not have to match, and
# `P15-T011` (the release workflow) will carry both as what they are.
#
# =============================================================================
# The architecture is established from the artifact, not from the runner
# =============================================================================
#
# **A file named `sure-<version>-aarch64-apple-darwin.tar.gz` is not evidence
# that it holds an ARM binary, and a checksum of it is not evidence that it
# runs.** `macos-latest` is *believed* to be an arm64 image and `ubuntu-latest`
# is *believed* to be x86_64; a belief is not a measurement, and the macOS
# label's meaning has changed before (`macos-13` is Intel, `macos-14` and later
# are Apple Silicon) and will change again. So nothing here reads the runner's
# name:
#
# * the build names its target explicitly — `--target aarch64-apple-darwin` —
#   so the artifact is what the invocation says it is rather than what the host
#   happens to default to, and it would be an arm64 binary even on an Intel
#   runner (Xcode's clang cross-compiles it);
# * the architecture this script *checks* is read from the artifact's own bytes.
#   There are two header families and the check is the family's own:
#
#   Mach-O (the two macOS targets), from the **first eight bytes**: the 4-byte
#   magic and the 4-byte `cputype`. Those are `cf fa ed fe` (64-bit Mach-O,
#   little-endian, the only shape a modern arm64 binary has) and `0c 00 00 01`
#   (`CPU_TYPE_ARM64`) or `07 00 00 01` (`CPU_TYPE_X86_64`).
#
#   ELF (Linux x64), from the **first twenty bytes**: the 4-byte magic
#   `7f 45 4c 46`, `EI_CLASS` at offset 4 and `EI_DATA` at offset 5 — `02 01`
#   is 64-bit little-endian — and `e_machine`, a **2-byte little-endian field
#   at offset 18**, `3e 00` for `EM_X86_64` and `b7 00` for `EM_AARCH64`.
#
#   The bytes read are printed either way, so a reader can check the reading by
#   hand rather than take it on trust;
# * `/usr/bin/file` is asked the same question as a second reader where it
#   exists, its answer is printed, and a disagreement is a failure. It is not
#   the required reader: the header read above is the measurement, and `file`
#   is a second one, so its absence is reported rather than silently tolerated;
# * the runner's own `uname -m` is printed and carried into the log, so a reader
#   can see whether "and it ran" was possible on this machine at all.
#
# =============================================================================
# Why the ELF check reads twenty bytes, and why it is not eight
# =============================================================================
#
# **The Mach-O check's shape cannot be copied to an ELF, and a check built by
# analogy would be a false green.** An ELF's first eight bytes are
# `7f 45 4c 46` (magic), then `EI_CLASS` = `02` (ELFCLASS64), `EI_DATA` = `01`
# (little-endian), `EI_VERSION` = `01` and `EI_OSABI` = `00` (System V) — that
# is `7f454c4602010100`, **and it is identical for an x86_64 ELF and for an
# aarch64 one**. An eight-byte read compared against a fixed expectation would
# therefore accept an arm64 image under `sure-...-x86_64-unknown-linux-gnu.tar.gz`
# and print that it had checked the architecture, which is the exact failure
# this repository exists to refuse. The field that tells the two apart is
# `e_machine` at offset 18, so the read is twenty bytes.
#
# **And it is not a twenty-byte expectation either.** Offsets 16-17 hold
# `e_type`, which is `03 00` for a PIE (`ET_DYN`) and `02 00` for a non-PIE
# (`ET_EXEC`) — the very two shapes the real bytes this was measured against
# carry, `x86_64-unknown-linux-gnu`'s own `/bin/ls` being `03 00`. Which of the
# two a build produces is a property of the linker invocation and not a promise
# this repository has ever made, so a fixed twenty-byte prefix would refuse a
# legitimate artifact for a reason that has nothing to do with architecture.
# What is compared is the **discriminating fields** and nothing else: the magic,
# `EI_CLASS`, `EI_DATA` and `e_machine`. The found and required values are both
# printed, so a refusal says which field disagreed.
#
# **What a thin header read does not say.** It does not say the file is a whole
# executable, and it is not treated as if it did: the checksum ties the archive
# to the bytes that were built, and the run step below is what says the bytes
# execute. A universal ("fat") binary is refused rather than accepted, because
# the build asks for one thin architecture and a fat binary appearing here would
# mean that invocation did not do what it says. The ELF reader refuses a
# Mach-O, a PE, a 32-bit ELF and an ELF whose `e_machine` is not the named
# target's, each by name.
#
# =============================================================================
# Where the bytes each row is measured against came from
# =============================================================================
#
# The Mach-O rows are `P15-T005`'s and `P15-T006`'s: the arm64 bytes are the
# ones CI run `35512934506` shipped, the x86_64 bytes are the
# `x86_64-apple-darwin` `std`'s own dylib, and the receiving direction is a real
# universal (fat) binary and a real PE.
#
# **The Linux rows are not the same kind of evidence, and the difference is
# recorded here rather than left for a reader to discover.** There is no aarch64
# ELF on the machine this was written on — no aarch64 linker and none may be
# installed — so:
#
# * the **accepted** row is a real, linker-produced x86_64 ELF: `cp /bin/ls` out
#   of the WSL Ubuntu installation, 11352352 bytes, SHA-256
#   `48893b0fb21436b54619db80486e83ef39dfccaf1aefe83dfa00c02d6146e8c0`,
#   `ELF 64-bit LSB pie executable, x86-64`. It is an executable rather than
#   this build, which is what a header read is a claim about;
# * the **refused** row of the same width — an aarch64 ELF under an x86_64 name
#   — is **constructed**: the real file above with only its 2-byte `e_machine`
#   at offset 18 changed from `3e 00` to `b7 00`. `file` reads the result as
#   `ELF 64-bit LSB pie executable, ARM aarch64`, so the patch is visible to a
#   second reader and not only to this script's own comparison;
# * two further refused rows are **real** ELF images of other machines, found in
#   this machine's Windows driver store rather than invented: Qualcomm's
#   `bdwlan.elf` (`ELF 32-bit LSB executable, ARM`, `e_machine` `2800`) and its
#   `m3.bin` (`ELF 32-bit LSB executable, Intel i386`, `e_machine` `0300`).
#   They are refused on `EI_CLASS` as well as on `e_machine`.
#
# So the accepted Linux row is real bytes and the arm64-refusal row is a
# constructed pair of bytes, and neither statement is stronger than that. This
# is what `RELEASE_PROCESS.md`'s Linux section records beside the table.
#
# =============================================================================
# How the version is obtained, and why not by running the artifact
# =============================================================================
#
# `docs/development/RELEASE_PROCESS.md` names the archive after the version
# `sure` itself reports. That value has to be read before the archive is named,
# and the artifact cannot be the thing that reports it: on an Intel runner an
# arm64 binary will not execute, and a packaging step that depends on running
# the artifact is a packaging step that fails on a machine where the artifact is
# perfectly good. So the version comes from `cargo run --bin sure -- --version`
# — a build for **this** host, which can run here — and the shape of that output
# is asserted rather than assumed. `cargo run --bin sure` selects the binary
# named `sure`, which is the same selection `Build-Release.ps1` makes through
# `cargo metadata`, and `crates/sure-cli/tests/cli_contract.rs` holds the two
# spellings of the version to the same number.
#
# =============================================================================
# The release gate, and why this script refuses to package without it
# =============================================================================
#
# `sure_core::release_gate`'s `GATE_CONTRACT` is the repository's own statement
# about packaging: "P15 may build, package or publish a release of this checkout
# only when this document's `decision` is `permitted`." This is a P15 packaging
# task and the sentence is not about Windows, so it is a precondition here too
# and not a report: with no gate document, or with a `blocked` one, this script
# produces no artifact.
#
# The document is written by `cargo test -p sure-core --test acceptance_report_runner`,
# which is part of `cargo test --workspace`. That is what makes the presence of a
# `permitted` gate on a fresh CI checkout evidence that the workspace's tests
# ran **on this runner** rather than merely that someone ran them somewhere:
# `target/` does not exist until the job creates it.
#
# This script reads exactly one field of that document, `decision`. It does not
# reproduce the document's corpus summary the way `Build-Release.ps1` does with
# `ConvertFrom-Json`: this script has no JSON parser, and a hand-rolled reader of
# a nested document is the kind of second implementation that agrees with the
# first one until it does not. The document itself is the place to read the rest
# of it.
#
# =============================================================================
# What "builds/tests" means here, and what it deliberately does not
# =============================================================================
#
# `P15-T005`'s acceptance is "aarch64 macOS artifact builds/tests and checksum
# generated in CI/release environment", and there are two readings of "tests",
# the same two `Build-Release.ps1` separates:
#
#   the workspace's tests pass  - about a *debug* build of the host, and about
#                                 the source tree rather than about the bytes in
#                                 the archive. This script does not run them; the
#                                 workflow does, in its own step, where the log
#                                 says so.
#   the artifact is exercised  - this script extracts the archive to a fresh
#                                 directory and runs `sure doctor` from **there**,
#                                 by absolute path, requiring the binary to
#                                 report `running from` **its own path** — the
#                                 executable the archive was extracted into,
#                                 which is a file inside that directory and not
#                                 the directory itself.
#
# The property that makes the second falsifiable is the one the Windows script
# states: **the bytes that are checksummed are the bytes that were run.** It is
# established by the order of the steps — the digest is written, re-read and
# checked, and only then is the archive extracted — and by a second comparison:
# in `--phase all` the `sure` inside the archive is hashed and compared with the
# one cargo built, so a package that silently contained something else reddens.
#
# =============================================================================
# Falsifiability: what was run on the machine that wrote this, and what was not
# =============================================================================
#
# **No macOS artifact was produced on the machine this was written on, and none
# is claimed.** There is no `aarch64-apple-darwin` `std` installed there and no C
# toolchain for it, so `cargo build --workspace --release --locked --target
# aarch64-apple-darwin` stops with rustc's own `E0463`, "the
# `aarch64-apple-darwin` target may not be installed", and independently with
# cc-rs's `failed to find tool "cc"`; both readings are in the log the script
# names. The run reaches the Build step, prints
# `FAILED: cargo build exited 101`, and exits 1. The half of this file that
# produces an artifact runs on a macOS runner or nowhere.
#
# **`P15-T006` asked the same question of the Intel target and got the same
# answer for a different reason.** `x86_64-apple-darwin` is a value this script
# accepts now, so whether *this* host can produce that artifact was measured
# rather than inherited. The `x86_64-apple-darwin` `std` **is** installed here —
# `rustup target list --installed` lists it — so the run gets past the target's
# own absence and stops at the same C dependency the Linux run below stops at:
# a crate's build script compiles C through `cc-rs`, which needs a compiler for
# the target — here one that emits x86_64 Mach-O objects — and a Windows host
# has none. The crate this log names is `ring v0.17.14`, and it is the crate the
# Linux log below names too; the sentence here used to name `libsqlite3-sys`,
# which neither log mentions: `cargo` stops at `ring`'s build script and never
# compiles `libsqlite3-sys`.
#
#   $ cargo build --workspace --release --locked --target x86_64-apple-darwin
#   cargo:warning=Compiler family detection failed due to error:
#     ToolNotFound: failed to find tool "cc": program not found
#   error occurred in cc-rs: failed to find tool "cc": program not found
#   $ echo $?
#   101
#   $ ls target/x86_64-apple-darwin/release/sure
#   ls: cannot access '...': No such file or directory
#
# The full log is `target/tmp/p15t006/local-x86_64-apple-darwin-build.txt` on
# the machine that wrote this and is not committed. So neither macOS artifact is
# built on a Windows host, and for the Intel one the missing piece is a C
# toolchain for the target and not the target itself — the same fact
# `docs/development/GITHUB_WORKFLOW.md` records about cross-target `clippy`.
#
# **`P15-T007` asked it of the Linux target and got the same answer again, this
# time with the C compiler's Linux name in it.** Unlike `aarch64-apple-darwin`,
# the `x86_64-unknown-linux-gnu` `std` **is** installed on that host, so the run
# gets past the target's own absence exactly as the Intel macOS one does:
#
#   $ cargo build --workspace --release --locked --target x86_64-unknown-linux-gnu
#   cargo:warning=Compiler family detection failed due to error: ToolNotFound:
#     failed to find tool "x86_64-linux-gnu-gcc": program not found (see
#     https://docs.rs/cc/latest/cc/#compile-time-requirements for help)
#   error occurred in cc-rs: failed to find tool "x86_64-linux-gnu-gcc":
#     program not found (see https://docs.rs/cc/latest/cc/#compile-time-requirements
#     for help)
#   $ echo $?
#   101
#   $ ls target/x86_64-unknown-linux-gnu/release/sure
#   ls: cannot access '...': No such file or directory
#
# The full log is `target/tmp/p15t007/local-linux-build.txt` on the machine that
# wrote this and is not committed. So the Linux artifact's build half is not run
# here either, for the reason the Intel macOS one is not: a crate's build script
# compiles C through `cc-rs`, and a Windows host has no compiler that emits ELF
# objects. The crate this log names is `ring v0.17.14` — the same one the Intel
# run above names — and the log is where that name is read rather than supplied
# from here. `cargo` stops at the first crate whose build script fails, so this
# says which dependency failed and not that it is the only one that would.
# **That says nothing about the target** — the same
# build on a Linux runner finds `cc` — and the job that runs it is where the
# artifact comes from.
#
# What *was* run there, so that the unrun half is the only unrun half:
#
# * `sh -n` and `dash -n` both parse the whole file, so it is a script and not a
#   text file that looks like one. `dash` is the point of saying so twice: it is
#   what `/bin/sh` is on the Ubuntu runner, and it is a different shell from the
#   one this file was written on.
# * **The whole check path was then run under `dash` and under `sh`, and the two
#   are identical.** Every `--phase verify` row below was run twice, once with
#   each interpreter, into the same output directories; stdout, stderr, exit
#   status and the failure text are byte-identical between the two runs. So the
#   shell the runner uses is not the shell this *parse* check was taken in, and
#   `printf`, `cut`, `od`, `tar` and `sed` were all exercised there rather than
#   inferred to behave the same. What that still does not establish is the same
#   tools under GNU coreutils on Linux: `dash` was run on this host, against
#   this host's programs.
# * The argument surface: `--help` exits 0, `--phase nonsense` exits 2, and each
#   target refusal exits 2 with its reason named — `aarch64-unknown-linux-gnu`,
#   which no artifact of this repository is built for, and an unknown triple by
#   name. `x86_64-unknown-linux-gnu` is no longer among the refusals: it is a
#   value this script builds.
# * The architecture reader, against **real Mach-O bytes** rather than invented
#   ones, in four directions. The installed `x86_64-apple-darwin` `std` supplies
#   a genuine linker-produced Mach-O `sure`; it is refused, with the message
#   naming what was found against what was required. That same binary patched
#   **only** in its 4-byte `cputype` field, `07000001` -> `0c000001`, is
#   accepted, with the eight bytes printed as `cffaedfe0c000001` and `file`'s
#   answer agreeing it is `Mach-O 64-bit arm64`. A real universal ("fat") binary
#   is refused as fat. A real PE is refused as "the Windows artifact shape". So
#   the check is known to refuse three shapes and accept a fourth: it
#   discriminates, and it is not a check that says yes to everything.
# * The architecture reader as a **discriminating** check, in four directions,
#   over archives assembled here from bytes this repository can name. Each row
#   below is one `--phase verify` run; the two middle rows hold bytes of one
#   architecture under the other's name and are the rows that make this a check
#   rather than a spelling:
#
#       archive name          sure's first bytes   Architecture step
#       aarch64-apple-darwin  cffaedfe0c000001     accepted, "Mach-O 64-bit, arm64"
#       x86_64-apple-darwin   cffaedfe07000001     accepted, "Mach-O 64-bit, x86_64"
#       x86_64-apple-darwin   cffaedfe0c000001     refused, "not ... x86_64"
#       aarch64-apple-darwin  cffaedfe07000001     refused, "not ... arm64"
#
#   The arm64 bytes are the real ones `P15-T005`'s CI run shipped, extracted
#   from the archive that run uploaded; the x86_64 bytes are the genuine
#   linker-produced Mach-O named in the target table above. Each refusal prints
#   the bytes it found against the bytes it required, so a reader can see that
#   the two rows differ in the reading and not only in the verdict. Every row
#   exits 1, at the *mode* check and not at this one, for the host reason named
#   below; the Architecture step is read in all four before that happens.
# * The architecture reader's **ELF** half, over real ELF bytes rather than
#   invented ones, with the one row that cannot be real on this machine labelled
#   as constructed. Each row below is one `--phase verify` run, the same shape
#   as the four above:
#
#       archive name                sure's first 20 bytes        step
#       x86_64-unknown-linux-gnu    7f454c4602010100..3e00       accepted, "ELF 64-bit, little-endian, x86_64"
#       x86_64-unknown-linux-gnu    7f454c4602010100..b700       refused, "not ... x86_64"
#       x86_64-unknown-linux-gnu    7f454c4601010161..2800       refused, "ELF 32-bit, little-endian, ARM"
#       x86_64-unknown-linux-gnu    7f454c4601010100..0300       refused, "ELF 32-bit, little-endian, i386"
#       x86_64-unknown-linux-gnu    cffaedfe07000001..           refused, "a Mach-O image"
#       x86_64-unknown-linux-gnu    4d5a9000..                   refused, "a PE image"
#
#   The accepted row is a real one: `/bin/ls` copied out of the WSL Ubuntu
#   installation on this machine, a linker-produced x86_64 ELF, PIE and
#   dynamically linked. Its refusal sibling is that same file with **only** its
#   2-byte `e_machine` field changed, `3e00` -> `b700`, and `file(1)` calls the
#   result `ARM aarch64`. No aarch64 linker exists on that machine and none may
#   be installed, so that row is **constructed**, and it is named as constructed
#   rather than passed off as a real arm64 binary. The ARM32 and i386 rows are
#   **real** objects another vendor shipped (Qualcomm WLAN firmware, and a
#   driver store's `m3.bin`), which is why the two 32-bit refusals are readings
#   rather than spellings. Every row exits 1 at the mode check, for the host
#   reason above, after the Architecture step has printed its reading.
# * The macOS rows, unchanged by this change. All four macOS rows above were run
#   again — through this file as it stood at `HEAD` and as it stands here, into
#   the same output directory so that the printed paths are the same strings —
#   and stdout, stderr and exit status are **byte-identical** for all four
#   (1841, 2201, 1901 and 2195 bytes). `--phase all --target
#   x86_64-apple-darwin` through both files, over the same Mach-O via the
#   stand-in `cargo`, produced two `RELEASE.txt` files of 3540 bytes each that
#   are identical apart from the `built at` timestamp. That is the measurement
#   behind "the macOS text did not move" rather than a reading of the diff:
#   the two family-specific passages below became variables, and a
#   parameterisation that rewrapped the Apple paragraphs would have reproduced
#   the same words in different bytes.
# * The Linux packaging half, end to end, by the same stand-in `cargo`:
#   `--phase all --target x86_64-unknown-linux-gnu` reached the Release gate,
#   the version, the stage, the `RELEASE.txt`, the package, the checksum write
#   (119 bytes, 1 LF, 0 CR), the entry list, the checksum re-read, the
#   extraction and the architecture read, which returned
#   `7f454c4602010100..03003e00` / `ELF 64-bit, little-endian, x86_64` with
#   `file` agreeing, and then stopped at the mode check. As with the Intel row,
#   the stand-in compiles nothing, so this says nothing about whether a real
#   Linux build succeeds; that half belongs to `package-linux`.
# * The arm64 path, unchanged. `--phase verify` over **the artifact CI actually
#   shipped** — `sure-0.0.0-bootstrap-aarch64-apple-darwin.tar.gz`, 4065656
#   bytes, SHA-256
#   `3308bb2c12aee7008ed7734565775e96cc092a6c46c1b2efaea87e6d2c820c23`, from run
#   `35512934506` — run through this file as it stood at `6226ce8` and again as
#   it stands here, both into the same output directory so that the paths the
#   run prints are the same strings. Stdout, stderr and exit status are
#   **byte-identical**: 39 lines of stdout, 0 lines of stderr, status 1 both
#   times. The refusal direction was compared the same way (aarch64 name over
#   x86_64 bytes, above) and is byte-identical too. That is the measurement
#   behind "the arm64 path is unchanged" rather than a reading of the diff.
# * The arm64 `RELEASE.txt`, unchanged in its **bytes** and not merely in its
#   words. `--phase all` was run through the file as it stood at `6226ce8` and
#   again as it stands here, both over the same arm64 binary via a stand-in
#   `cargo` on `PATH`, and the two `RELEASE.txt` files out of the two archives
#   are **3490 bytes each and identical apart from the `built at` timestamp**,
#   which differs by construction. That is the measurement, not the argument,
#   behind the newline carried inside `SIGNATURE_LOAD_NOTE` below: a
#   parameterisation that rewrapped that paragraph would have reproduced the
#   same words in different bytes, and this run is what says it did not.
# * The Intel **packaging** path, end to end, by the same stand-in `cargo`:
#   `--phase all --target x86_64-apple-darwin` over the real x86_64 Mach-O bytes
#   reached the Release gate, the version, the stage, the `RELEASE.txt`, the
#   package, the checksum write (114 bytes, 1 LF, 0 CR), the entry list, the
#   checksum re-read, the extraction and the architecture read, which returned
#   `cffaedfe07000001` / `Mach-O 64-bit, x86_64` with `file` agreeing, and then
#   stopped at the mode check for the host reason below. **That is what found the
#   `_` defect named above**: before the pattern was widened, this run failed at
#   the checksum-shape check with a message about the archive's own name. What
#   the stand-in does not do is compile anything, so the stand-in alone says
#   nothing about whether a real Intel build succeeds; that half is measured
#   instead by `35514769749`, whose `package-macos-intel` job ran the real
#   `cargo build --workspace --release --locked --target x86_64-apple-darwin`
#   and exited 0.
#
# **One line the arm64 path does execute was changed, and it is named here
# rather than left in the diff.** The checksum-shape pattern below was
# `[0-9A-Za-z.+-]` as inherited from `P15-T005`, which does not admit `_`; the
# target `x86_64-apple-darwin` contains one, so *every* Intel archive would have
# been refused at that check with a message about its own name. The fixture run
# above is what found it: the Intel row failed there, and only there, before the
# pattern gained the character. The arm64 output cannot differ from the change,
# because `aarch64-apple-darwin` contains no `_` and the new class is a strict
# superset of the old one — and that argument is a claim about a character class
# rather than a reading, which is why the byte-identical comparison above is the
# evidence offered for it.
# * The packaging half, end to end, by `--phase verify` over archives assembled
#   by hand: the entry list against the promised set, the digest recomputed from
#   the bytes on disk and cross-checked with a second tool, the extraction, and
#   the read of the extracted file. `--phase verify` does not build, which is
#   why it is the half that runs on this host whole.
# * The Signature and Run steps, reached by temporarily deleting the mode check
#   below — one mutation, reverted, the file's digest after the revert being the
#   one it had before. `codesign` is absent there, so that step printed that the
#   run says nothing about signing: that is the absent-tool branch working, and
#   it is **not** the `Authority=` branch being tested. The Run step was then
#   reached with a Mach-O this host cannot execute and failed loudly and
#   correctly — exit 126, `cannot execute binary file: Exec format error`, and a
#   message attributing it to the host rather than to the artifact.
# * The `running from` comparison, corrected here, exercised **directly** with
#   planted inputs rather than through the Run step, which this host cannot
#   reach at all: the extracted binary answering passes; a `sure` in another
#   directory, and one with another name in the extraction directory, both
#   fail with the same message shape; and a path reached through a Windows
#   directory junction passes after folding, which is the macOS
#   `/var` -> `/private/var` shape made with a real reparse point. What that
#   reading did not cover *by itself* was the comparison running inside a whole
#   macOS job — and that gap is now closed rather than left open: `35514769749`
#   ran this file end to end on macOS, `package-macos-intel` reaching the
#   extraction and the Run step with the comparison inside it.
#
# What this host cannot exercise at all, named rather than glossed over:
#
# * **The Run step over a correct artifact, here.** That host is MSYS/Cygwin,
#   where `chmod` is a no-op: an extracted `sure` comes out `-rw-r--r--` even
#   from a tar that records 755, so the mode check below fails for a *correct*
#   archive and nothing after it runs without the mutation above. That is a
#   property of the host, and `35514769749` is what says so rather than assuming
#   it: that job's `== Extract` step printed `same as the sure cargo built` on
#   macOS, so the recorded mode does survive packaging and extraction where
#   `chmod` is real, and the local stop was MSYS and not a packaging defect
#   hiding behind it.
# * **Building an arm64 artifact here.** There is no `aarch64-apple-darwin` `std`
#   on that machine, so the header patch `P15-T005` used to reach the accept case
#   is still the only way to *build* one locally. It is no longer the only way to
#   exercise the accept path over genuine arm64 bytes: `P15-T006` ran
#   `--phase verify` over the binary inside the archive `35512934506` uploaded,
#   which Apple's own toolchain linked, and the reader returned
#   `cffaedfe0c000001` / `Mach-O 64-bit, arm64` over it with `file` agreeing.
# * **The `Authority=` failure branch of the Signature step**, which needs a
#   signature chain to refuse and a `codesign` to read one with.
# * **Every step the Linux target runs after the mode check**: the Signature
#   step's *elf* branch, the Run step and the final verdict line. They are
#   unreachable here for the mode reason above, and no Linux artifact exists
#   yet for any other machine to have run them over. `package-linux` is what
#   runs them, and until it has, "the extracted `sure` runs on Linux and says
#   what it is" is unmeasured for this family.
# * **Anything about Gatekeeper**, which nothing in this repository has observed.
#
# What no machine had exercised, and what changed. **The Intel artifact's Run
# step** used to be listed here, and it is no longer a gap of that kind: run
# `35514769749`'s `package-macos-intel` job, `106088732392`, produced
# `sure-0.0.0-bootstrap-x86_64-apple-darwin.tar.gz` on a native Intel host,
# checksummed it, extracted it, and ran the extracted `sure doctor` **from the
# extraction directory**, which exited 0 and ended `the bytes that are
# checksummed are the bytes that were run`. So an Intel Mac can build and run
# what this project produces for it, and the aarch64 artifact is no longer the
# only macOS artifact that exists — there are two. What stays true is narrower
# than the sentences this block used to carry: nothing is published for either
# architecture, the binary is unsigned and unnotarized, and no second build of
# the same commit has been measured.
#
# A comment claiming the whole file is measured would be the defect this
# repository exists to prevent. So: the build half was not run *here* for any of
# the three targets; the check half was; the Run step over a genuine artifact is
# measured on macOS in CI and is still not reachable on this host, and for the
# Linux target no artifact exists on any machine yet; and the `Authority=`
# branch, Gatekeeper and reproducibility remain unmeasured on every machine.

# =============================================================================
# `set -eu`, and why `pipefail` is not in this line
# =============================================================================
#
# **It was in this line, and it is why the Linux artifact job went red.**
# `P15-T007`, run `35524124026`, job `package-linux`, step "Build, package,
# checksum and check the artifact" — 9 ms after the step started, before the
# release gate was read, before anything was staged or built:
#
#   scripts/Build-Release.sh: 530: set: Illegal option -o pipefail
#   ##[error]Process completed with exit code 2.
#
# The invocation is `sh scripts/Build-Release.sh` (the three artifact jobs in
# `.github/workflows/release-dry-run.yml`), and on that runner `sh` does not
# implement `pipefail`. This is not a defect this task introduced: both the `set`
# line and the shebang are `c522699`'s (`P15-T005`), and they were correct on
# every machine that had run this file before — macOS twice and this Windows
# host — because every `sh` those runs met accepts the option. The `/bin/sh` on
# the Ubuntu runner is the first that does not, and `P15-T007` is what put this
# script on that runner for the first time.
#
# **The measured contrast, so the mechanism is not guessed at.** In the same job
# on the same runner, at step 4, `.github/workflows/release-dry-run.yml` runs
# `set -euo pipefail` inside a `run:` step and that step concluded `success`:
# GitHub executes `run:` steps under bash, where the option is legal. This script
# is the only thing in the job that leaves bash — it is the only thing invoked as
# `sh` — and it is the only thing that failed. So the statement this fix rests on
# is "bash's `pipefail` is not `sh`'s", not "the runner's `sh` is dash", which is
# true but was inferred from an error message's shape rather than measured.
#
# **The lesson is not "also test under dash".** Three shells called `dash` are
# reachable from the machine this was written on, and two of them accept and
# implement `set -o pipefail` (the MSYS one, and WSL Ubuntu 26.04's
# `dash 0.5.12-12ubuntu3`) while the runner's does not. A local run therefore
# cannot see this, and the first hand-back for this task claimed one had seen it.
# What no local run can ever be is the runner's shell; the measurement that
# decides this is the runner's log above.
#
# **What the option was covering, and what covers it now.** `pipefail` makes a
# pipeline's status the failure of any element rather than the status of the
# last one, so dropping it leaves every pipeline whose *left* side can fail while
# its *right* side succeeds reading as a success. The shape in this file was the
# `wc` reading:
#
#   written_bytes="$(wc -c <"$SHA_PATH" | tr -d ' ')"
#
# `wc` failing there does not stop anything: `tr` reads empty input and succeeds,
# the variable holds the empty string, `set -e` sees the pipeline's status (0)
# and continues, and the check that consumes it is
#
#   if [ "$written_bytes" -ne "$expected_bytes" ]; then fail ...; fi
#
# which `test` answers with exit 2 when an operand is empty — measured here under
# `sh`, `dash` and `bash`, all three — and `if` reads any non-zero status as
# false. The check would be **skipped** and the run would walk on to its verdict.
# That is the quieter wrong answer, and it is the trade this repository exists to
# refuse. So every such reading is now taken by `count_of`/`count_char` below:
# the program runs with both streams captured and its status read, `tr` reads the
# file it wrote rather than feeding a pipeline, and a reading that is not a whole
# number is a named failure rather than a zero or an empty string. Every
# remaining pipeline in this file is listed with its reason in the block above
# `count_of`, and the two that are not obviously safe are commented at their own
# lines.
set -eu

usage() {
    cat <<'EOF'
SURE - build, package and check a release artifact for a non-Windows target.

  sh scripts/Build-Release.sh [options]

  --phase all|verify    all (default) builds, packages, checksums and checks.
                        verify re-checks an archive this script already
                        produced and does not build.
  --target TRIPLE       aarch64-apple-darwin, x86_64-apple-darwin or
                        x86_64-unknown-linux-gnu. Those three are the values
                        accepted; any other triple is refused by name.
                        Default: aarch64-apple-darwin, so a run with no
                        --target builds a macOS artifact whatever host it is
                        run on — including a Linux one.
  --output-dir DIR      where the archive, its .sha256 and the scratch
                        extraction go. Default: target/tmp/release.
  --help                this text.
EOF
}

PHASE=all
TARGET=aarch64-apple-darwin
OUTPUT_DIR=''

while [ $# -gt 0 ]; do
    case "$1" in
        --phase)
            [ $# -ge 2 ] || { usage >&2; echo "FAILED: --phase needs a value" >&2; exit 2; }
            PHASE="$2"
            shift 2
            ;;
        --target)
            [ $# -ge 2 ] || { usage >&2; echo "FAILED: --target needs a value" >&2; exit 2; }
            TARGET="$2"
            shift 2
            ;;
        --output-dir)
            [ $# -ge 2 ] || { usage >&2; echo "FAILED: --output-dir needs a value" >&2; exit 2; }
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help | -h)
            usage
            exit 0
            ;;
        *)
            usage >&2
            echo "FAILED: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

case "$PHASE" in
    all | verify) ;;
    *)
        usage >&2
        echo "FAILED: --phase is $PHASE; it is all or verify" >&2
        exit 2
        ;;
esac

# The script's own location, resolved. `cd -P` and `pwd -P` because on macOS
# `/var` is a symlink to `/private/var` and this repository's scratch directory
# can end up under either spelling; a repository root compared as a string would
# then disagree with itself.
SCRIPT_DIR="$(cd -P "$(dirname "$0")" && pwd -P)"
ROOT="$(cd -P "$SCRIPT_DIR/.." && pwd -P)"

if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$ROOT/target/tmp/release"
fi
case "$OUTPUT_DIR" in
    /*) ;;
    *)
        echo "FAILED: --output-dir must be an absolute path: $OUTPUT_DIR" >&2
        exit 2
        ;;
esac
case "$OUTPUT_DIR" in
    */) OUTPUT_DIR="${OUTPUT_DIR%/}" ;;
esac

GATE_PATH="$ROOT/target/tmp/release-gate.json"
MANIFEST_PATH="$ROOT/evaluation/acceptance-manifest.json"
LOGS="$OUTPUT_DIR/logs"
SCRATCH="$OUTPUT_DIR/scratch"
EXTRACT_ROOT="$SCRATCH/extracted"
STAGE_ROOT="$SCRATCH/stage"

# =============================================================================
# The target, and the facts the artifact has to agree with
# =============================================================================
#
# Three members, for the reason `Build-Release.ps1` gives about its own set: a
# script that accepted any triple would happily produce a file named after a
# platform it never built for. Two are a macOS header family and one is the
# Linux one.
#
# **`P15-T007` added the Linux row, and `x86_64-unknown-linux-gnu` stopped being
# a refusal.** The value used to reach the `case` below as a named refusal that
# said the Linux artifact was "not a value this script accepts: this script
# reads a Mach-O header, and an ELF has a different one" — which was true of the
# script and is true of the header, and is exactly why the row added here is not
# the macOS row with different constants. `aarch64-unknown-linux-gnu` is still
# refused, and now for a reason that does not go stale: **no artifact of this
# repository is built for it.** `docs/development/RELEASE_PROCESS.md` lists a
# "Linux x64 CLI archive" and `docs/architecture/RUST_DESIGN.md` names "Linux
# x64"; nothing names an arm64 Linux artifact, no job produces one, and a script
# that accepted the triple would produce a file named for a platform nothing
# here builds.
#
# **The two macOS targets are one code path and one table row apart.** `P15-T006`
# added the second row and changed nothing else: the architecture is read from
# the artifact's own first eight bytes for both, the second reader, the
# extraction, the checksum and the run are the same steps reached the same way,
# and the only values that differ are the four the check compares against. A
# second script for the Intel artifact would have been a second place for those
# reads to drift apart.
#
# **The Linux row is one code path and one table row apart in the same way, and
# the one thing it changes is how many bytes the header read takes.** The
# version read, the stage, the four files inside the archive, the `.sha256`
# format, the entry-list comparison, the extraction, the second reader and the
# run of the extracted binary are the same steps reached the same way. What
# differs is the family: `HEADER_FAMILY` selects the reader, because the two
# families do not merely have different constants — an eight-byte read
# discriminates a Mach-O's architecture and does **not** discriminate an ELF's.
# A sibling script for the Linux artifact would also have been a *third* place
# for the archive contract to drift, and the parts that would have drifted are
# the parts `P15-T005` and `P15-T006` measured.
#
# **`cffaedfe07000001` was confirmed against real bytes before it was written
# here**, because the supervisor's brief said not to trust it and was right not
# to. The real bytes are the `x86_64-apple-darwin` `std`'s own
# `libstd-*.dylib` — shipped by rustup, linked by Apple's own toolchain, and
# therefore a genuine 64-bit little-endian Intel Mach-O rather than a header
# someone typed:
#
#   $ head -c 8 "$HOME/.rustup/toolchains/1.98.1-x86_64-pc-windows-msvc/
#       lib/rustlib/x86_64-apple-darwin/lib/libstd-62092c68b9eb1b56.dylib" \
#     | od -An -tx1
#    cf fa ed fe 07 00 00 01
#
# and this host's own `file(1)` calls the same bytes `Mach-O 64-bit x86_64
# dynamically linked shared library`. The file's SHA-256 is
# `1cab997f5855c6ca803cad73478108c207180b91c84247960f7c52c6f243c150`, so the
# reading is over a file anyone can name again. `cf fa ed fe` is `MH_MAGIC_64`
# little-endian and `07 00 00 01` is `CPU_TYPE_X86_64` little-endian; both were
# read off the file rather than recalled.
#
# **`3e00` for the Linux row was read off real bytes the same way**, because a
# header constant taken from memory is the defect this file exists to refuse.
# The file is WSL Ubuntu's own `/bin/ls`, copied out with `cp` rather than piped
# through `cat` — a pipe produced a zero-byte file here, which is the shape of
# evidence that says nothing:
#
#   $ od -An -tx1 -N20 target/tmp/p15t007/bytes/sure-x86_64-real
#    7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
#    03 00 3e 00 ...
#   $ file -b target/tmp/p15t007/bytes/sure-x86_64-real
#   ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
#   interpreter /lib64/ld-linux-x86-64.so.2, ..., for GNU/Linux 3.2.0, stripped
#
# 11352352 bytes, SHA-256
# `48893b0fb21436b54619db80486e83ef39dfccaf1aefe83dfa00c02d6146e8c0`. Note
# `03 00` at offsets 16-17: that is `e_type` = `ET_DYN`, a PIE, which is why
# `e_type` is one of the fields this check deliberately does **not** compare.
#
# **`EXPECT_ARCH` is not a guess either.** The run step below requires the
# artifact to describe itself as built for `$EXPECT_OS $EXPECT_ARCH`, and those
# two words come from `std::env::consts::OS` and `std::env::consts::ARCH`
# (`crates/sure-core/src/doctor.rs`), which are the `target_os` and
# `target_arch` cfgs of the target the binary was built for. `rustc --print cfg
# --target <T>` prints the strings that will be compiled in:
#
#   x86_64-apple-darwin        target_arch="x86_64"   target_os="macos"
#   aarch64-apple-darwin       target_arch="aarch64"  target_os="macos"
#   x86_64-unknown-linux-gnu   target_arch="x86_64"   target_os="linux"
#
# so `macos x86_64` and `linux x86_64` are measurements of the targets rather
# than spellings chosen here. Note that `file(1)`'s word for the same cputype is
# different again (`arm64`, not `aarch64`; `x86-64` with a hyphen, not `x86_64`),
# which is why the second reader has its own value rather than being compared
# against `EXPECT_ARCH`.
case "$TARGET" in
    aarch64-apple-darwin)
        HEADER_FAMILY='macho'
        EXPECT_OS='macos'
        EXPECT_ARCH='aarch64'
        EXPECT_MACHO_BYTES='cffaedfe0c000001'
        EXPECT_MACHO_DESCRIPTION='Mach-O 64-bit, arm64'
        EXPECT_FILE_ARCH='arm64'
        ARTIFACT_LABEL='macOS Apple Silicon'
        ARTIFACT_MACHINES='Apple Silicon Macs'
        # **The newline in this value is deliberate and is not a typo.** It is
        # the line break the shipped aarch64 `RELEASE.txt` already carries, put
        # inside the value so that parameterising this sentence cannot silently
        # rewrap a paragraph of an artifact `P15-T005` already produced. A
        # value that is one long line would reproduce the same *words* and
        # different *bytes*, and this change's whole claim about the arm64 path
        # is that it is unchanged rather than merely equivalent.
        SIGNATURE_LOAD_NOTE='which the toolchain applies so
that the kernel will load the image'
        ;;
    x86_64-apple-darwin)
        HEADER_FAMILY='macho'
        EXPECT_OS='macos'
        EXPECT_ARCH='x86_64'
        EXPECT_MACHO_BYTES='cffaedfe07000001'
        EXPECT_MACHO_DESCRIPTION='Mach-O 64-bit, x86_64'
        EXPECT_FILE_ARCH='x86_64'
        ARTIFACT_LABEL='macOS Intel'
        ARTIFACT_MACHINES='Intel Macs'
        # Not the arm64 sentence: that one gives the *reason* the toolchain
        # applies an ad-hoc signature, and an arm64 Mach-O needs one before the
        # kernel will load it where an x86_64 one is not known here to. What is
        # claimed for the Intel artifact is only what is measured somewhere in
        # this repository — that the reading happens and how to read it.
        SIGNATURE_LOAD_NOTE='which the toolchain may apply; whether macOS requires an Intel binary to carry one
before it will load it has not been measured here'
        ;;
    x86_64-unknown-linux-gnu)
        HEADER_FAMILY='elf'
        EXPECT_OS='linux'
        EXPECT_ARCH='x86_64'
        # The four discriminating fields. They are four values rather than one
        # twenty-byte string, and the reason is in this file's header: offsets
        # 16-17 hold `e_type`, `03 00` for a PIE and `02 00` for a non-PIE, and
        # which one a build produces is the linker's business rather than a
        # promise this repository has made. A fixed twenty-byte expectation
        # would refuse a legitimate artifact for a reason that has nothing to do
        # with architecture.
        EXPECT_ELF_MAGIC='7f454c46'
        EXPECT_ELF_CLASS='02'     # ELFCLASS64
        EXPECT_ELF_DATA='01'      # ELFDATA2LSB, little-endian
        EXPECT_ELF_MACHINE='3e00' # EM_X86_64, little-endian, at offset 18
        EXPECT_ELF_DESCRIPTION='ELF 64-bit, little-endian, x86_64'
        # `file(1)`'s word, which is not the triple's. Measured with both the
        # `file` on this Windows host (file-5.48) and WSL Ubuntu's (file-5.46),
        # which agree: `ELF 64-bit LSB pie executable, x86-64, ...`.
        EXPECT_FILE_ARCH='x86-64'
        ARTIFACT_LABEL='Linux x64'
        ARTIFACT_MACHINES='x86_64 Linux machines'
        ;;
    aarch64-unknown-linux-gnu)
        echo "FAILED: $TARGET is not a target any artifact of this repository is built for." >&2
        echo "The Linux artifact this repository commits to is x86_64-unknown-linux-gnu" >&2
        echo "(docs/development/RELEASE_PROCESS.md, docs/architecture/RUST_DESIGN.md), no job" >&2
        echo "produces an arm64 Linux archive, and this script will not produce a file named" >&2
        echo "after a platform nothing here builds. Nothing was built." >&2
        exit 2
        ;;
    *)
        echo "FAILED: unknown target: $TARGET" >&2
        echo "The values this script accepts are aarch64-apple-darwin, x86_64-apple-darwin" >&2
        echo "and x86_64-unknown-linux-gnu." >&2
        exit 2
        ;;
esac

# =============================================================================
# Output, and the two rules that make a failure readable
# =============================================================================

step() {
    printf '\n== %s\n' "$1"
}

detail() {
    printf '   %s\n' "$1"
}

fail() {
    printf '\nFAILED: %s\n' "$1"
    exit 1
}

# Run one program with a typed argument array and both streams sent to files.
#
# Returns the exit status; never prints or throws on the text. **No exit status
# is read out of a pipeline here**, for the reason `Build-Release.ps1` records: a
# Windows capture once produced a wrong number about a child process by taking
# it from one. The status is `$?` on the line after the call and nowhere else,
# and the text a reader sees is read back from a file.
#
# Since `set -o pipefail` was removed from this script, that rule covers the
# *values* too and not only the statuses: a program whose output this script
# decides on is run through `run_captured` and read back from the file it wrote,
# never through a pipeline, because without `pipefail` a pipeline reports its
# last element's status and the earlier element's failure disappears into an
# empty value. `count_of` below is where that happens for every number; the
# pipelines this script still holds and why each is a different thing are listed
# in the block above `count_of`.
#
# `set +e` around the call is deliberate and is the only place this script turns
# it off: without it a failing program would abort the shell before the caller
# could name which program failed and print its stderr.
run_captured() {
    local program="$1"
    local out="$2"
    local err="$3"
    shift 3
    rm -f "$out" "$err"
    set +e
    "$program" "$@" >"$out" 2>"$err"
    local status=$?
    set -e
    return "$status"
}

# A program on PATH, or nothing. Used for the readers that are not required.
have() {
    command -v "$1" >/dev/null 2>&1
}

# -----------------------------------------------------------------------------
# Numbers, read from a program rather than out of a pipeline
# -----------------------------------------------------------------------------
#
# **Every number this script compares or prints is read by one of these two, and
# that is what took over the job `set -o pipefail` was doing before it was
# removed.** The line this replaces was, four times over,
#
#   written_bytes="$(wc -c <"$SHA_PATH" | tr -d ' ')"
#
# and the hazard is not cosmetic. Without `pipefail` a pipeline's status is its
# *last* element's, so a `wc` that failed — a file that vanished between two
# lines, a permission that changed, a `wc` that is not the one this script
# thinks it is — leaves `tr` reading empty input and succeeding. The pipeline
# reports 0, `set -e` continues, and the variable holds the empty string. The
# check that consumes it is `[ "$written_bytes" -ne "$expected_bytes" ]`, and
# `test` answers an empty operand with **exit 2**, which `if` reads as false:
# the check is *skipped* and the run walks on to its verdict. Measured here under
# `sh`, `dash` and `bash`, all three. A red job, which is what removing
# `pipefail` risks on a bad day, is the acceptable failure; a check that silently
# does not run is not.
#
# So a count is taken the way every other reading in this file is taken: the
# program runs with both streams captured and its status read, and the text is
# read back from the file it wrote. `tr` then reads *that file* rather than
# feeding a pipeline, so there is no pipeline left to have a status. And the
# reading is refused unless it is a whole number, because an empty or
# unparsable value is precisely what the skipped check above was made of.
#
# The pipelines that remain in this file, and why each is not this hazard:
#
#   digest fold (`digest_of`)      `printf '%s' "$DIGEST" | tr 'A-F' 'a-f'` — the
#                                  left side is the shell's own `printf` writing
#                                  a 64-character string, and the value is
#                                  refused immediately after unless it is 64
#                                  hex characters, so a short read is a failure
#                                  with a name and not a digest.
#   header reads (both readers)    `printf '%s' "$HEADER_BYTES" | cut -c...` —
#                                  `cut` is the last element, so a `cut` that
#                                  fails is the pipeline's status and `set -e`
#                                  stops on it; every value is then compared
#                                  against a constant, so a truncated read is a
#                                  refusal rather than agreement.
#   layout, `running from`         `sed ... | sort` and `sed ... | head -n 1` —
#                                  left sides that could only fail if the file
#                                  they read were gone, and each has a consumer
#                                  that turns an empty result into a named
#                                  failure (`cmp` against the promised entry
#                                  list; the `-z` check on `reported_from`).
#                                  Neither can report success over a failed
#                                  producer, which is the property that matters.
#
# `count_of <flag> <path> <label>` - one `wc` reading of one file, status read
# and value shape-checked. Sets COUNT.
count_of() {
    local flag="$1"
    local path="$2"
    local label="$3"
    local out="$LOGS/wc-$label.txt"
    local err="$LOGS/wc-$label.err.txt"
    if [ ! -f "$path" ]; then
        fail "there is no file at $path for wc $flag to read, so this run has no $label"
    fi
    local status=0
    run_captured wc "$out" "$err" "$flag" <"$path" || status=$?
    if [ $status -ne 0 ]; then
        fail "wc $flag exited $status on $path, so this run has no $label. Where wc ran, its stderr is $err."
    fi
    COUNT="$(tr -d ' \t\r\n' <"$out")"
    case "$COUNT" in
        '' | *[!0-9]*)
            fail "wc $flag printed '$COUNT' for $path, which is not a whole number and not one this script will print in a sentence or compare"
            ;;
    esac
}

# `count_char <char> <path> <label>` - how many bytes of one character a file
# holds, in two status-checked steps rather than in one three-stage pipeline:
# `tr -dc` writes the characters it matched to a file, `count_of -c` reads that
# file. Sets COUNT.
count_char() {
    local char="$1"
    local path="$2"
    local label="$3"
    local out="$LOGS/chars-$label.txt"
    local err="$LOGS/chars-$label.err.txt"
    if [ ! -f "$path" ]; then
        fail "there is no file at $path to count '$char' in, so this run has no $label"
    fi
    local status=0
    run_captured tr "$out" "$err" -dc "$char" <"$path" || status=$?
    if [ $status -ne 0 ]; then
        fail "tr exited $status reading $path for '$char', so this run has no $label. Its stderr is $err."
    fi
    count_of -c "$out" "$label"
}

# `require_whole_number <value> <what>` - the same shape check, for a number
# this script already holds in a variable and reads a status for by other means.
# It exists for the two readings that are counts and not `wc` output, so that
# "every number this script compares is a number" is a rule with no exceptions
# to remember.
require_whole_number() {
    case "$1" in
        '' | *[!0-9]*)
            fail "$2 is '$1', which is not a whole number; a number this script could not read is a check this script will not skip"
            ;;
    esac
}

COUNT=''

# -----------------------------------------------------------------------------
# The digest. One value, from one tool, printed with the name of the tool.
# -----------------------------------------------------------------------------
#
# `sha256sum` is not part of a macOS base install — it arrives with GNU
# coreutils — and `shasum` is, so the tool is discovered rather than assumed.
# Whichever is used is printed, because "the digest is X" without "computed by
# Y" is a number with nothing behind it.
#
# The extraction takes everything before the first space of the tool's first
# line: `sha256sum` writes `<hex>  <name>` for a text-mode read and
# `<hex> *<name>` for a binary-mode one, and **which of the two it writes is the
# platform's, not this script's** — on Git for Windows all three tools below
# print the `*` form, measured here, because MSYS opens files in binary mode.
# `openssl dgst -sha256 -r` writes `<hex> *<name>` everywhere. Only the hex is
# taken from these lines, so the separator is not part of any decision.
#
# The value is then required to be exactly 64 lowercase hex characters, so a
# tool that printed something else fails the check rather than producing a
# `.sha256` file holding the wrong shape.
digest_tool=''
second_digest_tool=''

choose_digest_tools() {
    local candidate
    for candidate in sha256sum shasum openssl; do
        if have "$candidate"; then
            if [ -z "$digest_tool" ]; then
                digest_tool="$candidate"
            else
                second_digest_tool="$candidate"
                break
            fi
        fi
    done
    if [ -z "$digest_tool" ]; then
        fail "none of sha256sum, shasum or openssl is on PATH, so no digest can be computed here"
    fi
}

# `digest_of <path> <label>` - sets DIGEST.
#
# `DIGEST_ERROR` is the first line of the tool's stderr when it failed, and
# `DIGEST_FAILS_FATALLY` decides what a failure in the tool means here. It is 1
# for every call whose value is the digest the artifact is named by, and 0 for
# the cross-check below, where a second tool erroring is reported as "this run
# has one measurement" rather than as a failure of the archive.
#
# **Why the cross-check is tolerant, and this is a judgement rather than a
# measurement.** The second tool on a macOS runner is `openssl`, whose
# coreutils-format flag (`dgst -sha256 -r`) is the reason it is used, and
# nothing here can run it: this script was developed on Windows, which has no
# macOS. Making its failure fatal would let one unsupported flag redden the only
# run that produces the artifact — a false red on the one job whose whole
# purpose is to say what the bytes are. A *disagreement* between two tools that
# both answered is still fatal, which is the check that matters, and the tool
# whose value names the artifact is always fatal on failure.
DIGEST=''
DIGEST_ERROR=''
DIGEST_FAILS_FATALLY=1

digest_of() {
    local path="$1"
    local label="$2"
    local out="$LOGS/digest-$label.txt"
    local err="$LOGS/digest-$label.err.txt"
    local status=0
    case "$digest_tool" in
        sha256sum) run_captured sha256sum "$out" "$err" -- "$path" || status=$? ;;
        shasum) run_captured shasum "$out" "$err" -a 256 -- "$path" || status=$? ;;
        openssl) run_captured openssl "$out" "$err" dgst -sha256 -r "$path" || status=$? ;;
    esac
    DIGEST_ERROR=''
    if [ $status -ne 0 ]; then
        DIGEST_ERROR="$(head -n 1 "$err" 2>/dev/null || true)"
        if [ "$DIGEST_FAILS_FATALLY" -eq 1 ]; then
            printf '   %s\n' "stderr      $DIGEST_ERROR"
            fail "$digest_tool exited $status on $path; its stderr is $err"
        fi
        return 1
    fi
    local line
    line="$(head -n 1 "$out")"
    DIGEST="${line%% *}"
    # Upper case would be a different string for the same value, so it is folded
    # rather than accepted: `RELEASE_PROCESS.md` and `sha256sum -c` both say
    # lowercase, and a `.sha256` that a verification tool rejects over its case
    # is a file that does not work for the reason it exists.
    DIGEST="$(printf '%s' "$DIGEST" | tr 'A-F' 'a-f')"
    printf '%s\n' "$DIGEST" >"$LOGS/digest-$label.hex.txt"
    if ! grep -Eq '^[0-9a-f]+$' "$LOGS/digest-$label.hex.txt"; then
        fail "$digest_tool printed a digest this script does not recognise: '$line'"
    fi
    if [ "${#DIGEST}" -ne 64 ]; then
        fail "$digest_tool printed ${#DIGEST} hex characters, and SHA-256 is 64: '$line'"
    fi
}

# The same value from a *different* implementation, where a second one exists.
#
# This is not decoration. Two tools written by different people agreeing on one
# file is a stronger statement than one tool's output, and the class of defect
# it catches is exactly the one a checksum exists to catch: a file that changed
# between the write and the read. `Build-Release.ps1` gets its second reading
# from the clock (write, then re-read) because Windows has one hashing API; here
# there can be two implementations, so there are.
cross_check_digest() {
    local path="$1"
    local label="$2"
    local expected="$3"
    if [ -z "$second_digest_tool" ]; then
        detail "agree       no second digest tool on PATH, so this run has one measurement and not two"
        return 0
    fi
    local saved=''
    saved="$digest_tool"
    digest_tool="$second_digest_tool"
    local read_status=0
    DIGEST_FAILS_FATALLY=0
    digest_of "$path" "$label-second" || read_status=$?
    DIGEST_FAILS_FATALLY=1
    local other=''
    other="$DIGEST"
    digest_tool="$saved"
    if [ "$read_status" -ne 0 ]; then
        detail "agree       $second_digest_tool exited $read_status and produced no reading ($DIGEST_ERROR), so this run has one measurement of the digest and not two"
        return 0
    fi
    if [ "$other" != "$expected" ]; then
        fail "$digest_tool and $second_digest_tool disagree about $path: $expected against $other"
    fi
    detail "agree       $second_digest_tool computed the same digest"
}

# -----------------------------------------------------------------------------
# The architecture, from the file's own header bytes
# -----------------------------------------------------------------------------
#
# `od` is the POSIX byte dumper and is in a macOS base install. `-An` drops the
# address column, `-tx1` prints one hex byte per field, `-N` reads a fixed
# number of them. The output is written to a file and read back, and the
# whitespace is stripped by `tr` reading from that file rather than from the
# `od` output on a pipe.
#
# **The Mach-O read is eight bytes and the ELF read is twenty, and the
# difference is not tidiness.** Eight bytes are the whole of what discriminates
# a Mach-O's architecture — the 4-byte magic and the 4-byte cputype — and they
# are not the whole of what discriminates an ELF's: the first eight bytes of an
# ELF are `7f454c4602010100` for an x86_64 image and for an aarch64 one alike,
# and the machine is two bytes at offset 18. Widening the Mach-O read would
# change the bytes this script has already printed over artifacts `P15-T005` and
# `P15-T006` measured, so the two reads are separate and each is the length its
# own header needs.
HEADER_BYTES=''
HEADER_DESCRIPTION=''
FILE_READING=''

read_macho_header() {
    local path="$1"
    local out="$LOGS/macho-header.txt"
    local err="$LOGS/macho-header.err.txt"
    if [ ! -f "$path" ]; then
        fail "there is no file at $path to read a Mach-O header from"
    fi
    local status=0
    run_captured od "$out" "$err" -An -tx1 -N8 "$path" || status=$?
    if [ $status -ne 0 ]; then
        fail "od exited $status reading $path; its stderr is $err"
    fi
    HEADER_BYTES="$(tr -d ' \t\r\n' <"$out")"
    if [ -z "$HEADER_BYTES" ]; then
        fail "$path is empty, so it has no Mach-O header and is not an executable"
    fi

    # The first eight characters are the magic; the second eight are the CPU
    # type. Both are read as bytes on disk rather than through any tool's prose.
    #
    # Both lines are pipelines, and neither is the shape `pipefail` was covering:
    # `cut` is the last element, so a `cut` that fails *is* the pipeline's status
    # and `set -e` stops here; the left element is the shell's own `printf`
    # writing a string this script already holds, with no file to fail on; and
    # both values are compared against constants below, so a truncation is a
    # refusal and never agreement.
    local magic=''
    local cpu=''
    magic="$(printf '%s' "$HEADER_BYTES" | cut -c1-8)"
    cpu="$(printf '%s' "$HEADER_BYTES" | cut -c9-16)"

    case "$magic" in
        cffaedfe)
            case "$cpu" in
                0c000001) HEADER_DESCRIPTION='Mach-O 64-bit, arm64' ;;
                07000001) HEADER_DESCRIPTION='Mach-O 64-bit, x86_64' ;;
                *) HEADER_DESCRIPTION="Mach-O 64-bit, cputype 0x$cpu" ;;
            esac
            ;;
        cefaedfe) HEADER_DESCRIPTION='Mach-O 32-bit, which no macOS release artifact is' ;;
        cafebabe) HEADER_DESCRIPTION='a universal (fat) binary, or a Java class file' ;;
        bebafeca) HEADER_DESCRIPTION='a universal (fat) binary, little-endian magic' ;;
        4d5a*) HEADER_DESCRIPTION='a PE image, which is the Windows artifact shape' ;;
        # The magic only. This line used to be the whole of the ELF answer here,
        # and it is true and says nothing about the machine — which is why the
        # ELF reader below exists rather than this one being widened. In this
        # family the verdict is a refusal whatever the machine is: no ELF is a
        # macOS artifact.
        7f454c46) HEADER_DESCRIPTION='an ELF image, which is the Linux artifact shape' ;;
        *) HEADER_DESCRIPTION="no Mach-O magic at all (first bytes: $HEADER_BYTES)" ;;
    esac
}

# The ELF reader. Same shape as the Mach-O one, twenty bytes of input, and the
# four fields it compares are the four that are about the architecture.
#
# The offsets are named here because they are the whole subject of this
# function: byte 0-3 magic, byte 4 `EI_CLASS`, byte 5 `EI_DATA`, and byte 18-19
# `e_machine`, which is 2 bytes little-endian on the only byte order any ELF
# this script accepts can have. `e_type` at bytes 16-17 is read past and
# deliberately not compared.
ELF_MAGIC=''
ELF_CLASS=''
ELF_DATA=''
ELF_MACHINE=''

read_elf_header() {
    local path="$1"
    local out="$LOGS/elf-header.txt"
    local err="$LOGS/elf-header.err.txt"
    if [ ! -f "$path" ]; then
        fail "there is no file at $path to read an ELF header from"
    fi
    local status=0
    run_captured od "$out" "$err" -An -tx1 -N20 "$path" || status=$?
    if [ $status -ne 0 ]; then
        fail "od exited $status reading $path; its stderr is $err"
    fi
    HEADER_BYTES="$(tr -d ' \t\r\n' <"$out")"
    if [ -z "$HEADER_BYTES" ]; then
        fail "$path is empty, so it has no ELF header and is not an executable"
    fi

    # Two hex characters per byte, so byte n is characters 2n+1 to 2n+2. A file
    # shorter than twenty bytes leaves the later of these empty, and an empty
    # value is refused below rather than read as agreement: `cut` on a line that
    # ran out is not an error and produces no output.
    #
    # Each line is a pipeline for the same reason and with the same answer as the
    # Mach-O reader above: `cut` is the last element and its status is the
    # pipeline's, the left element is `printf` over a variable, and every field
    # is compared against a constant — so `pipefail` had nothing to add here.
    ELF_MAGIC="$(printf '%s' "$HEADER_BYTES" | cut -c1-8)"
    ELF_CLASS="$(printf '%s' "$HEADER_BYTES" | cut -c9-10)"
    ELF_DATA="$(printf '%s' "$HEADER_BYTES" | cut -c11-12)"
    ELF_MACHINE="$(printf '%s' "$HEADER_BYTES" | cut -c37-40)"

    local class_word=''
    case "$ELF_CLASS$ELF_DATA" in
        0201) class_word='ELF 64-bit, little-endian' ;;
        0202) class_word='ELF 64-bit, big-endian' ;;
        0101) class_word='ELF 32-bit, little-endian' ;;
        0102) class_word='ELF 32-bit, big-endian' ;;
        *) class_word="ELF with EI_CLASS 0x$ELF_CLASS and EI_DATA 0x$ELF_DATA" ;;
    esac

    local machine_word=''
    case "$ELF_MACHINE" in
        3e00) machine_word='x86_64' ;;
        b700) machine_word='aarch64' ;;
        0300) machine_word='i386' ;;
        2800) machine_word='ARM' ;;
        '') machine_word='no e_machine, because the file is shorter than 20 bytes' ;;
        *) machine_word="e_machine 0x$ELF_MACHINE" ;;
    esac

    case "$ELF_MAGIC" in
        7f454c46)
            HEADER_DESCRIPTION="$class_word, $machine_word"
            ;;
        cffaedfe | cefaedfe) HEADER_DESCRIPTION='a Mach-O image, which is the macOS artifact shape' ;;
        cafebabe | bebafeca) HEADER_DESCRIPTION='a universal (fat) binary, or a Java class file' ;;
        4d5a*) HEADER_DESCRIPTION='a PE image, which is the Windows artifact shape' ;;
        *) HEADER_DESCRIPTION="no ELF magic at all (first bytes: $HEADER_BYTES)" ;;
    esac
}

# The second reader, where one exists. Its absence is reported rather than
# passed over: a machine with no `file` has one measurement of this file and a
# reader should know that from the log rather than infer it.
#
# One implementation for both families, because it is the same question. What
# differs per target is the word the answer is held to, and that is
# `EXPECT_FILE_ARCH` rather than a second check.
require_file_reading() {
    local path="$1"
    local label="$2"
    if have file; then
        local out="$LOGS/file-$label.txt"
        local err="$LOGS/file-$label.err.txt"
        local status=0
        run_captured file "$out" "$err" -b "$path" || status=$?
        if [ $status -ne 0 ]; then
            fail "file exited $status on $path; its stderr is $err"
        fi
        FILE_READING="$(head -n 1 "$out")"
        detail "file says   $FILE_READING"
        # `$EXPECT_FILE_ARCH` and not `$EXPECT_ARCH`: `file` words a machine
        # differently from the triple — it says `arm64` where the triple says
        # `aarch64`, and `x86-64` where the triple says `x86_64` — so the second
        # reader is held to the word it actually uses.
        case "$FILE_READING" in
            *"$EXPECT_FILE_ARCH"*) ;;
            *)
                fail "file reads $path as '$FILE_READING', which does not name $EXPECT_FILE_ARCH, and the header read above says $HEADER_DESCRIPTION. Two readers disagree and neither is overridden: $out"
                ;;
        esac
    else
        detail 'file says   (no file on PATH on this runner; the header read above is the measurement)'
    fi
}

# `require_macho_arch <path> <label>` - the whole check, in one place, so that
# both phases reach it and neither can be run without it.
require_macho_arch() {
    local path="$1"
    read_macho_header "$path"
    detail "header      $HEADER_BYTES"
    detail "reads as    $HEADER_DESCRIPTION"
    if [ "$HEADER_BYTES" != "$EXPECT_MACHO_BYTES" ]; then
        printf '\n' >&2
        printf 'FAILED: the bytes in %s are not %s.\n' "$path" "$EXPECT_MACHO_DESCRIPTION" >&2
        printf '\n' >&2
        printf '  found     %s (%s)\n' "$HEADER_DESCRIPTION" "$HEADER_BYTES" >&2
        printf '  required  %s (%s)\n' "$EXPECT_MACHO_DESCRIPTION" "$EXPECT_MACHO_BYTES" >&2
        printf '\n' >&2
        printf 'The name of the archive says %s and the header says something else, so the\n' "$TARGET" >&2
        printf 'name would be a claim about bytes that do not carry it. Nothing was run.\n' >&2
        printf 'A universal (fat) binary is refused even when one of its slices is %s: the\n' "$EXPECT_FILE_ARCH" >&2
        printf 'build asks for one thin architecture, so a fat image here would mean the\n' >&2
        printf 'invocation did not do what it says rather than that the artifact is better.\n' >&2
        printf 'The first eight bytes are read directly rather than through a tool, so this\n' >&2
        printf 'reading does not depend on how any tool words its answer.\n' >&2
        exit 1
    fi
    require_file_reading "$path" "$2"
}

# `require_elf_arch <path> <label>` - the same thing for the other family, and
# the four fields are compared one at a time rather than as one twenty-byte
# string. The reason is in this file's header and it is the difference between a
# check and a spelling: a twenty-byte comparison would include `e_type`, so it
# would refuse a legitimate non-PIE artifact over a linker detail, and the row
# this exists to refuse — an arm64 image under an x86_64 name — differs from the
# accepted row in exactly one of these four fields and in none of the others.
require_elf_arch() {
    local path="$1"
    read_elf_header "$path"
    detail "header      $HEADER_BYTES"
    detail "reads as    $HEADER_DESCRIPTION"
    detail "fields      magic $ELF_MAGIC, EI_CLASS $ELF_CLASS, EI_DATA $ELF_DATA, e_machine $ELF_MACHINE"
    if [ "$ELF_MAGIC" != "$EXPECT_ELF_MAGIC" ] ||
        [ "$ELF_CLASS" != "$EXPECT_ELF_CLASS" ] ||
        [ "$ELF_DATA" != "$EXPECT_ELF_DATA" ] ||
        [ "$ELF_MACHINE" != "$EXPECT_ELF_MACHINE" ]; then
        printf '\n' >&2
        printf 'FAILED: the bytes in %s are not %s.\n' "$path" "$EXPECT_ELF_DESCRIPTION" >&2
        printf '\n' >&2
        printf '  found     %s (%s)\n' "$HEADER_DESCRIPTION" "$HEADER_BYTES" >&2
        printf '  required  %s (magic %s, EI_CLASS %s, EI_DATA %s, e_machine %s)\n' \
            "$EXPECT_ELF_DESCRIPTION" "$EXPECT_ELF_MAGIC" "$EXPECT_ELF_CLASS" "$EXPECT_ELF_DATA" "$EXPECT_ELF_MACHINE" >&2
        printf '\n' >&2
        printf '  magic       found %s   required %s   bytes 0-3\n' "$ELF_MAGIC" "$EXPECT_ELF_MAGIC" >&2
        printf '  EI_CLASS    found %s         required %s         byte 4, ELFCLASS64\n' "$ELF_CLASS" "$EXPECT_ELF_CLASS" >&2
        printf '  EI_DATA     found %s         required %s         byte 5, ELFDATA2LSB\n' "$ELF_DATA" "$EXPECT_ELF_DATA" >&2
        printf '  e_machine   found %s       required %s       bytes 18-19, EM_X86_64\n' "$ELF_MACHINE" "$EXPECT_ELF_MACHINE" >&2
        printf '\n' >&2
        printf 'The name of the archive says %s and the header says something else, so the\n' "$TARGET" >&2
        printf 'name would be a claim about bytes that do not carry it. Nothing was run.\n' >&2
        printf 'The first eight bytes of an ELF are 7f454c4602010100 for an x86_64 image and\n' >&2
        printf 'for an aarch64 one alike: the machine is e_machine, two bytes at offset 18.\n' >&2
        printf 'That is why twenty bytes are read here and why the fields above are compared\n' >&2
        printf 'one at a time; a check that stopped at eight would accept an arm64 image\n' >&2
        printf 'under a name that says x86_64, and report that it had checked.\n' >&2
        printf 'e_type, at bytes 16-17, is deliberately not compared: 0300 is a PIE and 0200\n' >&2
        printf 'is not, and which one a build produces is the linker invocation and not a\n' >&2
        printf 'promise this repository has made.\n' >&2
        printf 'The bytes are read directly rather than through a tool, so this reading does\n' >&2
        printf 'not depend on how any tool words its answer.\n' >&2
        exit 1
    fi
    require_file_reading "$path" "$2"
}

# `require_arch <path> <label>` - the family's own check, chosen by the target
# table. The Architecture step calls this and neither reader directly, so a
# target cannot reach one phase without the check the other phase gets.
require_arch() {
    case "$HEADER_FAMILY" in
        macho) require_macho_arch "$1" "$2" ;;
        elf) require_elf_arch "$1" "$2" ;;
        *)
            fail "the target table names header family '$HEADER_FAMILY', which is neither macho nor elf, so this script has no architecture check for $TARGET and will not proceed without one"
            ;;
    esac
}

# =============================================================================
# Start
# =============================================================================

printf 'SURE release artifact (%s)\n' "$ARTIFACT_LABEL"
printf '  repository  %s\n' "$ROOT"
printf '  target      %s\n' "$TARGET"
printf '  output      %s\n' "$OUTPUT_DIR"
printf '  phase       %s\n' "$PHASE"
printf '  this host   %s %s\n' "$(uname -s)" "$(uname -m)"

# `logs/` is created here, where both phases reach it, and not inside the `all`
# branch. `Build-Release.ps1`'s Mutation 3 is exactly this line moved into the
# branch it was once in: a `verify` into a directory holding only an archive and
# its checksum then died inside the redirection *after* the checksum had matched
# and the archive had extracted, so a good artifact in a fresh directory was
# reported as FAILED. `target/tmp/release` passed only because an earlier `all`
# had left a `logs/` behind in it.
mkdir -p "$LOGS"

choose_digest_tools
if [ -n "$second_digest_tool" ]; then
    detail "digest      $digest_tool, cross-checked with $second_digest_tool"
else
    detail "digest      $digest_tool, and it is the only digest tool on PATH"
fi

# -----------------------------------------------------------------------------
# 1. The release gate. Read first, and before anything is built, because a
#    refusal here must cost nothing and must be the first thing a reader sees.
# -----------------------------------------------------------------------------
step 'Release gate'

if [ ! -f "$GATE_PATH" ]; then
    fail "no release gate at $GATE_PATH, so this checkout has no answer to the question
GATE_CONTRACT makes a precondition of packaging. Nothing was built.

  Write it with:  cargo test -p sure-core --test acceptance_report_runner

A missing gate is \"cannot confirm\", and \"cannot confirm\" is not \"permitted\"."
fi

# The one field this script reads. The document is pretty-printed JSON and
# `decision` is a top-level key, so the line is anchored at both ends: the
# pattern requires a line that *begins* with the key, which is what keeps the
# word out of the contract's own prose — that sentence names `decision` several
# times and not one of those lines starts with the key.
DECISION_LINES="$(sed -n 's/^[[:space:]]*"decision"[[:space:]]*:[[:space:]]*"\([^"]*\)".*$/\1/p' "$GATE_PATH" || true)"
DECISION_COUNT="$(printf '%s\n' "$DECISION_LINES" | grep -c . || true)"
# The count decides whether the gate was read at all, and an empty value would
# make the test below a skipped check rather than a refusal, so it is required to
# be a number before it is used as one. `grep -c` prints a count when it exits 1
# and prints nothing when it cannot read its input; this is about the second case.
require_whole_number "$DECISION_COUNT" "the number of top-level \"decision\" fields grep counted in $GATE_PATH"
if [ "$DECISION_COUNT" -ne 1 ]; then
    fail "the release gate at $GATE_PATH has $DECISION_COUNT top-level \"decision\" fields and this script reads exactly one. Expected one string field; the document may have changed shape, and a gate this script cannot read is not a gate that passed."
fi
DECISION="$DECISION_LINES"
if [ "$DECISION" != 'permitted' ]; then
    fail "the release gate says this release is $DECISION, and this script packages only a permitted one. The document is $GATE_PATH."
fi
detail 'decision    permitted'
detail "gate file   $GATE_PATH"

# The gate is a reading of `evaluation/acceptance-manifest.json`, and this is a
# *timestamp* comparison and not a content one. `corpus.manifest_digest` cannot
# be checked here: it is a domain-separated digest built by
# `sure_core::fingerprint::digest`, so `sha256sum` over the manifest file is a
# different value, and reimplementing that construction in shell would be a
# hand-rolled copy of a crypto format. So this check can say "the manifest was
# written after the gate" and cannot say "the manifest is the one the gate read".
# The gap is named rather than papered over.
#
# `find -newer` rather than `test -nt`, and the reason is a measurement rather
# than a preference. `-nt` is not defined by POSIX, and this file's shebang is
# `#!/bin/sh`, so the CI job that lints it pins the dialect to `sh` to match -
# which is the correct dialect and is what reported `-nt` as undefined
# (`SC3013`). The construct *worked* on the runner's own `dash`, so what the pin
# found was a portability gap and not a live breakage; those are different
# findings with different urgency and both halves of that sentence are true.
# `find -newer` is POSIX and asks the identical question.
#
# What it answers when it cannot answer is the part that had to be checked
# rather than assumed: measured under `dash`, `find <newer-file> -newer
# <older-file>` prints the path and `find <older-file> -newer <newer-file>`
# prints nothing, and with a **missing** reference file it prints nothing rather
# than treating the absent file as older. The reference for this check cannot be
# missing - the gate is read out of it above, and a gate that is not there fails
# the run before reaching this line - so the third case is closed by the order of
# the script rather than by the construct.
if [ -f "$MANIFEST_PATH" ] && [ -n "$(find "$MANIFEST_PATH" -newer "$GATE_PATH" 2>/dev/null)" ]; then
    fail "the acceptance manifest was written after the release gate:

  $MANIFEST_PATH
  $GATE_PATH

The gate is a decision about that manifest's release-blocking cases, so a
manifest newer than the gate means the gate is a reading of a different corpus.
Re-run it:  cargo test -p sure-core --test acceptance_report_runner"
fi
detail 'freshness   the manifest is not newer than the gate (timestamp, not content)'

# -----------------------------------------------------------------------------
# 2. Version, build and stage. `verify` reaches none of this.
# -----------------------------------------------------------------------------

VERSION=''
ARTIFACT_NAME=''
ARCHIVE=''
SHA_PATH=''
BUILT_BINARY=''
NOTICES_PATH=''

if [ "$PHASE" = 'all' ]; then
    step 'Version'

    # See the header: a host build, so that the version can be read on a machine
    # that could never execute the artifact it is naming.
    #
    # `--manifest-path` is required rather than tidy. `cargo` finds a workspace
    # by walking up from the **current working directory**, so a `cargo run`
    # without it reads whatever project the caller happened to be standing in —
    # and the run's own claim is that the artifact is named after the version
    # *this* repository reports. The `--target` build below passes it for the
    # same reason.
    version_out="$LOGS/version.txt"
    version_err="$LOGS/version.err.txt"
    version_status=0
    run_captured cargo "$version_out" "$version_err" run --quiet --bin sure --manifest-path "$ROOT/Cargo.toml" -- --version || version_status=$?
    if [ $version_status -ne 0 ]; then
        printf '   %s\n' "stderr      $(head -n 1 "$version_err" 2>/dev/null || true)"
        fail "cargo run --bin sure -- --version exited $version_status, so this script cannot name the artifact after the version sure reports; stderr is $version_err"
    fi
    version_line="$(head -n 1 "$version_out")"
    case "$version_line" in
        'sure '*)
            VERSION="${version_line#sure }"
            ;;
        *)
            fail "sure --version printed '$version_line', which is not the 'sure <number>' shape this script reads the version out of. Nothing was packaged, because a name built from a line this script does not understand is a name nobody checked."
            ;;
    esac
    case "$VERSION" in
        '' | *[!0-9A-Za-z.+-]*)
            fail "the version read from sure --version is '$VERSION', which is not a version this script will put in a file name"
            ;;
    esac
    detail "version     $VERSION (sure --version on this host)"

    step 'Build'
    detail "cargo build --workspace --release --locked --target $TARGET"
    build_out="$LOGS/cargo-build.txt"
    build_err="$LOGS/cargo-build.err.txt"
    build_status=0
    run_captured cargo "$build_out" "$build_err" build --workspace --release --locked --target "$TARGET" --manifest-path "$ROOT/Cargo.toml" || build_status=$?
    # Both streams are echoed, because `GITHUB_WORKFLOW.md`'s rule is that the
    # log is the diagnosis: a build failure whose text went to a file the reader
    # has to go and find is a failure the run's log does not explain.
    cat "$build_out" "$build_err" >"$LOGS/cargo-build.both.txt" 2>/dev/null || true
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            detail "$line"
        fi
    done <"$LOGS/cargo-build.both.txt"
    if [ $build_status -ne 0 ]; then
        fail "cargo build exited $build_status; the full log is $build_out and $build_err"
    fi
    detail 'exit        0'

    BUILT_BINARY="$ROOT/target/$TARGET/release/sure"
    if [ ! -f "$BUILT_BINARY" ]; then
        fail "cargo build succeeded but $BUILT_BINARY is not there"
    fi

    # The third-party license notices. `scripts/Generate-ThirdPartyNotices.mjs`
    # reads this checkout's Cargo.lock through `cargo metadata` and exits 1
    # rather than omitting a crate whose license it cannot state, so a run that
    # gets past this step has a complete notice file about these dependencies.
    # Generated before staging, because the archive's contents are what this
    # script states rather than what a directory happened to hold.
    step 'Third-party notices'

    if ! have node; then
        fail "node is not on PATH, so scripts/Generate-ThirdPartyNotices.mjs cannot run and this artifact cannot carry the third-party license notices it promises. Nothing was packaged."
    fi
    NOTICES_PATH="$LOGS/THIRD_PARTY_NOTICES.txt"
    notices_out="$LOGS/third-party-notices.txt"
    notices_err="$LOGS/third-party-notices.err.txt"
    notices_status=0
    run_captured node "$notices_out" "$notices_err" "$ROOT/scripts/Generate-ThirdPartyNotices.mjs" --output "$NOTICES_PATH" --target "$TARGET" || notices_status=$?
    if [ -s "$notices_out" ]; then
        while IFS= read -r line; do
            if [ -n "$line" ]; then detail "$line"; fi
        done <"$notices_out"
    fi
    if [ $notices_status -ne 0 ]; then
        if [ -s "$notices_err" ]; then
            while IFS= read -r line; do detail "stderr      $line"; done <"$notices_err"
        fi
        fail "scripts/Generate-ThirdPartyNotices.mjs exited $notices_status; its stderr is $notices_err. A release without a complete third-party notice file is not packaged."
    fi
    if [ ! -f "$NOTICES_PATH" ]; then
        fail "the notice generator exited 0 but $NOTICES_PATH is not there"
    fi
    count_of -c "$NOTICES_PATH" 'third-party-notices'
    detail "notices     $NOTICES_PATH ($COUNT bytes)"

    step 'Stage'
    ARTIFACT_NAME="sure-$VERSION-$TARGET"
    stage_dir="$STAGE_ROOT/$ARTIFACT_NAME"
    rm -rf "$STAGE_ROOT"
    mkdir -p "$stage_dir"

    staged_binary="$stage_dir/sure"
    cp "$BUILT_BINARY" "$staged_binary"
    # `tar` records a mode, and an archive whose extracted binary is not
    # executable is an artifact a user cannot run for a reason that is not the
    # build's. Set it here rather than inherit it: cargo's output mode is the
    # builder's, and the archive should not depend on it.
    chmod 755 "$staged_binary"
    cp "$ROOT/LICENSE" "$stage_dir/LICENSE"
    cp "$NOTICES_PATH" "$stage_dir/THIRD_PARTY_NOTICES.txt"

    commit='unknown'
    if have git; then
        commit_out="$LOGS/git-commit.txt"
        commit_err="$LOGS/git-commit.err.txt"
        commit_status=0
        run_captured git "$commit_out" "$commit_err" -C "$ROOT" rev-parse HEAD || commit_status=$?
        if [ $commit_status -eq 0 ]; then
            commit="$(head -n 1 "$commit_out")"
        else
            commit="unknown (git rev-parse exited $commit_status)"
        fi
    fi

    # A commit that does not describe the bytes is worse than no commit at all,
    # so the worktree's state at build time is recorded and the three outcomes
    # are kept apart. In particular a `git status` that *failed* is not "clean":
    # an empty stdout from a git that could not run is the shape a clean tree
    # also has, and reading one as the other is how a dirty build acquires a
    # clean provenance line.
    tree_out="$LOGS/git-status.txt"
    tree_err="$LOGS/git-status.err.txt"
    tree_state='unknown (git is not on PATH)'
    if have git; then
        tree_status=0
        run_captured git "$tree_out" "$tree_err" -C "$ROOT" status --porcelain || tree_status=$?
        if [ $tree_status -ne 0 ]; then
            tree_state="unknown (git status exited $tree_status)"
        elif [ -s "$tree_out" ]; then
            tree_state='dirty - uncommitted changes were present when this was built'
        else
            tree_state='clean'
        fi
    fi

    rustc_out="$LOGS/rustc-vV.txt"
    rustc_err="$LOGS/rustc-vV.err.txt"
    rustc_version='unknown'
    if have rustc; then
        if run_captured rustc "$rustc_out" "$rustc_err" -vV; then
            rustc_version="$(head -n 1 "$rustc_out")"
        fi
    fi

    binary_digest=''
    digest_of "$staged_binary" 'sure-binary'
    binary_digest="$DIGEST"
    # Read by `count_of` rather than by a `wc | tr` pipeline: this number is
    # written into RELEASE.txt inside the archive, so a `wc` that failed and
    # produced nothing would put an empty string in a document that ships.
    count_of -c "$staged_binary" 'sure-binary'
    binary_bytes="$COUNT"
    detail "sure        $binary_bytes bytes, SHA-256 $binary_digest"

    # The two passages of RELEASE.txt that cannot be the same text for every
    # target, selected by the header family the way the header check itself is.
    # An Apple Developer ID paragraph is not true of an ELF, and a glibc
    # paragraph is not true of a Mach-O, so a single heredoc carrying either one
    # into both archives would put a sentence about macOS into the Linux
    # artifact's own bytes. Everything else in the file below is shared, which
    # is why this is one heredoc with two variables in it rather than two files
    # that would drift apart.
    #
    # The line breaks inside the values are part of the values. P15-T005 and
    # P15-T006 read the shipped aarch64 `RELEASE.txt` out of an archive and
    # recorded it, so the `macho` branch reproduces those bytes exactly -
    # including the break inside SIGNATURE_LOAD_NOTE and the escaped backticks -
    # and only the `elf` branch is new text.
    case "$HEADER_FAMILY" in
        macho)
            RELEASE_SIGNATURE_SECTION="THIS BUILD CARRIES NO APPLE DEVELOPER ID SIGNATURE AND NOTHING NOTARIZES IT
Neither is an oversight: docs/development/RELEASE_PROCESS.md records Developer
ID signing and notarization as an external credential this project does not
have, and says \"Do not fake signing\". No step of this build applies one. What
that means is a fact about the build procedure and not a claim about the bytes,
and the bytes are read: scripts/Build-Release.sh runs \"codesign -d\" on the
extracted binary and prints everything it says. A signing *chain* there - an
Authority= line, which is what a certificate produces - fails the run, because
this file says there is none.

An $EXPECT_FILE_ARCH binary can carry an ad-hoc signature, $SIGNATURE_LOAD_NOTE. That is not a certificate, it names no
developer, and it does not contradict the paragraph above; if the reading says
\`Signature=adhoc\` that is what it is.

What macOS does with a program that carries no Developer ID signature is
Apple's behaviour and not SURE's, and this project has not observed it on a Mac
- the general shape is that Gatekeeper refuses or warns about one whose
com.apple.quarantine attribute is set, which is what a browser download sets
and what a command-line download may not. Nothing in SURE asks you to turn
Gatekeeper off. If a prompt appears, treat it as the unsigned state above and
decide for yourself; do not read this file as saying the build is trusted."

            RELEASE_HEADER_READING="reads the first eight bytes of the extracted
binary and requires them to be the Mach-O magic and the $EXPECT_FILE_ARCH CPU type, reads
the binary's signature with codesign"
            ;;
        elf)
            RELEASE_SIGNATURE_SECTION="THIS BUILD CARRIES NO SIGNATURE AND NO STEP OF THIS BUILD APPLIES ONE
Neither is an oversight: docs/development/RELEASE_PROCESS.md records code
signing as an external credential this project does not have, and says \"Do not
fake signing\". That sentence is deliberately a fact about the build procedure
and not a claim about the bytes, and unlike the macOS build there is no reading
that would turn it into one: Linux has no \`codesign\`, and a signature over an
ELF is a detached file beside it or a digest in a distribution packager's
database, never a field inside the image. So there is nothing in
$ARTIFACT_NAME.tar.gz to read a certificate out of. The entries of the archive
are listed and checked against the promised set before it is written, and
they are four files. The .sha256 beside the archive is an integrity digest,
not a signature: it says the bytes arrived unchanged and says nothing about
who wrote them.

WHAT THIS BINARY NEEDS FROM THE MACHINE IT RUNS ON
This is built for the x86_64-unknown-linux-gnu target, which links the GNU C
library (glibc) of the machine it was built on rather than a static C library,
so it needs a glibc at least as new as the symbols it asks for, and it does not
run on a musl distribution such as Alpine or against an older loader. It is
linked dynamically, not statically: the interpreter path it records (normally
/lib64/ld-linux-x86-64.so.2) is the loader the machine has to provide. The
oldest distribution it runs on is set by the glibc of the machine it was built
on, and this file does not name it: the binary carries the answer itself, as
GLIBC_x.yy lines among its undefined symbols, which \"objdump -p\" on the
extracted \`sure\` prints, and \"ldd --version\" on your machine prints what your
machine has. Nothing here patches or bundles a C library, and no step of this
build uses patchelf or similar: what the linker produced is what is inside the
archive."

            RELEASE_HEADER_READING="reads the first twenty bytes of the extracted
binary and requires the ELF magic, the 64-bit little-endian class and data
bytes, and the x86_64 e_machine field
at offset 18"
            ;;
    esac

    # The provenance travels inside the archive rather than beside it: an
    # archive that travels without its RELEASE.txt is the one whose origin
    # nobody can state. The worktree marker is here because a recorded commit
    # that does not describe the bytes is worse than no commit at all.
    cat >"$stage_dir/RELEASE.txt" <<EOF
SURE $VERSION - $ARTIFACT_LABEL release artifact

  target        $TARGET
  built from    $commit
  worktree      $tree_state
  built at      $(date -u '+%Y-%m-%dT%H:%M:%SZ')
  built on      $(uname -s) $(uname -m)
  built with    $rustc_version
  release gate  permitted
                read from $GATE_PATH

  sure          SHA-256 $binary_digest
                $binary_bytes bytes

WHAT THIS IS
The SURE command-line program for $ARTIFACT_MACHINES, built for the
$TARGET target. "sure doctor" reports the build it is running
from and where it is running from; "sure --help" lists the commands.

$RELEASE_SIGNATURE_SECTION

THIS ARCHIVE IS NOT BYTE-FOR-BYTE REPRODUCIBLE
A gzip stream records a modification time in its header and a tar records one
per entry, so building the same commit twice produces two archives with two
different digests. The .sha256 beside this archive is an integrity check over
the bytes that were shipped - that they arrived unchanged - and it is not a
claim that a rebuild would produce them again.

HOW THIS IS CHECKED
This file is written before the checks run, so it describes the procedure
rather than certifying its own archive. scripts/Build-Release.sh writes the
.sha256 beside this archive, re-reads it, verifies the archive against it,
lists the archive's entries and requires them to be the promised set, extracts
the archive to a fresh directory, $RELEASE_HEADER_READING, and runs the extracted "sure" from there,
comparing the running_from it reports with that directory. It prints OK and
exits 0 only when every one of those steps agreed, so a run that failed is a
run that said which step failed.
See docs/development/RELEASE_PROCESS.md for the artifact contract.
EOF

    step 'Package'
    mkdir -p "$OUTPUT_DIR"
    ARCHIVE="$OUTPUT_DIR/$ARTIFACT_NAME.tar.gz"
    SHA_PATH="$ARCHIVE.sha256"
    rm -f "$ARCHIVE" "$SHA_PATH"
    tar_status=0
    tar_out="$LOGS/tar-create.txt"
    tar_err="$LOGS/tar-create.err.txt"
    run_captured tar "$tar_out" "$tar_err" -czf "$ARCHIVE" -C "$STAGE_ROOT" "$ARTIFACT_NAME" || tar_status=$?
    if [ $tar_status -ne 0 ]; then
        printf '   %s\n' "stderr      $(head -n 1 "$tar_err" 2>/dev/null || true)"
        fail "tar exited $tar_status; its stderr is $tar_err"
    fi
    if [ -s "$tar_err" ]; then
        while IFS= read -r line; do detail "tar warns   $line"; done <"$tar_err"
    fi
    count_of -c "$ARCHIVE" 'archive'
    detail "archive     $ARCHIVE"
    detail "size        $COUNT bytes"

    # -------------------------------------------------------------------------
    # The checksum. Computed here, over the archive that was just written, and
    # then checked against its own bytes rather than trusted.
    # -------------------------------------------------------------------------
    step 'Write the checksum'

    sha_name="$(basename "$ARCHIVE")"
    digest_of "$ARCHIVE" 'archive'
    actual="$DIGEST"
    # `printf` with an explicit `\n` rather than `echo`, because `echo` is not
    # required to be any particular thing about backslashes and one `echo -e`
    # would put a carriage return in a file whose whole job is to be read by a
    # tool on another platform. The name is the archive's own basename with no
    # directory, because `sha256sum -c` is run from the directory the file was
    # downloaded into and a path inside the file would not resolve there.
    printf '%s  %s\n' "$actual" "$sha_name" >"$SHA_PATH"

    # The bytes are asserted, not assumed. `RELEASE_PROCESS.md` writes this
    # format down — ASCII, no BOM, one LF, two spaces — and a checksum file that
    # a verification tool refuses for a reason that is not the checksum is a
    # file that fails the one job it has.
    #
    # The three counts together pin the layout exactly: one LF, no CR, and a
    # total length of 64 hex + 2 spaces + the name + 1 LF. A BOM is caught
    # without being looked for, because `grep`'s `^[0-9a-f]` above cannot match
    # a line that begins with three non-ASCII bytes, and the total length would
    # be three too many.
    #
    # This is where `pipefail` was covering a verdict and not a display, and the
    # three readings below are why. Each of the three lines here used to be a
    # pipeline whose left side could fail while its right side succeeded, and
    # each of the three tests further down is `[ "$written_x" -ne N ]`, which an
    # empty value turns into a skipped check rather than a failed one — a
    # checksum file that is not the documented format, reported as one that is.
    # They are `count_of` and `count_char` calls now: status read, shape checked,
    # no pipeline left to report the wrong element's status.
    expected_bytes=$((64 + 2 + ${#sha_name} + 1))
    count_of -c "$SHA_PATH" 'checksum'
    written_bytes="$COUNT"
    count_char '\n' "$SHA_PATH" 'checksum-lf'
    written_lf="$COUNT"
    count_char '\r' "$SHA_PATH" 'checksum-cr'
    written_cr="$COUNT"
    detail "file        $SHA_PATH"
    detail "bytes       $written_bytes (expected $expected_bytes), $written_lf LF, $written_cr CR"
    if [ "$written_cr" -ne 0 ]; then
        fail "the checksum file holds $written_cr carriage returns. A CRLF line ending makes the file a different file from the one this repository documents, and a \`sha256sum -c\` that fails on it fails for a reason that has nothing to do with the artifact."
    fi
    if [ "$written_lf" -ne 1 ]; then
        fail "the checksum file holds $written_lf newlines; this format is one line ending in one LF"
    fi
    if [ "$written_bytes" -ne "$expected_bytes" ]; then
        fail "the checksum file is $written_bytes bytes and this format is $expected_bytes: 64 digest characters, two spaces, '$sha_name', one LF"
    fi
    detail "digest      $actual"
else
    step 'Existing artifact'
    # Exactly one, or a refusal. `Build-Release.ps1` refuses an ambiguous match
    # for the same reason: checking one of two archives and reporting on "the
    # artifact" is a sentence about a file nobody chose.
    found=''
    for candidate in "$OUTPUT_DIR"/sure-*-"$TARGET".tar.gz; do
        [ -f "$candidate" ] || continue
        if [ -n "$found" ]; then
            fail "$OUTPUT_DIR holds more than one sure-*-$TARGET.tar.gz; this phase checks one and will not guess which"
        fi
        found="$candidate"
    done
    if [ -z "$found" ]; then
        fail "no sure-*-$TARGET.tar.gz in $OUTPUT_DIR to verify; run this script with --phase all first"
    fi
    ARCHIVE="$found"
    SHA_PATH="$ARCHIVE.sha256"
    ARTIFACT_NAME="$(basename "$ARCHIVE" .tar.gz)"
    count_of -c "$ARCHIVE" 'archive'
    detail "archive     $ARCHIVE"
    detail "size        $COUNT bytes"
fi

# -----------------------------------------------------------------------------
# 3. The archive's entry list, stated rather than discovered.
# -----------------------------------------------------------------------------
step 'Layout'

entries_out="$LOGS/archive-entries.txt"
entries_err="$LOGS/archive-entries.err.txt"
entries_status=0
run_captured tar "$entries_out" "$entries_err" -tzf "$ARCHIVE" || entries_status=$?
if [ $entries_status -ne 0 ]; then
    fail "tar -tzf exited $entries_status on $ARCHIVE; its stderr is $entries_err"
fi
# A trailing slash on a directory entry is the writer's convention, not a
# difference in what is in the archive, so it is normalised away before the
# comparison. The list is then compared by *set* rather than by order, because
# the order of a tar's entries is the writer's and not something this script
# asked for.
#
# The pipeline stays, and it cannot report success over a failed producer: `sort`
# is the last element, its input is `sed`'s output, and the `cmp` immediately
# below turns an empty or half-written result into a named failure — an empty
# list is not the five-entry set this artifact promises. `pipefail` was not doing
# anything here that the comparison does not.
normalised="$LOGS/archive-entries.normalised.txt"
sed 's:/$::' "$entries_out" | LC_ALL=C sort >"$normalised"
expected="$LOGS/archive-entries.expected.txt"
cat >"$expected" <<EOF
$ARTIFACT_NAME
$ARTIFACT_NAME/LICENSE
$ARTIFACT_NAME/RELEASE.txt
$ARTIFACT_NAME/THIRD_PARTY_NOTICES.txt
$ARTIFACT_NAME/sure
EOF
LC_ALL=C sort -o "$expected" "$expected"
if ! cmp -s "$normalised" "$expected"; then
    printf '\n' >&2
    printf 'FAILED: the archive does not hold the entries this artifact promises.\n\n' >&2
    printf '  expected\n' >&2
    printf '    %s\n' "$(tr '\n' ' ' <"$expected")" >&2
    printf '  found\n' >&2
    printf '    %s\n' "$(tr '\n' ' ' <"$normalised")" >&2
    printf '\nA tar is not obliged to be identical across implementations, so this is\n' >&2
    printf 'asserted rather than assumed: an entry added by a different tar is a\n' >&2
    printf 'difference in what a user receives. The full listing is %s.\n' "$entries_out" >&2
    exit 1
fi
count_of -l "$normalised" 'entries'
detail "entries     $COUNT entries, exactly the promised set"

# -----------------------------------------------------------------------------
# 4. Verify the archive against the digest file, read back from disk. This is
#    the step that would catch a truncated download or an archive altered after
#    it was published, so it runs *before* extraction: the property in the
#    header is about the order.
# -----------------------------------------------------------------------------
step 'Verify the checksum file'

if [ ! -f "$SHA_PATH" ]; then
    fail "no checksum file at $SHA_PATH, so nothing verifies $ARCHIVE"
fi
# `grep -c` prints a count even when it exits 1 — no line matched — so the `|| true`
# here is about the status and not the value. What it is *not* is proof that a
# value arrived: a `grep` that could not read the file exits 2 and prints
# nothing, which would make the test below an empty operand and therefore a check
# that does not run. So the value is checked for being a number first, through the
# same helper `count_of` uses.
sha_lines="$(grep -c . "$SHA_PATH" || true)"
require_whole_number "$sha_lines" "the number of non-empty lines grep counted in $SHA_PATH"
if [ "$sha_lines" -ne 1 ]; then
    fail "$SHA_PATH holds $sha_lines non-empty lines; this format is one digest line"
fi
sha_text="$(head -n 1 "$SHA_PATH")"
printf '%s\n' "$sha_text" >"$LOGS/checksum-line.txt"
# The `sha256sum` format, which is what `sha256sum -c` reads and what
# `RELEASE_PROCESS.md` writes down for the Windows artifact: 64 lowercase hex
# characters, **two spaces**, then the file's name and nothing else. Two spaces
# rather than the `*` binary-mode marker the tools on Git for Windows emit, for
# the reason recorded at `digest_of`: the separator is the platform's and this
# file is written by `printf` so that it is not. `sha256sum -c` reads both.
#
# The name is matched against the charset the artifact name can use rather than
# against `.*`: a pattern that accepted anything would accept a path, and a
# checksum file naming `/somewhere/else/sure.tar.gz` is a checksum over a file
# this run has not seen. The exact comparison against the archive below is the
# real check; this is the shape.
if ! grep -Eq '^[0-9a-f]{64}  [0-9A-Za-z._+-]+$' "$LOGS/checksum-line.txt"; then
    fail "the checksum file is not one sha256sum-format line of 64 lowercase hex characters, two spaces and a name:

  $sha_text

  $SHA_PATH"
fi
sha_digest="${sha_text%%  *}"
sha_named="${sha_text##*  }"
if [ "$sha_named" != "$(basename "$ARCHIVE")" ]; then
    fail "the checksum file names '$sha_named' but the archive is '$(basename "$ARCHIVE")'"
fi

digest_of "$ARCHIVE" 'archive'
actual="$DIGEST"
detail "expected    $sha_digest"
detail "actual      $actual"
if [ "$sha_digest" != "$actual" ]; then
    fail "the archive does not match its checksum file: $ARCHIVE"
fi
cross_check_digest "$ARCHIVE" 'archive-cross' "$actual"
detail 'matches     the archive on disk is the archive the checksum file names'

# -----------------------------------------------------------------------------
# 5. Extract to a fresh directory and read the bytes that are in there.
# -----------------------------------------------------------------------------
step 'Extract'

rm -rf "$EXTRACT_ROOT"
mkdir -p "$EXTRACT_ROOT"
extract_err="$LOGS/tar-extract.err.txt"
extract_status=0
set +e
tar -xzf "$ARCHIVE" -C "$EXTRACT_ROOT" >/dev/null 2>"$extract_err"
extract_status=$?
set -e
if [ $extract_status -ne 0 ]; then
    fail "tar -xzf exited $extract_status; its stderr is $extract_err"
fi
# The extraction directory is deleted before it is written, so a run that does
# not extract cannot find a binary left over from an earlier one.
top_level_count=0
top_level=''
for entry in "$EXTRACT_ROOT"/*; do
    [ -e "$entry" ] || continue
    if [ -d "$entry" ]; then
        top_level_count=$((top_level_count + 1))
        top_level="$entry"
    fi
done
if [ "$top_level_count" -ne 1 ]; then
    fail "$EXTRACT_ROOT holds $top_level_count top-level directories; the layout this artifact promises is exactly one"
fi
extract_dir="$(cd -P "$top_level" && pwd -P)"
if [ "$(basename "$extract_dir")" != "$ARTIFACT_NAME" ]; then
    fail "the archive's top-level directory is '$(basename "$extract_dir")' and the archive is named '$ARTIFACT_NAME.tar.gz'"
fi
detail "into        $extract_dir"

extracted_binary="$extract_dir/sure"
for required in sure LICENSE RELEASE.txt THIRD_PARTY_NOTICES.txt; do
    if [ ! -f "$extract_dir/$required" ]; then
        fail "the archive extracted but $required is not in it"
    fi
done
# The **mode** is checked after the architecture below, and it used to be here.
# It was moved because a run on a host whose extraction cannot set modes showed
# what being first costs: the mode assertion fires, and the architecture of the
# artifact — the fact this whole script exists to read off the bytes — is never
# read at all. A check that cannot be reached is a check that did not run, and
# this repository's whole subject is the run that reads as though it did. The
# bytes are the artifact and the mode is a property of the extraction, so the
# bytes are asked first.

digest_of "$extracted_binary" 'sure-extracted'
extracted_digest="$DIGEST"
if [ "$PHASE" = 'all' ]; then
    # The archive's digest covers the archive; this line ties the archive to the
    # bytes that get run: the executable inside it is the executable cargo
    # produced.
    if [ "$extracted_digest" != "$binary_digest" ]; then
        fail "the sure inside the archive is not the one that was built:

  built     $binary_digest  $BUILT_BINARY
  packaged  $extracted_digest  $extracted_binary"
    fi
    detail 'same as     the sure cargo built'
fi

# -----------------------------------------------------------------------------
# 6. The architecture, from the artifact's own bytes.
# -----------------------------------------------------------------------------
step 'Architecture'

require_arch "$extracted_binary" 'extracted'

# The mode, now that the bytes have been read. An extracted binary without an
# execute bit cannot be run at all, and the failure a user would meet is their
# shell's rather than this one's — which is the reason the artifact is a tar and
# not a zip, so it is checked rather than mentioned.
if [ ! -x "$extracted_binary" ]; then
    # The whole listing rather than a `cut` of its mode column: it is one line,
    # and a reader who doubts the reading can see the file it is about.
    fail "the extracted 'sure' is not executable, so this artifact cannot be run by the person who downloads it. \`ls -ld\` says:

  $(ls -ld "$extracted_binary")

tar records the mode as a field of the format, so this is a packaging or extraction fault and not a build one."
fi

# -----------------------------------------------------------------------------
# 6b. The signature, read from the artifact rather than asserted in prose.
# -----------------------------------------------------------------------------
#
# For the macOS family, the RELEASE.txt inside this archive says the build
# carries no Apple Developer ID signature, and a sentence about a file is not
# evidence about that file. This is the reading behind the sentence: `codesign
# -d` is macOS's own question, its answer is printed in full whatever it is, and
# the failure is on the one direction that matters — a signature **chain**, which
# is what a certificate produces, arriving in an archive whose own text says
# there is none.
#
# **An arm64 binary is expected to carry an ad-hoc signature**, and that is not
# a certificate: it is what the toolchain applies so the kernel will load the
# image, it names no developer, and its presence does not contradict the
# sentence. So the failure is keyed on an `Authority=` line, which an ad-hoc
# signature does not produce and a Developer ID chain does, and **not** on the
# exit status — `codesign -d` exits 0 for an ad-hoc signature and 1 for none at
# all. Keying it on the exit status would have failed every correct artifact.
#
# A `codesign` that is missing, or that cannot read the file, leaves the reading
# unknown; unknown is reported as unknown rather than turned into "unsigned".
# **Notarization is not read here at all**: nothing in this build notarizes, so
# the sentence rests on there being no such step, not on this measurement.
#
# The ELF family has no equivalent question to ask — see the branch below, which
# reports that as not-read rather than printing a line that sounds like a
# measurement. The RELEASE.txt paragraph for that family is written to rest on
# there being no signing step, which is what can be established here.
step 'Signature'

if [ "$HEADER_FAMILY" = 'elf' ]; then
    # Linux has no `codesign`, and an ELF has no field a signature lives in: a
    # signature over one is a detached file beside it, and the entries of this
    # archive were just checked against the promised set, which is four files
    # and none of them a signature. So there is nothing to read, and the honest
    # report of a reading that did not happen is that it did not happen. A line
    # saying "no signature found" would describe a question this run never
    # asked, which is the shape of claim this repository exists to refuse.
    detail 'signature   not read'
    detail 'reason      an ELF carries no signature field and no step of this'
    detail '            build applies one, so this run measured nothing about'
    detail '            whether the binary is signed'
elif have codesign; then
    sign_out="$LOGS/codesign.txt"
    sign_err="$LOGS/codesign.err.txt"
    sign_status=0
    run_captured codesign "$sign_out" "$sign_err" -d --verbose=2 "$extracted_binary" || sign_status=$?
    # `codesign -d` writes its answer to **stderr**, including when it succeeds,
    # so both streams are read into one file — stderr first — and that file is
    # what is printed and what is searched. The exit status is carried beside it
    # rather than instead of it, because it is not the thing being asserted on.
    sign_log="$LOGS/codesign.reading.txt"
    cat "$sign_err" "$sign_out" >"$sign_log" 2>/dev/null || true
    if [ -s "$sign_log" ]; then
        while IFS= read -r line; do
            if [ -n "$line" ]; then detail "codesign    $line"; fi
        done <"$sign_log"
    else
        detail 'codesign    (it printed nothing on either stream)'
    fi
    detail "exit        $sign_status (0 with 'Signature=adhoc' is a linker signature, not a certificate)"
    if grep -q '^Authority=' "$sign_log"; then
        fail "codesign read a signing authority on $extracted_binary, and the RELEASE.txt this script writes into the archive says the build carries no Apple Developer ID signature. One of the two is wrong, and an archive whose own text contradicts its own bytes is the shape this repository exists to refuse. The full reading is $sign_err"
    fi
    detail 'authority   none, so the unsigned sentence in RELEASE.txt is what the bytes say'
else
    detail 'codesign    (no codesign on PATH on this runner, so this run says nothing about whether the binary is signed)'
fi

# -----------------------------------------------------------------------------
# 7. Run the extracted binary.
# -----------------------------------------------------------------------------
step 'Run the extracted binary'

run_out="$LOGS/extracted-doctor.txt"
run_err="$LOGS/extracted-doctor.err.txt"
run_status=0
# By absolute path, and `--store-dir` is deliberately not passed: a user runs
# `sure doctor` against their own store, so that is what is run here. On a CI
# runner there is no store to find, and `sure doctor` creates nothing.
run_captured "$extracted_binary" "$run_out" "$run_err" doctor || run_status=$?
detail "invoked     $extracted_binary doctor"
detail "exit        $run_status"
if [ -s "$run_err" ]; then
    while IFS= read -r line; do detail "stderr      $line"; done <"$run_err"
fi
if [ $run_status -ne 0 ]; then
    fail "the extracted sure exited $run_status on this host ($(uname -s) $(uname -m)). If this host's processor is not $EXPECT_FILE_ARCH, or its operating system is not $EXPECT_OS, a binary built for $EXPECT_OS $EXPECT_ARCH cannot be executed here at all, and that is a fact about the runner rather than about the artifact — the header read above already said what the bytes are. stderr is $run_err"
fi
if [ ! -s "$run_out" ]; then
    fail "the extracted sure wrote nothing to stdout; the report should be in $run_out"
fi

first_line="$(head -n 1 "$run_out")"
case "$first_line" in
    *"built for $EXPECT_OS $EXPECT_ARCH"*)
        detail "reports     $first_line"
        ;;
    *)
        fail "the extracted binary's first line is '$first_line', which does not contain 'built for $EXPECT_OS $EXPECT_ARCH'. The build's own statement about what it is disagrees with the target this script built for."
        ;;
esac

# `sure doctor` prints the path it is running from on the line after that one.
# It is what the binary says about itself, and it has to be the executable the
# archive was just extracted into: a run that picked up some other `sure` — a
# copy on PATH, one left by an earlier release — would still exit 0 and still
# print a well-formed report.
# The pipeline stays: `head` is the last element, the file it reads is the
# captured stdout of a run whose status was already read, and the `-z` check on
# the next line is what turns "no such line" into a failure rather than into a
# comparison that passes over nothing. A `sed` that failed would produce an empty
# value, and an empty value is refused by name one line later.
reported_from="$(sed -n 's/^running from //p' "$run_out" | head -n 1)"
if [ -z "$reported_from" ]; then
    fail "the extracted binary reported no 'running from' line, so which binary answered cannot be checked: $run_out"
fi
# What the field *is* decides what it may be compared with, so the reading comes
# from the product rather than from this script's expectation: `running from`
# prints `build.running_from`, `sure_core::doctor` fills it from
# `std::env::current_exe()`, and that field is documented there as "Where the
# running executable is." It is the path of the **file** on every platform. An
# earlier version of this check compared it with `$extract_dir`, the directory,
# which is one path component away from it — so the comparison could only ever
# fail, and it reddened the macOS job over a correct artifact.
#
# `current_exe()` is not required to return a canonical path, and on macOS it
# may not: a runner's `$TMPDIR` is under `/var`, which is a symlink to
# `/private/var`, so two spellings of one file are expected. Both sides are
# therefore folded the same way before they are compared — the directory
# component through `cd -P ... && pwd -P`, exactly as the extraction directory
# was already resolved above, and the basename as it is. Comparing the
# spellings, or comparing a file with a directory, would read as a mismatch on
# a machine where nothing is wrong.
#
# The check keeps its teeth: a `sure` from PATH, or one left by an earlier
# release, reports a path in some other directory and still fails here.
fold_binary_path() {
    local dir
    local base
    dir="$(dirname "$1")"
    base="$(basename "$1")"
    if [ -d "$dir" ]; then
        dir="$(cd -P "$dir" && pwd -P)"
    fi
    printf '%s/%s\n' "$dir" "$base"
}
required_binary="$(fold_binary_path "$extracted_binary")"
reported_binary="$(fold_binary_path "$reported_from")"
if [ "$reported_binary" != "$required_binary" ]; then
    fail "the binary that answered 'sure doctor' is not the one this script extracted:

  required  $required_binary
  reported  $reported_binary

The archive was extracted to $extract_dir, so a running_from that is not the
sure inside it means the run measured some other installation."
fi
detail "from        $required_binary"

# -----------------------------------------------------------------------------
# 8. The result.
# -----------------------------------------------------------------------------
#
# The two numbers in this block are read the same way every other number in this
# script is read, and not inline in the `printf` as they were. They are the last
# thing a reader sees and the sentence a release is described by, so an empty
# value here would be the most expensive version of the failure this file's
# `set` comment describes: `size        bytes`, printed by a script that exits 0.
count_of -c "$ARCHIVE" 'archive'
result_bytes="$COUNT"
count_of -l "$normalised" 'entries'
result_entries="$COUNT"
printf '\nRESULT\n'
printf '  artifact    %s\n' "$ARCHIVE"
printf '  size        %s bytes\n' "$result_bytes"
printf '  sha256      %s\n' "$actual"
printf '  computed by %s\n' "$digest_tool"
printf '  checksum    %s\n' "$SHA_PATH"
printf '  verified    the archive matches the checksum file, re-read from disk\n'
printf '  layout      %s entries, exactly the promised set\n' "$result_entries"
printf '  runs        %s\n' "$extracted_binary"
printf '  arch        %s, read from the header bytes %s\n' "$HEADER_DESCRIPTION" "$HEADER_BYTES"
printf '  gate        permitted; read from %s\n' "$GATE_PATH"
printf '  OK          the bytes that are checksummed are the bytes that were run\n'
exit 0
