# The project zoo

A curated corpus of real projects — pinned by commit — that SURE is run against
on demand, with invariants and a committed baseline.

The unit suites prove SURE's logic against fixtures this repository wrote. The
zoo measures SURE against projects this repository did not write: a setuptools
sample, an Express server, a Cargo workspace, a Go module, and (on the machine
that has them) two real working projects. Every ecosystem that joined SURE
after 0.1.2 arrived because a real project broke something the fixtures had not
imagined; the zoo is how that discovery stops being a user's job.

## Running it

From the repository root, after building the binary:

```
cargo build --release
node scripts/zoo.mjs                    # every entry; compares with the baseline
node scripts/zoo.mjs --only chailv      # one entry
node scripts/zoo.mjs --offline          # cached clones only; others skip honestly
node scripts/zoo.mjs --update-baseline  # record what this run observed
```

The binary is `--sure BIN` when given, otherwise the repository's own build
(`target/release`, then `target/debug`), then `SURE_BIN`, then `sure` on PATH —
this is a repository instrument, so the freshly built binary measures first and
an installed copy is only a fallback (2026-11-02: a machine whose `SURE_BIN`
pointed at a month-old build produced findings the current build does not).
`--sure` is not a hint: a name that cannot be found (as a path or on PATH) is an
error, never a silent fallback to another build.
Per-entry timeout: `--timeout-minutes N` (default 20).

Exit status: `0` when every entry matches its baseline, `1` when any entry
failed, drifted, or is new (a new entry needs `--update-baseline`), `2` on a
zoo-side error (bad arguments, no binary). A `DIRTY` local entry is none of
those — it was measured and set aside — so it does not fail the run.
`--update-baseline` records instead of comparing, so drift and new entries do
not fail it: it exits `1` only when an entry itself failed (crash, report that
breaks the invariants, timeout), and that entry's baseline is left as it was.
`DIRTY` entries are not recorded either.

## What a run asserts

Per entry — none of it about the checked project's own quality:

- **The check finished.** Exit 0 (green) or 1 (checked, not green). A crash, a
  refused command line or an unfinished run is a zoo failure.
- **The machine form parses** and carries `details.report` with an aggregate.
- **No check result is `error`.** A checker that crashed is SURE's defect.
- **Every skipped check carries a reason.** "Not run" must say why.
- **The run matches the committed baseline**: aggregate severity, findings and
  the not-checked list. A difference is a behavior change; either update the
  baseline in the same change and say why, or fix what moved. The baseline
  records the SURE version it was taken with, so a version bump alone does not
  hide a change. It is kept **per runner platform** (`win32`, `linux`,
  `darwin`): a Linux CI run compares against the Linux baseline, and a platform
  with no baseline reports every entry as new rather than borrowing another
  platform's answer.

The settings file the zoo writes disables the analysis provider — two runs of
one commit compare without model variance — and each entry gets its own
`--store-dir` under the run directory, so runs share nothing through history.

## The manifest

`projects.json` lists the entries. `kind: "git"` entries name a `repo` and a
pinned `commit`; clones are cached under `target/tmp/zoo/cache` and only reused
for the same commit. `kind: "local"` entries name an absolute `path` on the
machine — a machine that does not have it records the entry as skipped with
that reason, never as a pass.

A local entry whose working tree has uncommitted changes is measured and shown
as `DIRTY`: its findings are reported like any other entry's, but it is not
compared with the baseline and `--update-baseline` does not record it. A tree
somebody is editing is a moving target — comparing it would report the edits as
regression, and recording it would freeze a transient state as expected. The
same rule is not applied to `kind: "git"` entries: their tree is the pinned
commit, and a dirty clone means the pin is not what was measured.

`profiles` decide what a run may do: `static` inspects (commands are planned and
honestly recorded as not run); `dynamic` allows running the project's own
checks, which local entries use where their dependencies are already in place.
For every entry the runner prepends the project's own `.venv` (or `venv`)
interpreter directory to the child's PATH when one exists — the same rule the
MiQi panel applies — so `python -m pytest` in a local entry resolves to the
project's interpreter, not the machine's; the run summary says when it did.

Adding an entry: pick a project whose shape SURE does not yet see in the
corpus, pin its commit, run `--update-baseline`, and commit the baseline with
the manifest change so the review sees what SURE said about it first.

## Where the output goes

`target/tmp/zoo/runs/<timestamp>/` — one JSON summary (`zoo-report.json`), each
entry's stdout/stderr, and its settings/store. Nothing is written into the
checked projects.

## One entry that records a known limitation

`newtonsoft-json-dotnet` keeps its solution and projects under `Src/`, and
SURE's discovery reads root manifests only, so its baseline is *no stack
recognised* rather than a .NET reading — a sentinel on purpose: the day nested
layouts become visible to discovery, the comparison against this baseline says
so with a diff. `restsharp-dotnet` (a root `.slnx`) is the entry that measures
the .NET stack today.

## What it is not

- Not a judgement of the corpus projects; their own findings are SURE's answer
  about them, recorded faithfully, and nothing here fixes them.
- Not a substitute for the fixture suites: it cannot pin an exact expected
  report, only compare against what the baseline observed.
- Not green when it did not run: an entry with no clone and no local path is a
  skip with a reason, and the summary keeps skips visible.

## In CI

`.github/workflows/zoo.yml` runs the zoo on `ubuntu-latest` nightly (an
off-minute cron), on demand, and on pull requests that touch the zoo itself
(`evaluation/zoo/**`, `scripts/zoo.mjs`, the workflow). It builds the release
binary, caches the clone corpus by manifest hash, and uploads the run's
`zoo-report.json` plus the baseline as an artifact.

The local `kind: "local"` entries have no path on a CI runner and are recorded
as skipped with that reason — the run summary keeps them visible and the job
does not treat them as passes.

**A platform's first run.** Dispatch the workflow with
`update_baseline: true`: it runs `--update-baseline`, writes that runner
platform's section into `baseline.json`, and uploads the file as an artifact.
Download it, commit the platform's section, and dispatch again — the second
run compares against it. Nothing writes the baseline into the repository from
CI itself.
