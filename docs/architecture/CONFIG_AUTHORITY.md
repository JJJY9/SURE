# Configuration authority

The checked project may be controlled by the same AI whose work SURE is evaluating. Therefore project-controlled configuration is not trusted to grant SURE additional authority.

## Authority order

Highest authority:
1. explicit interactive/user approval for the current action;
2. user-level SURE configuration stored outside the project;
3. organization policy (future team edition, where applicable);
4. project `sure.yaml` suggestions;
5. inferred defaults.

A lower-authority source cannot weaken a higher-authority safety/privacy restriction.

**Which file rank 2 is.** The user's own file, at the location the platform
reports — `%APPDATA%\SURE\sure.yaml` on Windows, read through
`Paths::discover_with`. A caller may name a different one with `--settings-file`
(`docs/architecture/CLI.md`), which is a testing and automation surface: the
named file is read at rank 2, by the same reader, so it can grant what rank 2 can
grant and nothing above it, and a file the checked project could have written is
refused before it is read. Nothing a project writes — its `sure.yaml`, its
harness configuration, the environment of a process it starts — is a way to
choose it.

## Project config may

- select/disable noncritical checks;
- describe project components;
- provide explicit project goal/spec paths;
- suggest start/test commands;
- configure report preferences.

## Project config may not silently

- enable host execution if the user did not allow it;
- enable dependency installation/network access;
- disable user protection rules;
- enable full transcript recording;
- keep recorded content for longer than the user allowed;
- provide/override secret credentials as an authority bypass;
- delete authoritative history;
- exclude paths from the scan (`scan.exclude` is read from the user's file only,
  see below).

If project config requests a privileged behavior, SURE treats it as a request requiring higher-authority approval.

## What is implemented, and what is not

Ranks 2 and 4 exist and are resolved against each other by
`crates/sure-core/src/config/authority.rs`. Rank 1 is a decision rather than a
file and is recorded as `ConsentGrantor::InteractiveUser` when it exists; the
prompt it comes from is P3-T005. **Rank 3 does not exist in this release**, and
neither `Layer` nor `ConsentGrantor` offers a way to name it — a source a caller
can name but never obtain is how a documented feature becomes a believed one.

Read plainly: this layer decides what the two files, together, are allowed to
mean. **Four things route through it.** Since P7-T010 `sure check` reads its
settings through `Authority::load`, which is where the arbitrated privacy mode
and the statement about models come from; since P13-T003 `sure hook ingest` reads
`Authority::full_recording_retention_days` for the same reason — how long a full
recording is kept is a restriction, and a restriction resolved anywhere else
would be a second rule — and since P13-T009 the consent a recording is made
under at all is `Authority::full_recording()`, so a project's file can neither
turn recording on nor outlast the user's own period; since P13-T004 it takes the
**protection mode in force** from `Authority::protection()` before it decides a
pre-action tool request, so a project's file can raise the mode and cannot lower
the one the user set; and since P13-T009 the **execution mode and the permission
set** come from `Authority::execution()` on both paths that plan work — `sure
hook ingest` and the check pipeline. One value for the two, deliberately, so that
`sure_domain::execution::decide` cannot be handed a mode from one file and
permissions from another.

The execution mode resolves by a rule of its own, and it is not "the stricter of
the two wins". **The mode in force is the user's own mode, and only when the
user's own file named a mode that runs project code; otherwise it is
`inspect_only`.** A project file cannot move it in either direction. The reason
is not caution but the shape of the two settings: `ExecutionConfig::default()` is
inspect-only and `ExecutionMode` has no `Default`, so a project's *silence* and a
project's `execution.mode: inspect_only` are the same parsed value. "The stricter
of the two" would then read a project that said nothing as a project that asked
for nothing to run, which lets a project's silence settle a question its words
could not. A project that names `host_confirmed` is refused and recorded as a
`ProjectRequest::RunProjectCode` in `Authority::privileges()`, so a report can
say what was asked for.

## The two answers

A merge — folding the project's settings into the user's, keeping whichever is
safer per field — was rejected (ADR 0011). It reinterprets intent: a user who did
not mention a setting has not expressed a preference to be maximised, and the
merged result cannot be reported back in terms of the files they wrote.

Two answers are well defined, and they are the two the layer gives.

### Requests: every ask is on the record

`Authority::privileges()` returns one entry per behaviour any layer asked for. A
`Privilege` names the request, every layer that asked for it (most trusted
first), and who was able to grant it. Four outcomes, all of them visible:

| Who asked | Who granted | What it means |
| --- | --- | --- |
| the user's file | the user's file | allowed |
| the user's file and the project's | the user's file | allowed, and the project agreed |
| the project's file only | nobody | **refused** — a recorded escalation |
| nobody | — | not in the list at all |

The refusal is a value rather than an omission. A file that asked for network
access and did not get it leaves a `Privilege` behind, so a report can say what
was asked for. Dropping it would make "the project asked and was refused" and
"the project asked for nothing" the same list, which is the shape of report this
product exists to replace.

One request in that list cannot be read off a single file, and it is worth
naming here because it is the only one: `ExtendedRetention`. A project naming 30
days has asked for nothing if the user already allows 30, and has asked for more
than they allowed if the user allows 7 or named nothing at all. So it is not in
`Config::requested_privileges` — that reads one file — and is decided by
`Authority::privileges()` from both, which is also where `ProjectRequest::ALL`
puts it.

`Authority::permissions()` is the permission set those grants add up to. It is
not the answer to whether an action may run: that is
`sure_domain::execution::decide`, which also needs a mode and treats a command it
cannot classify as needing its own consent in every mode. `Authority::execution()`
is the two of them together — this set and the mode — so that a caller cannot
take one from each file.

### Scan exclusions

`scan.exclude` is resolved from the user's own file alone: a map from project
root to project-relative paths the scan should not read. An exclusion narrows
the evidence a finding could come from, so it is the person's decision and not
the project's — `Authority::load` refuses a project file that names it, and the
scan records each excluded path as `SkipReason::UserExcluded` rather than
dropping it silently. A project's own `.gitignore` is deliberately not used for
this: repository membership is a different question from what a check should
read, and a file the agent under evaluation can edit must not decide what SURE
reads (ADR 0011).

### Restrictions: the stricter of the two wins

Protection and privacy mode resolve to the stricter value either layer set, and
`Resolved::by` names the most trusted layer that asked for it. A project may ask
for *more* protection and is named as the reason; it may not ask for less.
`fully_local` beats `local_first` whichever layer wrote it, because sending less
out is never the escalation.

A layer that asked for nothing is `by: None`, which means "nothing beyond the
default" and not "SURE did not work it out". A report that could not tell those
apart would be unable to say whether it had looked.

**`privacy.full_recording_retention_days` is a restriction that is not
symmetric**, and it is the one place where "the stricter value" needs saying out
loud: shorter is stricter, whoever asked for it. The user's own file may name any
number of days, including one longer than SURE's default, because how long a
person keeps their own machine's records is their decision. A project file may
only shorten it. Naming a longer period does not raise the number that is used
and does not silently keep the shorter one either: it leaves a refused
`ProjectRequest::ExtendedRetention` in `Authority::privileges()`, so a report can
say what was asked for. The comparison is against the user's number, or SURE's
default when the user named none — a repository the user merely opened is not a
reason to keep their activity longer than SURE would have kept it unasked.

This is the same rule as `full_recording` one step along: recording more is not
running more, and keeping what was recorded for longer is recording more.
`crates/sure-core/src/config/authority.rs` states it as "Protection and privacy
mode are symmetric... Retention is not", and it is why this cannot be resolved by
the same function that resolves protection with the rank turned round.

`Authority::privacy_mode()` is not only a rule the code enforces; it is what a
run **reports**. `sure check` reads its settings through `Authority::load`, and
the mode it prints is the arbitrated one, with `by` named when a file asked for
something stricter than the default. Reporting the project's own `privacy.mode`
would be a false statement about the user's policy — worse than reporting
nothing, because it reads as an answer. The statement a run makes about this, and
about models, is `crates/sure-core/src/privacy.rs`; where it appears is
`docs/architecture/PRIVACY_AND_MODEL_STRATEGY.md`.

One consequence of reading both files is worth naming here: a user settings file
that cannot be parsed stops a check rather than being ignored, with status 5 and
a message naming the file. That is the `Authority::load` rule above, seen from the
command that now depends on it.

`sure hook ingest` is the one caller that does not stop. A hook is a pre-action
gate on a Tier 1 harness, where a process that refuses to answer leaves the
harness to fall open; so a settings file it cannot read — unparseable, or naming
`protection.mode: custom`, which this release refuses — leaves it deciding under
`strict` rather than under the default. The firmer implemented answer is a real
answer and the weaker one is not, and which of the two a harness does with it is
documented per integration (P13-T007) in
`docs/integrations/HOOK_FAILURE_SEMANTICS.md`, one row per harness per event its
manifest wires — including the events where the answer is that this repository
cannot confirm the harness's side and what would settle it.

## What this deliberately does not do

**There is no merged `Config`.** There is no `Authority::effective()`.

**Scope reductions are not overridden, only reported.** A project may turn a
check off; `Config::scope_reductions` says so. The user's file cannot be said to
have overridden it, because a project that sets a check to the value SURE uses by
default is indistinguishable from one that never mentioned it — the claim would
be one SURE cannot support.

**Nothing here is a consent prompt.** An interactive approval is per action and
names the exact command; a configuration file grants a class. The two are
different objects and are not merged into one "allowed" flag.

## Enforced by

| Where | Holds |
| --- | --- |
| `crates/sure-core/src/config/authority.rs` | the layers, the resolution, and its unit tests |
| `crates/sure-core/src/config/mod.rs` | `Config::load_file`, and `requested_privileges` / `scope_reductions` |
| `crates/sure-domain/src/execution.rs` | the frozen vocabulary: `Permission`, `ExecutionPermissions`, `ConsentGrantor`, `decide` |

`crates/sure-core/tests/config_loading.rs` covers the filesystem path a project
file is read from. The user's file is read by the same code, at the path
`Paths::user_config_file()` names.
