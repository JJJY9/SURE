# The command line

`sure` is the universal surface: every user can run every check without
installing a harness plugin (`docs/adr/0004-thin-harness-integrations.md`), and
a harness that wants an active tool surface calls these commands rather than
reimplementing them.

P1-T008 built the framework: what SURE accepts, and how a result reaches a
person and a script. P1-T009 added the first command whose answer depends on
what it found; P1-T010 made `sure protocol` answer a caller that asks whether
the two can talk; the harness work added `sure hook ingest`; P12-T009 added
`sure mcp serve`; P7-T010 gave `check`, `recheck` and `repair` the pipeline
behind them. Eight commands do their work. The rest are recognised, and say so.

That pipeline is one orchestrator in `sure-core` — `sure_core::pipeline` —
running the twelve stages of `docs/architecture/CHECK_PIPELINE.md` in order. It
is the only path from these three commands into the engine: the CLI renders what
the orchestrator returns and calls no detector, aggregator or renderer of its
own. How far down the twelve stages a command goes is the whole of the difference
between them — `check` performs 1–10, `repair` continues to the repair contract,
`recheck` to the re-check — and the stages it does not perform are recorded as
`not part of this run` rather than omitted, so every run shows all twelve.

One exception is stated rather than hidden. To print *the checks that must pass
before this closes*, `crates/sure-cli/src/check.rs` asks
`sure_core::repair_impact::select_impacted_checks` for them, because that is the
function stage 12 hands to the lifecycle and a second derivation in the CLI is
how a sentence a person reads and a test the run applies come apart. It is a
call into the module that owns the rule, not a rule of the CLI's own.

P2-T010 gave `sure check` its first flag with an effect: `--goal TEXT` records
what the user asked for. It is the one place on this surface where a command
changes something the output does not contain, so it has its own section below —
and since P7-T010 the recorded goal is also what the run resolves its intent
from, so the run does not stop there.

P1-T012 added the surface's first global option that changes where something is
written: `--store-dir DIR` says which directory this run's record store lives in.
Its section below is short because the design is: the value comes from the
process's argument vector and from nowhere else. `--settings-file FILE`, added by
P15-T025, is the second, and it is the same design one layer along: the file whose
answer decides what SURE may do. It is documented as what it is — a testing and
automation surface rather than something to hand a user — and it carries the
refusal the first one does not need, because a settings file can grant and a
store directory cannot.

## The commands

| Command | What it will do | In this build |
| --- | --- | --- |
| `sure check [PATH] [--goal TEXT]` | check a project and report what it found | works: the pipeline, a per-stage record, and a verdict |
| `sure recheck [PATH]` | check again and compare with last time | works: the same run, carried on to the last stage, which compares it with what an earlier run left open |
| `sure repair [PATH]` | turn what was found into instructions an agent can act on | works: the same run, carried on to the repair-contract stage, one contract per finding. Each names the check that produced it and the further checks that must pass before it closes, and each is recorded, so the next run has something to compare against |
| `sure history [list\|show\|delete\|export]` | show what SURE has recorded | works, except `export`: the sessions this machine has recorded, one session's events, and the delete |
| `sure doctor` | report where SURE keeps its files on this machine, and what it found there | works |
| `sure config show [PATH]` | show the settings in effect and which layer each came from | works: one row per setting with the value and the layer that chose it; the analysis endpoint, model and command are shown only as set or not set, never as values. With no PATH the user layer is read; with PATH the project's `sure.yaml` is read too |
| `sure config [paths\|validate]` | show where SURE keeps its files, or report configuration problems without checking a project | recognised, not implemented |
| `sure config set SETTING VALUE` | write one setting into your own settings file, the one outside every project | works: only the settings a run reads from that file, only on request, and never a project's own `sure.yaml` |
| `sure hook ingest` | record one event from a coding harness | works; for a pre-action event it also answers with the action SURE would take and a sentence saying why |
| `sure hook allow-once --tool NAME (--command WORDS \| --path PATH) [--project DIR] [--minutes N]` | record a one-time allowance for one request SURE would otherwise hold | works; SURE reads the settings in force and the tool name, and if together they leave a request naming that tool that this project could be held for, it writes the grant to its store and says which acts that covers, read off the settings in force at the moment it writes. If they leave none — the default configuration does, for every tool, and strict-on-its-own does for any tool that is not a read — it refuses, names the tool, and writes nothing, because a grant no matching request could spend is a promise SURE cannot keep. What the sentence offers with it is the change that would make the grant spendable — a setting, where a setting is what stands in the way — which for a tool whose action would change the project's own files is `execution.allow_project_write: true` in the user's own settings file, together with `protection.mode: strict` where the protection in force would otherwise allow the change outright; a project's `sure.yaml` cannot grant that permission, and the sentence says so. Where no setting in this build is the cause the sentence says that instead of naming one, because naming one would be advice to change the wrong thing — and there is no such tool in this build, so that arm is kept for a build in which a permission is once again out of reach rather than deleted. Either way the sentence says the request that spends it has to be one SURE *holds*, rather than promising that the next matching request is let through — see `docs/security/PROTECTION_MODE.md` |
| `sure explain [ID]` | explain one recorded result in plain language | works: a stored finding or check result, by its id or store row; with no ID, the most recent recorded finding (or check result if no finding is recorded). It does not re-run a check and does not turn a stored `CannotConfirm` into a pass |
| `sure mcp serve` | answer a coding harness that speaks the Model Context Protocol | works; each tool it exposes runs one command in this table and returns that command's own answer |
| `sure protocol [--speaks VERSION]` | say which harness protocol this build speaks, or whether it can talk to a caller that speaks one | works |
| `sure version` | print the version of this build | works |

Four options are global — accepted before or after the command name, because they
describe the run rather than the command: `--format human|json`, which the last
section of this document is about, `--store-dir DIR`, which says where the run's
record store goes, `--settings-file FILE`, which says which user-level settings
file the run reads, and `--commands-file FILE`, which supplies user-declared
check commands for a project SURE cannot discover. A command line may name a store location or a
settings file whether or not the command in it writes to the store: a location
that is wrong is a wrong command line, and finding that out only when a command
happens to write would make the same mistake a usage error in one invocation and
a silent success in another.

"Recognised, not implemented" is not a euphemism for a stub. The command parses
its arguments, decides it cannot do its job, **exits with status 3**, and says in
one sentence what it did not do. Nothing is half-done and nothing is reported as
done. `check`, `recheck`, `repair`, `history`, `config show` and `explain` have
left that list; `config paths`, `config validate` and `sure history export`
remain.

`sure config set` and `sure config show` are actions of `sure config` and are not
on that list: `set` writes and `show` reads, both exit 0 or 5 and never 3, and
each is documented in its own section below. The `config paths` and `config
validate` rows stay marked "not implemented" because they are still readers this
build does not carry out.

Where a command is scheduled is `tasks/tasks.json`. That file is not quoted here
on purpose: a phase number in a message a user reads is a promise the command
cannot keep, and the phase a command is scheduled for is not the phase a user
cares about.

### Arguments arrive with the phase that can act on them

No command carries a flag that nothing yet honours. A grammar that accepts
`--deep` and ignores it teaches the user that SURE understood them when it did
not, and the output gives them no way to find out otherwise. This is the same
rule as `additionalProperties: false` on the event schema: an input SURE does
not act on must be a visible error, not a dropped one.

A path is accepted where the documented form has one, and defaults to the
current directory. An identifier is accepted where a command names something.
Both are optional in this build, because making one required is a decision about
the command's contract that belongs to the phase implementing it.

`--goal` on `sure check` is the first flag that is honoured rather than carried,
and it arrived with the phase that could act on it. It is deliberately not
optional-with-a-default: absent means "check the project", and present means
"check it against this". P7-T010 gave both paths their answer — the bare form
runs the pipeline, and a run with `--goal` records the goal and then runs the
same pipeline with the goal resolved as intent (stage 2).

## `sure doctor`

The first command whose answer depends on what it found, and therefore the first
place where the status carries news rather than the fact that SURE ran.

It reports the four paths SURE uses on this machine — evidence and history, the
settings directory, the settings file, and the record store — which of the two
store locations this run is using and which of the two settings locations, what
is at each of them, what is in the store if there is one, whether `git` is on
`PATH`, and everything wrong that it found. It also prints **what it did not
check**, always, because a report that stops at what it found invites the reader
to assume it looked everywhere.

Either location is one line, `store location` and `settings location`, because a
path alone cannot say whether the run is using the platform's own location or one
a caller named — and a caller who cannot tell a redirect that worked from one that
was ignored will debug the wrong thing. The two sentences are "the platform's own
location for this user" and "named for this run, not the platform's own"; the
machine form carries `details.places.store_location` and
`details.places.settings_location` as `"platform"` or `"caller"`, and puts the
files themselves in `details.places.store_file.path` and
`details.places.settings_file.path`. Naming a store directory moves the store and
nothing else, because a caller who points the store somewhere has not asked SURE to
read a different configuration; naming a settings file moves the settings and
nothing else, for the same reason the other way round. The other two paths — the
evidence directory and the settings directory — are always the platform's, because
neither is a thing a caller can name at all.

Three things it deliberately does not do, each of which is what makes the report
safe to paste into a bug report:

- **It does not read the settings file.** It reports the path and whether
  something is there. `docs/architecture/DIAGNOSTICS.md` requires that a secret
  never have to be handled in order to be reported, and the way to keep that true
  is never to open the file that may hold one. Reading settings is `sure config
  show`.
- **It does not create the store.** A store that is not there is reported as
  nothing recorded yet. A diagnostic that changes what it is diagnosing is worse
  than one that says it did not look.
- **It does not run a program.** Finding a program on `PATH` is an observed fact
  about the filesystem; running it is a different claim, and SURE has no process
  runner yet. This is one of the entries under "What this did not check", so a
  reader cannot mistake one for the other.

`sure doctor` is also the first command whose status is not the same on every
machine: 0 when it found nothing wrong, 1 when it did. That is the false-green
rule applied to SURE's own installation — `sure doctor || fix it` has to work.

## `sure history`

The command the two harness integrations had been telling people to run since
before it existed. It answers about **this machine**, not about a project: what
SURE has recorded here, and how to be rid of it. `sure history` and
`sure history show` never create the store — a machine where nothing has been
recorded answers "SURE has recorded nothing on this machine yet" rather than
printing an empty table, because an empty table and a store SURE could not read
would otherwise look the same.

| Form | What it does |
| --- | --- |
| `sure history` | every session SURE has recorded, most recently recorded first, with the project and harness each came from and how long it is kept. `--limit N` shortens the listing; the count of what there is stays the count |
| `sure history show ID` | one session and the events in it, each with the record it wrote |
| `sure history delete --all\|--session ID\|--project ROOT` | removes the rows the scope names, and says how many of each |
| `sure history export` | not implemented in this build: status 3 |

**The scope on the command line is the consent.** Nothing prompts, so a delete
is scriptable by construction: exactly one of `--all`, `--session` and
`--project` is required. Naming none or two is a usage error (status 2) rather
than a default, and a delete with no scope can never be read as a delete of
everything — the one mistake this command must not be able to make by omission.

**A delete that matched nothing is an answer.** It exits 0 and says it removed
nothing, because "there was nothing to remove" is a fact about the store rather
than a failure of the command, and a script that treated it as an error would
stop on the ordinary case. An id that is not in the store is different:
`sure history show` on one cannot answer what was asked, so it exits 5 and says
which store it looked in.

**Nothing is removed because a date passed.** Every session carries a
`kept until` date and this build has no job that acts on one; the listing says
so in the same breath as the date, because a date printed alone reads as a
retention policy that is being enforced. Deleting is something a user does.

What a delete reaches is every table the session touched — `sessions`,
`session_events`, the `records` those events own, and any full recording written
for one of them — in one transaction. The counts are reported apart because
"the transcript is gone too" is a different claim from "the session row is
gone", and a single total would answer neither.

`sure history` is also the first command here whose answer is **not about a
project**, which is why it does not go through `Store::open`: there is no
project to keep it out of, and a history that read one project's records would
be answering a question nobody asked.

## `sure protocol`

Asked with nothing, it prints the version of the harness protocol this build
speaks — the same number every response frame carries as `protocol_version`.

Asked with `--speaks VERSION`, it answers whether this build can talk to a
caller that speaks `VERSION`. This is the handshake an adapter runs before it
sends anything, and the reason it is a command rather than a sentence in each
adapter's own language: the rule about which versions can talk lives in
`crates/sure-protocol/src/handshake.rs`, in one function that the event reader
also uses to refuse a document. An adapter reading the answer cannot be told
"yes" by the CLI and then refused at the first event, which is a failure that
would look like a broken adapter and send somebody looking in the wrong place.

The rule is **exact equality**. A protocol version changes exactly when an older
reader would get the format *wrong*, so a version mismatch means a document that
would be misread — and a misread event becomes wrong evidence about a project.
There is no range of "still close enough".

The two directions are not the same answer, and the message says which one it
is, because a caller that has just been refused will otherwise try the fix that
cannot work:

| Caller speaks | Status | What the caller has to do |
| --- | --- | --- |
| this build's version | 0 | nothing; both sides speak it |
| an older version | 3 | update itself — a newer SURE will not accept it either |
| a newer version | 3 | update SURE |

Status **3**, not 4. A version SURE will not speak is a command this build
cannot carry out, which is what 3 means everywhere else on this surface, and in
the newer-caller direction the remedy is literally a newer build. 4 is reserved
for a refusal grounded in the user's configuration — what SURE's own settings
say it is allowed to do — and no setting makes this build speak a protocol it
was not compiled with.

The machine form carries the numbers and which side moves, and not the sentence:
a script that read prose would break the first time the prose was improved.

```json
{"command":"protocol","details":{"agreed":false,"caller_speaks":2,"sure_speaks":1,"update":"sure"},"exit_code":3,"outcome":"unavailable","protocol_version":1,"sure_version":"0.1.2"}
```

## `sure mcp serve`

The one command that runs for as long as its caller wants it to rather than until
it has an answer, and a surface on the other commands rather than a command of
its own. A coding harness launches the process, speaks the Model Context Protocol
on its standard input and output, and closes the stream when it is done. SURE
never listens on anything: there is no socket and no port, and the caller is the
process that started this one.

It answers a handshake, `ping`, `tools/list` and `tools/call`, and it exposes five
tools: `sure_check`, `sure_get_report`, `sure_get_repair`, `sure_recheck` and
`sure_status`. Each tool builds the command line in the table above and asks
`Command::report` — the same dispatch every other command goes through — so a
tool cannot check, repair or report anything by a path of its own, and cannot
answer in words the command line would not use. A tool whose command this build
cannot carry out is a *tool error carrying that command's own refusal*, not a
refusal of `sure mcp`: the caller asked for a check, and telling it the bridge is
missing would name the wrong thing.

A tool call may name a project and nothing else. Execution mode, privacy settings
and protection policy come from the user's own SURE configuration on the user's
own machine, and **no argument can select or override them**; a call that tries
is refused with a protocol error that says so. A project path is passed to the
command unchanged, so a relative or unreadable path is refused exactly as the
command line refuses it.

`stdout` carries protocol messages and nothing else, in **every** mode,
`--format json` included. The session summary is one CLI envelope, and the
session's stream is not the place for it: Model Context Protocol revision
`2025-11-25` says "The server **MUST NOT** write anything to its `stdout` that is
not a valid MCP message", and an envelope is not a message. So a session summary
goes to `stderr` whichever format was asked for — the one report in this
document that does not follow the rule below — and a caller that reads this
command's `stdout` as a protocol stream may pass `--format json` like any other
caller. Until P12-T010 the flag put one unparseable line after the last message,
which is what the fix removed; `Format::emit` in `crates/sure-cli/src/output.rs`
is the whole of the exception, and
`crates/sure-cli/tests/mcp_protocol.rs::no_line_that_is_not_a_protocol_message_reaches_stdout_in_any_mode`
reads three command lines back from the process to check it.

The process returns 0 when the session ends normally and 5 when the stream it was
talking on could not be read or written. The statuses of the commands behind the
tools do not travel in the process's status: each tool result carries its
command's own frame, `exit_code` included. `docs/architecture/MCP_BRIDGE.md` is
the contract for the protocol side.

## `sure check --goal TEXT`

The first place on this surface where a command changes something the output does
not contain: the goal goes into the user's record store. Everything below follows
from having to be honest about that.

**What a run with `--goal` does.** It writes the text as a project intent whose
`source` is `explicit_user_goal` — the source the domain marks as a user
requirement, and the one that asks for no transcript recording. The text is kept
as it arrived with one exception: the store removes credential-shaped values from
every document it accepts, and `P15-T024` decided that rule wins here rather than
the goal being exempt from it. `docs/architecture/PROJECT_INTENT.md` is the
contract, and it holds the decision and the case against it; this section is the
command-line half of it. There is no session to capture: the words arrived with
the command that stored them.

**Then the check runs against it.** The recorded goal is stage 2's input: the run
resolves its intent partly from what the user stated, and what it resolves is the
text the record holds rather than the words as they were typed — so the
requirement quoted in a not-checked line is the requirement that was written
down. The verdict says what that intent was worth (`must_caveat_requirements`) as
it does for a run with no goal at all. Reporting a receipt and no check would be
the worse of the two answers — the user asked for a check.

**The report says what was recorded.** `details.recorded_goal` carries the goal as
the record holds it — read back out of the row rather than kept from the words
that were typed, so that the sentence a person reads and the text beside it are
about the same record. The same object carries its requirement identifier, the
source as the domain's wire name, and the project state it was recorded against —
the kind and the digest, which is what two runs can compare, plus the identifier
of the reading itself. The prose prints the same facts in words. A run with no
`--goal` answers with `null` there rather than a placeholder: an empty goal
object would be a stored goal no user ever stated, and
`null` is what this frame says wherever something did not happen — `reason` and
`stopped_at` in the stage records are the same spelling.

**The status is the run's own.** A run that recorded a goal and checked the
project returns 0 for a clean project, 1 for a project that was checked and is
not clean, and 5 for a run that tried and did not finish — the same three
statuses every other check returns. It is **not** 3. 3 is "this build cannot
carry that out", whose remedy is a newer build, and this build just carried it
out.

**The goal is bound to a project state.** The store's only project-aware write
takes a fingerprint, and the binding is right: a goal recorded with no project is
a row no reader looking for *this project's* goal can find. The report names the
kind and the digest of the state it recorded against.

**The project is read before the store is opened.** Opening a store creates its
directory and its file. Every refusal in this path therefore leaves the machine
as it found it, which is a promise a user can check and a failure report can
stand on. A run with no `--goal` does not create a store either: it opens the
history only when there is one already, so a check on a machine that has never
used SURE writes nothing at all.

**A run that could not finish is 5, not 3.** 3 is "this build cannot carry that
out", whose remedy is a newer build. A run that met an unreadable project or a
store it could not open tried and did not finish, which is what 5 is for. One
status for both is how a broken installation gets read as a build that has
nothing to do. The one failure in this path that *did* write something says so in
its own words rather than reusing the sentence for the refusals.

An empty goal — `--goal ""`, or one holding nothing but whitespace — is a
failure, not a usage error. It is a goal with no words in it, which is a thing a
user can type, so the parser accepts it and the check refuses it.

### What this flag does not do

SURE cannot authenticate its own command line. `--goal "…"` records that
*somebody who could run this binary* stated that goal; it cannot establish that
the words are what a person asked for rather than what a script decided to
record. That is why the source is `explicit_user_goal` and remains a claim about
provenance rather than a proof of it, and why a goal is never turned into a
finding by being stored. `docs/architecture/PROJECT_INTENT.md` states the limit
in full.

## `--store-dir DIR`

Where this run's record store goes, as a directory: `sure.db` is written inside
it. It is global, so it is accepted before or after the command name, and it is
the only thing on this surface that changes where SURE writes something.

**Which commands write there, and which does not.** `--store-dir` says *where*;
this says *whether*. `sure check` reports and remembers nothing: it opens a store
only when one is already there and creates nothing, before or after, so a check
on a machine that has never used SURE writes no file at all. `sure repair` and
`sure recheck` carry the repair loop, and a loop with no memory is not a loop, so
those two create the store when it is missing and record every finding the run
leaves open. That is what lets a second run say what the first left open, and it
is why the same project gives a different answer to `sure recheck` on its second
run than on its first. A run that checked the project and then could not record
what it left open returns status 5 and says exactly that, rather than reporting a
clean-looking run whose evidence was thrown away.

**The value comes from the process's argument vector and from nowhere else**, and
that is the whole of the design rather than a detail of it. It is not read from
`.sure/config`, from a manifest field, or from a file beside the sources: the
project being checked may be edited by the agent whose work SURE is evaluating,
so a location its own file could name is a location it could point at a directory
it can write to — and the history a verdict is read from would then be the
history the judged thing writes. There is deliberately **no environment
variable** either, for the same reason one step out: a checked project's harness
configuration can set the environment of the processes it starts, so
`SURE_STORE_DIR` would be settable from inside the checked project.
`docs/architecture/STORAGE_AND_DATA_PATHS.md` carries the full reasoning, and two
tests in `crates/sure-cli/tests/cli_contract.rs` hold it to it rather than
stating it: `nothing_a_project_can_write_decides_where_the_store_goes` reads the
modules that decide the location and fails if one of them reads the environment,
and `every_command_is_reached_by_the_location_the_caller_named` reads every
crate's shipped code and fails if a command calls the no-argument
`Paths::discover()` — the shape a command that ignored its caller would take.

**The default is unchanged, and it is not a fallback chain.** A caller who names
nothing gets the platform's own per-user location through `sure_core::paths`,
exactly as before this flag existed. Nothing tries the platform location first
and falls back to a named one, or the reverse: a location that cannot be used is
an error rather than a quiet write somewhere else.

**What a wrong location does.** A path that is relative — including the empty
string — is refused by the parser, status 2, because a relative path resolves
against whatever directory SURE happened to be started in and whether it was
inside the project would then depend on that. A location the run cannot write to
is status 5: it tried and did not finish, which is the same status every other
unusable store gets. A location that does not exist yet is not an error:
`doctor` reports it as not created yet, the first write creates it, and `doctor`
still does not create it.

**A location inside the project being checked is refused when the run opens the
store there**, by the same `Paths::ensure_outside` rule the `--goal` path already
used, and in the same shape: status 5, a message that says what it did and did not
do, and no store directory created. The reason is the one a few paragraphs above —
a location the judged project can write to is a history the judged thing writes —
and the rule is asked of a store the run is about to use, so which runs meet the
refusal follows the paragraph above about which commands write: `sure repair` and
`sure recheck` create the store and are refused in every state, while `sure check`
opens one only when it is already there and is refused exactly when there is a
`sure.db` to open.

Measured, three states of one command line, on Windows:

| what is at the named location | `sure check` | `sure repair`, `sure recheck` |
| --- | --- | --- |
| nothing — the directory does not exist | exit 1, a full report, no refusal, nothing created | exit 5, the refusal, nothing created |
| the directory, empty | exit 1, a full report, no refusal, nothing created | exit 5, the refusal, nothing created |
| a `sure.db` inside it | exit 5, the refusal | exit 5, the refusal |

**The two silent cells are not a gap in the guarantee.** What the rule protects is
*what was read and what was written*, and in both of them `sure check` reads no
store — it opens the history only when one is already there — and writes none. The
security property holds in those cells in exactly the words it is written in; what
a user does not get there is the warning, and the report does not mention the
location it ignored. **The refusal comes before the store is opened**, in every
cell, so it leaves the machine as it found it.

`sure doctor` says which of the two locations a run is using, so a caller who is
not sure whether their redirect took effect can ask instead of guessing.

## `--settings-file FILE`

Which user-level settings file this run reads, as a file rather than a directory:
the file that would otherwise be `<settings directory>/sure.yaml`, which on
Windows is `%APPDATA%\SURE\sure.yaml`. It is global, so it is accepted before or
after the command name.

**It is a testing and automation surface, and it is not for users.** A user's
settings file is found for them, once, at the location their platform reports
(`sure_core::paths`, `SHGetKnownFolderPath` on Windows); a user who wanted a
different file would be a user with two configurations and no way to know which
one was in force. The flag exists because a suite has to be able to observe the
consented case at all. The consent to keep a full recording is the user's own
word and comes from no other layer (`Authority::full_recording`), so without a way
to point a run at a file this program wrote, the only settings file a test could
ever exercise would be the one belonging to the person running the suite — which
no test may write, and which on a machine where it happens to grant recording
would silently answer a different question. `crates/sure-cli/tests/privacy_suite.rs`
drives both halves from the corpus: the case
`a-full-recording-written-under-consent-is-redacted-on-disk` points a real `sure
hook ingest` at a granting file it wrote and asserts the recording, and
`no_settings_file_at_all_is_the_premise_the_binary_cases_run_under` asserts the
default run is still about the platform's own path and not about a named one.

**What it may grant: exactly what the user's own file could grant, and no more.**
The named file stands where the user's file stands — the same layer, the same
schema, the same reading (`Authority::load`) — so it can turn on full recording,
lengthen a retention, and set the execution and protection rules a user's file can
set. It can do nothing else. It changes no other location: the store, the evidence
directory and the settings directory are the platform's or the caller's
respectively, and naming this file moves none of them. It grants nothing to a
project. And it is not an authority above the user's own file: a run that names
one reads *that* file and not the platform's, so the worst a named file can do is
what the user could have written in the file it stands in for.

**A settings file inside the project is refused.** Before the file is read, and
before anything is decided or recorded under it, the run asks
`Paths::ensure_settings_outside` about the project it is about — for `sure check`,
the project on the command line; for a hook, the project the harness event names,
which is the harness's claim about which project this is. A file inside it is
status 5, with a sentence saying SURE stopped rather than treat it as the user's
own word, and nothing is recorded. This is the refusal that makes the flag not a
way to escalate: a checked project's harness configuration can name the command a
hook is run as (`.claude/settings.json`, Cursor's hooks file, both in the project's
own directory), so it can put `--settings-file` on a command line it causes SURE to
be started with. What it cannot do is read a file it wrote and have SURE obey it.
The corpus drives the attempt —
`a-settings-file-the-project-could-write-grants-nothing` in
`fixtures/privacy/manifest.json` puts a *granting* file inside the project, names
it, and requires the refusal rather than a recording.

The question is asked of the root itself as well as of the file: a `project_root`
that is not an absolute path is refused here, with the same status and nothing
recorded, because such a root would have to be resolved against whatever
directory the hook was started in — and the store keys a session by that same
root, so the project an event belonged to would depend on the harness's working
directory. `P15-T035` decided this rather than inherited it, and
`docs/integrations/HOOK_FAILURE_SEMANTICS.md` §2.3 records what each shipped
harness pack does with the refusal.

**The value comes from the process's argument vector and from nowhere else.** No
environment variable, for the reason `--store-dir`'s section gives one step out:
a checked project's harness configuration can set the environment of the processes
it starts, so `SURE_SETTINGS_FILE` would be settable from inside the checked
project, and the file that decides whether a recording is kept is not a value that
may be set from inside the thing being recorded. Two tests in
`crates/sure-cli/tests/cli_contract.rs` hold this rather than state it:
`nothing_a_project_can_write_decides_where_the_store_goes` fails if a module that
decides a location reads the environment, and
`a_project_cannot_set_a_settings_file_through_the_environment` sets the variable a
project would have to use and requires the run to ignore it.

**One command refuses the flag outright.** `sure mcp serve` answers tool calls on
behalf of a session that a harness is driving, and it takes its store from the
session it was started with; there is no consent question in it that a settings
file would answer, so a name given there is refused with status 5 and the session
is not started, rather than accepted and ignored.

**What a wrong value does.** A path that is relative — including the empty string
— is refused by the parser, status 2, for the reason `--store-dir`'s section
gives: a relative path resolves against whatever directory SURE happened to be
started in, and whether it was inside the project would then depend on that. A
file that is not there is not an error: SURE reads the defaults and records the
refused requests, exactly as it does on a machine that has no settings file at
all, and the report says in that many words that no file was found.

A file that is there and will not parse is **two different answers**, and this
paragraph said one of them for as long as it was wrong. Both readings come from
`Authority::load`, whose rule is that one bad file stops the read rather than
being skipped: a file SURE cannot read is not a file that declared nothing, and
carrying on would run under defaults while the user believes their settings are
in force.

- **A check, a recheck or a repair stops.** Status 5, with the parse error and
  the path in it, and no verdict about the project — because the execution mode
  every dynamic check is authorised under is a setting that file decides, so a
  run that could not read it has nothing to check with. The status is 5 and not
  3 for this document's own reason: 3 means *this build cannot do that*, and this
  build can; the file is the thing that could not be read.
- **A hook falls back, and falls back downwards.** `hook ingest` answers a
  harness event, and a harness is waiting: the event is still recorded, and what
  the run decides with is `inspect_only`, an inspect-only permission set and
  `protection.mode: strict` — the least permissive answer SURE has, never the
  project's ask and never a default that happens to be looser. The same fallback
  is what reads the recording settings, so a file that asks for a full recording
  and does not parse gets the event and no transcript: one run measured here
  wrote `event` and nothing else, where the same event under a granting file that
  *does* parse wrote `event` and `recording`. See
  `docs/integrations/HOOK_FAILURE_SEMANTICS.md` for why a refusal there is not
  the same act as a refusal at a command line.

Either way nothing was silently given up: the difference between the two is that
one of them has somebody waiting and the other does not.

## `--commands-file FILE`

The check commands a user declares for a project SURE cannot discover — a
Makefile, a shell script, a build system with no manifest SURE knows. The file is
YAML, names a program and its arguments per role, and is read by `sure check`,
`sure recheck` and `sure repair`:

```yaml
commands:
  test: ["make", "test"]
  build: ["make", "build"]
  lint: ["make", "lint"]
  typecheck: ["make", "typecheck"]
```

The first element is the program and the rest are arguments, one element per
argument. **SURE never splits a shell string**, so a command line with pipes,
redirections or variable expansion is not accepted; write the argv the program
would receive. Unknown roles, an empty vector and an empty program are refused
before any check is planned.

**The file replaces the native plan, and it is outside the project.** The file is
a path from this process's argument vector, refused when it is inside the project
being checked, for the same reason `--settings-file` is: the project is the thing
being judged, and a file it can edit is a plan it wrote for its own verdict. A
role the file omits is recorded as not declared rather than silently dropped, so
a test-only override is not a green verdict. Commands are planned under the same
execution mode and permissions as every other check; a run that has not been
granted `run_project_code` does not run them.

## `sure config set SETTING VALUE`

Write one setting into **your own settings file** — the one outside every project,
the file `--settings-file` names when a caller names one and
`%APPDATA%\SURE\sure.yaml` on Windows otherwise. It is the only writer of that
file in this build, and it exists because the rule it serves had no remedy
without it.

The rule: full recording and every execution mode other than `inspect_only` are
granted by the user's own settings file and by **no other layer**
(`Authority::full_recording`, `Authority::execution_mode`, and
`Layer::can_grant` in `docs/architecture/CONFIG_AUTHORITY.md`). A project's
`sure.yaml` may ask for either and can never grant it, because a file the agent
under test can write cannot be the authority for what SURE may do. Before this
command, a person read *"asked for, and not in force"* and had nowhere to go: the
file had no writer and nothing told them where it would be. A rule a user cannot
satisfy is a refusal with no remedy, so the refusal now names the file and the
command, and the command writes the file.

```
sure config set privacy.full_recording true

sure config set wrote your settings file.

  Setting    privacy.full_recording
  Written    true
  File       C:\Users\you\AppData\Roaming\SURE\sure.yaml

That file is your own, and it is the only one that can grant this: a project's sure.yaml may ask for something and can never grant itself anything, because a file the agent under test can write cannot be the authority for what SURE may do. It is outside every project you check.
```

Run again with nothing left to change, it prints a **different sentence**:

```
sure config set wrote nothing.

  Setting    execution.mode
  Already    host_confirmed
  File       C:\Users\you\AppData\Roaming\SURE\sure.yaml

That file already said this, so it was left exactly as it was — not rewritten, not reformatted, and its comments are all still there. This is not a failure: what you asked for was already true.
```

And a third, when it will not write what was asked:

```
sure config set wrote nothing, and here is why.
```

Three different openings, on purpose: a person has to be able to tell a write
from a no-op from a refusal without opening the file, and a status alone is not
enough — a no-op and a write are both 0, because both did what was asked. A
refusal is status 5, never 3: this build can write the file, and the answer is
that it will not write *this*.

### What it will write

Exactly the settings a **run** reads from that file, and it proves each one while
it works. There are nine, and every one of them is read from the user's own
layer by `Authority`:

| Setting | Values |
| --- | --- |
| `execution.mode` | the execution modes this build knows, from `ExecutionMode::ALL` |
| `execution.allow_dependency_install` | `true`, `false` |
| `execution.allow_network` | `true`, `false` |
| `execution.allow_project_write` | `true`, `false` |
| `privacy.full_recording` | `true`, `false` |
| `privacy.full_recording_retention_days` | `0` or more |
| `privacy.mode` | the privacy modes this build knows, from `PrivacyMode::ALL` |
| `analysis.provider` | the analysis providers this build knows, from `AnalysisProvider::ALL`; `analysis.endpoint`, `analysis.model` and `analysis.command` are edited in the file, not by this command |
| `protection.mode` | the protection modes this build knows, from `ProtectionMode::ALL` |

The value lists are the product's own — read out of those `ALL` lists rather than
copied into the command — so a mode added to the product is a mode this command
accepts, and a mode removed from it is not.

**A setting this command will not write is refused with its reason**, not
silently skipped and not written anyway. `privacy.telemetry` is the one that
matters most: nothing in this release implements it, no code path sends usage data
anywhere, so a file saying `telemetry: false` would look like a decision the
person had made and be read by nothing. The others are family refusals —
`analysis.`, `project_intent.`, `checks.`, `report.`, `redaction.` — for settings
whose value a run reads from the *checked project's* file. Writing one into the
user's file would be writing a setting with no effect, and a person who then read
that file would believe something about their machine that was not true. The
refusal says which of the two it is.

**A value the release refuses is refused too, in the product's own words.** The
text is `Config::from_yaml`'s — the same message a run would give if the file had
been edited by hand — so the command cannot drift into accepting something a run
would reject. `privacy.mode: cloud_enhanced` is the case this is for: it is in
the schema and not in this release, and what the person reads is why.

One consequence worth stating rather than leaving for a person to notice: that
text was written about a *project's* file, so where it says "would let a project
file claim a privacy arrangement SURE does not actually provide" it is naming a
danger that does not apply to the file being edited. The reason it gives is the
same either way — this release does not implement that mode — and the command
prefers one honest message from the reader to a second copy of the refusal,
hand-written here, that could drift from it. Two refusals that disagree about why
a value is refused would be the worse defect.

### What it will not touch

**A project's `sure.yaml` is unreachable from every path of this command.** The
file it writes is the one `Paths::user_config_file()` names, and before it writes
anything it asks `Paths::ensure_settings_outside` the same question a run asks
about the file it reads: a settings file inside the project being judged is status
5, with the reasoning, and nothing is written. So a person standing in a project
who names the file that is right there is refused, and a project whose own
`sure.yaml` names the very setting being written gets a file that is byte-for-byte
what it was.

That is the whole of the third acceptance criterion of the task this arrived
with, and it is checked as bytes rather than as intent:
`no_path_of_a_config_write_reaches_the_projects_own_sure_yaml` in
`crates/sure-cli/tests/cli_contract.rs` walks the project's files before and
after, and `a_settings_file_inside_the_project_is_refused_and_nothing_is_written`
does the same for the refusal.

**It creates the directory, and nothing else.** A settings file whose parent
directory does not exist yet is written into a directory created for it — the
first run on a machine that has never had one has nowhere to put it otherwise —
and the file is written to `<file>.yaml.sure-new` beside it and then renamed into
place, so a run that fails half way through leaves the previous file exactly as it
was rather than a truncated one. The temporary is removed when the rename fails.

**It edits rather than re-renders.** A settings file is a file a person owns and
may have commented, and re-serialising it would be this command reformatting
somebody's file to change one value. So the value's own line is rewritten in
place, everything else is left as it was, and a trailing comment on that line
survives (`# changed on 2026-01-02` stays where it was). The one cosmetic change
is that the whitespace before a trailing comment is normalised to a single space.
A file that already says what was asked says nothing at all: it is not rewritten,
not reformatted, not even touched — that is the no-op sentence above, and it is
checked as bytes.

**It is not a way to make SURE accept a file it cannot read.** If the existing
file will not parse, the command refuses and leaves it alone. The reason is visible
rather than subtle: what it writes is checked against `Config::from_yaml` *and*
compared against the same file with only the leaf changed, before anything is
written, so an edit that did not mean what it looked like meaning is a refusal
rather than a file that silently says something else.

### What it tells you afterwards

The confirmation names the file in the operating system's own terms — the path
`Explorer` would show on Windows — and the report continues into the same grants
section every run carries (see below), read back through `Authority::load`, which
is the reader every run and every hook uses. So the machine form of the command
carries `details.granted`: the mode, the permissions, whether a full recording is
on, the retention, the protection mode, and what was refused, exactly as a check
reports it. A command that wrote a file and a run that reads the same file cannot
disagree about what it says, because it is one function reading it.

```

{"command":"config set","details":{"granted":{"execution_mode":"host_confirmed", …},"setting":"privacy.full_recording","settings_file":"…","state":"written","value":"true"},"exit_code":0,"outcome":"ok"}
```

`state` is a closed set — `written`, `already_said`, `refused` — so a script can
tell the three apart without reading the sentence, and `granted_error` is filled
in instead of `granted` when the file was written and the read-back could not be
done: the file *was* changed, and saying so is more important than the read-back.

## `sure config show [PATH]`

Print the settings in effect, one row per setting, and the layer that chose it:
your own settings, the project's `sure.yaml`, or the default. With no `PATH` only
the user layer is read; with `PATH` the project's `sure.yaml` is read too.

It never prints the analysis endpoint, model or command. Those rows say **set**
or **not set**; the values stay in the file, so the output can be pasted into an
issue without carrying a credential. `sure doctor` still does not read settings at
all — this command is where the arbitration between the two layers is reported.

Exit 0. A project path that is relative, or a path where there is no directory,
exits 5 with the reason.

## `sure explain [ID]`

Explain one recorded finding or check result in plain language. `ID` may be the
stable finding id (`fnd_…`), the check-result id (`chk_…`), or the store row
number `sure history show` prints. With no id, the most recent recorded finding
is explained; if no finding was recorded, the most recent check result is.

It opens the store, decodes the document that was recorded, and prints what it
says — title, severity, status, evidence and next step. It never re-runs a check
and never turns a stored `CannotConfirm` into a pass. `sure check` does not record
a result; `sure repair` and `sure recheck` do.

Exit 0 when a result was explained. Exit 5 when there is no store, no matching
result, or the row is not a finding or check result.

## Two output paths, and no third

| `--format` | Stream | Shape |
| --- | --- | --- |
| `human` (default) | stdout for an answer, stderr for a complaint | prose for a person |
| `json` | stdout, except for the one report row three names | one object on one line |
| `human` or `json`, `sure mcp serve` | stderr | the session summary, which is not a result |

`--format` is global, so it is accepted before or after the command name.

The rule that matters is not that there are two renderers. It is that there is
no third way out: `crates/sure-cli/src/output.rs` is the only module in the
crate that names a process stream, and
`crates/sure-cli/tests/cli_contract.rs::only_the_output_module_writes_to_a_stream`
reads the sources and fails if another one appears. That is a source scan
rather than a test of behaviour because what is being ruled out is an
*absence* — a stray `println!` is invisible until the day somebody pipes the
output into a JSON reader, and by then it is in a release.

A command's answer is prose on stdout, which is what makes `sure check >
report.txt` put the report in the file. A complaint goes to stderr, so the same
redirection leaves it where the person can see it. The machine form always goes
to stdout, including when the command failed: the object *is* the result, and a
script that asked for the reason has to be able to read it.

The third row is the one exception, and it is not a judgement about output. A
session summary is not a result of this program being asked something; it is a
diagnostic about a conversation SURE is having with a harness on the very stream
the other two rows would use, and the caller on that stream is parsing messages.
So it goes to stderr in both formats, and nothing else about the two paths
changes: `Report::McpSession` is the only report that takes it, and `Format::emit`
is the only place that decides.

### The frame

A complaint:

```json
{"command":"history","does":"…","exit_code":3,"instead":"…","outcome":"unavailable","protocol_version":1,"sure_version":"0.1.2"}
```

A report:

```json
{"command":"doctor","details":{"build":{…},"not_checked":[…],"places":{…},"problems":[…],"store":{…},"tools":[…]}},"exit_code":0,"outcome":"ok","protocol_version":1,"sure_version":"0.1.2"}
```

A run that did not finish is a complaint too, and keeps the envelope:

```json
{"command":"check","details":{"detail":"…","what":"Nothing was recorded, and nothing was checked."},"exit_code":5,"outcome":"failed","protocol_version":1,"sure_version":"0.1.2"}
```

A check that finished puts the whole run under `details`, including one entry per
stage in the order `CHECK_PIPELINE.md` lists them, each with its outcome
(`ran`, `not_run`, `not_part_of_work`, `unfinished`) and, when it did not run,
the vocabulary's own reason plus the sentence a person reads:

`details.check_results` carries the run's explicit `CheckResult` rows, including
passes that the verdict's `findings` and `not_checked` lists do not contain.
Each row names the check, its status, evidence class and project fingerprint.
The human form lists only the passing rows, under **Checks that passed**: a
failing or warning check is already a finding above, and one that did not run is
already under **Could not check**, so listing them here would print one result
twice. A passing project-owned test means that test passed; it does not validate
external payment, email, authentication or other live services.

```json
{"command":"check","details":{"checked_count":0,"green":false,"has_critical_gaps":true,"mode":"inspect_only","not_checked_count":18,"project":"…","purpose":"check","recorded_goal":null,"report":{…},"stages":[{"detail":"…","number":1,"outcome":"ran","reason":null,"stage":"discover","title":"Find the project's parts"},…,{"detail":"…","number":6,"outcome":"not_run","reason":"execution_not_authorized","reason_explained":"Checking this would have meant running your project's code, and you have not allowed that.","stage":"dynamic-checks","title":"Run the project's own checks"},…],"state":"finished","stopped_at":null,"support":{"letter":"C","level":"inspect_only","reason":"…"}},"exit_code":1,"outcome":"not_green","protocol_version":1,"sure_version":"0.1.2"}
```

Five fields are always present: `sure_version` and `protocol_version`, so that a
captured response says which build and which protocol produced it — those are
the two things that make a stored answer unreadable, and a response that names
neither invites the reader to assume the current ones — `command` and `outcome`,
which are what a reader switches on, and `exit_code`, which is the status the
process returned. The last was first written only for a complaint, on the idea
that a field should appear when it says something; that is the wrong test for
this one, because a frame where it is sometimes absent is a frame a script has
to special-case. The status is a fact about every run.

`outcome` is a closed set: `ok`, `not_green`, `unavailable`, `failed`. It grows
when a command can end another way, and every reader's switch has to grow with
it. `failed` arrived with `sure check --goal` (P2-T010), the first command that
can try and not finish, and a check that stops at a stage it cannot get past —
an unreadable project, a history it cannot read — ends the same way.

`outcome` and `exit_code` are one decision written twice: `Report::outcome` and
`Report::exit_code` read the same predicate, so a build where they disagree is
not a build that can happen. They are both here because they are read by
different things — `outcome` is what a person's script switches on in the body,
and the status is what a caller acts on without parsing anything.

`not_green` says the answer is not a clean one — `sure doctor` on a machine
where SURE found something wrong with its own files, or `sure check` on a project
that was checked and is not clean. That is still an *answer*: it goes to stdout,
so `sure doctor > report.txt` puts the report in the file and the exit status
carries the bad news on its own. A complaint is SURE saying it could not do the
thing at all, and that goes to stderr.

Anything a command found goes under `details`, one key, written by that command's
own module. The five fields above then keep meaning exactly what this section
says they mean, whatever a command has to report. `sure protocol --speaks` is
the case that shows why: it answers with a complaint — `unavailable`, status 3 —
and still has three facts to hand over, so they go under `details` rather than
becoming three more top-level fields that only one command ever writes.

**This frame is not one of the seven documents in
`docs/architecture/PROTOCOL.md`.** Those are statements about a project or an
event, each with a JSON Schema in `schemas/`; this is the envelope a command
answers in. `docs/architecture/PROTOCOL.md` carries the same note, because a
sentence there says that everything SURE writes is one of the seven, and a CLI
response is written.

The frame lives in `sure-cli` rather than in `sure-protocol` because it has one
consumer. `sure-protocol` holds contracts with things outside this repository,
and generalising a shape before a second caller needs it is how a contract
becomes a guess — which is the reasoning ADR 0012 used to turn down a logging
framework. When P12-T009's MCP server needs the same envelope, it moves, with a
real second consumer in hand.

P12-T009 arrived and the move did not happen, which is a decision rather than an
omission. The bridge did not need a second envelope: it lives in this crate, it
builds `Report::Mcp` values, and a protocol message *is* that report's machine
form — the same `Report::frame` writes both. The tool results embed the
command's frame verbatim under `structuredContent.sure`, which is that same call
rather than a second renderer agreeing with the first. The trigger for the move is
a consumer outside this crate needing the shape; a bridge inside it is not one.

### What a run says about privacy and models

A check report carries one more section in each rendering, and it exists because
neither answer is derivable by a user from anything else SURE prints: which
privacy mode the run was under, and whether a model was consulted.

```
Privacy and model use

  Mode in effect: local_first
    Nothing set this: it is what SURE does when no settings file asks for something stricter.
    Evidence stays on this machine. External analysis is allowed only where your own settings configure it, and nothing is sent by a check that does not ask for it.
  Analysis provider: disabled
  No model was consulted: no analysis provider is configured (`analysis.provider` is `disabled`). The deterministic checks are unaffected.
```

The machine form carries `details.privacy` (`mode`, `mode_set_by`,
`project_mode`, `external_analysis_allowed`, `analysis_provider`) and
`details.model_use` (`state`, `provider`). `model_use.state` is a closed set —
`no_provider`, `nothing_asked`, `provider_unusable`, `consulted`,
`cannot_confirm` — and it is deliberately not a boolean: `false` would have to
stand for both "a model was not consulted" and "this run cannot say", and a
script reading the reassuring half of an ambiguous field is how "nothing was
sent" gets asserted about a run that never reached the stage.

Three rules, each of which a test holds:

- **The mode is the arbitrated one.** It is `Authority::privacy_mode()`'s value,
  not the project's `privacy.mode`, and `mode_set_by` names the layer that
  decided. A run that reported the project's request as the user's policy would
  be making a false statement about the user's own settings — see
  `docs/architecture/CONFIG_AUTHORITY.md`.
- **The no-model case is stated, never omitted.** Silence reads both as "nothing
  left this machine" and as "SURE did not look", and only one of those is true.
- **A stopped run is not a run that sent nothing.** It has settings, so it
  answers; and because it has no record of the stage that would ask a model, it
  says it cannot confirm rather than that nothing was used.

`docs/architecture/PRIVACY_AND_MODEL_STRATEGY.md` is the semantics behind all of
this, and the honest limit of this release: no check in this build asks for
model-backed analysis, so external model use cannot be observed happening, and
`consulted` is unreachable. What the run states is a fact about its
configuration and its own record, not a report of traffic.

### What a run says about your own settings, and what they allow

A check or recheck report carries one more section, and it exists for the reason
`sure config set` exists: full recording and every execution mode other than
`inspect_only` come from the user's own file and from no other layer, so a person
cannot tell from a verdict alone whether that file was read, whether it was there
at all, or why a project's own `sure.yaml` asking for the same thing did not get
it.

```
Your own settings, and what they allow

  Your settings file: C:\Users\you\AppData\Roaming\SURE\sure.yaml
    There is no file there. SURE is using its own defaults together with this project's own sure.yaml, and a project's file cannot grant itself anything below: only your own file can, and `sure config set <setting> <value>` writes it for you.
  Execution mode: inspect_only
    SURE will read your project's files only. Nothing in your project will be run.
  Permissions: read this project's files and nothing else
  Full recording: off — no full transcript of the session is kept. Your own file is the only one that can turn it on: `sure config set privacy.full_recording true`.
  Full recording kept for: 3 days
  Protection: standard

  Asked for, and not in force
    run this project's own commands on this computer, asked by this project's own sure.yaml. It was not granted, and that is the whole of what not granting it means: SURE did not do it.
      Only your own settings file can allow it, and it is C:\Users\you\AppData\Roaming\SURE\sure.yaml
      `sure config set execution.mode host_confirmed` writes that grant there.
```

The machine form carries `details.grants`: `settings_file`, `settings_file_read`,
`execution_mode`, `permissions`, `full_recording`, `full_recording_retention_days`,
`protection`, `granted` and `refused` (each refused row a `request` and the layers
that `asked_by` it).

Three rules, each of which a test holds:

- **It is about the arbitrated answer, not about the project's file.** The mode
  is `Authority::execution_mode()`'s, and a request the project made and the
  user's layer did not grant is reported as refused rather than applied — the
  same pair `a_setting_only_a_users_own_file_can_grant_is_written_and_a_later_run_reports_it_in_force`
  drives in both directions in `crates/sure-cli/tests/cli_contract.rs`.
- **No file at all is stated, and stated differently from a file that says
  nothing.** The first line either says SURE read the file or says there is no
  file there; `settings_file_read` carries the same distinction to a script. The
  two are different answers, and a person whose settings are not in force needs
  to know which of them they have.
- **A refusal comes with its remedy.** Every request that was not granted names
  the file that could grant it and the `sure config set` line that writes it
  there. Where no setting in this build grants the request — an external
  analysis provider's own settings, which a run reads from the project — the
  section says so instead of naming a command that would not help. A refusal
  without a remedy is what this section was added to stop.

`sure config set` prints the same section, from the same function, reading the
file back through `Authority::load`. A command that writes the file and a run
that reads it therefore cannot describe it differently.

## Exit statuses

| Status | Meaning | Who returns it |
| --- | --- | --- |
| 0 | the command did what it says it does | `version`, `protocol`, `doctor` when it found nothing wrong, `history` — including a listing with nothing in it and a delete whose scope matched nothing — `--help`, `--version`; `hook ingest` when the action it answered with is allow or warn, so a launcher is not stopped; `hook allow-once` when the grant was written; `config set` when it wrote the setting, and when the file already said it — a no-op is not a failure, and its sentence is a different one |
| 1 | the command ran, and the answer is not a clean one | `doctor` when it found something wrong; `check`, `recheck` and `repair` when the project was checked and is not clean; `hook ingest` when the action it answered with is a block, which is the answer a launcher relays |
| 2 | the command line was wrong | the parser, including a bare `sure` |
| 3 | the command exists, and this build cannot carry it out | everything in the table above marked "not implemented"; `sure protocol --speaks` for a version this build does not speak |
| 4 | SURE declined, and can say why in the user's terms | reserved; configuration authority and path rules |
| 5 | the command tried and did not finish | `check`, `recheck` and `repair` when the project, the store or the goal could not be read or written — including when the user's own settings file is there and will not parse; `mcp serve` when its stream could not be read or written; `history show` for an id that is not in the store, and any history command when the store is there and cannot be read; `hook allow-once` when it declines to write the grant — a window it does not record, or a project and tool whose settings leave no request naming that tool an allowance could be spent on; `config set` when it will not write what was asked — a setting that cannot take effect, a value this release refuses, or a file inside the project it would be writing the authority from; anything, including a result that could not be written out |

**A check reaches 0 only through the pipeline's own answer**, and the way to it
is the same under either authority. Under the mode a run starts in, a project
SURE can plan for has its project-running checks refused before a runner sees
them (`inspect_only`) and stage 8 recorded as `analysis_provider_disabled` (no
model provider is configured); a project with no parts at all still has stage 8
unconfigured. With `run_project_code` granted by the user's own settings file —
since `P18-T007` wires the pipeline to the runner — those checks are carried out
and each reports one result, and the answer is what the runner reported: a check
it produced nothing for is an `Error`, never a pass, and an unreported critical
check aggregates to `not_enough_checked`. Either way a stage that did not run is
recorded as such, and a run with one of those is never reported as clean — which
is what the false-green rule asks for. Under the settings this build starts
with, `sure check` returns 1 for a project it can read and 5 for one it cannot;
`sure repair` and `sure recheck` return the same statuses for the same reasons.
Stages 11 and 12 do their work now, on a project that has findings, and that
changes no status either: a repair contract checks nothing — it says what would
have to pass — so a command that wrote one and reached 0 would be the false
green this table exists to prevent. **The day the runner landed, nothing in this
table moved, which was the point of writing it this way**: the status comes from
the verdict, and what moved was the verdict.

The whole table is in `crates/sure-cli/src/report.rs` as `report::exit`, and it
is the only place a status is chosen. `main` handles clap's parse error itself
rather than letting `clap::Parser::parse` exit the process, because a table
where one row is a library's decision is a table that quietly becomes wrong.

Two statuses are reserved before anything returns them. A script written against
this release should not have to be rewritten because a later one reused a number
for something else.

**1 and 3 are not the same and must not be merged.** "The project has problems"
and "SURE cannot do that here" need opposite responses from the person reading
them, and one status for both is how a tool that is broken gets read as a
project that is clean.

One code for two meanings is right where a caller does the same thing with both.
`sure check` finding problems and `sure doctor` finding a damaged store are both
"stop and read the report": the report says which, and the status is what stops
the script.

### A bare `sure` is not a success

It did nothing, so status 0 would let a script that invoked the wrong thing read
it as a clean run. It is status 2, the same as any other wrong command line.

## Why clap

`docs/architecture/RUST_DESIGN.md` names it, and it earns its place on a surface
this user-visible: usage errors that name the flag, `--help` that cannot drift
from the grammar the parser actually accepts, and the `--` handling that decides
whether a path beginning with a dash is a flag or a path. Hand-rolling that is
where "an unknown flag was accepted and ignored" comes from, which is this
program's version of a false green.

What clap decides is what the command line means. What it does not decide is
anything about output or status: both are SURE's, and both have one home.

## What keeps this honest

| Claim | Test |
| --- | --- |
| Every documented command parses | `crates/sure-cli/tests/cli_contract.rs`, `every_documented_command_parses` |
| A command that did nothing never exits 0 | same file, `no_command_that_did_nothing_reports_success` |
| The two paths use the streams the table above names | same file, `a_refusal_reads_on_the_terminal_and_leaves_standard_output_empty` and `the_machine_form_is_one_object_on_one_line_of_standard_output` |
| Both paths describe the same outcome | same file, `the_two_paths_disagree_about_nothing_that_matters` |
| A doctor report's status, outcome and problems agree | same file, `a_doctor_report_is_an_answer_however_it_turns_out` |
| No module outside `output.rs` writes to a stream | same file, `only_the_output_module_writes_to_a_stream` |
| `sure hook ingest` reads the event from standard input and answers a protection decision | same file, `hook_ingest_reads_standard_input_and_evaluates_protection` |
| A recorded allowance is spent by the exact request it names, once, by no other, and only by a request SURE holds for one of the three acts it covers | `crates/sure-cli/src/hook.rs`, `a_broad_delete_is_held_and_an_allowance_for_it_lets_one_through`, `an_allowance_covers_one_request_and_not_its_neighbours`, `a_force_push_is_held_and_an_allowance_for_it_lets_one_through`, `a_read_of_credentials_is_held_under_strict_and_an_allowance_for_it_lets_one_through`, `a_refused_grant_is_never_written_and_a_written_one_can_be_spent` |
| `sure hook allow-once` refuses a project and tool whose settings leave no request naming **that tool** an allowance could be spent on, names the tool and what would have to change — the setting that stands in the way, or the build’s own limit where no setting does — and writes no row; a grant it does write is one a matching request spends, and the confirmation names the acts the settings in force when it was recorded leave **for that tool** | `crates/sure-cli/src/hook.rs`, `a_refused_grant_is_never_written_and_a_written_one_can_be_spent` and `a_grant_carries_the_acts_the_settings_in_force_leave_for_it`; `crates/sure-cli/tests/cli_contract.rs`, `an_allowance_the_settings_cannot_spend_is_refused_and_the_store_stays_empty` and `a_recorded_allowance_is_one_the_request_it_names_spends`; `crates/sure-core/src/hook_protection.rs`, `the_acts_left_for_an_allowance_are_read_off_the_rule`, `the_refusal_names_the_setting_and_only_a_change_that_would_work` and `every_kind_a_tool_name_can_reach_has_a_witness`; `crates/sure-cli/src/report.rs`, `a_recorded_allowance_names_the_acts_the_settings_left_for_it` |
| The mode a decision is made under is the arbitrated one, and `strict` holds an operation `standard` allows | `crates/sure-cli/tests/cli_contract.rs`, `the_protection_mode_a_project_names_is_the_one_sure_decides_under`; `crates/sure-cli/src/hook.rs`, `a_project_file_cannot_lower_the_mode_the_user_set` and `the_same_read_is_allowed_under_standard_and_held_under_strict` |
| The grammar is the list in this document | `crates/sure-cli/src/main.rs`, `the_grammar_is_the_one_docs_architecture_cli_md_lists` |
| Every MCP tool answers with what the command line behind it answers | `crates/sure-cli/tests/mcp_protocol.rs`, `every_tool_answers_what_the_command_line_behind_it_answers` |
| No MCP tool reports success for a project that was never checked | same file, `no_tool_reports_success_for_a_project_that_was_never_checked` |
| No MCP argument can reach the execution, privacy or protection policy | same file, `no_argument_can_reach_the_execution_privacy_or_protection_policy` |
| The bridge writes protocol messages to stdout and its summary to stderr | same file, `stdout_carries_protocol_messages_and_the_session_summary_goes_to_stderr` |
| No line that is not a protocol message reaches stdout, in any mode | same file, `no_line_that_is_not_a_protocol_message_reaches_stdout_in_any_mode` and `the_machine_format_leaves_stdout_to_the_protocol_and_writes_its_envelope_to_stderr` |
| The doctor's labels and values line up | `crates/sure-cli/src/doctor.rs`, `every_label_the_report_prints_is_separated_from_its_value` |
| `sure doctor` never reads the settings file | `crates/sure-core/tests/doctor.rs`, `the_diagnostic_never_reaches_for_the_settings_module` |
| `sure doctor` never creates the store | same file, `the_report_never_creates_what_it_reports_on` |
| The doctor names the files the store writes | same file, `the_diagnostic_names_the_files_the_store_actually_uses` |
| The report always states what it did not check | same file, `the_report_always_says_what_it_did_not_look_at` |
| A goal with no words in it is a failure, not a wrong command line | `crates/sure-cli/tests/cli_contract.rs`, `a_goal_with_no_words_is_a_failure_and_not_a_wrong_command_line`; `crates/sure-cli/src/commands.rs`, `a_goal_with_no_words_reaches_the_check_and_fails_rather_than_being_a_wrong_command_line` |
| A goal recorded before the check is in the run's own report | `crates/sure-cli/src/report.rs`, `a_goal_recorded_before_the_check_is_in_the_run_s_own_report` |
| A command that did not finish is not a command that cannot be carried out | same file, `a_command_that_did_not_finish_is_not_a_command_that_cannot_be_carried_out` |
| A project that was checked and is not clean exits 1, never 3 | same file, `a_project_that_was_checked_and_is_not_clean_exits_one_and_never_three` |
| A run that tried and did not finish exits 5 | same file, `a_run_that_tried_and_did_not_finish_exits_five` |
| `sure check` on a real project answers with a verdict, never status 3 | `crates/sure-cli/tests/cli_contract.rs`, `a_check_of_a_real_project_answers_with_a_verdict_and_never_with_status_three` |
| `check`, `recheck` and `repair` are one orchestrator under three purposes | same file, `the_three_pipeline_commands_are_one_orchestrator_with_three_purposes` |
| A project that cannot be read is status 5, not status 3 | same file, `a_project_that_cannot_be_read_is_status_five_and_not_status_three` |
| No check this build can run is ever reported as clean | `crates/sure-cli/src/check.rs`, `no_check_this_build_can_run_is_ever_reported_as_clean` |
| A dynamic check the execution mode did not authorise is not checked and never passed | same file, `a_dynamic_check_the_mode_did_not_authorise_is_not_checked_and_never_passed` |
| Every stage that did not run cannot aggregate to a clean verdict | same file, `every_stage_that_did_not_run_cannot_aggregate_to_a_clean_verdict` |
| An unconfigured model provider is a recorded state and not an omission | same file, `an_unconfigured_model_provider_is_a_recorded_state_and_not_an_omission` |
| `recheck` and `repair` reach the same orchestrator and go further down it | same file, `recheck_and_repair_reach_the_same_orchestrator_and_go_further_down_it` |
| `--goal` records a goal that reads back as the user stated it | `crates/sure-core/tests/project_intent_ingest.rs` |
| Recording a goal writes no recording row | same file, and `crates/sure-cli/src/check.rs`, `the_goal_is_written_verbatim_and_before_the_check` |
| Every refusal on the `--goal` path leaves the machine as it found it | `crates/sure-cli/src/check.rs`, `a_goal_with_no_words_is_refused_before_the_store_exists` and `a_project_that_cannot_be_read_leaves_no_store_behind` |
| A check with no goal creates no store on a machine that has none | same file, `a_check_with_no_goal_on_a_machine_with_no_history_writes_nothing` |
| The store may not be inside the project it records a goal for | same file, `the_store_may_not_be_inside_the_project_it_records_a_goal_for` |
| Every refusal says what did not happen | same file, `every_refusal_in_this_module_says_what_did_not_happen` |
| A run writes to the store location the caller named | `crates/sure-cli/tests/cli_contract.rs`, `a_named_store_directory_is_the_one_a_real_run_writes_to` |
| A real process names its privacy mode and answers the model question | same file, `a_run_says_which_privacy_mode_it_was_under_and_what_it_did_about_models` |
| The mode a report names is the arbitrated one, not the one a file names | `crates/sure-cli/src/check.rs`, `the_mode_in_a_report_is_the_arbitrated_one_and_not_the_one_a_file_names` and `a_project_cannot_lower_the_mode_the_users_own_settings_set` |
| A stopped run still says what it was allowed to send | same file, `a_run_that_stopped_still_says_what_it_was_allowed_to_send` |
| No run in this build can say a model was consulted | same file, `no_run_in_this_build_can_say_a_model_was_consulted` |
| The three modes say what `PRIVACY_AND_MODEL_STRATEGY.md` says they say | `crates/sure-core/src/privacy.rs`, `the_three_modes_say_what_the_document_says_they_say` |
| The two settings files can only differ in one direction | same file, `the_two_settings_can_only_differ_in_one_direction` |
| A store location inside the checked project is refused when the run opens it, and nothing is written | same file, `a_store_inside_the_project_is_refused_before_anything_is_recorded` — the refusal is driven on the `--goal` road, which opens the store; a `sure check` with no goal opens none and never meets the rule, and the `--store-dir` section above states which states each command is refused in |
| `sure doctor` says whether the location is the platform's or the caller's | same file, `a_doctor_report_says_which_store_location_the_run_is_using` |
| Nothing a project can write decides where the store goes | same file, `nothing_a_project_can_write_decides_where_the_store_goes` |
| Every command is reached by the location the caller named | same file, `every_command_is_reached_by_the_location_the_caller_named` |
| `sure config set` writes a setting only the user's own file can grant, and a later run reports it in force | `crates/sure-cli/tests/cli_contract.rs`, `a_setting_only_a_users_own_file_can_grant_is_written_and_a_later_run_reports_it_in_force` and `a_full_recording_granted_by_the_users_own_file_is_one_a_real_run_keeps` |
| A write, a no-op and a refusal print three different sentences, and only the write changes the file | same file, `a_write_a_no_op_and_a_refusal_are_three_different_sentences` |
| No path of `sure config set` reaches the project's own `sure.yaml`, and a setting a project's file decides is refused | same file, `no_path_of_a_config_write_reaches_the_projects_own_sure_yaml` and `a_settings_file_inside_the_project_is_refused_and_nothing_is_written`; `crates/sure-cli/src/settings.rs`, `a_project_level_setting_is_refused_and_no_project_file_is_written` and `a_settings_file_inside_the_project_is_refused` |
| A setting that cannot take effect, and a value this release refuses, are refused with the reason and leave no file behind | same file, `a_setting_that_cannot_take_effect_is_refused_with_its_reason`; `crates/sure-cli/src/settings.rs`, `a_refused_value_or_setting_leaves_the_file_alone` |
| Every setting `sure config set` will write is one a run reads from the user's own layer, and every remedy a refusal names is one of them | `crates/sure-cli/src/settings.rs`, `every_writable_setting_is_one_the_product_reads_from_the_users_own_file` and `every_hint_points_at_a_writable_setting` |
| An edit keeps every other line of the file, and a no-op does not rewrite one | same file, `an_edit_keeps_every_other_line_of_the_file`, `a_no_op_does_not_rewrite_a_differently_spelled_value` and `a_file_the_product_cannot_read_is_not_edited` |
| A run reports what is in force as the user's own, and names the file and the command that would grant what is missing | `crates/sure-cli/tests/cli_contract.rs`, `a_run_reports_a_grant_as_the_users_own_and_the_absence_of_one_as_the_projects_request` |
| A user settings file that will not parse stops a check and is never more permissive for a hook | same file, `a_settings_file_that_will_not_parse_is_never_more_permissive_than_no_file_at_all`; `crates/sure-cli/src/check.rs`, `a_user_settings_file_that_cannot_be_read_stops_the_run_rather_than_being_ignored` |
| A new command cannot ship with no answer about whether it works | the exhaustiveness of `Command::report` — see below |

The last row has no test, because it does not need one: `Command::report` and
`Command::name` both match every variant with no fallback arm, so adding a
command to the grammar stops the build until somebody decides. That was checked
by adding one and watching the build fail in both places, not argued.

### The gap that was here, and how it closed

Until P1-T012 this section recorded a gap rather than a test. `cli_contract.rs`
runs the binary as a process, and it deliberately never ran `sure check --goal`
with a goal that had words in it: such a run writes to the store **the
developer's own machine really uses** — on Windows the data directory comes from
`SHGetKnownFolderPath`, which ignores `LOCALAPPDATA`, so no environment variable
could point it at a scratch directory. A test that did it would put an invented
requirement into somebody's history and look exactly like a green test.

**That was not hypothetical, and the instance is worth keeping.** During
`P2-T010`'s mutation run the mutation that deletes the empty-goal refusal — the
first mutation in `target/tmp/mutate12.py` — made exactly that happen: the
process-level test ran the real binary, the refusal was gone, and six empty-text
`project-intent` rows were written to the developer's store. The unmutated suite
was then measured around a single run and left that store byte-identical, so it
was a coverage gap rather than active pollution. But the margin was a refusal in
the module under test, not a boundary around the store, and the whole of the
flag's process-level coverage was the refusal rather than the write.

`--store-dir` is what closes it, and it closes both halves:

- **The write is covered by a process test.**
  `cli_contract.rs::a_named_store_directory_is_the_one_a_real_run_writes_to` runs
  a real `sure check --goal` with words in it against a store the test names, and
  asserts the file appeared *there* and that the store the machine really uses is
  byte-identical afterwards. The happy path is no longer only reachable by
  `crates/sure-cli/src/check.rs`'s in-process tests.
- **The store the machine uses is now fenced off rather than relied upon.**
  Every run in `cli_contract.rs` and `mcp_protocol.rs` that could write names a
  store under `target/tmp/`, and the two tests that specifically must not name one
  — the bare `sure doctor` in
  `a_doctor_report_says_which_store_location_the_run_is_using` and the hook
  ingest — assert the machine's store is unchanged around them.
  `hook_ingest_reads_standard_input_and_evaluates_protection` is the one that
  used to write: it drove a real `sure hook ingest`, and that process opened and
  wrote `%LOCALAPPDATA%\SURE\sure.db` (measured: 4096 bytes added by one isolated
  run).

**What that test can and cannot see.** `assert_untouched` in `cli_contract.rs`
compares the store file's bytes before and after the runs it makes, and its
failure message names the outside writers it cannot rule out — another test
binary, a `sure` process somebody started, or a harness hook. It cannot see a
write from a test binary that has not run yet; it sees the runs made in this
file, in the order this file makes them. What covers the rest is the full
`cargo test --workspace`, watched from outside with the file hashed immediately
before and after, which is a measurement rather than a test and is recorded in
`progress/` by whoever runs it rather than asserted here.

## What this document does not cover

- **What a check finds, and the twelve stages that find it.**
  `docs/architecture/CHECK_PIPELINE.md` is the list of stages, and
  `crates/sure-cli/src/json_report.rs` is the versioned report shape a script
  reads (`schema_version` 3). What a stage means is that stage's own module.
- **What a goal becomes once it is stored, and what may be read out of it.**
  `docs/architecture/PROJECT_INTENT.md`. That document owns the trust labels and
  the rule that an unauthenticated statement is never a finding; this one owns
  the flag that carries it.
- **What a hook receives.** `docs/architecture/EVENT_PROTOCOL.md` and
  `docs/integrations/`.
- **Who has to run the handshake.** The rule is here and
  `docs/architecture/PROTOCOL.md` states it; the hook and the MCP adapter are
  commands SURE does not implement yet, so nothing but a caller's own shell has
  used it. They arrive with the phases that build them, and they have to use the
  same function rather than their own comparison.
- **How `sure doctor` decides what a problem is.** That is
  `crates/sure-core/src/doctor.rs`, which says what each state means and why a
  fresh installation is not one of them.
- **Interactive prompting.** Nothing prompts yet. `sure history delete` needs no
  prompt: it is non-interactive by construction, and the scope on the command
  line is the consent — see its section above. A command that deletes things has
  to answer a script, and a prompt is the one answer a script cannot give.
