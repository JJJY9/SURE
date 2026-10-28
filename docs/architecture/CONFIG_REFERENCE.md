# `sure.yaml` reference

Every setting SURE reads from a project, what it defaults to, and what the
project is allowed to ask for with it.

`sure.example.yaml` in the repository root is the same surface written as a file
to copy. A test loads that file and asserts it equals the defaults, so the
example cannot drift away from this document's subject matter.

## Where the file is read from

| Name | Read? |
| --- | --- |
| `sure.yaml` in the project root | yes |
| `sure.yml` | **no** — a near-miss name is an error, not a fallback |
| anything else | no |

A missing `sure.yaml` is not an error. It means the project has declared
nothing, and every setting below takes its default. The loader records which of
the two happened, so a report can say whether a setting was chosen by the user
or by the project.

The same file format is read at one other path: the user's own configuration,
outside any project, at `Paths::user_config_file()`. It is the same reader
rather than a second one, so a near-miss `sure.yml` beside it is the same
mistake. `Config::load_file` reads a file at exactly the path it is given;
`Config::load` reads `sure.yaml` from a project root. Which layer a setting came
from is `docs/architecture/CONFIG_AUTHORITY.md`.

That second path has a writer in this build, and only one: `sure config set`,
which writes a setting into the user's own file on request and never into a
project's. What it will and will not write is
[below](#the-users-own-file-and-what-writes-it), and what it prints is in
[CLI.md](CLI.md#sure-config-set-setting-value).

## Rules that apply to every setting

1. **An unknown setting stops the run.** SURE does not warn and continue. A
   setting that was silently dropped looks exactly like a setting that was
   applied, so the difference has to be visible.
2. **A setting written twice stops the run.** There is no last-one-wins
   resolution. Whichever value were picked, the other would vanish without a
   word, and a setting written twice is usually one being changed.
3. **A value outside the accepted list stops the run**, and the message names
   the accepted values plus the closest one when the mistake looks like a typo.
4. **A credential-shaped key stops the run**, and its value is never printed.
5. **A combination that cannot take effect stops the run.** See
   [Contradictions](#contradictions).
6. **A path that leaves the project stops the run.**

A UTF-8 byte-order mark is tolerated, and CRLF line endings are normal input —
both are what Windows editors write by default.

## Settings

### `privacy`

| Key | Type | Default | Accepted values |
| --- | --- | --- | --- |
| `mode` | enum | `local_first` | `local_first`, `fully_local` (see below) |
| `full_recording` | boolean | `false` | `true`, `false` |
| `full_recording_retention_days` | integer, in days | SURE's own default when no file names it | `0` or more |
| `telemetry` | boolean | `false` | `true`, `false` |

`local_first` keeps evidence on this machine and allows external analysis only
where it is separately configured. `fully_local` sends nothing out at all, and
cannot be combined with an external analysis provider.

This file and the user's own file outside the project are read together, and the
mode in effect is the stricter of the two — see
[CONFIG_AUTHORITY.md](CONFIG_AUTHORITY.md#restrictions-the-stricter-of-the-two-wins).
A project may ask for more privacy than the user configured; it may not ask for
less. What each mode means, and where a run states which one it was under, is
`docs/architecture/PRIVACY_AND_MODEL_STRATEGY.md`.

`cloud_enhanced` is described in the privacy documentation as a future mode and
is **refused** rather than accepted. Nothing in this release implements it, and
accepting the setting would let a project file claim a privacy arrangement SURE
does not provide. The refusal names what to write instead — the local-only
alternative of `local_first` or `fully_local`.

`full_recording` and `telemetry` are opt-in. Both are reported as requests, and
neither is meant to take effect without higher-authority approval: a project file
asking for either produces a refusal in `Authority::privileges()` rather than a
grant.

`telemetry` cannot take effect at all in this release, because nothing implements
it. `full_recording` can, and since `P13-T009` both halves of it are arbitrated:
`sure hook ingest` takes the consent from `Authority::full_recording()` and the
duration from `Authority::full_recording_retention_days()`, so a project file
asking for a recording gets a refusal in `Authority::privileges()` rather than a
recording, and a project file that asks to keep one longer than the user allowed
gets a refusal rather than the shorter period. Before that, the consent was read
from the project's own file, and a repository the user merely opened turned
recording on.

`full_recording_retention_days` is how long the raw content a full recording
kept is kept for. It is an integer number of days, `0` means "until the moment
it is written", and a negative number is refused as a bad value.

- **When no file names it**, nothing changes: the duration is the one SURE uses
  anyway. Absent is not "zero" and not "forever", and a report that named a file
  for it would be telling the user they had chosen something.
- **The user's own file may name any duration**, including one longer than the
  default. A person deciding how long their own machine keeps their own
  records is making a decision about their own data.
- **A project file may only shorten it.** A project naming a longer period than
  the user allowed is a **refused** escalation rather than a clamped one: the
  refusal is on the record and what is written is the shorter period — see
  [CONFIG_AUTHORITY.md](CONFIG_AUTHORITY.md#restrictions-the-stricter-of-the-two-wins).
  "Recording more is not running more", and a repository the user merely opened
  may not decide how long their activity is kept.

This is not the same setting as `full_recording`, and the difference is the
whole reason both exist: `full_recording` decides *whether* raw content is kept
and `full_recording_retention_days` decides *how long*. They are also about
different rows — this one governs the recording, and a session and its events
carry their own retention, which no configuration file can change in this
release.

### `protection`

| Key | Type | Default | Accepted values |
| --- | --- | --- | --- |
| `mode` | enum | `standard` | `standard`, `strict` |

`custom` needs a rule editor and a rule format, neither of which exists in this
release, and is refused for the same reason as `cloud_enhanced`.

The mode is a restriction, so it is arbitrated like the others: the stricter of
the two files runs, and a project may raise it and may not lower it
([CONFIG_AUTHORITY.md](CONFIG_AUTHORITY.md#restrictions-the-stricter-of-the-two-wins)).
What it changes is decided by `sure hook ingest`, for a pre-action tool request:
`strict` holds the categories named in
[PROTECTION_MODE.md](../security/PROTECTION_MODE.md), and every answer it gives
carries a sentence in the user's terms. In this release that answer is advisory —
both integrations are capability tier 1 — so it states what SURE would do rather
than what the harness did.

### `execution`

| Key | Type | Default | Accepted values |
| --- | --- | --- | --- |
| `mode` | enum | `inspect_only` | `inspect_only`, `host_confirmed` |
| `allow_dependency_install` | boolean | `false` | `true`, `false` |
| `allow_network` | boolean | `false` | `true`, `false` |
| `allow_project_write` | boolean | `false` | `true`, `false` |

`inspect_only` runs none of the project's code. `host_confirmed` allows the
project's code to run on this machine, and always needs confirmation for an
action SURE cannot classify.

All three booleans are **requests for a permission**, never a grant. Setting
`mode: host_confirmed` is a request to run project code; it does not grant it.
The same is true of `allow_project_write`, and by the same rule rather than a
stricter one. A project's own file cannot grant **any** request — see
[CONFIG_AUTHORITY.md](CONFIG_AUTHORITY.md#requests-every-ask-is-on-the-record),
the rule `P13-T009` settled for `execution.mode` and the one
`privacy.full_recording` is held to as well — so this key in a project's
`sure.yaml` is refused and recorded as a refusal, exactly like every other
request a project makes. A change to the project's files is then blocked with
*the current execution mode does not permit this action*. Nor is the mode what
decides a change: none of the three booleans is in any execution mode's baseline
permissions, so a request is the only route to each of them, and `write_project`
is what a change needs — a change is allowed in `inspect_only` once the user
grants it, because writing the project's files does not run the project's code.

### `analysis`

| Key | Type | Default | Accepted values |
| --- | --- | --- | --- |
| `provider` | enum | `disabled` | `disabled`, `local_command`, `claude_cli`, `openai_compatible` |
| `endpoint` | text or `null` | `null` | an absolute `http` or `https` URL, with no password in it |
| `model` | text or `null` | `null` | any name the provider recognises |

`disabled` consults no model at all. `local_command` runs a program on this
machine and nothing leaves it; the other two are **external** and are reported
as such — `openai_compatible` because a service receives the content, and
`claude_cli` because the program it runs talks to one.

Both `endpoint` and `model` are only meaningful with a provider that uses a
model. Setting either while the provider is `disabled` is a contradiction and
is refused, because the setting could never take effect and leaving it in place
would suggest analysis is configured when it is not.

A password inside `endpoint` is refused, and the value is never printed. Keep
credentials in user-level configuration or an environment variable.

Both layers may name these settings. A provider the checked project's own
`sure.yaml` names is the one in force; when the project names none — the
ordinary case for a project that never wrote the file — a provider your own
settings file names is in force instead (`Authority::analysis`). Your layer is
the one that can hand a behaviour to a run at all, and the rule follows it. A
project cannot veto your provider by naming `disabled`: disabling is the
absence of a request rather than a request.

### `project_intent`

| Key | Type | Default | Accepted values |
| --- | --- | --- | --- |
| `goal` | text or `null` | `null` | a non-empty goal |
| `spec_path` | text or `null` | `null` | a path inside this project |

Both are read from a project-controlled file, so both are classified as
`IntentSource::ProjectSpec`, which is **documentation, not a user requirement**.
A goal written here can never become the requirement the project is graded
against, because a file anyone can edit cannot state what the user asked for.
Without a requirement from a trusted source, every report states the
after-the-fact limitation instead of claiming the work is complete.

An empty `goal` is refused rather than treated as absent.

### `checks`

| Key | Type | Default | Accepted values |
| --- | --- | --- | --- |
| `existing_tests` | boolean | `true` | `true`, `false` |
| `start_local_services` | enum | `auto` | `auto`, `always`, `never` |
| `browser_probe` | enum | `auto` | `auto`, `always`, `never` |
| `services` | list | `[]` | service declarations — see below |

`always` and `never` are requests as well as settings: turning a check off
reduces what SURE covers, and a reduced scope is reported rather than passed
over.

#### `checks.services`

The one place a project says how to start itself. It is **not a command line**:
there is no field anywhere in a declaration that accepts a line to run, and no
string SURE reads is ever split back into arguments.

```yaml
checks:
  services:
    - name: demo-api
      launcher:
        kind: node_entry
        entry: server.js
      port: 4319
      readiness: /readyz
      page: /
```

| Key | Type | Default | Accepted values |
| --- | --- | --- | --- |
| `name` | string | required | non-empty, and not another declaration's name |
| `directory` | path | the project root | relative, inside the project — by its spelling **and** by where it resolves to — and a directory that is there |
| `launcher` | tagged type | required | `kind: node_entry`, with `entry` beside it naming the file to start |
| `port` | integer | required | 1–65535 — **zero is refused** |
| `readiness` | path | required | a path `probe::Endpoint` accepts on this port |
| `page` | path | none | as `readiness`; absent means no browser check |

The launcher's `kind` is a key SURE reads and a key it does not know is a load
error, as is any key written beside `entry` — the shape refuses what it does not
understand instead of dropping it. It is spelled as a `kind` key rather than a
YAML `!tag` because the format's deserializer requires a tag for the other
spelling, which makes `launcher: { node_entry: { … } }` unparseable rather than
merely unusual. `sure_core::config::services` carries the argument and the test
that holds it.

Each declaration plans a **Service** check — start the declared program in the
declared directory, wait for the readiness path to answer, then stop it — and,
when `page` is present and `browser_probe` allows, a **Browser** check that
opens the page inside that same service's lifetime. `start_local_services`
governs the first and `browser_probe` the second, with the same three
preferences as everywhere else: `never` plans neither and records why, `auto`
plans the service and not the page, `always` plans both.

A declaration **proposes**. It cannot grant itself a permission, cannot move the
execution mode, and starts nothing under `inspect_only` — the mode and the
permissions come from the user's own file. A declaration SURE will not act on is
a planning refusal with a sentence attached, never a row that quietly disappears.
[EXECUTION_SAFETY.md](EXECUTION_SAFETY.md) has the safety argument and
[ADR 0016](../adr/0016-declared-services.md) the decision record.

> YAML 1.1 read `yes`, `no`, `on` and `off` as booleans. YAML 1.2 — the version
> this file is parsed as — does not, so `existing_tests: yes` is a string that
> is neither `true` nor `false`. SURE reports the two values that work rather
> than leaving the user to work out why the type did not match.

### `report`

| Key | Type | Default | Accepted values |
| --- | --- | --- | --- |
| `format` | enum | `human` | `human`, `json` |

## What a project may and may not ask for

A project file is untrusted input: the project being checked may be controlled
by the same AI whose work SURE is evaluating. `docs/architecture/CONFIG_AUTHORITY.md`
sets the authority order, and this file can only ever sit below the user's own
configuration.

**Requests** — parsed, reported by `Config::requested_privileges`, and inert
until a higher authority agrees. The user's own configuration at
`Paths::user_config_file()` is that higher authority; a request only this file
makes is refused and recorded as a refusal, not granted and not dropped. What
each request becomes is in `docs/architecture/CONFIG_AUTHORITY.md`:

| Setting | Request |
| --- | --- |
| `execution.mode` other than `inspect_only` | run project code |
| `execution.allow_dependency_install: true` | install dependencies |
| `execution.allow_network: true` | network access |
| `execution.allow_project_write: true` | change this project's own files |
| `privacy.full_recording: true` | full recording |
| `privacy.full_recording_retention_days` longer than the user allowed | keep recorded content for longer than you allowed |
| `privacy.telemetry: true` | telemetry |
| `analysis.provider` that is external | connect to a service |

One row is decided by more than this file. Whether
`privacy.full_recording_retention_days` is a request is a fact about the project
file **and the user's file together**: the same number is a request when the
user allows less and is nothing at all when the user allows the same. So it is
not in `Config::requested_privileges`, which reads one file, and is produced by
`Authority::privileges()` instead — see
[CONFIG_AUTHORITY.md](CONFIG_AUTHORITY.md#restrictions-the-stricter-of-the-two-wins).
A build that reported it from the project file alone would have to guess.

**Scope reductions** — reported by `Config::scope_reductions`, so that a check
that did not happen is never mistaken for a check that passed:

| Setting | Reduction |
| --- | --- |
| `checks.existing_tests: false` | the project's own tests were not run |
| `checks.start_local_services: never` | local services were not started |
| `checks.browser_probe: never` | the interface was not checked in a browser |

## The user's own file, and what writes it

The file at `Paths::user_config_file()` — `%APPDATA%\SURE\sure.yaml` on Windows —
is the layer that **grants**. Every request in the table above is inert until
that file agrees, and two settings are its alone: `privacy.full_recording` and
any `execution.mode` other than `inspect_only`
([CONFIG_AUTHORITY.md](CONFIG_AUTHORITY.md), `Layer::can_grant`).

`sure config set SETTING VALUE` is the only writer of that file in this build.
How it behaves, what it prints and what it does about a file it cannot read are
in [CLI.md](CLI.md#sure-config-set-setting-value). What belongs here is which
settings it will write and which it refuses, because that list is a fact about
the schema rather than about the command.

**It writes the nine settings a run reads from the user's own layer:**
`execution.mode`, `execution.allow_dependency_install`, `execution.allow_network`,
`execution.allow_project_write`, `privacy.full_recording`,
`privacy.full_recording_retention_days`, `privacy.mode`, `protection.mode` and
`analysis.provider` (a provider the project's own file names is the one in
force; yours is in force when the project names none — see the `analysis`
section above).
The accepted values for the enums are the product's own `ALL` lists rather
than a second copy of them, so a mode added to a table above is a value the
command accepts without anybody remembering to change it.

**It refuses the settings a run reads from somewhere else, and says which
somewhere:**

| Setting | Why it is not written |
| --- | --- |
| `privacy.telemetry` | nothing in this release implements telemetry — no code path sends usage data anywhere — so the setting could not take effect whatever it said. A file saying `telemetry: false` would look like a decision the person had made and be read by nothing |
| `analysis.endpoint`, `analysis.model`, `analysis.command` | they are written by editing your settings file: this command writes settings that are a word, a flag or a number of days, and these are free text or a command list. `analysis.provider` is writable |
| `project_intent.*` | the goal and the spec path are read from the project, and the place for the user's own words is `sure check --goal` |
| `checks.*` | which optional checks run is read from the project, which may switch its own checks off |
| `report.*` | the report format is decided by `--format` on the command line, and nothing reads this setting from any file |
| `redaction.*` | the redaction that runs is the built-in one; no settings file builds a redactor |

Each refusal gives its reason, and a value the schema accepts but this release
does not — `privacy.mode: cloud_enhanced`, `protection.mode: custom` — is refused
in `Config::from_yaml`'s own words, so the command cannot come to accept
something a run would reject.

**It writes no other file, and never a project's `sure.yaml`.** The path comes
from `Paths::user_config_file()` and from nowhere else, and
`Paths::ensure_settings_outside` refuses a settings file inside the project being
checked before anything is written — the same refusal, from the same function,
that a run makes about the file it reads.

## Contradictions

Each of these is refused, naming both settings and saying why they cannot both
hold:

| Combination | Why |
| --- | --- |
| `privacy.mode: fully_local` with an external `analysis.provider` | fully-local means nothing leaves the machine; both named external providers send what they are given to a service |
| `analysis.provider: disabled` with `endpoint` or `model` set | no model is consulted, so the setting could never take effect |
| `execution.mode: inspect_only` with `allow_network` or `allow_dependency_install` | nothing runs, so nothing could use the permission; it would read as an allowance SURE does not have |

## Connection to the frozen semantics

This document describes a *request*. The rules about what those requests become
— execution modes, permissions, grantors, intent trust — are frozen in
`docs/architecture/FROZEN_SEMANTICS.md` and enforced in `crates/sure-domain`.
Nothing here restates them; this file can only narrow them or ask for them.

## Enforced by

`crates/sure-core/src/config/`:

| File | Holds |
| --- | --- |
| `mod.rs` | the model, `from_yaml`, `load`, `load_file`, validation, the request and reduction lists |
| `values.rs` | the seven enums, their wire names and what each one means |
| `error.rs` | every message a bad file can produce |
| `authority.rs` | which layer a setting came from, and what a lower layer may do with it |

`crates/sure-core/src/redact.rs` is the second line of defence against a secret
reaching a message. It lives at the crate root rather than here because
`diagnostics` applies it to every recorded field as well; see
`docs/architecture/DIAGNOSTICS.md`.

`crates/sure-cli/src/settings.rs` is the only writer of the user's own file, and
it holds its own list — `WRITABLE`, the eight settings above with the value kind
each one takes, and `NOT_WRITABLE`, the refusal families with the reason the
command prints. Two of its tests are what keep that list from drifting away from
the reader: `every_writable_setting_is_one_the_product_reads_from_the_users_own_file`
loads a file containing each of them through `Authority::load` and requires the
value to come back from the user's layer, and `every_hint_points_at_a_writable_setting`
requires every remedy the report module can suggest to be a setting this command
will actually write.

`crates/sure-core/tests/config_loading.rs` covers the filesystem path — spaces
and non-ASCII directory names, byte-order marks, CRLF, a non-UTF-8 file, the
`yaml`/`yml` near-miss, an absent file, and a directory occupying the file's
name.
