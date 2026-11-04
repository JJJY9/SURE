# Protection mode

User-facing modes:

## Standard — recommended
Warn/block only clearly dangerous operations where the integration has Tier 2 pre-action control.

## Strict
Also asks before additional sensitive changes such as migrations, CI/CD config, secret/config areas and broad filesystem modifications.

## Custom
Advanced rules.

**Not implemented in this release.** `custom` needs a rule editor and a rule
format, neither of which exists, and a settings file naming it is **refused**
rather than accepted — see the `protection` table in
[CONFIG_REFERENCE.md](../architecture/CONFIG_REFERENCE.md#protection), which is
the same shape as `privacy.cloud_enhanced`. A hook that meets the value anyway —
or any settings file it cannot read at all — answers under `strict`, the firmest
mode this release implements, and never under the default: a user who cannot be
asked must not end up with less protection than they set.

Default UX explains consequence, not policy jargon.

Example:

> AI is about to delete 47 files. This may be a valid refactor, but it can also remove working code.
>
> [Allow once] [Do not allow]

## What the mode changes in this release

The mode is read from the user's settings file and the project's, and the
**stricter of the two** runs: a project may ask for more protection than the
user set and may not ask for less
([CONFIG_AUTHORITY.md](../architecture/CONFIG_AUTHORITY.md#restrictions-the-stricter-of-the-two-wins)).

`strict` differs from `standard` on the categories named above and on nothing
else. A **change** — a write or a delete — is held when it lands in a migration,
in CI/CD configuration, in a secret, or in SURE's own configuration area; so is
a change that names a whole location rather than a file (`.`, `..`, a drive
root, a wildcard, or a request that names no path at all), because that is the
shape of "delete 47 files". A **read** is held only where the read is the
sensitive act — a secret file — which is what "secret/config areas" means for an
operation that reads. Everything else is answered exactly as `standard` answers
it, so a read of ordinary source is not a mode difference.

Every answer carries a sentence in the user's terms rather than the policy's: a
held read of `.env` says the file is where credentials live, and a held change
across a whole location says the change may be a valid refactor and may also
remove working code. An allowed request carries the sentence it was allowed
with, so a decision with no sentence means no request was put to the rule at all
— a lifecycle event, not a verdict on a tool.

**Whether the answer is advisory depends on the integration.** Cursor and
Claude Code are capability tier 1 (Observed): their manifests do not confirm
that the harness interprets or enforces the response, so a decision states what
SURE *would* do and not what the harness did — nothing in this build can
establish the second sentence for them. MiQi is **Protected** (tier 2): its
plugin enforces a `block` answer before the action runs, and that claim is the
integration's own, held to its own real-SURE test matrix and end-to-end tests
(see `integrations/miqi/README.md`, and MiQi PR #1353 for the tests).

## Who owns consent

`sure hook ingest --consent-owner harness` declares that the harness asks its
own user before an action runs — MiQi's approval panel does. Under that owner
the execution-mode and consent outcomes stop blocking: the decision is a `warn`
carrying what the engine said, and obtaining consent is the harness's job. The
**danger rules still block** — a broad delete, a force push, a read of
credentials — because judging danger is the part of the answer the harness
delegated to SURE, and that danger is read even where the execution mode or the
permissions **denied** the action: the harness may still run it after its own
approval. A `strict`-mode hold on a sensitive area is the user's protection
instruction and applies under the harness owner in the same way. `sure hook
allow-once` still spends against a danger block that answers a request held for
consent; a danger named beside a denied action is still a block, but no
allowance may answer it, because an allowance is not a way to run under
settings the user did not change (ADR 0020). The default, `sure`, keeps the
older answer: a request SURE would hold for consent is blocked, because a hook
cannot ask. Whether a harness enforces either answer is still the harness's own
claim to make, with its own tests.

## The one-time override, and what it reaches

The example above shows `[Allow once]`. In this release the way a user gives
that answer is a command:

```
sure hook allow-once --tool NAME (--command WORDS | --path PATH)
                     [--project DIR] [--minutes N]
```

It records a grant in SURE's store for **one** request: the tool name and the
command line or the path, exactly as the harness spells them. The first request
that matches both exactly **spends** it, and if SURE names that request as one of
the three acts below, SURE would let it through. The next request with the same
words is held again. The window is thirty minutes unless the user says otherwise,
never more than a day, and the spend is one store transaction — two hooks racing
on one allowance cannot both spend it.

**The command reads the settings and the tool name before it writes, and refuses
when together they leave nothing an allowance could be spent on.** An act is
named only for a request SURE holds, and a grant is spent by a request that
matches the tool and the words exactly, so whether any matching request could
spend it is a question about `execution.mode`, the permissions, `protection.mode`
and the tool the user named — and not about the words they typed. Under the
default configuration no request can be held for any of the three acts below, so
`sure hook allow-once` refuses, says what would have to change, and writes no
row. A grant recorded there would sit in the store looking like a
permission while being a promise SURE cannot keep, and the user would learn that
only when the request it names arrived and was held anyway. The same refusal
answers a grant whose *settings* leave an act that its *tool* cannot reach: with
`protection.mode: strict` and nothing else, SURE holds a read of a file where
credentials live, and a grant recorded for a shell command under those settings
is spent by nothing — a shell request is refused by the mode before any danger is
read. The sentence a refusal is answered with names the tool, because that is
half of what the grant promises.

Where an act is reachable **for the tool that was named** the command records,
and the sentence it answers with says which acts the settings in force **when it
was recorded** leave for it — so a confirmation cannot describe an outcome those
settings make unreachable, and a reader can tell it is describing the moment of
recording rather than claiming the answer is fixed for the window's life. A user
who changes their settings afterwards has changed what the grant can be spent on:
a request the new settings hold for an act an allowance covers can spend it, and
a request they no longer hold for one — or refuse for another reason, including
the mode — spends nothing. A grant refused for the tool it names is not always inert
forever either. Where the action that tool names needs a permission a setting can
grant, the refusal is about the settings in force: it is a row a *later* settings
change would have made spendable, and SURE refuses it rather than recording it,
because the two settings that would make it spendable are the two a user can name
now, and a row that cannot be spent under the settings in force is a promise the
user has no way to check. That is the sentence `--tool Shell` and `--tool Read`
are refused with. Where the action needs a permission **no** setting in this
build grants, no settings change makes such a grant spendable and the refusal
says that instead: it does not name `execution.mode` or `protection.mode`,
because neither is the cause and there is nothing the user could change. Which of
the two sentences a tool gets is read off the vocabularies rather than written
down beside them, so a release that makes such a permission grantable answers
with the first sentence with no sentence here to edit — and a test fails until
someone says so. **`P13-T011` is that release, and this is where the document said
it would be.** Until it, the case was a tool whose action would change the
project's own files — `Write`, `Edit` and `Delete` — because nothing granted SURE
the permission to change them then. That permission is now one the **user's own
settings file** grants, by `execution.allow_project_write`; a project's `sure.yaml`
still cannot grant it, and both halves are observed at the process boundary: the
same request under the same setting is allowed when the user's file names it, and
blocked with *the current execution mode does not permit this action* when the
project's does. Those three tools are refused today with that setting named rather
than with this build's own limit, and the test the paragraph above promised would
fail — `no_setting_grants_the_permission_a_change_to_the_project_needs` — is the
test that failed. It is now `every_permission_is_in_reach_of_a_setting_now` and
asserts the other direction, *nothing is out of reach*. The sentence about the
build's own limit is kept and still computed, so a build in which some permission
is once again out of reach answers with it rather than with advice that would not
help: a promise that a test fails is only worth making if the sentence outlives
the fact it was read from. Which *subject* is a request SURE would hold is still
not knowable at write time: the words are read when a request arrives, so a grant
recorded for a tool that can reach an act may still name a request SURE never
holds and be spent by nothing when its window expires.

An allowance reaches the three acts this document calls dangerous and nothing
else:

- a change that names a whole location rather than a file;
- a push that would replace commits that were already published;
- a read of a file where credentials or keys live.

A request held for any other reason cannot be let through by one — a mode that
does not permit it, an execution setting the user has not changed, a migration,
CI/CD configuration, SURE's own configuration area — and neither can a request
whose command line has more than one reading, or one SURE cannot call destructive
from its own rule table. That is the fail-closed direction on purpose: an
allowance answers a question a hook cannot ask, and it is not a way to run under
settings the user did not change.

For Cursor and Claude Code — capability tier 1 (Observed) — nothing here is a
claim that the harness honours the answer: a spent allowance produces a
sentence saying SURE **would** let that one request through; whether anything
then runs is not something this build can confirm. For MiQi — tier 2
(Protected) — the harness documents and tests that it refuses the action a
block names, which is that integration's claim and not this command's.

`sure hook allow-once` is a command a **person** runs. Nothing a checked project
can write and nothing an agent can say records an allowance: the grant is a row
in SURE's own store, written on a command line the user typed, and the settings
the command reads to decide whether to write are read to *describe* them and
never to grant anything — a project file asking for `host_confirmed` is still a
request the user's own file has to agree to, and in this build the only setting
that puts an act within reach is one the user writes themselves.

The **tool** name is read, and the subject is not, and the difference is what can
be known at write time. A tool name is the harness's own vocabulary and maps to
the action kind SURE would answer a request carrying it with — in the vocabulary
that claims the name, so a name only one harness has is not also read as the
other's unrecognised tool — which is a fact about the tool, not about what the
user typed after it, and reading it does not read the subject. The words are read
when a request arrives, because there is no request to read them against before
then. So a grant whose words are not something SURE would ever hold is spent by
nothing and expires: a request matches it exactly and SURE still answers that
request as it would have answered it without the grant. That residual is
deliberate and is not closed by this command.
What the write does close is the other half: settings and a tool that together
leave **every** matching request unspendable are refused before anything is
recorded, so a row written at a given moment is one the settings in force at that
moment left reachable by a request naming that tool. It says nothing about a row
written earlier under different settings, which is why the confirmation dates
itself.

Every integration must document whether its hook failure behavior is fail-open or fail-closed for the relevant event.

That documentation is `docs/integrations/HOOK_FAILURE_SEMANTICS.md`: one row per
harness per event its manifest wires, the measured exit status and stream shape
for each way a hook event can fail before it answers, and — separately, because
the two are not the same kind of statement — what each harness is documented to
do with a non-zero status. `crates/sure-testkit/tests/hook_failure_semantics.rs`
reads that table and fails when a manifest wires an event the table does not
answer for.

A count is a claim, and this sentence used to carry one — "the four ways" — while
the table it pointed at had already grown a fifth row and then a sixth, so the
sentence had stopped being true before anyone edited the table. The count is
removed rather than re-set, because the next input added would falsify it again.
The same reasoning removed the count from that page's own heading, and the
deliberate member of that set — a project naming a settings file it could have
written, which SURE refuses — is named as deliberate there rather than left
looking like a malfunction.
