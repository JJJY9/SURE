# Project intent / requirements

This is a critical truth boundary.

SURE cannot know what the user originally wanted merely by looking at code.

## Intent sources

Each requirement/goal records its source:

### explicit_user_goal
User supplied a goal/spec directly to SURE.

### observed_user_request
A supported harness exposed the user request and the selected privacy mode permits SURE to retain/normalize it.

### project_spec
README/spec/task file found in the project. This is documentation, not necessarily the user's current intent.

### agent_claim
Agent says a feature is complete. Useful for claim checking, not proof of requirement.

### inferred
SURE inferred likely purpose. Never treated as a user requirement.

## The channel is the claim

The five labels are not a ranking of how much SURE believes the words. They are a
statement of **which channel the words arrived on**, and that is the only thing
SURE can actually establish. `IntentSource::is_user_requirement` is the domain's
predicate over that: it is true of `explicit_user_goal` and
`observed_user_request`, and false of the other three.

The two channels are genuinely different in kind, and the difference is who can
write them. A project's README, its `sure.yaml`, its task list: every one of them
is a file inside the project, and the project is written by the same agent whose
work is being judged. An agent that wants its work to look complete can edit any
of them, so a goal found there is `project_spec` — documentation — however
emphatically it is worded. `Config::goal_source` is a `const` returning exactly
that, and it is the one place the decision is made for every caller
(`docs/adr/0011-project-configuration-is-a-request.md`).

The command line is the other channel, and until `P2-T011` it was the only one
with a producer. It is still the only one a person reaches by typing: every
channel now has a **door** in `crates/sure-core/src/intent_model.rs`, which is
where a label is written, and a door is not a producer. The doors with nobody
knocking are named in that module's comment rather than left to be inferred from
the table there — a table of five labels reads as a pipeline whether or not one
exists. Two have a producer today: the command line
(`crate::project_intent::explicit_goal`) and a goal written into `sure.yaml`
(`crate::intent_model::documented_goal`); a third arrives from a document's
fenced commands, which `crate::documents` produces and nothing in `sure-cli`
builds yet; `agent_claim` and `inferred` have none, and the reason is in that
comment.

**A door writes its own label, and no function in that module takes one as an
argument.** A caller holding a command it read out of a README has nothing to
ask for, because there is no parameter to ask with, so the mistake this section
is about — a document's sentence arriving as something the user said — is
prevented by a shape rather than by a rule the code follows.

## The explicit channel

`sure check --goal "…"` stores the text as a requirement whose source is
`explicit_user_goal`, verbatim except for the one removal the section below
states, and the run then checks the project against it.

**That sentence used to end "then reports that it checked nothing."** It was true
when it was written and `P7-T010` is what stopped it being true: before the check
pipeline existed there was no checking for a goal to be reported against. Measured
now, on a scratch project holding one `package.json` and one `--goal`, the run
goes through all twelve stages and the goal comes back as a **not-checked line** —
`SURE checked 0 of 1 checks. 1 check could not run.`, with a `Cannot confirm`
finding whose own text is "SURE planned this check and did not run it". So the
goal is not checked *and the run does not say it checked nothing*: it says which
check did not run and why. The two are different claims and the old sentence made
the stronger, wrong one.

The command-line half of the contract is in `docs/architecture/CLI.md`; this
section is what the stored requirement means.

**Nothing is normalized, and one thing is removed.** The text is kept as it
arrived, with a single exception: the store's redaction removes credential-shaped
values before the row is written.

`P15-T024` decided which of the two rules wins, and **the store's redaction won
and the goal is not exempt from it**. What this means on the surfaces:

- the row holds the user's words with credential-shaped values replaced by `***`;
- the report prints **the row's own text** — `crate::check`'s `record_goal` reads
  the row back and hands that text to every surface, so the sentence "Your goal
  was written to the history as record N" and the text beside it are about the
  same record, and are the same text;
- the run checks against the text it recorded: stage 2 resolves the requirement
  from the record's own text, so the not-checked line for an unmatched
  requirement — which quotes the requirement — cannot become a second place the
  removed value is printed;
- `crates/sure-core/src/store/mod.rs` keeps **no** exception. `redact_document`
  is applied to every accepted document including this one, and its
  documentation says so at the place the exception would have been written.

**The case against that decision, recorded rather than left out.** A stored
requirement with a value removed is not, word for word, what the user typed, so a
later reader comparing a project against the recorded goal compares against a
sentence the user did not write in full; and the honest form of the alternative
is not absurd — the words *were* handed to SURE in the same breath as the
command, and the goal is the one thing on this surface that is a user's own
statement rather than material SURE collected. It is still the wrong way round,
for three reasons. The report has a machine form (`--format json`) that a harness
captures, redirects or logs, and `docs/security/SECRET_REDACTION.md` requires
redaction to happen *before user-visible reports* — an exemption would need that
sentence to mean something narrower than it says. The store is local but not
private to the run: `docs/security/PRIVACY.md` promises the user can inspect it,
and a credential written into it is in every backup and every copy of that file.
And an exemption is not a one-time choice: the channels that carry a goal are
growing (a documented goal in `sure.yaml` has a producer today), so a door opened
for the explicit goal is a door the next channel walks through unless someone
argues this again each time.

SURE rewording what the user asked for is the overclaim `MASTER_PROMPT.md` §3
forbids, and a summary that dropped a clause would be a requirement the user never
stated. `Requirement::raw_retained` is set, because the stored text is the user's
own wording rather than a summary of it. Redaction is neither rewording nor
summarising: it removes a value and leaves the sentence, and it is bounded by a
detector that `docs/security/SECRET_REDACTION.md` says is imperfect — so the flag
does not claim the row holds no secret, only that the row is not a paraphrase.

**No opt-in is consulted, and no recording is written.** The privacy rule is
about *captured material* — a transcript from a harness session, kept only under
the opt-in `docs/security/PRIVACY.md` describes. A goal typed to SURE is not
captured material: there is no session and nothing is retained that the user did
not hand over in the same breath as the command. `IntentSource::requires_full_recording`
is true of exactly one source, `observed_user_request`, and the explicit channel
is not it. `crates/sure-core/tests/project_intent_ingest.rs` asserts the absence
directly, because "no recording was written" is the half of P2-T010's acceptance
that a test asserting only "a row appeared" would miss.

**One requirement, one row.** `schemas/project-intent.schema.json` describes a
single `Requirement`, not the `ProjectIntent` container around it — the container
has no source of its own, being the union of its requirements' sources. Storing
an intent is therefore storing each of its requirements, and a reader that wants
the container back reassembles it. A one-line explicit goal is one requirement
and one row; a goal written on several non-empty lines is one requirement per
line, so a partially implemented goal cannot be matched as a whole. A
multi-source intent is written in part if the store refuses somewhere in the
middle, and the task that first produces one owns that answer.

The first requirement's identifier is the fixed string `goal`; further lines of
a multi-line goal are `goal-2`, `goal-3`, ... rather than generated identifiers.
Within one project a reader comparing today's goal with last week's has to be
able to find both; a fresh identifier per invocation would make "did the user
change what they asked for?" an identity-matching problem instead of a
comparison of two strings.

## What "explicit" does not claim

**SURE cannot authenticate its own command line.** The label records that the
words entered SURE through an argument rather than through a file inside the
project being checked. It does not record that a person typed them. An agent that
runs `sure check --goal "…"` supplies a goal exactly as a person would, and
nothing in this build can tell the two apart.

That is why `explicit_user_goal` remains a **claim about provenance rather than a
proof of it**, and why storing a goal never turns it into a finding. A requirement
says what the project is to be judged against; whether the project meets it is a
separate question, answered by a check that this build does not have yet. An
unauthenticated statement is evidence of what the operator asserted, and it is
never evidence that the assertion is true.

## Reading a goal back

A reader looking for *this project's* goal has to find it by **the project root
and the record kind**, taking the most recent row, and not by the fingerprint the
row carries.

The reason is that `FingerprintId` is minted per run: `ProjectFingerprint::git`
and `ProjectFingerprint::content` generate a fresh identifier each time they are
called, so the same unchanged project gets a different id on every invocation.
The `kind` and `digest` are the fields that answer "which state was this?" and
are stable across runs; the id identifies a *computation* of a state, not the
state. `Evidence::is_fresh_for` compares ids, and the question of whether a
fingerprint id is meant to be stable across runs is recorded in
`progress/HANDOFF.md` as an open question rather than answered here.

**A known gap in the store's API stands in the way.** `HistoryFilter` can filter
by project fingerprint and by record kind, and has **no `project_root` filter**,
so a reader asking a shared user-level store for one project's goal must fetch by
kind and filter by root itself. Nothing in this build reads a goal back at the
user level — `sure check --goal` only writes — so the gap is recorded rather than
worked around. The task that first reads one owns closing it.

## After-the-fact mode

Without explicit intent, SURE may say:

- the project starts;
- a button is dead;
- a payment path is mocked;
- README claim is false;
- a migration is missing.

It may **not** say:

> "Everything the user requested is complete."

## Full-session mode

Standard recording should avoid raw prompt retention by default.

Possible strategy:
- transiently observe the task where supported;
- retain a minimal structured goal/acceptance summary only when permitted;
- full raw prompt retention remains full-recording/opt-in.

If goal extraction requires an external model, disclose that model use and respect fully-local mode.

**The permission is implemented and the capture is not.** No harness integration
writes an observed request yet, so the strategy above describes a pipeline this
build does not have. What `P2-T011` implements is the rule such an integration
will have to satisfy: `IntentSource::requires_full_recording` is true of exactly
one source, `observed_user_request`, and
`crate::intent_model::observed_user_request` refuses to produce one unless
`Authority` says the privilege was **granted**. It takes the authority rather
than a `Config` for the reason the section above gives: `sure.yaml` is inside the
project, so a project that sets `privacy.full_recording: true` has asked, and
only the user's own settings outside the project can allow it.

## What this document does not cover

- **What a check does with a goal.** `docs/architecture/CHECK_PIPELINE.md`, when
  it exists. Nothing in this build compares a goal against a project.
- **The command line that carries a goal.** `docs/architecture/CLI.md`.
- **What is kept, for how long, and what the user can do about it.**
  `docs/security/PRIVACY.md`.
