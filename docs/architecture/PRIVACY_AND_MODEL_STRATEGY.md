# Privacy and model strategy

ADR 0006 (`docs/adr/0006-no-hosted-model-service.md`) freezes two decisions that
meet here: SURE is not an LLM reseller, and a model is consulted only where the
user configured one. It also asks that disclosure be explicit — what leaves the
machine, to whom, under which privacy mode, and the local-only alternative — and
names this document as where the privacy modes' semantics are frozen.

`docs/security/PRIVACY.md` states the **requirements**: what is recorded, what is
not, and that the user can delete it. This document states the **behaviour**: what
each mode permits and forbids, which of them this release implements, what to
write instead of the one it does not, where the mode in effect is stated, and
what a run says about models.

Every claim below is checked against the code named under
[Enforced by](#enforced-by) rather than against the other prose, and the modes'
sentences are transcribed in `crates/sure-core/src/privacy.rs`, where a test
fails if the two drift.

## The three modes

`privacy.mode` accepts three wire names. Two are implemented; the third is
**refused** rather than accepted, and the refusal is the point of it.

| Mode | Wire name | Available | External analysis |
| --- | --- | --- | --- |
| Local-first | `local_first` | yes | allowed only where the settings configure it |
| Fully local | `fully_local` | yes | forbidden, and refused alongside an external provider |
| Cloud-enhanced | `cloud_enhanced` | **no** | nothing is implemented, so nothing is permitted |

### Local-first — `local_first`

The default, and what a project that says nothing gets.

- **Permits**: deterministic checks, reading the project, and external analysis
  *where the user's own settings configure it*. An external provider named only
  by a project's `sure.yaml` is a request (`ProjectRequest::ExternalAnalysis`,
  the permission `ConnectService`) and not a grant — see
  `docs/architecture/CONFIG_AUTHORITY.md`.
- **Forbids**: nothing by itself. What it does not do is configure anything: with
  no provider named, no model is consulted, and `analysis.provider` defaults to
  `disabled`.
- **In this release**: implemented, and the default.
- **Alternative**: `fully_local`, for a machine where no project content may
  leave at all.

### Fully local — `fully_local`

- **Permits**: every deterministic check, the whole verdict, and a
  `local_command` provider — a program already on this machine. `is_external()`
  is false for it, and SURE does not claim to know whether that program calls
  out; that uncertainty is why it is not treated as external.
- **Forbids**: `claude_cli` and `openai_compatible`, which send what they are
  given to a service. A single settings file naming `fully_local` and one of
  those is refused outright, with both settings named.
- **In this release**: implemented.
- **Alternative**: `local_first` where external analysis is wanted and
  configured.

### Cloud-enhanced — `cloud_enhanced`

- **Permits**: nothing. There are no external analysis or sync features in this
  release, so there is nothing for the mode to switch on.
- **Forbids**: nothing either — it never reaches a run.
- **In this release**: **not implemented, and refused.** A settings file that
  names it stops the run with an explanation and an alternative rather than
  being accepted and ignored. Accepting it would let a project file claim a
  privacy arrangement SURE does not provide, which is the false guarantee this
  product exists to refuse. It also ranks lowest in the arbitration below, so no
  path through the authority can produce it.
- **Alternative** — the local-only alternative, and what the refusal itself
  says to write: `local_first` to keep evidence here and allow external analysis
  only where it is configured, or `fully_local` to send nothing out at all.

## Which mode is in effect

A run has two settings files: the project's `sure.yaml`, which is untrusted
input, and the user's own file outside the project, which outranks it. Neither
may decide the other's business, so the mode in effect is **arbitrated**:

1. Both files are read, and one that cannot be read stops the run rather than
   being ignored. Running on defaults while the user believes their settings are
   in force is the failure both readers exist to prevent.
2. The stricter of the two modes wins, whichever layer wrote it. `fully_local`
   beats `local_first` whether it came from the project or from the user.
3. A project may therefore ask for **more** privacy than the user configured, and
   it becomes the mode in effect. It may not ask for less: the user's stricter
   value stands, and the project's file changes nothing.
4. `cloud_enhanced` ranks below both, so an unreachable value can never become
   the answer through the arbitration.

`Resolved<T>` carries both the value and `by: Option<Layer>`. `None` means
"nothing beyond the default" — never "SURE did not work it out" — and the report
says the first of those, because the second would be false.

## Where a run states it

**The check report**, in both renderings, for every run that reaches the point
where settings have been read:

```
Privacy and model use

  Mode in effect: local_first
    Nothing set this: it is what SURE does when no settings file asks for something stricter.
    Evidence stays on this machine. External analysis is allowed only where your own settings configure it, and nothing is sent by a check that does not ask for it.
  Analysis provider: disabled
  No model was consulted: no analysis provider is configured (`analysis.provider` is `disabled`). The deterministic checks are unaffected.
```

and, in the frame a script reads, `details["privacy"]` with `mode`,
`mode_set_by`, `project_mode`, `external_analysis_allowed` and
`analysis_provider`.

Two cases get a line of their own, because a report that stayed silent about them
would be read as the reassuring half of an ambiguous statement:

- **The project's own settings are not the ones in effect.** The report names
  what the project's settings come to and says that the stricter of the two is
  the one in effect. Because the rule is a maximum, this can only ever mean the
  user was stricter — a single-file reader would report the project's mode and be
  wrong about the user's own policy.
- **A local-only mode is in effect and the provider is external.** No single file
  can be in this state (`fully_local` with an external provider is refused), so
  the report says the two came from different files.

### Why the check report and not `sure doctor`

`sure doctor` examines **this machine** — its files, its locations, its store,
its tools — and it never reads a project or a settings file at all:
`crates/sure-core/tests/doctor.rs::the_diagnostic_never_reaches_for_the_settings_module`
fails if `doctor.rs` so much as names the configuration module. That is not an
obstacle to be worked around; it is the reason the answer cannot live there.
Arbitration needs a project *and* a user, and the doctor has neither. A doctor
that printed one layer's `privacy.mode` under the name "privacy mode" would be
making exactly the false statement about the user's policy that the arbitration
exists to prevent.

`docs/architecture/CLI.md` records the same rule from the other side, as one row
of its table of claims each witnessed by a test: "`sure doctor` never reads the
settings file".

`sure config show` is the natural third candidate and is implemented in this
release: it is the right place to print both layers and the arbitration between
them, and it reads the settings rather than the doctor doing so. The analysis
endpoint, model and command are shown only as *set* or *not set*; their values
never reach the output, so the command can report what is in force without
handling a secret. The check report still states the policy for the run that was
actually made, which is what ADR 0006's "before anything is sent" asks for.

## Model use per run

`details["model_use"]` carries one state, and the human report carries one
sentence. The states are read from the run's own record of stage 8 — the one
stage that would ask a model — and not from a sentence written once:

| State | Means |
| --- | --- |
| `no_provider` | `analysis.provider` is `disabled`, so no model can be consulted |
| `nothing_asked` | a provider is configured and nothing in this run asked it about the project |
| `provider_unusable` | a provider is configured and SURE could not build it; a configuration fault |
| `consulted` | stage 8 did its work; the only state in which a model may have been consulted |
| `cannot_confirm` | the run stopped before stage 8, or the record is one this build does not read |

Three rules make this honest rather than merely present:

- **The no-model case is stated, never omitted.** Silence would read both as
  "nothing left this machine" and as "SURE did not look", and only one of those
  is true.
- **A stopped run is not a run that sent nothing.** A run that stopped before
  stage 8 has no record of what stage 8 did — the stages it never reached are
  recorded the same way stage 8 records "nothing to do" — so the answer is
  `cannot_confirm` and not the reassuring one.
- **The state is read from the run, not written as a constant.** The tempting
  sentence is "no check in this build asks for model-backed analysis, so no model
  was consulted". It is true today, and it is the shape of statement this product
  exists to refuse: the day a check asks, a constant would keep saying the
  reassuring thing.

### The honest limit of this release

**No check in this build asks for model-backed analysis, so external model use
cannot be observed happening.** Stage 8 says so in its own words when a provider
is configured, and records `not_part_of_work` rather than a gap. What this
document describes is therefore the disclosure a run makes about its
*configuration* and about its own record — the statement ADR 0006 asks for
before anything is sent — and not a report of traffic. `consulted` is
unreachable in this build, and a test says so in the terms that would fail the
day it stops being true.

### What SURE will not say

- Nothing here is a claim about a model's behaviour. A privacy claim about what a
  model received is not a fact SURE can establish, and asking the model is not
  evidence about the model.
- Model assessment is a distinct evidence class and cannot by itself carry a
  blocking `must_fix` finding (`EvidenceClass::can_alone_support_must_fix`).
  Nothing in this document promotes model output into a deterministic fact.
- The `external_analysis_allowed` field is the mode's rule. It is enforced at the
  settings-file boundary — `validate_privacy_and_analysis` — and nothing on a
  send path consults it, because there is no send path in this release. A report
  that promised "nothing *could* be sent" would be a guarantee this build does
  not implement.

## Enforced by

| File | Holds |
| --- | --- |
| `crates/sure-core/src/config/values.rs` | `PrivacyMode`, its wire names, `is_available()`, `allows_external_analysis()`, `AnalysisProvider::is_external()` |
| `crates/sure-core/src/config/mod.rs` | `validate_available_features` refusing `cloud_enhanced`, `validate_privacy_and_analysis` refusing `fully_local` with an external provider, `validate_analysis`'s provider contradictions |
| `crates/sure-core/src/config/authority.rs` | `Layer`, `Resolved<T>`, `Authority::load`, `privacy_mode` and the ranking that makes the stricter mode win |
| `crates/sure-core/src/privacy.rs` | the statement a run makes: the mode in effect, where it came from, the provider, and `ModelUse` read from the run's own record |
| `crates/sure-cli/src/check.rs` | reading settings through the authority, and the human section and frame fields above |
| `crates/sure-cli/src/report.rs` | carrying the statement on `CheckReport`, so no renderer derives one of its own |

Tests: `crates/sure-core/src/privacy.rs` (the arbitration, the five model states,
the transcription of the three modes), `crates/sure-cli/src/check.rs` (the mode
in a report is the arbitrated one; an external provider under `local_first`; the
refusal of the pair in one file and the split-file case; a stopped run), and
`crates/sure-cli/tests/cli_contract.rs` (a real process names its mode and
answers the model question).
