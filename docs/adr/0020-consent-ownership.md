# ADR 0020 — Consent ownership is declared, not inferred

Status: Accepted

Date: 2026-11-03

## Context

`sure hook ingest` answers a `PreToolUse` request with `allow`, `warn` or
`block`. The answer is built from two different questions:

- the **execution engine**: may SURE itself run this action, under the
  execution mode and the permissions in force? Its outcomes are allowed, needs
  consent and denied.
- the **protection rule**: is this a dangerous act — a broad delete, a force
  push, a read of credentials?

A hook process cannot ask a person for consent, so the first question's
"needs consent" outcome is answered `block` ("the hook cannot obtain consent"),
and "denied" is answered `block` as well. That is correct for a harness whose
only consent path is SURE. It is wrong for a harness that has its own approval
flow and its own user: MiQi asks before a tool runs, and its approval is the
consent SURE's hook could not obtain. Measured on 2026-11-03 against MiQi's
decision as it stood: enforcing that answer would have blocked every `exec`
(any command) and, under the default `inspect_only`, every file write — not
because they are dangerous, but because SURE was not authorised to do them
itself (see `docs/security/PROTECTION_MODE.md` and the MiQi integration's
capability-tier section).

## Decision

The consent owner is **declared by the caller of the hook**, not inferred from
the harness name and not configured in a file:

```
sure hook ingest --consent-owner harness
```

- The default is `sure`: the answer is exactly what it was, and a request SURE
  would hold for consent is blocked.
- `harness`: the execution-mode and consent outcomes stop blocking. A held
  request with no named danger is answered `warn`, carrying the engine's own
  sentence and saying that the harness must obtain the consent. A request that
  *names a danger* still blocks under either owner: the danger rules are the
  part of the answer the harness delegated to SURE.
- The one-time allowance (`sure hook allow-once`) still spends against a
  danger block, under either owner. It is the person's answer to the one
  question SURE can still name.
- A command line SURE cannot read into one meaning (safety refuses it) names no
  danger; under `harness` it is a warning, under `sure` a block. The harness's
  own approval is what the request then needs.

## Why a flag and not a setting

The owner is a property of the **caller**, not of the project and not of the
user's settings: a project file is attacker-controlled (ADR 0011), and a
user-level setting would have to be kept in step with which harness is asking.
The flag is written by the integration's own code, is visible in the process
list, and grants nothing — it changes which of SURE's own questions SURE
enforces in its answer.

## Consequences

- A harness that passes `harness` and enforces the answer gets protection
  against the acts SURE can name, while its own approval flow remains the
  consent path. The capability claim belongs to the integration and is earned
  there, with its own tests — SURE's answer is a precondition, not the claim.
- The block sentence stays SURE's and must be shown to the person; a harness
  that turns it into a generic failure sentence has removed the only part of
  the answer a person can act on.
- Harnesses that do not pass the flag see no change. The advisory status of
  their decisions (`PROTECTION_MODE.md`) is untouched.

## Rejected

- **Hardcoding the owner per `--source`.** A harness name is not a promise
  about how the harness handles approvals; the answer would change for a client
  that never asked it to.
- **A user-level setting.** The user does not choose per hook invocation, and
  keeping a file in step with which harness is asking is a second source of
  truth for one fact.
- **Answering "needs consent" as allow under `harness`.** The danger read for a
  command SURE cannot settle would be lost, and the answer would stop saying
  that consent is outstanding. A warning says both.
- **Letting the harness's approval suppress the danger rules.**
  `allow-once` is the person's answer for a danger, and it is one request, on
  the record. A harness that could silence the rules by approving in its own UI
  would move the decision out of SURE's store.
