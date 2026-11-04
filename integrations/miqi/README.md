# SURE MiQi Integration

MiQi (the MiqroForge desktop agent) sends its session events to SURE through
`sure hook ingest --source miqi`. There is no launcher script in this package:
MiQi is a Python application, and its own plugin layer calls `sure hook ingest`
directly with the event on stdin — the route the harness itself controls,
rather than a shell command written into a config file that the project could
have written. This package is the contract: the event fixtures and the
documentation around them. It contains no checking logic and nothing to
install.

## What MiQi sends

One JSON object per event on stdin, `--source miqi` on the command line. The
fixtures in `fixtures/` are exactly this shape — one per event, including a
project root with a space and non-ASCII characters, because MiQi projects live
wherever the user keeps them.

| `event` | When MiQi sends it | SURE event type |
|---|---|---|
| `SessionStart` | the session begins | `session.started` |
| `PreToolUse` | before a tool call executes | `tool.requested` |
| `PostToolUse` | after a tool call **completed** | `tool.completed`; a completed `write_file` / `edit_file` / `apply_patch` is `file.written` (payload carries `path` and `written: true`) |
| `Stop` | the session ends | `session.stopped` |
| `AgentClaim` | the agent asserts something it did (`claim_id`, `claim_text`, `claim_type`) | `agent.claim` |
| `ExecClassified` | an `exec`, classified locally by MiQi (`kind`: `test` / `build` / `compile` / `run` / `git` / `dependency`; `target`: a short label such as `pytest` or `npm install`; `success` records whether the run succeeded — failures are sent too, so a "passed" or "installed" claim can be contradicted; `subcommand` for git) | `test.ran` / `build.ran` / `compile.ran` / `run.ran` / `git.action` / `dependency.changed` — the families `claim_checker` reads for `test_ran` / `current_code` / `git_state` / `dependency_changed` |
| `McpCall` | an MCP tool call finished (completed or failed); `tool` is the registered name (`mcp_<server>_<tool>`), `success` says whether it completed | `mcp.called` |
| `SubagentStart` | MiQi starts a subagent job; `agent_type` and `job_id` identify it | `subagent.started` |
| `SubagentStop` | the subagent job ended; `success` says whether it completed without error | `subagent.stopped` |

`dependency_changed` claims ("installed dependencies with npm") are checked
against the `dependency.` family; a claim that names no package manager is
answered "cannot confirm", never widened to the family. A recorded failed
install contradicts the claim.

Required fields: `event`, `harness_session_id` (MiQi's session key),
`timestamp_utc` (RFC 3339), `source` (the literal string `miqi`).

Optional fields: `project_root` (the session's project, an absolute path),
`tool` (MiQi's own tool name — see the vocabulary below), `result` (the string
`ok`), `args` (only when MiQi's argument-forwarding switch is on: the `exec`
command line and nothing else), `error`, `path` (a write-like tool's target;
carried on the pre-tool event and, since v1, on the post-tool one), `claim_id` /
`claim_text` / `claim_type` (AgentClaim only; SURE stores the claim as a Claim
document and checks it against the recorded events — `claim_text` is redacted
before it is stored), `kind` / `target` / `success` / `subcommand` / `counts`
(ExecClassified only — these are MiQi's own normalized classification, never
the command line), and `server` / `agent_type` / `job_id` (McpCall / subagent
lifecycle only — names MiQi already holds, never tool arguments or task text).

A failed or refused tool call sends **no** `PostToolUse`: it appears in the
record as a request without a completion, which is what it was. Nothing is
reported as completed unless it completed.

### What the integration does not send

**`args`, unless the user turns forwarding on.** The shell command line stays
in MiQi by default. The current integration adds an explicit opt-in
(`sure.forward_tool_arguments`): with it on, the `exec` command line is
attached to the pre-tool event so SURE can name a command's danger. Without
it a shell request carries no command line, and SURE holds it on the strength
of the tool name alone. A write-like tool's target `path` is carried on the
pre-tool event regardless — the same path its post-tool event has always
carried, and the word SURE's `strict` rules are read from. `ExecClassified`
does not weaken any of this: MiQi classifies the command locally and sends
only the normalized label (`pytest`, `cargo build`, `git commit`), never the
command text, its arguments, or the paths it named.

**MCP arguments and results, and subagent prompts.** An `McpCall` carries the
registered tool name and whether it succeeded, nothing the server returned and
nothing the model passed to it. A subagent lifecycle event carries the agent
type and MiQi's job id; the job's task text (which may quote the user) stays in
MiQi. Both are observations, not claims.

## Tools and vocabulary

| MiQi tool | SURE action kind |
|---|---|
| `exec` | `ArbitraryCommand` |
| `read_file` | `ReadFile` |
| `write_file` | `WriteProjectFile` |
| `edit_file` | `WriteProjectFile` |
| `apply_patch` | `WriteProjectFile` |

`list_dir` is deliberately **not** in SURE's MiQi vocabulary: SURE's domain has
an action kind for a directory listing, but no danger witness reaches it, and
every name a vocabulary claims must map to a kind the witness list can reach
(held by `every_kind_a_tool_name_can_reach_has_a_witness`). An event naming an
unclaimed tool — `list_dir` today, anything MiQi adds tomorrow — is read as an
unrecognised name, which means SURE answers it as a shell: the fail-closed
reading, and not a claim about what the tool does.

## Capability tier

MiQi is **Protected** (tier 2): its plugin asks before an action runs. For
`exec` / `write_file` / `edit_file` / `apply_patch` it calls `sure hook ingest
--consent-owner harness` (ADR 0020), reads the machine frame, and turns a
`block` answer into a refused tool call — SURE's sentence is what the model and
the user see. Consent stays with MiQi's own approval flow: SURE judges only the
dangers it can name (a broad delete, a force push, a read of credentials, and
the strict mode's sensitive areas), while the execution-mode and consent
outcomes are reported as warnings rather than enforced.

**The claim belongs to the integration and is earned there**, with its own
tests: MiQi's repository carries a real-SURE matrix (`allow` / `warn` /
`block`, argument forwarding, and the failure paths — missing SURE, timeout,
refusal, an older build) and a real-LLM end-to-end test in which a blocked
command surfaces as the tool's result (MiQi PR #1353). What this page records
is the contract those tests hold MiQi to; whether a harness truly honours the
answer remains the harness's own claim, not something SURE can observe from
the outside.

Failure policy is the integration's too: when SURE is missing, times out or
refuses to answer, MiQi continues the call by default and says so (a warning,
plus an audit entry in its acceptance panel); its strict switch makes the same
failure a refusal instead. `read_file` is not put in front of SURE — the extra
~250 ms on every read is not worth it — and its pre-tool event stays on the
observation channel; the danger a read could name (credentials under `strict`)
is checked when MiQi runs its own SURE checks.

## Binary resolution, installation, and rights

There is nothing to install from this package, and no administrator rights are
involved in anything it describes. On the MiQi side, the SURE binary is
resolved in the same order SURE documents elsewhere — `SURE_BIN` first, then
`sure` on `PATH`, then `%LOCALAPPDATA%\SURE\bin\sure.exe` — and MiQi feeds
events with a whitelisted child environment, so platform tokens and agent
secrets are not passed through to the hook process.

## Fixtures

`fixtures/` holds one sample per event type, shaped exactly as MiQi v1 sends
them. They are the normalizer's test input
(`crates/sure-core/src/normalizer/miqi.rs`) and this contract's examples at
once; `crates/sure-testkit/tests/integration_thinness.rs` holds their shape
(source `miqi`, the required keys, one per event) the way it holds the other
packages' fixtures.
