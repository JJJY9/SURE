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
| `ExecClassified` | a successful `exec`, classified locally by MiQi (`kind`: `test` / `build` / `compile` / `run` / `git`; `target`: a short label such as `pytest`; `success: true`; `subcommand` for git) | `test.ran` / `build.ran` / `compile.ran` / `run.ran` / `git.action` — the families `claim_checker` reads for `test_ran` / `current_code` / `git_state` |

Required fields: `event`, `harness_session_id` (MiQi's session key),
`timestamp_utc` (RFC 3339), `source` (the literal string `miqi`).

Optional fields: `project_root` (the session's project, an absolute path),
`tool` (MiQi's own tool name — see the vocabulary below), `result` (v1 sends
the string `ok`), `args`, `error`, `path`, `claim_id` / `claim_text` /
`claim_type` (AgentClaim only; SURE stores the claim as a Claim document and
checks it against the recorded events — `claim_text` is redacted before it is
stored), and `kind` / `target` / `success` / `subcommand` (ExecClassified
only — these are MiQi's own normalized classification, never the command
line).

A failed or refused tool call sends **no** `PostToolUse`: it appears in the
record as a request without a completion, which is what it was. Nothing is
reported as completed unless it completed.

### What v1 does not send

**`args`.** Tool arguments — a shell command line above all — stay in MiQi.
The consequence is stated rather than hidden: a shell request from this
harness carries no command line, so SURE holds it on the strength of the tool
name alone, and no recorded allowance can name the command's own acts until a
later version adds an explicit opt-in for forwarding arguments. `ExecClassified`
does not weaken this: MiQi classifies the command locally and sends only the
normalized label (`pytest`, `cargo build`, `git commit`), never the command
text, its arguments, or the paths it named.

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

MiQi is **Observed** (tier 1): SURE records what the agent did, after the
fact. **Tier 2 (Protected) is not claimed.** SURE answers each `PreToolUse`
request with a decision and v1 of the integration records that answer, but the
harness does not act on it yet — the fail-closed bridge that would make acting
safe (what must happen when SURE is missing, times out, or cannot be verified)
is a separate project with its own test matrix. Until that lands and its tests
pass, the decision is documentary evidence, not protection.

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
