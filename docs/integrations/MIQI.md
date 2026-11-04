# MiQi integration

Priority: **Protected (tier 2)** — MiQi asks before an action runs and refuses
the actions SURE blocks. It records what the agent did as well, so the observed
tier is still met; the protection claim is the integration's own and is earned
by its tests (MiQi PR #1353), not asserted here.

Package:

`integrations/miqi/`

The package is the event contract and its fixtures. There is no launcher,
because MiQi calls `sure hook ingest --source miqi` from its own plugin layer
(Python module hooks) rather than through a shell command written into a
harness config file.

Required behavior (v0.1 reached tier 1; the protection release adds tier 2):

- session lifecycle and tool events are ingested in the shape
  `integrations/miqi/README.md` records;
- a failed or refused tool call stays visible as a request without a
  completion, never as a completed one;
- an event naming a tool SURE does not know fails closed (read as a shell);
- protection: `exec` and the write-like tools ask before they run, through
  `sure hook ingest --consent-owner harness` (ADR 0020), and a `block` answer
  becomes a refused tool call. The harness owns consent; SURE names only the
  dangers it can read;
- SURE answering nothing, slowly, or unreadably must not silently disable
  protection: the integration's default is fail-open **and visible** (a
  warning plus an audit entry), and its strict switch fails closed instead.

The achieved capability tier is stated as **Protected (tier 2)** in the event
envelope and in `integrations/miqi/README.md`. The claim belongs to the
integration and to its own real-SURE test matrix; SURE stamps what the contract
declares and cannot confirm enforcement from the outside.
