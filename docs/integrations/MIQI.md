# MiQi integration

Priority: Tier 1 for v0.1 — MiQi records what the agent did, after the fact,
and the integration says so plainly wherever it is described.

Package:

`integrations/miqi/`

The package is the event contract and its fixtures. There is no launcher,
because MiQi calls `sure hook ingest --source miqi` from its own plugin layer
(Python module hooks) rather than through a shell command written into a
harness config file.

Required v0.1 behavior:
- session lifecycle and tool events are ingested in the shape
  `integrations/miqi/README.md` records;
- a failed or refused tool call stays visible as a request without a
  completion, never as a completed one;
- an event naming a tool SURE does not know fails closed (read as a shell),
  and the achieved capability tier is stated as **Observed (tier 1)** with
  tier 2 explicitly not claimed;
- SURE answering nothing, slowly, or unreadably never stops MiQi — the event
  feed is fire-and-forget until a protection bridge exists.

Do not block on tier 2: the fail-closed protection bridge is a separate
project with its own test matrix, and until it lands the decision SURE
returns is documentary evidence, not protection.
