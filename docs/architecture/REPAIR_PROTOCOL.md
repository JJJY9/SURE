# Repair protocol

A repair contract is both human-readable and machine-readable.

Required fields:

- issue ID;
- problem;
- why it matters;
- evidence anchors;
- required fix;
- behavior to preserve;
- acceptance criteria;
- suggested re-checks;
- forbidden shortcuts where useful.

Example:

```yaml
problem: "The app reports that an email was sent, but the real send path only logs to the terminal."
why_it_matters: "Users are told an action succeeded when no email leaves the app."
required_fix:
  - "Call the configured email provider on the real send path."
  - "Handle provider rejection without exposing secrets."
preserve:
  - "Current successful UI flow."
acceptance:
  - "Provider is called on successful send."
  - "Provider failure is handled and tested."
```

After repair, SURE selects affected + regression checks. Agent self-report does not close the finding.

## Only settled evidence becomes a repair task

A contract is written only for a finding whose own evidence can carry its
severity (`Finding::is_grounded`). A blocking finding that is still a candidate —
`must_fix` with `inference` evidence, such as "a click handler exists; no command
has settled it" — is reported as **`cannot_confirm`** with a manual next step. It
is deliberately not a repair contract: SURE would be asking an agent to fix
something SURE never established, and the check behind it is not a command that
can observe the fix. A non-blocking candidate (a TODO marker) remains repairable,
because removing the marker is a change the check can observe.

This keeps the contract's meaning: *this fix is needed, and here is how SURE will
know it worked.* See `docs/adr/0018-repair-contracts-need-settled-evidence.md`.
