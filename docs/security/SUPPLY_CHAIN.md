# Supply-chain security

v0.1 engineering should include:

- pinned Rust toolchain;
- committed lockfiles when dependencies are introduced;
- dependency update automation;
- `cargo audit`/equivalent release check;
- license review/deny configuration as dependencies appear;
- Node plugin packages with minimal/no dependencies where practical;
- no curl-pipe-shell in automated SURE project checks;
- release checksums.

Cryptographic artifact attestation/signing is future-capable but not required to prove product value in v0.1.

## Where this release stands

The list above is the **requirement**. Which parts of it are true today is a
separate question, and the items that are not there are named here rather than
left for a reader to discover:

- **In place:** `rust-toolchain.toml` pins the compiler; `Cargo.lock` is
  tracked; `.github/dependabot.yml` asks for weekly version-update pull requests
  for cargo and for GitHub Actions; `release.yml` and `release-dry-run.yml`
  build, package, checksum and re-verify the artifact they produce.
- **Not there: an advisory check.** Neither `cargo audit` nor a
  `cargo-deny`-style configuration exists anywhere in this repository — no
  `deny.toml`, no workflow step, no script. A dependency version with a
  published advisory can therefore sit in `Cargo.lock` and **nothing in this
  repository will say so.** Dependabot's update pull requests are not a
  substitute: they propose newer versions, and an advisory query asks which
  versions are known-bad. The consequence is that "this release has no
  dependency with a known advisory" is a claim this repository cannot currently
  support, and it is not made here.
- **Partly there: license disclosure, not license policy.** Dependencies have
  appeared, and the disclosure side now exists:
  `scripts/Generate-ThirdPartyNotices.mjs` reads `cargo metadata --locked`,
  lists every third-party crate with its SPDX expression, collects the license
  texts the crate sources carry (embedding a canonical SPDX text only when none
  can be found for a must-have license), and writes `THIRD_PARTY_NOTICES.txt`.
  Both `scripts/Build-Release.*` stage that file into every archive and
  `scripts/Install-Sure.ps1` installs it beside the binary. The generator fails
  the packaging run when a crate declares no license at all or a must-have
  license text cannot be produced, and `--check` re-reads a shipped copy
  against the lockfile. What is still missing is a **policy**: no `deny.toml`
  or compatibility configuration exists, so a license this project should not
  ship is disclosed rather than refused, and whether a listed license is
  acceptable remains a person's review — the pre-publish checklist in
  `docs/development/RELEASE_PROCESS.md` carries that step rather than claiming
  it is automated.
- **Node plugin packages:** there are none to review — no package under
  `integrations/` carries a `package.json` — so that item is met by there being
  nothing to meet it with rather than by a dependency review.
