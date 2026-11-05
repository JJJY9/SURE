# Supported stacks and support levels

Support claims must use levels.

## Level A — first-class

Framework-aware discovery and meaningful deterministic checks.

Initial target families:
- Node.js / TypeScript web and server projects;
- Python app/API projects;
- Rust app/service projects.

## Level B — generic

SURE can discover common manifests/commands and run approved generic checks, but does not claim framework-specific completeness.

The build currently ships generic Go discovery (`go.mod`; `go.work` modules
each get `go test ./...`, `go build ./...`, `go vet ./...`), generic .NET discovery (`*.sln`/`*.csproj`,
`dotnet test`, `dotnet build`, plus `dotnet format --verify-no-changes` when the
project declares `.editorconfig`), and generic Maven discovery (`pom.xml`, including the module
`pom.xml` files a reactor names; `mvn -B -ntp test` and `mvn -B -ntp package -DskipTests` at the root)
beside the Node/Python/Rust paths. A Gradle build is inspected only: its build
script is code, and SURE does not execute or interpret build scripts.

## Level C — inspect-only

SURE can inspect files/config and report obvious issues but lacks safe/reliable run semantics.

Every report should state the achieved support level rather than silently pretending all stacks are equal.

## The achieved level, and what sets it

`Project::support` is the level for the project as a whole, and
`sure_core::support::classify` is the one rule that fills it. The rule is **the
weakest of two things: what SURE read, and what SURE can do with it**.

Both level A and level B include running something. Since 2026-10-23 the ceiling
is **B (`generic`)**, held in `sure_core::support::CEILING`: a tracked,
three-platform reading shows a real project's declared `cargo test` completing
and passing under the product's runner, the result mapping refuses a pass for a
run nobody saw finish, and Windows package-manager shims have a product answer.
A project discovery grades `generic` is therefore reported at B; a project whose
reading is `inspect_only` stays C. Level A is not claimed: no discovery path
grades A, and framework-aware checks have not been measured on every platform.
[ADR 0017](../adr/0017-lifting-the-support-ceiling.md) is the record, its
residual gaps included.

Level B does **not** mean SURE runs your project by default. The default mode is
still `inspect_only`; checks run only when the user's own settings allow it, and
a check whose command cannot be started is reported as not checked rather than
passed. `SupportLevel::plain_description` and the report's reason sentence say
both.

The per-ecosystem `grade` in `docs/architecture/ECOSYSTEM_DISCOVERY.md` measures
what SURE **understands**; this document's levels measure what SURE can **do**.
For B the two now agree; level A remains a higher bar.
