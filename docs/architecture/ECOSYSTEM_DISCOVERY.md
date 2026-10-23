# Ecosystem discovery

Ecosystem discovery is the second half of step 1 of
`docs/architecture/CHECK_PIPELINE.md`. The first half — which files SURE will
look at, and which it will not — is `docs/architecture/PROJECT_DISCOVERY.md` and
is implemented by `sure_core::scan`. This half is **reading a few named files and
saying what they claim the project is**; it is implemented by
`sure_core::discover` (`crates/sure-core/src/discover/`).

Two ecosystems are implemented, each as a module with one entry point:
**Node** (`node.rs`, from `package.json` and the lockfiles beside it) and
**Python** (`python.rs`, from `pyproject.toml`, `Pipfile`, `requirements*.txt`
and the lockfiles beside them). The rule, the four answers, the bounds and the
gaps below are the same for both; `Ecosystem::ALL` is the list of what a build
looks for, and `discover()` calls each module in that order.

The whole of this document is one requirement:

> **A manifest states a request, not a fact.**

`"test": "jest"` in a `package.json` means the project *declares* that command.
It does not mean `jest` is installed, that the script runs, or that a single test
passes. `"react": "^18"` is a range handed to a resolver, not the version on
disk. SURE has run no resolver and no package manager, so it has nothing to say
about what either resolves to, and everything here is written so that it cannot
say it by accident.

## The distinction the reading is built on: not there vs. not readable

Every caller asks the same first question — *is there a `package.json` here?* —
and there are four different answers:

1. there is nothing at that name;
2. there is something, and it is a link, a directory or a pipe, which SURE does
   not read;
3. there is a file, and SURE could not turn it into a value;
4. there is a file, and here is what it says.

**Collapsing (1) and (3) into an `Option` is the mistake this half is built to
make impossible**, and it is not a corner case. A project whose `package.json`
failed to parse would be reported as a project with *no manifest*: SURE would
say the project declares no scripts, no dependencies and no package manager, and
every one of those would be a claim about a file it never read. That is a false
statement about the project wearing the clothes of a negative finding, which is
the failure `CLAUDE.md` calls more serious than a visible error.

So no type in `discover` answers that question with an `Option`:

- `read::ReadFile` — what reading one named file produced, one arm per answer
  above, with no value accessor that lets the other three be skipped.
- `node::ManifestState` — `Read(Box<Package>)`, `Absent`, `Unread(UnreadReason)`.
- `node::MemberManifest` — `Present`, `Absent`, `NotReadable(kind)` for a
  workspace member, answered without reading it.
- `node::MemberManifest` — `Present`, `Absent`, `NotReadable(kind)` for a
  workspace member, answered without reading it.
- `python::ManifestState` — the same three answers, holding a `PyProject`.
  `project()` answers yes/no by returning the manifest `Option`ally, and
  `is_absent()` is `true` only for the `Absent` arm — so the one question a
  caller may collapse is the one that collapses to `false` for a file that is
  there but unread, which is the safe direction.

`UnreadReason` carries the seven ways a file that is there can fail to become a
value: `OutOfBudget`, `TooLarge`, `Unreadable`, `NotText`, `NotParsed`,
`WrongShape`, `NotReadableKind`. Each has a constant sentence
(`plain_description`), a stable name (`as_str`), and — for the three that carry
one — a `detail()` that is the operating system's or the parser's own words,
kept as data and never spliced into a sentence.

**An unread file is a finding about the project, not a diagnostic.** This is why
`Discovery::unread` is a list in the result rather than a line in
`crate::diagnostics`: that module is what SURE says about *its own* work and is
documented as never evidence about the project. A project with an unreadable
`pnpm-workspace.yaml` and a readable `package.json` is a project SURE can still
say something true about; what it must not do is report the readable half and
stay silent about the half it lost.

### The rule, enforced structurally rather than by convention

`read_manifest` in `node.rs` is **one function**, not a reader plus a converter.
The first version of the file had them apart, and it was wrong in exactly the
way this section describes: `[1, 2, 3]` parses as JSON, so the reader had
nothing to record, and the shape failure the converter produced reached
`ManifestState::Unread` without ever reaching `Discovery::unread`. The same
project was described two ways by two fields of one result. Pairing them means
every arm that produces an `Unread` sits in the same `match` as the line that
records it, so there is no ordering or convention for a later edit to get wrong.

## What SURE looks at, and what counts as a project

| File | What it answers |
| --- | --- |
| `package.json` | the whole of what the project declares |
| `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lockb`, `bun.lock` | which package manager the project used |
| `pnpm-workspace.yaml` | workspace members, for the one manager that keeps them outside `package.json` |
| `tsconfig.json`, `jsconfig.json` | that this is a TypeScript project, when the manifest does not say |

**Four things make this a Node project, and every one is a project-level file:**
a manifest, a lockfile, a pnpm workspace file, a compiler configuration. Source
files are *not* on the list. A directory containing a `.js` file is a directory
containing a `.js` file, and calling that a Node project on the strength of one
stray file is the kind of inference this product exists not to make.

A lockfile is **not parsed**. Its contents are a resolved dependency graph SURE
has no use for and that costs megabytes to read; what is wanted from it is one
bit — *this project has a `pnpm-lock.yaml`* — and that bit is the file's
existence. Which is also why the manifest byte budget is never spent on one.

Names are matched the way the platform matches them. On Windows a project with
`Package.json` is a project with a `package.json`, because Windows would open it
and a lookup that missed it would report the project as having no manifest. The
rule comes from `ScanOptions::case` rather than from the module, so both
platform rules are testable on one machine.

`Tree` is built once from the `Scan` the walk already produced, rather than
asking the filesystem again — so discovery cannot disagree with the scan it
reports beside it.

## The package manager, and why it is not "the one with a lockfile"

Projects get this wrong, and SURE reporting a confident answer where the project
contradicts itself is worse than SURE reporting the contradiction. Three kinds of
evidence are collected and kept apart, strongest first:

| Evidence | Where it comes from | What it means |
| --- | --- | --- |
| `Declared` | the `packageManager` field | the project's own statement about itself; Corepack reads it |
| `Lockfile` | a lockfile exists for that manager | that manager has run here |
| `EnginesRange` | an `engines` range names it | a hint about what a contributor should install, and nothing more |

`Managers::disagreement()` reports the two cases where the evidence points two
ways — a declaration naming one manager while the lockfile names another, or two
lockfiles for two managers — and `Managers::agreed()` answers `None` for both
rather than picking a winner. **There is no code path here that silently prefers
one lockfile to another.** A `packageManager` field naming something not in
`PackageManager::ALL` is not guessed at; the field is carried verbatim and no
manager is named from it.

## Workspaces

Both spellings of the field are read — `"workspaces": ["packages/*"]` and
`"workspaces": { "packages": ["packages/*"] }` — and `pnpm-workspace.yaml` is
read as a third source. Patterns are carried verbatim and resolved against the
same `Tree`.

- **The root is never its own member.** The seen-set is seeded with the root's
  own lookup key, so `"."` in a pattern list resolves to the root and is then
  dropped as already seen.
- **A pattern cannot leave the project.** `contained_relative` accepts only
  `Component::Normal`, so an absolute path, a root, `.` and `..` are refused as
  `NotInsideProject`. The patterns are project-controlled text, and this is the
  same containment rule the fingerprint applies to the paths Git reports.
  **"Absolute" is the platform's idea, not a spelling**: `C:\Windows` is refused
  on Windows and is one relative name on Unix, where a backslash is an ordinary
  character and a file may legally be called that. Accepting it there is correct
  — the name is inside the project and resolves to nothing — and a test asserting
  the Windows answer on every platform **failed on the macOS and Ubuntu jobs**
  before this sentence was here.
- **`**` is refused, not approximated.** A pattern containing it is
  `UnsupportedPattern` — a statement about the pattern — which is kept apart
  from `NoMatch`, a statement about the project. Answering one with the other
  would turn "SURE cannot read this pattern" into "this workspace is empty".
- **A member whose manifest is absent is still a member.** `MemberManifest`
  answers `Absent` from the walk without reading anything, so a workspace whose
  members are declared but not materialised is described as that.
- **Truncation is recorded.** At `max_workspace_members` the list stops and
  `Workspaces::truncated` is `true`. A workspace with ten thousand members is a
  project SURE cannot describe member by member, and saying so is the useful
  answer.

## Scripts

`Package::scripts` is verbatim: the name the project wrote and the command it
wrote, neither interpreted. An entry whose value is not a string is not dropped
— it is recorded in `scripts_not_commands`, because "the project declared a
script and SURE cannot read it as a command" and "the project declared no such
script" are different facts.

`ScriptRole` is **SURE's** list, not the project's: `build`, `test`, `lint`,
`typecheck`, `format`, `dev`, `start`, `clean`. That is the point — a project
with no `test` script is a finding, and it can only be reported by looking for a
name the project did not choose. `conventional_scripts()` returns **a row for
every role whether or not it is declared**, because silence is not a finding.
One name per role: a project that spelled its test script `test:unit` has not
declared a `test` script, and mapping one onto the other would be SURE inventing
a convention and then running a command on the strength of it.

`command_for(manager, role)` returns the command a person would type — `npm test`
and `npm start` without `run`, `npm run build` with it, `{manager} run {name}`
for every other manager. It is **returned and never executed**: choosing a
command is a plan, and running it is a later step with its own authorisation.

## Frameworks and tooling

`TOOLS` is a fixed table of package names and the role each one has —
meta-framework, web framework, server framework, test runner, end-to-end test,
linter, formatter, bundler, monorepo tool, runtime, language. A `Tooling` value
stores the **table's own `&'static str`**, never the project's spelling, so no
dependency name a project wrote can reach a sentence SURE prints. A package not
in the table is not reported at all, which is a deliberate silence: "SURE did not
recognise this package" is not a finding, and guessing from a name would be. One
package may appear twice when it is genuinely two things — Biome lints *and*
formats, and both are reported, because picking one would be SURE choosing which
half of a tool to mention.

A dependency's `requirement` is stored exactly as the manifest wrote it, and
dependencies are grouped by the section they were declared in —
`dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`.
`bundledDependencies` is deliberately **not** a section: it is an array of names
with no versions, every one of which must also appear in `dependencies`, so
reading it would add nothing and reading it as a fifth section would report each
bundled package twice.

## TypeScript

Three pieces of evidence, each with its own `Source`: a compiler in the
dependencies, a `tsconfig.json` or `jsconfig.json`, and `.ts`/`.tsx`/`.mts`/`.cts`
source files. Counted files are evidence, and `source_files` is a count rather
than a list — a project with three thousand `.ts` files does not need three
thousand paths in a discovery result.

## Python

### What SURE looks at, and what counts as a project

| File | What it answers |
| --- | --- |
| `pyproject.toml` | dependencies, optional-dependency groups, entry points, the interpreter, the build backend, and any tool table |
| `Pipfile` | dependencies and dev-dependencies, for pipenv |
| `requirements*.txt` | dependencies, when a project declares them in a flat file |
| `uv.lock`, `poetry.lock`, `Pipfile.lock`, `pdm.lock` | which installer the project used |
| `.python-version` | the interpreter, as the file's own text, trimmed of surrounding whitespace |
| `setup.py`, `setup.cfg` | that the project declares itself in a way SURE will not read |

**Seven things make this a Python project**, and every one is a project-level
file: a `pyproject.toml`, a `Pipfile`, a `.python-version`, a `setup.py`, a
`setup.cfg`, a lockfile, a `requirements*.txt`. As with Node, **source files are
not on the list** — a directory containing a `.py` file is a directory containing
a `.py` file. `looks_like_one` is a disjunction over presence probes taken
*before* any read or any budget spend, so "is this a Python project?" costs
nothing and a directory that fails it is never opened.

### `setup.py` is a program, so it is never read

This is the ecosystem where "read the manifest" could most easily become "run the
project". `setup.py` declares its dependencies by *executing Python*, and the
obvious next step — import it, or shell out to `python setup.py --name` — is the
step this product does not take at any stage of step 1.

So a `setup.py` is evidence that a project exists and is reported as
`unread_legacy`, a list of names carried through to the result. **A project whose
only manifest is a `setup.py` gets `InspectOnly`**: SURE knows it is a Python
project and knows nothing about what it declares, and says exactly that. A test
writes a `setup.py` that would leave a file behind if anything executed or
imported it, runs discovery, and requires that no such file exists.

### The installer, and why a requirements file is the weakest evidence

Three kinds of evidence, kept apart, strongest first:

| Evidence | Where it comes from | What it means |
| --- | --- | --- |
| `Declared` | a `[tool.<installer>]` table, or a build backend naming one | the project's own statement about itself |
| `Lockfile` | a lockfile exists for that installer | that installer has run here |
| `RequirementsFile` | a `requirements*.txt` exists | somebody installs with `pip`-style flags — and nothing more |

`Installer::from_build_backend` maps only the backends that *are* an installer's
— `poetry.core.masonry.api` is poetry, `pdm.backend` is pdm. `hatchling.build`,
`setuptools.build_meta` and `flit_core.buildapi` answer `None`, because hatch,
setuptools and flit build distributions and do not install; they appear in
`TOOLS` under `ToolRole::BuildBackend`, where a build backend belongs.

**A requirements file is never evidence of disagreement.** pip, uv, poetry and
pdm all read `requirements.txt`; a `uv.lock` beside one is the ordinary shape of
a project that moved to uv, not a contradiction. Reporting it as one would be a
false alarm, and a false alarm next to a real one is how a reader learns to
ignore both. The evidence is still collected and still reported — as the third
tier, where it decides only when nothing stronger is present.

`Disagreement` is the same enum idea as Node's, with Python's three cases: two
installers declared by two tool tables, two lockfiles, or a declaration and a
lockfile naming different installers. The third is the one that needs saying out
loud, because a project configured for poetry with a `uv.lock` beside it is a
project mid-migration, and `agreed()` answers `None` rather than picking a
winner. `two_tool_tables_naming_two_installers_are_a_disagreement` records a
correction: the first version of this code reported two *declarations* as
`TwoLockfiles`, and the test that came first was asserting the bug.

### Requirements files, line by line

The names after `requirements` are the project's to choose, so the rule is a
prefix and a suffix (`requirements*.txt`) rather than a list, and the count is
bounded by `MAX_REQUIREMENTS_FILES` because an unbounded count is work a project
does not get to ask for. The files read are the first N in sorted order, so which
ones are left out is a function of the project rather than of the walk.

Every line of a file is accounted for in exactly one of three places —
`requirements`, `directives`, or a `comments` count — and a test asserts that the
three add up to the file's line count, so a line cannot be silently dropped.

**A URL is not a distribution name.** `https://example.invalid/pkg-1.0.whl`
begins with a run of perfectly good name characters, so a naive reader reports
the project as depending on a package called `https` — an invented fact about the
project, in the one place the product promises not to invent any. Two rules
reject it, and both are about what may *follow* a name:

- a name immediately followed by `:` or `/` is not a name, because a URL scheme
  or a path separator cannot come after one — this is what stops `https://…`;
- a run that ends in a non-alphanumeric is not a name, because `foo-` and `foo.`
  are prefixes rather than distributions.

`foo @ https://example.invalid/foo.tar.gz` is still read as `foo`, because that
is what the line declares. `path.whl` on its own is read as a name called
`path.whl`, which is correct: nothing follows it, so it is not a URL.

### Tooling, and commands that are only planned where a tool was declared

`TOOLS` is a fixed table of roughly a hundred package names mapped to SURE's own
`ToolRole` names, matched under pypa name normalisation (case-insensitive; runs
of `-`, `_` and `.` are equivalent). A project's spelling never reaches a
finding: `Scikit_Learn` is reported as `scikit-learn`, because the string in a
finding is SURE's and only a *name recorded as data* may come from the project.

`conventional_commands` returns a row for every `CommandRole` whether or not
there is a command, for the same reason Node's `conventional_scripts` does: "there
is no way to check this project's types" is a finding, and a missing line is not.
**A command is planned only where the tool it would run was declared**, and a row
with no command carries no `because` — naming the tools a plan rests on when there
is no plan would be a reader's evidence for a command that does not exist.

The build row names a *frontend* and never a backend library: `setuptools` is
what a frontend calls, so the plan is `python -m build` with `setuptools` in its
`because`. Naming `setuptools` as the command would be a plan that does not run,
and it is the obvious wrong answer here.

### The interpreter is carried verbatim, from every place that states it

`requires-python`, Poetry's `python`, `.python-version` and the
`Programming Language :: Python :: …` classifiers are four independent claims,
each with its own `Source`, and `PythonVersion::claims()` yields them separately.
**SURE does not merge them into one answer.** `>=3.9,<4` is carried as that string
and not interpreted, because interpreting it means being a version resolver and
SURE has not run one. That the four can disagree is the project's business, and
merging them would destroy the disagreement before anyone could see it.

## Rust

### What SURE looks at, and what counts as a project

| File | What it answers |
| --- | --- |
| `Cargo.toml` | the whole of what the project declares, for the root package and for a workspace |
| `Cargo.lock` | that a resolver has run here — one bit, and its contents are never parsed |
| `rust-toolchain.toml`, `rust-toolchain` | which toolchain the project pins, and which components it asks for |
| `rustfmt.toml`, `.rustfmt.toml` | that the project configures its formatter |
| `clippy.toml`, `.clippy.toml` | that the project configures its linter |

**Three things make this a Rust project**, and every one is a project-level file:
a `Cargo.toml`, a `Cargo.lock`, a pinned toolchain. **A `.rs` file is not on the
list**, and this is the ecosystem where a lazy marker is most tempting — a
directory holding one `.rs` file looks more like a Rust project than a directory
holding one `.js` file looks like a Node one. It is also where the cost is
highest: a `.rs`-file marker would put a `Rust` stack into the report of a
project that has no Rust in it, which is the failure `looks_like_one`'s own test
is written around. As with Node and Python, the disjunction is over presence
probes taken *before* any read and before any of the manifest budget is spent, so
a directory that fails it is never opened and never contributes an `Unread`.

`Cargo.lock` is not parsed, for the reason `node.rs` gives about lockfiles: its
contents are a resolved graph SURE has no use for, and what is wanted from it is
one bit. The four `rustfmt`/`clippy` configuration files are not parsed either —
the question asked of them is *is this tool configured here*, which their
existence answers.

### `[package]` and `[workspace]` are siblings, and either can be absent

They are two tables of one document. A `Cargo.toml` with only `[workspace]` is a
**virtual manifest** — how a workspace that is not itself a crate is written —
and it declares a great deal: the members, their shared dependencies, their
shared lint levels. It is graded exactly as a manifest with a package is, and the
distinction that matters is drawn at the commands rather than at the level:
`cargo run` needs a package to run, and `cargo build` at a virtual root builds
every member.

**The workspace tables are held on the document, not on the package**, which is
why `Manifest` is a separate type from `PackageSection`. This is a correction
rather than a first design: the first draft hung them off `PackageSection`, where
a virtual manifest's entire workspace — the case such a manifest exists for —
would have been dropped. Two mutations in the task's mutation harness revert
decisions of this shape, and this is one of them.

A third fact is kept apart from both: `[dependencies]` is meaningful only where
`[package]` exists, because Cargo refuses a virtual manifest that declares
dependencies. A dependency table under a `[workspace]` with no package is
therefore not read as the project's dependencies, and the module has a test for
the no-package case specifically.

### The members, and what is *not* done to them

`members` and `exclude` are patterns, and they are expanded by the same
`discover::pattern` module Node's `workspaces` uses — one `*` per component, each
component expanded in turn, a pattern whose component contains `**` reported as
`UnsupportedPattern` rather than approximated, and any component that would leave
the project refused. Two ecosystems expanding `*` two ways would report two
different member lists for one directory tree.

**An `exclude` list is not subtracted from the member list.** Whether a directory
named by both `members` and `exclude` is a member is Cargo's rule and SURE has
not read it, so both facts are reported and neither is applied:
`Workspaces::excluded_members` is the overlap, as data. Reporting the overlap is
reversible by a reader who knows the rule; silently honouring it would be SURE
asserting a rule it cannot cite. The mutation harness has the other version of
this — an `exclude` that deletes a member — and it is caught.

A member's own `Cargo.toml` is read, because a workspace's frameworks and test
tools are usually not in the root manifest: a root declaring nothing but
`[workspace]` says nothing about the crate in `crates/parser`. It is kept per
member rather than merged, because the two are different manifests and a merged
list could not say which declared what. A member whose manifest is *there and not
a file* is `MemberManifest::NotReadable`, which is a different fact from
`Absent` — the first is a directory tree SURE could not read, the second is one
that states nothing — and `MemberManifest` lives in `discover/mod.rs` rather than
in either ecosystem's module so that one directory cannot be `Present` in one
module's vocabulary and `NotReadable` in another's.

### The toolchain pin, and why the file's name decides how it is read

Two forms, and which one a file is depends on **both** its text and its name.

- A text that parses into a `[toolchain]` table is one, under **either** name. A
  `rust-toolchain` holding a table is read as a table, because that is what it
  says it is.
- The bare form is a channel on a line by itself, and it is accepted **only**
  under the name `rust-toolchain`. That name predates the TOML file and is not
  defined as TOML at all, so text there need not parse.

`rust-toolchain.toml` **is** defined as TOML, and text under that name which does
not parse is a file SURE could not read. This is the module's sharpest correction
and it was found by mutation rather than by inspection: an earlier revision
decided the form from the text alone, so invalid TOML under the `.toml` name fell
through to the bare-channel branch and **its whole text became the channel** — a
version number SURE invented, which is the exact class of finding this product
exists not to produce. The bare form is also required to be one line with one
whitespace-token in it; a file with more is not the file rustup documents, and
taking its first line would silently drop the rest of whatever somebody wrote.

The components list is matched **case-insensitively** against a constant the
caller passes, because `Clippy` is the same component as `clippy` and the list is
the project's own text. What is compared is SURE's constant, so no project string
reaches a finding.

### Targets: what Cargo finds without a table

Seven paths, of which four are directories:

| Path | Kind | Shape |
| --- | --- | --- |
| `src/lib.rs` | `Library` | file |
| `src/main.rs` | `Binary` | file |
| `src/bin` | `Binary` | directory |
| `examples` | `Example` | directory |
| `tests` | `Test` | directory |
| `benches` | `Benchmark` | directory |
| `build.rs` | `BuildScript` | file |

Both shapes are checked as what they are, and a check that looked for a file at
all seven would find the two files and silently report no tests, examples or
benchmarks — a shorter program than the one the project has. The mutation harness
has that mutation and it is caught.

**A `build.rs` is a program, and it is reported and never run.** Cargo compiles
and executes it before the crate, which makes it the one file in a Rust project
that runs arbitrary code at build time — the same standing `setup.py` has in
Python. The test writes a `build.rs` that would leave a file behind if anything
executed it, and requires that no such file exists.

The path list is also where this module leans on a Cargo **convention** rather
than on a declaration, which is the one thing it does that the other two
ecosystems do not. See gap 11.

### Tooling and the conventional commands

`TOOLS` is a fixed table of twenty-two crate names mapped to four `ToolRole`s —
web framework, async runtime, test runner, benchmark runner. It is deliberately
short and deliberately excludes `serde`, `rand`, `regex` and `log`: those are
libraries a project *uses*, not tools that answer a question about the project,
and a role-less table entry would be SURE naming a crate for no purpose a person
could act on. A dependency not in the table is not reported at all — "SURE did
not recognise this crate" is not a finding, and guessing from a name would be.

`conventional_commands` returns a row for every `CommandRole` whether or not
there is a command, for the same reason Node's `conventional_scripts` and
Python's do: "there is no way to check this project's types" is a finding and a
missing line is not.

**A role is planned only where SURE read a manifest**, because without one there
is nothing that says a `cargo` command would act on this project at all. A
virtual manifest passes, and must: a workspace SURE read is a workspace
`cargo build` acts on, building every member. This gate is on the *document* and
not on the package, and the difference is another correction — gating on
`package()` would have left a virtual manifest with no command at all. Two roles
carry a second gate: `Run` needs a package **and** a binary target, `Bench` needs
a benchmark target **or** a benchmarking crate in the dependencies. Either
evidence alone is enough for `Bench`, because a project that declares only a
harness has benchmarks the harness would run and a project with only a target has
a benchmark with no harness named.

The lint row is `cargo clippy --all-targets` rather than a bare `cargo clippy`,
and it is a decision rather than a default: clippy without `--all-targets` does
not lint the test and example code, so the plan would report on a smaller program
than the one the project has. `Check` carries the same flag for the same reason.

### What is carried verbatim, and what is refused

**A `src/lib.rs` is reported and not inferred from.** Its *existence* is a
conventional target, because Cargo discovers one there without a table — but the
report says what is at the path and never what the file contains. This is the one
place this module leans on a convention rather than on a declaration, and it is
recorded as gap 11 rather than presented as a declaration.

**A requirement is carried verbatim.** `"1.0.1"`, `"^1"` and `"=1.0.1"` are three
strings and not three constraints, and `Requirement` keeps the three ways a
dependency can have no version *here* apart: `FromWorkspace` (`workspace = true`,
which may sit beside a feature list and states no version either way),
`Unstated` (a `path` or `git` dependency, where there is nothing to resolve), and
`NotReadable` (the value was not a string or a table at all). `build = false`,
the key being absent, and `build = "path"` are three `BuildScript` values for the
same reason.

**A lint level from a tool Cargo does not define is not named.** `[lints]` has
`clippy` and `rust`; a third table would be a tool SURE does not know, and
naming it would be repeating a project's text in SURE's own vocabulary.

## Support levels

`grade` returns the level and the sentence together, as constants, so a level and
its reason cannot be assigned in two places and disagree. Each ecosystem module
has its own, because what counts as "the manifest" differs.

**Node:**

| What was found | Level | Why |
| --- | --- | --- |
| a readable `package.json` | `Generic` | SURE can find how the project is built and run |
| a `package.json` it could not read | `InspectOnly` | it can only look at the project's files |
| no manifest, but a lockfile | `InspectOnly` | it is plainly a Node project and nothing is declared |
| no manifest and no lockfile | `InspectOnly` | only `tsconfig.json`/`pnpm-workspace.yaml` said so |

**Python:**

| What was found | Level | Why |
| --- | --- | --- |
| a readable `pyproject.toml` or `Pipfile` | `Generic` | SURE can find how the project is built and run |
| a manifest it could not read | `InspectOnly` | it can only look at the project's files |
| no readable manifest, but a lockfile | `InspectOnly` | it is plainly a Python project and nothing is declared |
| only a `requirements*.txt` | `InspectOnly` | a requirements file says what to install and not how the project is built |
| only `setup.py`, `setup.cfg` or `.python-version` | `InspectOnly` | nothing SURE will read declares anything |

**Rust:**

| What was found | Level | Why |
| --- | --- | --- |
| a readable `Cargo.toml`, virtual or not | `Generic` | SURE can find how the project is built and run |
| a `Cargo.toml` it could not read | `InspectOnly` | it can only look at the project's files |
| no readable manifest, but a `Cargo.lock` | `InspectOnly` | it is plainly a Rust project and nothing is declared |
| no readable manifest, but a workspace table or a pinned toolchain | `InspectOnly` | something here says it is a Rust project and nothing SURE reads declares anything |
| no readable manifest and none of the above | `InspectOnly` | it can see the project's files and cannot read how it is built |

The three `Absent` rows are separate arms rather than one, because the *reason* a
reader is given differs: a lockfile is a stronger statement about a project than
a toolchain pin is, and a level with three different sentences underneath it is
three facts wearing one label.

**A `grade` measures what SURE understood, and it is not the project's support
level.** It is the input to it: `sure_core::support::classify` takes the weakest
of these grades and the best level this build's capability allows, and
`docs/product/SUPPORTED_STACKS.md` defines the levels by what SURE can do —
including running approved checks. Since ADR 0017 the ceiling is B, so a
readable `Cargo.toml` graded `generic` here is reported at level B (generic); a
project discovery grades `inspect_only` stays C. The two are kept apart rather
than merged because collapsing them would mean one of the two questions getting
a wrong answer; level A remains a higher bar than the discovery grade.

## What is bounded, and how

Limits are on work, in the same spirit as `ScanOptions` and `FingerprintOptions`,
and every one that is reached is reported rather than applied quietly.

| Limit | Default | Reaching it |
| --- | --- | --- |
| `max_manifest_bytes` | 8 MiB | `TooLarge` — a refusal, **not** a parse of the first however-many bytes |
| `max_manifests` | 512 | `OutOfBudget` for the manifests after it |
| `max_workspace_members` | 512 | `Workspaces::truncated` |
| `MAX_REQUIREMENTS_FILES` | 32 | the files after it are not read; the first 32 in sorted order are |
| `MAX_REQUIREMENTS_LINES` | 4096 | `RequirementsFile::truncated` |
| `scan.max_depth`, `scan.max_entries` | see `PROJECT_DISCOVERY.md` | as that document says |

**One budget serves every ecosystem.** `discover()` builds a single `Budget` and
hands the same one to `node::look`, then `python::look`, then `rust::look`, in
`Ecosystem::ALL` order. A project with five hundred Node manifests therefore
leaves nothing for Python, and its Python manifest is `OutOfBudget` rather than
read. That is the intended reading of "how many manifests SURE will read in one
discovery" — the limit is on the run and not on the ecosystem — but it is a
consequence of the call order rather than of anything a later module does, so it
is recorded here rather than left to be discovered.

The module has a test for the consequence rather than the shape, because the
shape is a `Vec` and the consequence is a finding: with `max_manifests(1)` in a
directory that is all three ecosystems at once, the affected files are
`pyproject.toml` **and** `Cargo.toml` — two, not one. Rust is starved by Node's
spend even though Python sits between them, which is what makes this a property
of the shared budget rather than of a neighbouring pair.

Two rules are taken from the rest of SURE rather than decided here. **A link is
never read through**: `crate::scan` does not follow one and `crate::fingerprint`
records one by its target, so a manifest that read through a link would be the
one place in the product that reads whatever a project points at, including
somewhere outside the project. A manifest at a link is `NotReadableKind`. And
**reaching a byte limit is a refusal**: half a `package.json` is not a smaller
`package.json`, it is a document that fails to parse with a message about a
syntax error the project does not have. The limit is checked after reading one
byte more than allowed, so a file that grows while SURE reads it is caught too.

An absent optional file does **not** spend the manifest budget: `Probe::Nothing`
and `Probe::Other` are answered before `Budget::take()` is called, so a project
with no `pnpm-workspace.yaml` does not pay for looking.

## What discovery does not do

**It runs nothing.** No `npm`, no `node`, no `python`, no `uv`, no `cargo`, no
resolver, no network. Reading a manifest is not executing a project, and the
whole of step 1 is on the inspect-only side of
`docs/architecture/EXECUTION_SAFETY.md`. Three tests hold this line, one per
ecosystem: the Node one writes a `build` script whose command would leave a file
behind, the Python one writes a `setup.py` and a `conftest.py` that would each
leave one behind if executed *or imported*, and the Rust one writes a `build.rs`
that would leave one behind if anything compiled and ran it. All three require
the file to be absent afterwards.

**It does not look at `node_modules`, `.venv`, `target`, or what is installed
anywhere else**, and not only because the scan leaves those out. What is
installed is the package manager's answer, and a directory that is usually
absent, usually stale and never committed is not a fact about the project a
person can act on.

**It does not decide whether the project is good.** It says what the project
declares and at what support level; whether the declaration is honest is what the
checks after it are for.

**It is not the diagnostics module.** See above.

## Known coverage gaps

Recorded so they are not forgotten. None is resolved by a task yet.

1. **The byte budget has only been exercised where the manifest is the thing
   that crossed it.** Reaching `TooLarge` for a file that grows *during* the
   read needs a writer racing the reader, which no fixture builds. The `+ 1`
   read is what makes the case correct and nothing on this machine demonstrates
   it firing.

2. **`Unreadable` is not tested against a genuinely unreadable file.** The arm
   is real and is reached in tests by a path that does not exist and by a path
   with an interior NUL byte, refused before any system call. What those do not
   establish is that the operating system produces that error for a file with
   permissions that forbid reading — making one needs a privileged user or an
   ACL change, and `chmod 000` does nothing when the tests run as root. This is
   the same gap `PROJECT_DISCOVERY.md` records for its own `Err` arm.

3. **Case-sensitive lookup is not exercised on this machine for the manifests
   themselves.** `Tree` takes its case rule from `ScanOptions::case`, so both
   rules are testable here, and `lookup_key` is tested directly. What is not
   tested on Windows is a project that has *both* `package.json` and
   `Package.json` — constructible only on a case-sensitive filesystem, so the
   CI Linux and macOS jobs are where it would run.

4. **A workspace pattern's `*` is expanded one level, and only one.** `packages/*`
   is a child directory lookup; `packages/*/sub` works because each component is
   expanded in turn. A pattern relying on brace expansion or character classes —
   which npm itself does not support either — is reported as
   `UnsupportedPattern` rather than approximated.

5. **The link at a manifest's name is a directory link.** `mklink /J` needs no
   privilege on Windows and a file symbolic link does; both Developer Mode and
   administrator rights were probed on this host and are absent. The walk's
   symlink arm runs before it looks at what is at the other end, so the refusal
   is one code path for both kinds — but that is an argument, and what a test
   would show is a link whose target is a *file*. The macOS and Linux CI jobs are
   where it could run.

6. **A file can be *replaced by a link* between the walk and the read.** The walk
   records what is at a name; `read_text` then calls `File::open` on the path the
   walk recorded, and an open follows whatever is at that path *now*. A project
   that swaps `package.json` for a link pointing outside the project, in the
   window between the two, is read through.

   **What bounds it.** Everywhere else, containment is by construction rather
   than by a check that could be wrong: a path a manifest names is resolved
   through the walk's own records (`Tree::is_directory`, `child_directories`)
   and never by joining onto the filesystem, and `read_json` takes the `Probe`
   the walk produced rather than a path, so that what is read and what was found
   cannot come from two different walks. This gap is the one place where the
   filesystem is consulted a second time.

   **What it is not.** It is an **integrity** problem, not a disclosure: the
   content lands in SURE's own report, which is read by the person who could
   already open the file the link points at. It also needs an adversary running
   code on the machine during the same milliseconds as SURE, and it changes
   nothing that is executed.

   **Why it is not closed.** Closing it needs an open that does not follow a
   link — `O_NOFOLLOW` on Unix, `FILE_FLAG_OPEN_REPARSE_POINT` on Windows — and
   the Windows flag is not reachable from `std` without `unsafe`, which this
   workspace forbids. `FINGERPRINTING.md` gap 5 records the same window for the
   fingerprint's reader, where the consequence is a stale digest rather than a
   foreign reading; the two are the same shape and neither is closed. Recorded
   here rather than left implicit because a **push security review flagged this
   file for "path traversal / symlink TOCTOU"** on 2026-09-14 — see
   `progress/HANDOFF.md`, which also records that the notification carried no
   finding text and that this gap is what an inspection of the file found.

7. **`*.egg-info` is not skipped, and cannot be with the table as it is.**
   `scan/ignore.rs` matches **exact names only**, deliberately — there is no glob
   language in it — and `foo.egg-info` is `foo`'s name with a suffix. `.tox`,
   `.nox` and `.eggs` were added to `IGNORED_DIRECTORIES` as `Vendored` by
   P2-T005; `*.egg-info` is recorded here as the entry that belongs beside them
   and cannot be expressed. Adding a suffix rule to the table would change what
   the whole ignore list means for every entry in it.

8. **Python workspace members are not resolved.** uv
   (`[tool.uv.workspace] members`) and PDM (`[tool.pdm.workspace]`) both have a
   first-class member list, and neither is followed. The table's *presence* is
   read, and correctly: it is evidence that the installer is configured. Its
   contents are not, so a Python monorepo reports as one project with one
   manifest read, and `max_workspace_members` — a Node-era limit — does not apply
   to Python at all.

9. **A project that declares its tooling outside the manifest reports none.**
   `noxfile.py`, `tox.ini` and `.pre-commit-config.yaml` are three real ways to
   declare a test runner or a linter, and none is on the list of files SURE looks
   at — so a project that names `ruff` only in `.pre-commit-config.yaml` is
   reported as having no linter, which is a negative finding about tooling the
   project does have. This bears directly on P2-T005's "declared test and lint
   tooling": SURE detects the tooling declared *in the files it reads*, and
   `.pre-commit-config.yaml` is not one of them. `noxfile.py` is the same shape as
   `setup.py` — a program — so reading it would need its own decision rather than
   an entry in a table.

10. **`Installer::Pip` is inferred, never declared.** There is no `[tool.pip]`
    table in any real project, so pip reaches a finding only through a
    `requirements*.txt` — the third evidence tier. A project that installs with
    plain `pip` and no requirements file is reported with no installer at all,
    which is the honest answer and not a satisfying one.

11. **The conventional target list is a Cargo convention, not a declaration.**
    `src/lib.rs`, `src/main.rs`, `src/bin`, `examples`, `tests`, `benches` and
    `build.rs` are paths Cargo discovers without being told. Reporting them is
    reporting what is *at* a path, which is a fact about the directory tree — but
    a `src/lib.rs` is reported as a `Library` target on the strength of where it
    is and not on anything the project said, and this is the one place any of the
    three ecosystems leans on a convention rather than on a declaration. Two
    Cargo settings change the answer and neither is read: `autobins`,
    `autotests`, `autoexamples` and `autobenches` turn automatic discovery *off*,
    so a project with `autotests = false` and a `tests/` directory is reported
    with a test target Cargo would not build. It is not closed by reading the
    four keys, because a `[lib] path = "…"` moves a target too, and the general
    answer is that SURE reports the conventional paths it can see rather than a
    resolved target list — which is what "SURE has not run `cargo`" means here.

12. **`[workspace.dependencies]` is reported by its keys and never its values.**
    The table is the workspace's shared dependency list, and a member inheriting
    from it gets `Requirement::FromWorkspace` — a requirement that is stated, and
    stated in a file SURE read, but not read. So a workspace whose shared
    dependencies are all inherited reports every member's version as
    inheriting-something rather than as a version, even though the version is in
    the root `Cargo.toml`. Reading the values is possible and is not done yet.

13. **A `path` dependency's manifest is not read.** `foo = { path = "../foo" }`
    is `Requirement::Unstated`, and `../foo/Cargo.toml` is not opened, so a
    project that assembles itself through `path` dependencies rather than through
    a `[workspace]` is one project with no members. The `path` is recorded as
    nothing at all — it is not in `Dependency` — so a reader cannot tell a `path`
    dependency from a `git` one.

14. **`[patch]`, `[replace]` and `[profile]` are not read.** All three are real
    Cargo tables that say something about the project, and a manifest holding
    only those is reported as one SURE read with no package and no workspace —
    which is true and is not the whole truth. `[profile]` in particular is the
    table a person reads to find out how the project is built for release.

15. **A target's `required-features` and a feature's `dep:` syntax are not
    read.** Features are read as a name, the list it enables and whether it is
    `default`, which is the shape a person reads them in; a feature that turns a
    dependency on through `dep:foo` is reported as enabling the string `dep:foo`
    rather than as enabling `foo`, and no feature resolution is attempted at all.

16. **An `exclude` pattern that is refused, or that names nothing, leaves no
    trace.** The list is resolved only to work out its overlap with the members
    (`Workspaces::excluded_members`), and a pattern with no overlap contributes
    nothing — so `exclude = ["../../elsewhere"]` is refused by the same rule that
    refuses a member pattern, and the refusal is dropped rather than reported.
    This does **not** misstate membership, which is why it is a gap and not a
    defect: `excluded_members` means *these resolved members are also named by
    `exclude`*, and an empty list is true in every one of those cases. What is
    lost is a reader's ability to tell an `exclude` list SURE could not follow
    from one that named nothing — and a member list cut off by
    `max_workspace_members` is the reason the two are worth telling apart, since
    the overlap is computed against the truncated list. `Workspaces::truncated`
    is what says the list was cut.

## Enforced by

Node tests are in `crates/sure-core/tests/discover_node.rs`; Python tests are in
`crates/sure-core/tests/discover_python.rs`; Rust tests are in
`crates/sure-core/tests/discover_rust.rs`; unit-test names without a file are in
`src/discover/python.rs` or `src/discover/rust.rs` as named.

| Statement | Where the meaning lives | Enforced by |
| --- | --- | --- |
| A finding always names the file it came from | this document | every `Source` field; `the_conclusion_names_the_files_it_rests_on`, `a_pyproject_toml_project_is_found_and_read`, `the_files_sure_read_are_named_and_sure_writes_nothing` |
| "Not there" is never "there and unreadable" | this document, `discover/read.rs` | `a_manifest_that_is_valid_json_and_not_a_manifest_is_unread_too`, `a_manifest_that_is_not_json_is_unread_and_never_absent`, `every_reason_says_which_of_the_four_answers_it_is`; for Python `a_manifest_that_is_not_toml_is_unread_and_never_absent`, `a_manifest_too_large_to_read_is_unread_rather_than_half_read`, `a_manifest_sure_ran_out_of_budget_for_is_unread_and_never_absent`; for Rust `a_cargo_toml_that_is_not_a_manifest_is_still_not_a_project_that_declares_nothing`, `a_manifest_that_is_oversized_is_reported_rather_than_half_read`, `a_toolchain_file_sure_could_not_read_is_not_a_project_that_pins_nothing`, `a_member_whose_cargo_toml_is_not_a_file_is_not_a_member_with_no_manifest` |
| An unread file is recorded in the result, not only in the state | this document, `read_manifest` in `node.rs`, `python.rs` and `rust.rs` | the same tests' assertions on `Discovery::unread` |
| A link is never read through | this document, `PROJECT_DISCOVERY.md` | `a_link_named_package_json_is_not_read_through` (a real link out of the project, and a real manifest at the far end) |
| A byte limit is a refusal, not a partial read | this document | `a_file_too_large_to_read_is_unread_rather_than_half_read`; `a_requirements_file_that_could_not_be_read_is_named_and_not_dropped`; `a_manifest_that_is_oversized_is_reported_rather_than_half_read` |
| The manifest budget is finite and reported when spent | this document | `a_manifest_sure_ran_out_of_budget_for_is_unread_and_never_absent`, `a_budget_of_zero_reads_nothing_and_says_so_rather_than_reading_anything` |
| One budget serves every ecosystem, in `Ecosystem::ALL` order | this document | `one_budget_is_shared_by_every_ecosystem_and_reaching_it_says_so`, `a_directory_that_is_every_ecosystem_at_once_is_reported_as_all_of_them` |
| A pattern cannot leave the project | this document | `a_workspace_pattern_cannot_reach_outside_the_project`, `a_member_pattern_that_would_leave_the_project_is_refused`; directly, in `pattern.rs`, `a_pattern_that_would_leave_the_project_is_refused_in_every_position`, `an_absolute_pattern_is_refused_where_this_platform_says_it_is_absolute` |
| A pattern SURE will not expand is reported and not approximated | this document, gaps 4 and 11 | `a_member_pattern_sure_will_not_expand_is_reported_rather_than_dropped`; directly, `a_pattern_this_cannot_expand_is_refused_rather_than_partly_expanded` |
| The root is never its own member | this document | `the_root_is_never_a_member_of_its_own_workspace`; directly, `the_root_is_named_by_a_dot_and_is_never_a_member_of_itself` |
| A pattern names directories, and one directory is one member | this document | `a_star_names_directories_and_never_files`, `two_patterns_that_reach_one_directory_name_it_once` |
| A refusal is told apart from a pattern that named nothing | this document, gaps 4 and 11 | `a_refusal_is_told_apart_from_a_pattern_that_named_nothing`; the reasons reach a report through `every_reason_a_pattern_can_fail_for_can_be_named_and_described` |
| A pattern is matched by the platform's case rule, not by a spelling | this document | `a_pattern_is_matched_by_this_platform_s_case_rule_and_not_by_a_spelling` |
| Two pieces of manager evidence pointing apart is reported | this document | `a_project_that_names_one_manager_and_locks_another_is_reported_not_resolved`, `two_lockfiles_for_two_managers_are_a_disagreement`, `two_lockfiles_for_two_managers_are_a_disagreement_and_two_for_one_are_not` |
| The same, for installers | this document, `python.rs` | `two_tool_tables_naming_two_installers_are_a_disagreement`, `a_configured_installer_and_a_lockfile_for_another_are_a_disagreement`, `two_lockfiles_are_reported_as_a_disagreement_rather_than_resolved`, `a_configured_installer_and_another_lockfile_are_a_disagreement` |
| A requirements file is evidence and never a disagreement | this document | `a_requirements_file_is_the_weakest_evidence_and_never_a_disagreement` |
| An `exclude` list is reported beside the member list and never applied to it | this document, gap 12 | `a_member_the_exclude_list_also_names_is_reported_as_both` |
| A member limit that was reached says so | this document | `members_beyond_the_limit_are_cut_and_the_workspace_says_so` |
| A virtual manifest's workspace is read from the document | this document, `rust.rs` | `a_workspace_table_is_read_when_there_is_no_package_table`, `a_virtual_manifest_is_a_manifest_and_its_members_are_read`, `an_explicit_workspace_table_with_no_members_is_not_no_workspace_table` |
| No project string reaches a sentence | this document | the fixed `TOOLS` tables; `Source::says` is `&'static str`; `a_tool_is_named_from_the_table_and_never_from_the_manifest`, `a_project_declares_its_test_and_lint_tooling_and_sure_names_it`, `what_a_finding_names_is_the_tables_own_crate_and_never_the_projects_spelling`, `a_command_names_a_constant_and_never_anything_a_project_wrote` |
| A value is read without the whitespace around it, and a number is not a name | this document | `a_value_is_read_without_the_whitespace_around_it`, `a_number_in_a_members_list_is_not_turned_into_a_directory_name` |
| Discovery runs no program | this document, `EXECUTION_SAFETY.md` | `discovery_runs_none_of_the_scripts_it_reads` (Node — a fixture that would leave a file behind if anything ran it, plus a source-text grep over all six files in the module tree that drops whole-line comments, so that a sentence *about* the rule is not read as a breach of it), `discovery_runs_nothing` (Python, where a `setup.py` and a `conftest.py` would each leave a file behind), and `a_build_script_is_reported_as_a_target_and_never_run` (Rust) |
| A conventional role with no script is still a row | this document | `every_conventional_role_has_a_row_whether_or_not_it_is_declared`; `a_command_is_planned_only_for_a_tool_the_project_declared`; `a_row_exists_for_every_conventional_role_whether_or_not_it_can_run`, `a_row_that_has_no_command_carries_no_reason_for_one` |
| A planned command names a frontend and not a backend library | this document | `a_build_plan_names_a_frontend_and_never_the_backend_library` |
| A command is planned only where SURE read a manifest, and `run`/`bench` only where there is something to run | this document | `a_command_is_only_offered_for_a_role_the_project_declared_a_tool_for`, `cargo_run_is_planned_only_where_there_is_a_program_to_run`, `cargo_bench_is_planned_only_where_there_is_a_benchmark_to_run`, `a_benchmark_is_reachable_by_either_kind_of_evidence_and_by_both_together`, `a_member_target_makes_a_role_available_to_the_workspace` |
| The toolchain pin is read in both of its forms, and its name decides how | this document | `the_toolchain_pin_is_read_in_both_of_its_forms`, `a_toolchain_pin_is_a_marker_on_its_own_and_its_components_are_read`, `a_toolchain_file_that_is_not_what_its_name_says_is_not_read_as_a_channel`, `a_toolchain_component_is_matched_without_regard_to_case` |
| The conventional targets are found in both of their shapes | this document, gap 11 | `the_targets_cargo_finds_without_a_table_are_found_in_both_of_their_shapes`, `a_build_script_is_reported_as_a_target_and_never_run` |
| `setup.py` is reported and not read | this document | `a_setup_py_is_reported_rather_than_read` |
| The interpreter is carried verbatim from every source | this document | `the_interpreter_the_project_asks_for_is_carried_verbatim_from_every_place`, `a_python_version_file_is_read_as_its_whole_text` |
| Every line of a requirements file is accounted for | this document | `a_requirements_file_keeps_every_line_in_exactly_one_place` |
| A URL line is not a dependency | this document | `a_url_line_in_a_requirements_file_is_not_a_dependency_named_https` |
| A requirement is carried as written and never resolved | this document | `a_requirement_is_recorded_as_written_and_never_resolved`, `the_three_ways_a_dependency_has_no_version_here_are_three_facts`, `build_false_is_not_the_same_as_the_key_being_absent`, `a_dependency_sure_cannot_read_is_not_a_dependency_that_is_not_there` |
| Only a project-level file makes a project | this document | `a_directory_of_python_files_with_no_manifest_is_not_a_python_project`, `every_file_that_marks_a_python_project_is_enough_on_its_own`, `a_toolchain_pin_is_a_marker_on_its_own_and_its_components_are_read` |
| A directory that is not a project is not reported as one | this document | the tests above; `a_directory_with_no_node_files_in_it_is_not_a_node_project`, `a_rust_source_file_alone_is_not_a_rust_project`, `a_directory_that_is_not_a_rust_project_is_left_entirely_alone` |
| Order is fixed and independent of the filesystem | `PROJECT_DISCOVERY.md` | `discovery_is_a_function_of_the_project_and_not_of_the_run`, `thicker_requirements_files_are_all_read_and_in_a_fixed_order`, `a_project_that_is_both_node_and_python_reports_both_in_a_fixed_order` |
| A project SURE could not read is not reported as completely understood | `PROJECT_DISCOVERY.md` | `a_scan_that_looked_at_everything_says_so_and_one_that_did_not_says_what_it_missed` |

The "runs nothing" test is worth a note: no run of the code demonstrates that a
program was never executed, so the test also greps every file in
`src/discover/` — `mod.rs`, `node.rs`, `pattern.rs`, `python.rs`, `read.rs` and
`rust.rs` — for `process::Command` and `std::process`. It lives in the Node test
file and names all six, because the claim is about *discovery* rather than about
Node: a check that named one ecosystem's files would have let the next one shell
out unnoticed, which is what happened between P2-T005 and P2-T006. That catches
the apparatus and not the guarantee, and says so.

## Related decisions

| ADR | Topic |
| --- | --- |
| 0001 | Rust local core and crate boundaries — `discover` is in `sure-core`, and it reuses `scan` rather than walking again |
| 0002 | Local-first privacy — reading a manifest tells nobody anything and sends nothing anywhere |
| 0007 | Windows primary development — case-insensitive lookup and spaces in paths are primary cases |
| 0010 | Frozen domain semantics live in code — `StackClassification` and `SupportLevel` are the domain's types, re-exported rather than restated |
| 0012 | Diagnostics are records, not a logging framework — and an unread manifest is not a diagnostic at all |

[`Discovery`]: ../../crates/sure-core/src/discover/mod.rs
[`UnreadReason`]: ../../crates/sure-core/src/discover/read.rs
[`NodeProject`]: ../../crates/sure-core/src/discover/node.rs
