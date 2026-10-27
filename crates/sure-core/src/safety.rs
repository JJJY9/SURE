//! What a command may do, read from the command line SURE assembled.
//!
//! `P3-T004` acceptance: *"Static/read-only, dynamic host, install, network,
//! destructive categories are distinct."* The five categories are
//! [`sure_domain::execution::CommandClass`]; this module is the rule that puts a
//! command into them, and [`classify`] is its only door.
//!
//! # Why this is not in `process`
//!
//! [`crate::process`] runs a program. This module decides **whether what it
//! would run is a thing SURE is allowed to do**, and that is a question asked by
//! a caller *before* there is anything to run — so the runner does not depend on
//! this module, this module does not depend on the runner, and neither imports
//! the other. `process/mod.rs` states the same split from its own side. The
//! shape of [`classify`] follows from it: it takes a program name and an
//! argument vector, which is exactly what a caller has before it builds a
//! [`ProcessRequest`](crate::process::ProcessRequest) — and taking one of those
//! instead would make this module a caller of the runner and trip the rule in
//! `tests/spawn_sites.rs` that is there to notice.
//!
//! # The one rule that makes this safe to use
//!
//! **Nothing is [`CommandClass::Static`] unless a rule in this file says so.**
//! Every other answer is available as a fallback and `Static` is not one of
//! them:
//!
//! - a program this table does not know is [`Source::UnknownProgram`];
//! - a program it knows and an operation it does not is
//!   [`Source::UnknownOperation`];
//! - a command line whose meaning is in text SURE cannot read is
//!   [`Source::UnreadText`].
//!
//! All three land on the same [`CommandEffects`]: every category **except**
//! `Static`. That is the direction the whole module fails in. A classifier that
//! answered "read-only" for a command it did not recognise would be the false
//! green this product exists to prevent, and it is the one mistake here that no
//! downstream check could catch.
//!
//! The four sources are kept apart because they have four different follow-ups.
//! An unknown program means the table needs a row; an unknown operation means
//! the same program needs a row; unread text is the only one of the four that
//! more table work cannot fix, because the command SURE assembled is not what
//! decides what runs. A reader who sees only "not static" learns none of that.
//!
//! # The answer is a set, and it is an upper bound
//!
//! `cargo add serde` installs a package *and* reaches the registry. One value
//! would have to drop one of those facts, so the answer is a
//! [`CommandEffects`] — and **it is always an over-approximation**: the
//! categories the command *may* fall into, never a claim that it does all of
//! them. Asking for one consent too many costs a prompt; asking for one too few
//! is the failure this module exists to prevent, so where a form is uncertain
//! the class is added rather than argued away.
//!
//! Two flag rules are applied to every program, because both flags mean the same
//! thing wherever they appear:
//!
//! - **`--dry-run`** takes away [`CommandClass::Install`] and
//!   [`CommandClass::Destructive`] — the two that change this machine. It does
//!   **not** take away [`CommandClass::Network`]: a dry run still looks. A
//!   command left with nothing takes its program's own class instead, which is
//!   how `git clean --dry-run` reads as the report it is.
//! - **`--offline`** takes away [`CommandClass::Network`]. Only that spelling,
//!   deliberately: `--frozen` means "do not update the lockfile" to some tools
//!   and "do not touch the network" to others, and a rule that guessed which
//!   would be reading two tools' grammars as one.
//!
//! # The name is read the way the operating system reads it
//!
//! [`classify`] takes the last path component, and on Windows it does two more
//! things the operating system does: it ignores case, and it elides a trailing
//! `.exe`. On Unix it does neither, because neither is true there — and
//! lowercasing there would classify a program SURE never looked at, which is
//! how a project's own `GIT` on `PATH` would be read as git. The condition is
//! `cfg!(windows)` and not `#[cfg(windows)]`, so both arms are compiled and the
//! difference is a value rather than a deleted branch.
//!
//! A `.cmd` or `.bat` **name** is unread text, whatever it is called and
//! whatever is in it. `npm.cmd` on a Windows `PATH` is a batch file that
//! forwards to a JavaScript file, and it would be comfortable to read the name
//! and answer for the file behind it — but **a name is not evidence of
//! behaviour**. The decision is stated rather than dodged: `process/mod.rs`
//! records that Windows starts `cmd.exe` for such a name without being asked,
//! and this module's answer is that SURE cannot see what runs.
//!
//! # What this does not establish
//!
//! **Nothing about the code the command runs.** The categories are a statement
//! about the command SURE was asked to run, not about everything the code it
//! runs might do — the domain's own model is the same, where
//! `Permission::RunProjectCode` is a separate decision from
//! `Permission::Network` and neither implies the other. A project's test script
//! can delete a directory; that is a fact about the script.
//!
//! **Nothing about what is on `PATH`.** This is a classifier for names, and it
//! does not look for the program, does not stat it, and does not read it. A
//! project that puts its own `git.exe` first on `PATH` gets that classified as
//! git. Finding the program is a different question, and answering it here would
//! not make the answer safe: the file can be replaced between the looking and
//! the running.
//!
//! **No shell grammar, and no wrapper is read through.** `env`, `timeout`,
//! `nice`, `xargs`, `sudo` and `cmd` are not looked behind, because a wrapper is
//! an argument grammar SURE would have to implement before it could see the
//! program behind it — and a grammar implemented by guesswork produces a
//! confident answer about a program nobody read. All of them are unread text or
//! unknown programs, which is the loud answer.
//!
//! **No category for writing inside the project.** The acceptance names five,
//! and "changes files in this directory without destroying anything" is not one
//! of them — so a command whose only effect is that is **not** a sixth class and
//! **not** `Static`. `git commit` and `git branch -m` are
//! [`Source::UnknownOperation`]: the table does not have a row that fits them,
//! and adding `Static` beside them would say a command that writes the
//! repository only reads it. `git pull` is different and is classified, because
//! one of *its* effects — reaching the network — is a class the vocabulary has.
//! Where the sixth category should live is `P3-T005`'s question, and inventing
//! it here would put a permission decision in the classifier.
//!
//! **Not a list of every program SURE will ever run.** The table below holds
//! what SURE's own discovery names today — `cargo test`, `npm test`,
//! `npm run build`, `python -m pytest`, `python -m pip install`,
//! `uv run pytest`, `uv sync`, `poetry run pytest` — and the neighbours a reader
//! would expect to find beside them. Every other program is
//! [`Source::UnknownProgram`], which is the safe answer and a visible one: the
//! source says the table is where the work is.

use std::ffi::{OsStr, OsString};

use sure_domain::execution::{CommandClass, CommandEffects};

/// Why [`classify`] answered the way it did.
///
/// Four causes with four different follow-ups — see the module documentation.
/// None of them carries the program or operation *name*, because the caller
/// passed those in and already has them; what a report needs to print is the
/// string it printed before it asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// A rule in this module's table decided, and is named by it.
    Rule {
        /// The row that matched, by the first name it is filed under — so a
        /// command named `py` reports as `python`.
        program: &'static str,
        /// What decided the answer, when it was not the program itself: the
        /// operation after the program name, or the module `-m` named.
        decided_by: Option<&'static str>,
    },
    /// The program is not in the table.
    UnknownProgram,
    /// The program is in the table and this operation is not.
    ///
    /// A different fact from [`Self::UnknownProgram`], and the one the table is
    /// meant to grow into. For `cargo` it is worth knowing that this is not
    /// merely a gap: an operation cargo does not implement is looked for on
    /// `PATH` as `cargo-<operation>` and run if it is there, so an unlisted
    /// cargo operation is a program SURE has never heard of rather than an
    /// error git would have given.
    UnknownOperation,
    /// The command line SURE assembled is replaced, before it runs, by text
    /// SURE did not read.
    UnreadText(&'static str),
}

/// What a command may do, and why SURE says so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    effects: CommandEffects,
    source: Source,
}

impl Classification {
    fn of(classes: &[CommandClass], program: &'static str) -> Self {
        Self {
            effects: CommandEffects::of(classes),
            source: Source::Rule {
                program,
                decided_by: None,
            },
        }
    }

    fn unknown(source: Source) -> Self {
        Self {
            effects: CommandEffects::anything(),
            source,
        }
    }

    /// A command the user named in a `--commands-file`.
    ///
    /// The user wrote the program and its argv themselves, in a file SURE
    /// refuses to read from inside the checked project. It is treated as one
    /// category — [`CommandClass::DynamicHost`] — rather than through the
    /// program table: the table exists to answer *what would this unknown text
    /// do*, and the user has already answered it by naming the argv. The command
    /// still needs `run_project_code`, so a run that has not been granted it does
    /// not start anything, and SURE does not silently install or reach the
    /// network on its behalf.
    #[must_use]
    pub fn declared_by_user() -> Self {
        Self {
            effects: CommandEffects::single(CommandClass::DynamicHost),
            source: Source::Rule {
                program: "a command you declared",
                decided_by: None,
            },
        }
    }

    fn unread(reason: &'static str) -> Self {
        Self::unknown(Source::UnreadText(reason))
    }

    /// Every category the command may fall into.
    #[must_use]
    pub fn effects(&self) -> &CommandEffects {
        &self.effects
    }

    /// Why this answer, and not another.
    #[must_use]
    pub fn source(&self) -> Source {
        self.source
    }

    /// Whether SURE can say that this command only reads and reports.
    ///
    /// The one question a caller should branch on to run something without
    /// asking, and it is true of exactly one shape of answer. A caller that
    /// wants the permissions to ask for instead should walk
    /// [`effects`](Self::effects) and take each class's
    /// [`required_permission`](CommandClass::required_permission).
    #[must_use]
    pub fn is_static_only(&self) -> bool {
        self.effects.is_static_only()
    }

    /// The permission this command needs that nobody can grant, when there is
    /// one.
    ///
    /// [`CommandClass::Destructive`] has no permission — see its own
    /// documentation — so a command SURE has read and found destructive lands
    /// here, and so does every command SURE could not read at all. The caller's
    /// half of this is `P3-T005`'s; the fact is reported rather than swallowed,
    /// because "no consent you can give covers this" is exactly what a user
    /// needs to be told.
    #[must_use]
    pub fn ungrantable(&self) -> Option<CommandClass> {
        self.effects
            .classes()
            .iter()
            .copied()
            .find(|class| class.required_permission().is_none())
    }
}

/// What a command may do, read from its program name and arguments.
///
/// # One element per argument
///
/// The signature is [`ProcessRequest::new`](crate::process::ProcessRequest::new)
/// followed by
/// [`with_arguments`](crate::process::ProcessRequest::with_arguments), so a
/// caller can classify exactly what it is about to run without a conversion in
/// between — and so that there is nowhere to put a command line. There is no
/// variant here that takes a string to be split, for the same reason the runner
/// has none: splitting shell text is itself the act of starting a shell.
///
/// # Arguments SURE cannot read
///
/// An argument that is not valid UTF-8 is not dropped and not skipped: the whole
/// answer becomes [`Source::UnreadText`]. Dropping it would be the quiet
/// failure this module is built to avoid — `git <bytes> status` has an unknown
/// operation in it, and a classifier that discarded the token would read the
/// `status` behind it and answer `Static`.
#[must_use]
pub fn classify<I, S>(program: impl Into<OsString>, arguments: I) -> Classification
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let program = program.into();
    let Some(name) = normalise(&program) else {
        return Classification::unknown(Source::UnknownProgram);
    };

    if is_batch_file(&name) {
        return Classification::unread(BATCH_FILE);
    }

    let Some(entry) = ENTRY_TABLE
        .iter()
        .find(|entry| entry.names.contains(&name.as_str()))
    else {
        return Classification::unknown(Source::UnknownProgram);
    };

    let mut given: Vec<String> = Vec::new();
    for argument in arguments {
        let argument: OsString = argument.into();
        match argument.into_string() {
            Ok(text) => given.push(text),
            Err(_) => return Classification::unread(NOT_TEXT),
        }
    }
    let arguments = given;

    let leading = leading(&arguments, entry);
    let (classes, decided_by, verb) = match leading {
        Leading::Text => return Classification::unread(TEXT_FLAG),
        Leading::Module(module) => {
            let Some(found) = entry.modules.iter().find(|row| row.names.contains(&module)) else {
                return Classification::unknown(Source::UnknownOperation);
            };
            (found.classes, Some(found.names[0]), None)
        }
        Leading::Positional(_) if entry.verbs.is_empty() => {
            return match entry.positional {
                Bare::Program(classes) => Classification::of(classes, entry.names[0]),
                Bare::Unread(reason) => Classification::unread(reason),
            };
        }
        Leading::Positional(operation) => {
            let Some(found) = entry
                .verbs
                .iter()
                .find(|verb| verb.names.contains(&operation))
            else {
                return Classification::unknown(Source::UnknownOperation);
            };
            (found.classes, Some(found.names[0]), Some(found))
        }
        Leading::Nothing => {
            return match entry.bare {
                Bare::Program(classes) => Classification::of(classes, entry.names[0]),
                Bare::Unread(reason) => Classification::unread(reason),
            };
        }
    };

    let mut settled = classes.to_vec();
    if let Some(verb) = verb {
        // A form of the operation that is a different thing replaces what the
        // operation would otherwise be; a flag that makes it worse adds.
        for unless in verb.unless {
            if has_flag(&arguments, unless.flags) {
                settled = unless.classes.to_vec();
            }
        }
        for add in verb.adds {
            if has_flag(&arguments, add.flags) {
                settled.extend_from_slice(add.adds);
            }
        }
    }

    let mut effects = CommandEffects::of(&settled);
    for (flags, removed) in [
        (
            DRY_RUN,
            &[CommandClass::Install, CommandClass::Destructive][..],
        ),
        (OFFLINE, &[CommandClass::Network][..]),
    ] {
        if has_flag(&arguments, flags) {
            effects = take_away(&effects, removed, entry);
        }
    }

    Classification {
        effects,
        source: Source::Rule {
            program: entry.names[0],
            decided_by,
        },
    }
}

/// The words of a command line a harness says it is about to run, or `None`
/// when SURE declines to read it.
///
/// # Why there is a function here that splits a string
///
/// [`classify`] takes a program and an argument vector, and it has no variant
/// that takes a string, because splitting shell text is itself the act of
/// starting a shell. This function is not an exception to that rule; it is the
/// only alternative to having no reading at all. A harness's `Bash` tool sends
/// **one string** and no argument vector, so a caller that wants to know what
/// the harness claims it is about to run has either this reading or none.
///
/// # What it does is refuse first, and read only what is left
///
/// A line is read only when it has exactly one reading. Any character that
/// could mean something to a shell other than itself — quoting, substitution,
/// a separator, a redirection, a comment, a variable, an escape — makes the
/// whole line unreadable and this function answers `None`. What is left is
/// words separated by whitespace, and splitting *that* is not interpretation,
/// because there is nothing left in the text that could have been interpreted.
///
/// `~`, `*`, `?`, `[` and `]` are read as ordinary characters rather than
/// refused, because the only reading a caller makes of a word is the cautious
/// one: those characters name a whole location rather than standing for one,
/// and refusing them would throw away the answer that matters most
/// (`rm -rf *`) to avoid a question nobody asked.
///
/// # The answer is the harness's claim, not a fact about what runs
///
/// It is the harness's own words about itself — data, like every other field of
/// a harness event. SURE does not establish that the line it was handed is the
/// line that will run, and nothing here should be read as though it did.
#[must_use]
pub fn read_simple_command(line: &str) -> Option<Vec<String>> {
    if line.chars().any(is_shell_syntax) {
        return None;
    }
    let words: Vec<String> = line
        .split(|character: char| character.is_ascii_whitespace())
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect();
    if words.is_empty() {
        return None;
    }
    Some(words)
}

/// Whether this character would have to be interpreted before the line could be
/// read as words.
///
/// Not a parser for any shell, and not a list of every character any shell
/// treats specially: it is the list of characters whose meaning is *not* the
/// character, and one of them being present is what makes the whole line
/// unreadable. `"` and `'` quote, `\` escapes, `$` and `` ` `` substitute, `;`
/// `&` `|` separate commands, `<` `>` redirect, `(` `)` `{` `}` `!` `^` group
/// or expand, `#` begins a comment, `%` expands a variable in cmd.exe, and a
/// line break would end this command and begin another.
///
/// `\` is on the list although it is also a path separator on the platform SURE
/// is built for, and that is the deliberate half: in the shells these harnesses
/// run through it escapes the next character, so a line containing one has two
/// readings and SURE takes neither. The cost is a Windows-style path in a shell
/// command — which is therefore not read, named, or offered for a one-time
/// allowance — and the alternative cost is a reading SURE would have to guess
/// at.
fn is_shell_syntax(character: char) -> bool {
    matches!(
        character,
        '"' | '\''
            | '\\'
            | '$'
            | '`'
            | ';'
            | '&'
            | '|'
            | '<'
            | '>'
            | '('
            | ')'
            | '{'
            | '}'
            | '!'
            | '#'
            | '%'
            | '^'
            | '\n'
            | '\r'
            | '\0'
    )
}

/// Remove classes from a set, without ever producing an empty one.
///
/// Empty is not a state [`CommandEffects`] has, and it is not the right answer
/// here either: `git clean --dry-run` has had its one class taken away and is
/// not therefore unclassifiable, it is the report the flag makes it. The
/// program's own class is what is left, and where the program has none — an
/// interpreter, which is unread text with nothing to read — nothing was taken
/// away in the first place.
fn take_away(effects: &CommandEffects, removed: &[CommandClass], entry: &Entry) -> CommandEffects {
    let kept: Vec<CommandClass> = effects
        .classes()
        .iter()
        .copied()
        .filter(|class| !removed.contains(class))
        .collect();
    if !kept.is_empty() {
        return CommandEffects::of(&kept);
    }
    match entry.bare {
        Bare::Program(classes) => CommandEffects::of(classes),
        // Nothing was taken away from a program that has no classes of its own
        // to file, so this arm is unreachable through the table as it stands:
        // every program with a `--dry-run` or `--offline` form is one with a
        // `Bare::Program`. It is written out rather than asserted away because
        // the safe reading of "I cannot say what is left" is the loud one.
        Bare::Unread(_) => CommandEffects::anything(),
    }
}

/// The first thing on the command line that is not a flag.
///
/// Read from the leading run of flags only, and that is a decision rather than a
/// shortcut: an interpreter's own flags come before the file it runs, so a `-c`
/// *after* `python script.py` belongs to the script and reading it as python's
/// would turn a script with an argument into unread text. The run ends at the
/// first token that is not a flag, which is what makes the reading positional.
enum Leading<'a> {
    /// A flag that means the rest of the line is text for an interpreter.
    Text,
    /// The module an interpreter was told to run with `-m`.
    Module(&'a str),
    /// The first token that is not a flag.
    Positional(&'a str),
    /// No flags and no operands.
    Nothing,
}

fn leading<'a>(arguments: &'a [String], entry: &Entry) -> Leading<'a> {
    let mut index = 0;
    while let Some(token) = arguments.get(index) {
        if token == "-" {
            return Leading::Positional(token);
        }
        if entry.module_flag == Some(token.as_str()) {
            return match arguments.get(index + 1) {
                Some(module) => Leading::Module(module),
                None => Leading::Nothing,
            };
        }
        if entry.text_flags.contains(&token.as_str()) {
            return Leading::Text;
        }
        if !is_flag(token) {
            return Leading::Positional(token);
        }
        index += if entry.value_flags.contains(&token.as_str()) {
            2
        } else {
            1
        };
    }
    Leading::Nothing
}

/// Whether a token is a flag rather than an operand.
///
/// A single `-` is not one: it is the conventional name for standard input, and
/// it is an operand. Nor is a token that only starts with `/`, which is a path
/// on Unix — the one entry that takes `/c` names it in its own flag list rather
/// than being recognised by its punctuation.
fn is_flag(token: &str) -> bool {
    token.len() > 1 && token.starts_with('-')
}

/// Whether any token on the line is exactly one of `flags`.
///
/// The whole line rather than the leading run, because these are read after the
/// operation: `git push origin main --force` puts the force at the end. Exact
/// token equality, so `-f` never matches `--force` and a value that happens to
/// contain a flag's text is not a flag.
fn has_flag(arguments: &[String], flags: &[&str]) -> bool {
    arguments
        .iter()
        .any(|token| flags.contains(&token.as_str()))
}

/// The last path component, in the form the operating system resolves it in.
///
/// `None` where there is nothing to look up: an empty name, a name that is not
/// text, or a name that is only a `.exe` suffix.
fn normalise(program: &OsStr) -> Option<String> {
    let text = program.to_str()?;
    // Both separators on every platform: a Windows path handed to a Unix build
    // is still a Windows path, and the component after the last separator is
    // the only part either operating system looks for on `PATH`.
    let name = text.rsplit(['/', '\\']).next().unwrap_or(text);
    let name = if cfg!(windows) {
        let lowered = name.to_ascii_lowercase();
        if lowered.ends_with(EXE) {
            &name[..name.len() - EXE.len()]
        } else {
            name
        }
    } else {
        name
    };
    if name.is_empty() {
        return None;
    }
    Some(if cfg!(windows) {
        name.to_ascii_lowercase()
    } else {
        name.to_owned()
    })
}

/// Whether a name is one Windows starts a command interpreter for.
///
/// Read here even on a platform where the name means nothing, because the answer
/// is the same either way — an unknown program and unread text both come back as
/// every category but `Static` — and a name that says "batch file" is a better
/// thing to report than "not in the table".
fn is_batch_file(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    lowered.ends_with(".cmd") || lowered.ends_with(".bat")
}

const EXE: &str = ".exe";

const NOT_TEXT: &str =
    "an argument is not text SURE can read, so the command line it read is not the one that runs";
const BATCH_FILE: &str = "a batch file: Windows starts a command interpreter to run it, and what \
                          runs is the text inside rather than the name";
const TEXT_FLAG: &str = "the command line SURE built is replaced by text an interpreter reads, so the program that \
     runs is not named on it";

/// `--dry-run`: takes away what changes this machine, and leaves what looks.
const DRY_RUN: &[&str] = &["--dry-run"];

/// `--offline`: the one spelling whose meaning does not depend on the tool.
const OFFLINE: &[&str] = &["--offline"];

// The categories, named for the table below rather than spelled out in it.
const STATIC_ONLY: &[CommandClass] = &[CommandClass::Static];
const RUNS_CODE: &[CommandClass] = &[CommandClass::DynamicHost];
const REACHES_NETWORK: &[CommandClass] = &[CommandClass::Network];
const DESTROYS: &[CommandClass] = &[CommandClass::Destructive];
const UNPUBLISHES: &[CommandClass] = &[CommandClass::Network, CommandClass::Destructive];
/// Changing which packages the project depends on, without running any of them.
///
/// The narrow half of installing, and the reason it can be narrow is that the
/// operations in it only edit a manifest and ask the registry what the edit
/// means — `cargo add` writes `Cargo.toml` and resolves. A command line that
/// installs *from a package* is the other constant, because installing from a
/// package runs install steps the package's author wrote.
const RESOLVES: &[CommandClass] = &[CommandClass::Install, CommandClass::Network];
/// Installing from a package, which runs code as well as fetching it.
///
/// A source distribution is built by a build backend the package wrote, and npm
/// runs a package's lifecycle scripts around an install, so this is not SURE
/// being cautious — it is what installing is. The domain's own mapping agrees:
/// `ActionKind::InstallDependencies` reports `executes_project_code()` and
/// `can_touch_network()` both true, and it is one action there because a user
/// grants one permission for it. This is the description, not the permission,
/// and a caller that reads the classes will ask for more than the one — which is
/// the direction this module fails in.
const INSTALLS_AND_RUNS: &[CommandClass] = &[
    CommandClass::DynamicHost,
    CommandClass::Install,
    CommandClass::Network,
];
/// `cargo test` reaches the network on a cold cache, and SURE will not read the
/// cache to find out whether this is one.
const BUILDS_AND_FETCHES: &[CommandClass] = &[CommandClass::DynamicHost, CommandClass::Network];

/// What a program is when there is no operation to read.
#[derive(Debug, Clone, Copy)]
enum Bare {
    /// The program itself.
    Program(&'static [CommandClass]),
    /// SURE cannot see the program: an interpreter with nothing to run reads
    /// its program from somewhere that is not the command line.
    Unread(&'static str),
}

/// A flag that makes an operation something worse.
#[derive(Debug, Clone, Copy)]
struct FlagEffect {
    flags: &'static [&'static str],
    adds: &'static [CommandClass],
}

/// A form of an operation that is a different thing.
#[derive(Debug, Clone, Copy)]
struct Unless {
    flags: &'static [&'static str],
    classes: &'static [CommandClass],
}

/// One operation of a program.
#[derive(Debug, Clone, Copy)]
struct Verb {
    /// The spellings that name this operation. The first is the one a
    /// [`Source::Rule`] reports.
    names: &'static [&'static str],
    classes: &'static [CommandClass],
    /// Flags anywhere on the line that add a class.
    adds: &'static [FlagEffect],
    /// Flags anywhere on the line that make this a different operation.
    unless: &'static [Unless],
}

const fn verb(names: &'static [&'static str], classes: &'static [CommandClass]) -> Verb {
    Verb {
        names,
        classes,
        adds: &[],
        unless: &[],
    }
}

const fn verb_adding(
    names: &'static [&'static str],
    classes: &'static [CommandClass],
    adds: &'static [FlagEffect],
) -> Verb {
    Verb {
        names,
        classes,
        adds,
        unless: &[],
    }
}

const fn verb_unless(
    names: &'static [&'static str],
    classes: &'static [CommandClass],
    unless: &'static [Unless],
) -> Verb {
    Verb {
        names,
        classes,
        adds: &[],
        unless,
    }
}

/// A module an interpreter runs with `-m`.
#[derive(Debug, Clone, Copy)]
struct Module {
    names: &'static [&'static str],
    classes: &'static [CommandClass],
}

/// One program, and what SURE knows about what it does.
///
/// **A verb is in this table only when every form SURE can name has an effect
/// SURE can name.** That is why `git branch`, `git tag`, `git config`,
/// `git remote` and `git stash` are absent although their common form only
/// reads: `branch -m` renames, `tag -d` deletes, `config user.name x` writes the
/// config, `remote add` adds, `stash drop` drops. Reading the common form would
/// be reading *the form*, not the grammar, and the difference between them is
/// where the false green lives. The same rule takes `cargo clean` out — it
/// deletes, and the vocabulary has no class for deleting build output — and
/// `npm audit`, whose `fix` form installs and whose other forms do not.
#[derive(Debug, Clone, Copy)]
struct Entry {
    /// The names this row answers to. The first is the row's name.
    names: &'static [&'static str],
    /// No operand at all.
    bare: Bare,
    /// An operand that is not an operation — a script, a path.
    positional: Bare,
    /// The operations, or empty for a program that has none.
    verbs: &'static [Verb],
    /// Modules `-m` may name.
    modules: &'static [Module],
    /// The flag that means the next token is a module name.
    module_flag: Option<&'static str>,
    /// The flags that mean the rest of the line is text for an interpreter.
    text_flags: &'static [&'static str],
    /// The flags that take the token after them as their value.
    value_flags: &'static [&'static str],
}

/// The npm family, which answers to one command set.
const NPM_VERBS: &[Verb] = &[
    verb(
        &["test", "start", "stop", "restart", "run", "run-script"],
        RUNS_CODE,
    ),
    // Every one of these can run a package's own install steps — npm runs
    // `preinstall`, `install`, `postinstall` and `prepare` around an install,
    // and a package that ships source is built by a script it brought with it.
    verb(
        &[
            "install",
            "i",
            "ci",
            "add",
            "update",
            "upgrade",
            "dedupe",
            "rebuild",
            "uninstall",
            "remove",
            "rm",
            "prune",
            "link",
        ],
        INSTALLS_AND_RUNS,
    ),
    verb(
        &[
            "publish",
            "view",
            "info",
            "show",
            "search",
            "ping",
            "whoami",
            "outdated",
            "deprecate",
            "owner",
            "login",
            "logout",
            "token",
            "access",
            "profile",
            "star",
            "team",
            "docs",
            "repo",
            "fund",
        ],
        REACHES_NETWORK,
    ),
    // Unpublishing takes a version back off the registry, and the registry will
    // not let it be published again under that number — so unlike `publish`,
    // which is merely public, this one does not come back.
    verb(&["unpublish"], UNPUBLISHES),
    verb(
        &[
            "ls", "list", "ll", "la", "why", "explain", "root", "prefix", "bin", "pkg", "help",
        ],
        STATIC_ONLY,
    ),
];

const GIT_VERBS: &[Verb] = &[
    verb(
        &[
            "status",
            "log",
            "diff",
            "show",
            "rev-parse",
            "rev-list",
            "describe",
            "blame",
            "grep",
            "ls-files",
            "ls-tree",
            "cat-file",
            "shortlog",
            "whatchanged",
            "for-each-ref",
            "show-ref",
            "name-rev",
            "merge-base",
            "check-ignore",
            "count-objects",
            "verify-commit",
            "var",
            "version",
            "annotate",
            "diff-tree",
            "diff-files",
            "diff-index",
        ],
        STATIC_ONLY,
    ),
    verb(&["fetch", "pull", "clone", "ls-remote"], REACHES_NETWORK),
    verb_adding(
        &["push"],
        REACHES_NETWORK,
        &[FlagEffect {
            flags: &["-f", "--force", "--force-with-lease", "--force-if-includes"],
            adds: DESTROYS,
        }],
    ),
    // The one operation with a form that is a different thing, and the short
    // spelling is why it is here rather than left to `--dry-run`: `-n` is a
    // number elsewhere on this command line (`git log -n 5`), so it can only be
    // read as a dry run once the operation is known to be this one.
    verb_unless(
        &["clean"],
        DESTROYS,
        &[Unless {
            flags: &["-n"],
            classes: STATIC_ONLY,
        }],
    ),
    verb(
        &["reset", "checkout", "restore", "rm", "prune", "gc"],
        DESTROYS,
    ),
];

/// Go's own commands.
///
/// `test`, `build` and `vet` run the project's code and are classified as
/// `DynamicHost`; `go get` and `go mod download` change the module cache and are
/// install/network. The distinction matters because SURE plans the first three
/// under `host_confirmed` without demanding a network grant, the same way it
/// plans a Python test runner.
/// .NET's own commands.
///
/// `test`, `build`, `run`, `format` and the MSBuild entry points run the
/// project's code; `restore`/`add`/`new`/`tool`/`workload` install or fetch;
/// the version/info queries are static.
const DOTNET_VERBS: &[Verb] = &[
    verb(
        &[
            "test", "build", "run", "format", "publish", "pack", "msbuild", "vstest",
        ],
        RUNS_CODE,
    ),
    verb(
        &["restore", "add", "new", "tool", "nuget", "workload"],
        INSTALLS_AND_RUNS,
    ),
    verb(&["help"], STATIC_ONLY),
];

const GO_VERBS: &[Verb] = &[
    verb(
        &[
            "test", "build", "vet", "run", "install", "generate", "fmt", "doc",
        ],
        RUNS_CODE,
    ),
    verb(&["get", "mod"], INSTALLS_AND_RUNS),
    verb(&["env", "version", "list", "help"], STATIC_ONLY),
];

const CARGO_VERBS: &[Verb] = &[
    verb(
        &[
            "test", "run", "bench", "build", "check", "clippy", "doc", "rustc",
        ],
        BUILDS_AND_FETCHES,
    ),
    verb(
        &[
            "add",
            "update",
            "upgrade",
            "remove",
            "vendor",
            "generate-lockfile",
        ],
        RESOLVES,
    ),
    verb(&["install"], INSTALLS_AND_RUNS),
    verb(
        &[
            "fetch", "publish", "login", "logout", "owner", "search", "yank", "download",
        ],
        REACHES_NETWORK,
    ),
    verb(
        &[
            "tree",
            "metadata",
            "pkgid",
            "locate-project",
            "verify-project",
            "version",
            "help",
        ],
        STATIC_ONLY,
    ),
];

const UV_VERBS: &[Verb] = &[
    verb_unless(
        &["run"],
        INSTALLS_AND_RUNS,
        &[Unless {
            flags: &["--no-sync"],
            classes: RUNS_CODE,
        }],
    ),
    verb(&["sync", "add", "remove"], INSTALLS_AND_RUNS),
    verb(&["lock"], REACHES_NETWORK),
    verb(&["version", "help"], STATIC_ONLY),
];

const POETRY_VERBS: &[Verb] = &[
    verb(&["run"], RUNS_CODE),
    verb(
        &["install", "add", "update", "remove", "sync"],
        INSTALLS_AND_RUNS,
    ),
    verb(&["lock"], REACHES_NETWORK),
    verb(&["show", "check"], STATIC_ONLY),
];

const PYTHON_MODULES: &[Module] = &[
    // `-m pip install` is SURE's own wording for a Python dependency install,
    // and `-m build` makes an isolated environment and installs the build
    // requirements into it before building anything. Both build whatever the
    // packages brought with them.
    Module {
        names: &["pip", "build"],
        classes: INSTALLS_AND_RUNS,
    },
    Module {
        names: &["pytest", "unittest"],
        classes: RUNS_CODE,
    },
];

const COMMAND_INTERPRETER: &str = "a command interpreter: whether what follows it is a program or \
                                   text for its own parser is its grammar, not SURE's";

const ENTRY_TABLE: &[Entry] = &[
    Entry {
        names: &["git"],
        bare: Bare::Program(STATIC_ONLY),
        positional: Bare::Program(STATIC_ONLY),
        verbs: GIT_VERBS,
        modules: &[],
        module_flag: None,
        text_flags: &[],
        value_flags: &[
            "-C",
            "-c",
            "--git-dir",
            "--work-tree",
            "--namespace",
            "--exec-path",
        ],
    },
    Entry {
        names: &["cargo"],
        bare: Bare::Program(STATIC_ONLY),
        positional: Bare::Program(STATIC_ONLY),
        verbs: CARGO_VERBS,
        modules: &[],
        module_flag: None,
        text_flags: &[],
        value_flags: &[
            "-p",
            "--package",
            "--manifest-path",
            "--target",
            "--config",
            "-Z",
            "--color",
            "--jobs",
            "-j",
        ],
    },
    Entry {
        names: &["go"],
        bare: Bare::Program(STATIC_ONLY),
        positional: Bare::Program(STATIC_ONLY),
        verbs: GO_VERBS,
        modules: &[],
        module_flag: None,
        text_flags: &[],
        value_flags: &["-C", "-mod", "-tags", "-o", "-ldflags", "-gcflags"],
    },
    Entry {
        names: &["dotnet"],
        bare: Bare::Program(STATIC_ONLY),
        positional: Bare::Program(STATIC_ONLY),
        verbs: DOTNET_VERBS,
        modules: &[],
        module_flag: None,
        text_flags: &[],
        value_flags: &[
            "--configuration",
            "-c",
            "--framework",
            "-f",
            "--output",
            "-o",
            "--runtime",
            "-r",
            "--verbosity",
            "-v",
        ],
    },
    Entry {
        names: &["npm", "yarn", "pnpm"],
        bare: Bare::Program(STATIC_ONLY),
        positional: Bare::Program(STATIC_ONLY),
        verbs: NPM_VERBS,
        modules: &[],
        module_flag: None,
        text_flags: &[],
        value_flags: &[
            "--prefix",
            "-C",
            "--registry",
            "--cache",
            "--userconfig",
            "--workspace",
            "-w",
            "--omit",
            "--include",
            "--loglevel",
        ],
    },
    // `npx` fetches a package and runs it, so it is all three of the categories
    // a caller would ask about separately.
    Entry {
        names: &["npx"],
        bare: Bare::Program(STATIC_ONLY),
        positional: Bare::Program(INSTALLS_AND_RUNS),
        verbs: &[],
        modules: &[],
        module_flag: None,
        text_flags: &[],
        value_flags: &["-p", "--package", "--registry", "--cache"],
    },
    Entry {
        names: &["uv"],
        bare: Bare::Program(STATIC_ONLY),
        positional: Bare::Program(STATIC_ONLY),
        verbs: UV_VERBS,
        modules: &[],
        module_flag: None,
        text_flags: &[],
        value_flags: &["--directory", "--project", "--cache-dir", "--python", "-p"],
    },
    Entry {
        names: &["poetry"],
        bare: Bare::Program(STATIC_ONLY),
        positional: Bare::Program(STATIC_ONLY),
        verbs: POETRY_VERBS,
        modules: &[],
        module_flag: None,
        text_flags: &[],
        value_flags: &["-C", "--directory", "--project"],
    },
    Entry {
        names: &["node"],
        bare: Bare::Unread(
            "node with no script reads its program from standard input, which is not the command \
             line",
        ),
        positional: Bare::Program(RUNS_CODE),
        verbs: &[],
        modules: &[],
        module_flag: None,
        text_flags: &["-e", "--eval", "-p", "--print"],
        value_flags: &[
            "-r",
            "--require",
            "--loader",
            "--import",
            "--conditions",
            "-C",
        ],
    },
    Entry {
        names: &["python", "python3", "py"],
        bare: Bare::Unread(
            "python with no script reads its program from standard input, which is not the command \
             line",
        ),
        positional: Bare::Program(RUNS_CODE),
        verbs: &[],
        modules: PYTHON_MODULES,
        module_flag: Some("-m"),
        text_flags: &["-c"],
        value_flags: &["-W", "-X", "--check-hash-based-pycs"],
    },
    // A test runner's operand is a path, and running it is running the
    // project's code — which is what the file it collects is.
    Entry {
        names: &["pytest"],
        bare: Bare::Program(RUNS_CODE),
        positional: Bare::Program(RUNS_CODE),
        verbs: &[],
        modules: &[],
        module_flag: None,
        text_flags: &[],
        value_flags: &["-c", "--rootdir", "-o", "--import-mode", "-n", "-p"],
    },
    Entry {
        names: &["sh", "bash", "dash", "zsh", "ksh", "fish"],
        bare: Bare::Unread(
            "a shell with no script reads its program from standard input, which is not the command \
             line",
        ),
        positional: Bare::Program(RUNS_CODE),
        verbs: &[],
        modules: &[],
        module_flag: None,
        text_flags: &["-c"],
        value_flags: &["-o", "--init-file", "--rcfile"],
    },
    Entry {
        names: &["powershell", "pwsh"],
        bare: Bare::Unread(
            "an interactive shell reads its program from standard input, which is not the command \
             line",
        ),
        positional: Bare::Program(RUNS_CODE),
        verbs: &[],
        modules: &[],
        module_flag: None,
        text_flags: &["-Command", "-c", "-EncodedCommand"],
        value_flags: &["-ExecutionPolicy", "-ep", "-WorkingDirectory", "-wd"],
    },
    // Both of these are read as unread text whatever follows them, and neither
    // is a placeholder for a missing rule. `cmd` is the interpreter Windows
    // starts for a batch file whether or not anyone asked; `wsl` hands the name
    // to another operating system, which resolves it against a `PATH` SURE
    // cannot see.
    Entry {
        names: &["cmd"],
        bare: Bare::Unread(COMMAND_INTERPRETER),
        positional: Bare::Unread(COMMAND_INTERPRETER),
        verbs: &[],
        modules: &[],
        module_flag: None,
        text_flags: &["/c", "/k"],
        value_flags: &[],
    },
    Entry {
        names: &["wsl"],
        bare: Bare::Unread(
            "another operating system resolves the name, against a PATH SURE cannot see",
        ),
        positional: Bare::Unread(
            "another operating system resolves the name, against a PATH SURE cannot see",
        ),
        verbs: &[],
        modules: &[],
        module_flag: None,
        text_flags: &[],
        value_flags: &["-d", "--distribution", "-u", "--user", "-e", "--exec"],
    },
    // The destructive names a caller might reach for. There is nothing to read
    // past the name: every form of these deletes, and the arguments are the
    // things to delete.
    Entry {
        names: &["rm", "rmdir", "del", "erase", "shred"],
        bare: Bare::Program(DESTROYS),
        positional: Bare::Program(DESTROYS),
        verbs: &[],
        modules: &[],
        module_flag: None,
        text_flags: &[],
        value_flags: &[],
    },
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_verb_of_every_row_is_reachable_and_answers_with_its_own_classes() {
        // The coverage rule, and it walks the table rather than a list beside
        // it: a row nobody can reach is a row nobody can test, and it would sit
        // in the table looking like coverage. This is the check that fails when
        // someone adds a row and nothing else.
        for entry in ENTRY_TABLE {
            for verb in entry.verbs {
                for name in verb.names {
                    let classification = classify(entry.names[0], [name]);
                    assert_eq!(
                        classification,
                        Classification {
                            effects: CommandEffects::of(verb.classes),
                            source: Source::Rule {
                                program: entry.names[0],
                                decided_by: Some(verb.names[0]),
                            },
                        },
                        "{} {name} did not answer with its own row",
                        entry.names[0]
                    );
                }
            }
            for module in entry.modules {
                let flag = entry
                    .module_flag
                    .expect("a module needs a flag to be named by");
                let classification = classify(entry.names[0], [flag, module.names[0]]);
                assert_eq!(
                    classification,
                    Classification {
                        effects: CommandEffects::of(module.classes),
                        source: Source::Rule {
                            program: entry.names[0],
                            decided_by: Some(module.names[0]),
                        },
                    },
                    "{} {flag} {} did not answer with its own row",
                    entry.names[0],
                    module.names[0]
                );
            }
        }
    }

    #[test]
    fn every_row_with_no_verbs_answers_with_itself_both_ways() {
        // These rows have two halves — the program with nothing and the program
        // with an operand — and both are reachable, so both are checked.
        for entry in ENTRY_TABLE {
            if !entry.verbs.is_empty() {
                continue;
            }
            let bare = classify(entry.names[0], Vec::<String>::new());
            let with_operand = classify(entry.names[0], ["something"]);
            for (described, classification, expected) in [
                ("with nothing", &bare, entry.bare),
                ("with an operand", &with_operand, entry.positional),
            ] {
                match expected {
                    Bare::Program(classes) => {
                        assert_eq!(
                            classification.effects(),
                            &CommandEffects::of(classes),
                            "{} {described}",
                            entry.names[0]
                        );
                        assert_eq!(
                            classification.source(),
                            Source::Rule {
                                program: entry.names[0],
                                decided_by: None,
                            },
                            "{} {described}",
                            entry.names[0]
                        );
                    }
                    Bare::Unread(_) => assert!(
                        matches!(classification.source(), Source::UnreadText(_)),
                        "{} {described} was not read as unread text",
                        entry.names[0]
                    ),
                }
            }
        }
    }

    #[test]
    fn no_two_verbs_of_one_program_share_a_name() {
        // A duplicate would make the later row unreachable, and the sweep above
        // would then check the first row twice rather than checking both.
        for entry in ENTRY_TABLE {
            let mut seen: Vec<&str> = Vec::new();
            for verb in entry.verbs {
                for name in verb.names {
                    assert!(
                        !seen.contains(name),
                        "{} lists {name} twice",
                        entry.names[0]
                    );
                    seen.push(name);
                }
            }
        }
    }

    #[test]
    fn no_row_is_filed_under_a_name_the_lookup_would_never_produce() {
        // The lookup is on the normalised name, and normalisation takes the last
        // path component and elides `.exe` on Windows. A row filed under a name
        // with either in it could never match.
        for entry in ENTRY_TABLE {
            for name in entry.names {
                assert!(!name.contains('/'), "{name} has a separator in it");
                assert!(!name.contains('\\'), "{name} has a separator in it");
                assert!(
                    !name.to_ascii_lowercase().ends_with(".exe"),
                    "{name} would only match a name normalisation has already shortened"
                );
                assert!(
                    !is_batch_file(name),
                    "{name} is a batch-file name, answered before the table is reached"
                );
            }
        }
    }

    #[test]
    fn a_batch_file_is_recognised_in_whatever_case_its_name_is_written() {
        // Called directly rather than through `classify`, and the reason is the
        // one thing this test is about. `classify` normalises before it asks,
        // and normalisation lowercases on Windows — so on this platform the
        // lowercasing in here is a second copy of a rule that has already run,
        // and **a mutation that deletes it is invisible through the front
        // door**. That was measured, not assumed: the mutation harness reported
        // exactly this line as NOT CAUGHT while the integration test above it —
        // which does pass `NPM.CMD` and `thing.Bat` — stayed green.
        //
        // Deleting it is not harmless on the platform where it is the only copy.
        // A name whose case normalisation left alone would stop reading as the
        // batch file Windows starts an interpreter for, and start reading as a
        // program nobody has heard of. Both answers are every category but
        // `Static`, so nothing downstream could tell the two apart; what changes
        // is the reason SURE reports, which is the whole of what the doc comment
        // above argues this function exists for.
        for name in [
            "npm.cmd",
            "NPM.CMD",
            "Npm.Cmd",
            "build.bat",
            "BUILD.BAT",
            "Build.Bat",
        ] {
            assert!(is_batch_file(name), "{name} is a batch-file name");
        }
    }

    #[test]
    fn an_operation_belonging_to_one_program_is_not_read_for_another() {
        // The table is per program. `clean` is an operation git has and npm does
        // not, and if the rows were shared — or if a verb were looked up across
        // the whole table — `npm clean` would inherit git's answer.
        //
        // What npm gets instead is `anything()`, and that is not the same as
        // git's answer even though both mention destruction: git's is the one
        // category, exactly, and npm's is every category because SURE did not
        // read the operation. The third assertion is the one that would catch a
        // lookup that fell through to the wrong row.
        let git = classify("git", ["clean"]);
        let npm = classify("npm", ["clean"]);
        assert_eq!(npm.source(), Source::UnknownOperation);
        assert_eq!(git.effects(), &CommandEffects::of(DESTROYS));
        assert_ne!(npm.effects(), git.effects());
        assert_eq!(npm.effects(), &CommandEffects::anything());
    }

    #[test]
    fn a_program_named_twice_in_the_table_is_named_once() {
        // Two rows answering to one name would make the second unreachable.
        let mut seen: Vec<&str> = Vec::new();
        for entry in ENTRY_TABLE {
            for name in entry.names {
                assert!(!seen.contains(name), "{name} is filed under two rows");
                seen.push(name);
            }
        }
    }

    #[test]
    fn every_name_a_row_answers_to_answers_the_same_way_as_its_first() {
        // `py` and `python` are one row, and that is only true if every
        // spelling reaches it. A row that listed a name the lookup normalises
        // differently would show up here.
        for entry in ENTRY_TABLE {
            let subject = entry.verbs.first().map(|verb| verb.names[0]);
            for name in entry.names {
                let (first, other) = match subject {
                    Some(verb) => (classify(entry.names[0], [verb]), classify(*name, [verb])),
                    None => (
                        classify(entry.names[0], Vec::<String>::new()),
                        classify(*name, Vec::<String>::new()),
                    ),
                };
                assert_eq!(first, other, "{name} does not answer as {}", entry.names[0]);
            }
        }
    }

    #[test]
    fn a_line_with_one_reading_is_read_as_its_words() {
        let cases = [
            ("rm -rf build/", vec!["rm", "-rf", "build/"]),
            (
                "git push --force origin main",
                vec!["git", "push", "--force", "origin", "main"],
            ),
            ("npm   test", vec!["npm", "test"]),
            // A separator SURE reads past rather than interpreting: `--` ends
            // the flags, and to this reading it is a word like any other.
            ("rm -rf -- build", vec!["rm", "-rf", "--", "build"]),
            // Unicode survives, because a project path may be one.
            ("rm -rf Ünïcödé", vec!["rm", "-rf", "Ünïcödé"]),
            // Characters that name a whole location are kept: the reading a
            // caller makes of a word is the cautious one.
            ("rm -rf *", vec!["rm", "-rf", "*"]),
            ("rm -rf ~", vec!["rm", "-rf", "~"]),
            ("del *.*", vec!["del", "*.*"]),
        ];
        for (line, expected) in cases {
            assert_eq!(
                read_simple_command(line),
                Some(
                    expected
                        .iter()
                        .map(|word| (*word).to_owned())
                        .collect::<Vec<_>>()
                ),
                "{line:?}"
            );
        }
    }

    #[test]
    fn a_line_a_shell_would_read_first_is_not_read_at_all() {
        // One character per case, and each of them means something other than
        // itself to a shell. The answer is `None` and not a guess: a caller
        // that cannot read the line cannot say anything about it, which is the
        // state SURE was in before this function existed.
        let cases = [
            "rm -rf \"my dir\"",
            "rm -rf 'my dir'",
            "rm -rf my\\ dir",
            "rm -rf $HOME",
            "rm -rf `pwd`",
            "cargo test && rm -rf .",
            "cargo test; rm -rf .",
            "cargo test | tee out",
            "cat secrets > out",
            "cat < in",
            "echo (x)",
            "echo {a,b}",
            "echo !history",
            "echo x # comment",
            "echo %PATH%",
            "echo ^x",
            "echo a\nrm -rf .",
            "echo a\rrm -rf .",
            "echo \u{0}",
        ];
        for line in cases {
            assert_eq!(read_simple_command(line), None, "{line:?} was read");
        }
    }

    #[test]
    fn a_line_holding_no_words_is_not_a_command() {
        for line in ["", "   ", "\t", "  \t  "] {
            assert_eq!(read_simple_command(line), None, "{line:?}");
        }
    }
}
