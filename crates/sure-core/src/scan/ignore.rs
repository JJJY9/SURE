//! The names that are not project content.
//!
//! Two tables, in one place, so that what SURE declines to look at is a list
//! somebody can read and disagree with rather than a rule spread through the
//! walker.
//!
//! # Why files and directories are separate tables
//!
//! `build` is a directory full of compiled output, and `build` is also a shell
//! script at the root of a great many projects — one a person wrote, typed by
//! hand, and would be right to expect SURE to read. The same is true of `target`
//! and `dist`. A single table keyed on the name alone cannot tell those apart,
//! and the version that cannot tell them apart loses a file that is genuinely
//! part of the project.
//!
//! So a rule says which kind of entry it is about, and the two tables are
//! separate because that is the honest shape of the knowledge: *this name is
//! never a directory a project keeps its work in* and *this name is never a file
//! a project keeps its work in* are two different claims, each true of a
//! different set of names.
//!
//! # Why matching is by exact name and not by pattern
//!
//! A glob language — `**/target/**`, `*.pyc` — is more expressive and much
//! harder to be sure about. The question these tables answer is narrow ("is this
//! name always something a tool produced rather than something a person wrote
//! for this project?"), and a name that cannot answer it plainly does not belong
//! in a table. Patterns arrive when something needs them.
//!
//! # What is deliberately not in either table
//!
//! `bin`, `obj`, `out`, `Debug`, `Release` and `third_party` are all output or
//! vendor directory names for some toolchain, and all of them are ordinary
//! directory names too — `bin/` holds hand-written scripts in a great many Node
//! and Python projects, and `third_party/` is usually vendored source that the
//! project is answerable for. Leaving a real directory out of a scan is a
//! **loss**, so a name that could plausibly be project content stays out of the
//! tables and in the scan. `dist`, `build` and `target` are in the directory
//! table because a project that keeps its own source in `build/` is rare enough
//! that being told "SURE did not look inside build/" is a better failure than
//! silently reading a stale output tree.
//!
//! # Case
//!
//! A name is compared under the platform's case rule, and [`matching_rule`]
//! takes that rule as an argument so both can be tested on one machine. On
//! Windows there is no `NODE_MODULES` distinct from `node_modules`, so it is the
//! same directory and the same answer. On Linux there is, and a directory called
//! `NODE_MODULES` there is a directory the project made.

use std::path::Path;

use crate::paths::CaseSensitivity;

use super::{EntryKind, SkipReason};

/// One name that is not project content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IgnoreRule {
    /// The exact name, compared under the platform's case rule.
    pub name: &'static str,
    /// Why anything with this name is not project content.
    pub reason: SkipReason,
}

/// Names that are never a directory a project keeps its own work in.
///
/// Ordering is by reason and then roughly by how common the name is, so that a
/// person reading the source sees the groups the report groups by. Nothing
/// depends on the order apart from ties, and [`no_two_rules_share_a_name`]
/// shows there are none.
///
/// [`no_two_rules_share_a_name`]: self#tests
pub const IGNORED_DIRECTORIES: &[IgnoreRule] = &[
    // Version control. The repository SURE is checking may itself be a
    // checkout inside another one, so the name is matched at any depth and not
    // only at the root.
    IgnoreRule {
        name: ".git",
        reason: SkipReason::VersionControl,
    },
    IgnoreRule {
        name: ".hg",
        reason: SkipReason::VersionControl,
    },
    IgnoreRule {
        name: ".svn",
        reason: SkipReason::VersionControl,
    },
    IgnoreRule {
        name: ".bzr",
        reason: SkipReason::VersionControl,
    },
    IgnoreRule {
        name: ".jj",
        reason: SkipReason::VersionControl,
    },
    // Installed code. Each name belongs to one ecosystem's installer, and a
    // project using none of them never has a directory with any of these names.
    IgnoreRule {
        name: "node_modules",
        reason: SkipReason::Vendored,
    },
    IgnoreRule {
        name: "bower_components",
        reason: SkipReason::Vendored,
    },
    IgnoreRule {
        name: "vendor",
        reason: SkipReason::Vendored,
    },
    IgnoreRule {
        name: ".venv",
        reason: SkipReason::Vendored,
    },
    IgnoreRule {
        name: "venv",
        reason: SkipReason::Vendored,
    },
    IgnoreRule {
        name: "virtualenv",
        reason: SkipReason::Vendored,
    },
    // `.tox`, `.nox` and `.eggs` are the same claim as `venv`: a tool made the
    // directory, it holds installed distributions rather than a person's work,
    // and it is rebuilt by running the tool again. `.tox` and `.nox` are what
    // `tox` and `nox` build their per-environment virtualenvs in, and `.eggs` is
    // `setuptools`' own installation directory.
    //
    // `*.egg-info` is the name that belongs here and cannot be: it is a *suffix*
    // — `foo.egg-info` is one distribution's metadata — and this table matches
    // exact names only, deliberately (see the module comment). Adding a pattern
    // language to catch it would make every rule in both tables harder to be
    // sure about, so it is recorded as a gap in
    // `docs/architecture/ECOSYSTEM_DISCOVERY.md` instead.
    IgnoreRule {
        name: ".tox",
        reason: SkipReason::Vendored,
    },
    IgnoreRule {
        name: ".nox",
        reason: SkipReason::Vendored,
    },
    IgnoreRule {
        name: ".eggs",
        reason: SkipReason::Vendored,
    },
    IgnoreRule {
        name: ".bundle",
        reason: SkipReason::Vendored,
    },
    IgnoreRule {
        name: "Pods",
        reason: SkipReason::Vendored,
    },
    // Build output.
    IgnoreRule {
        name: "target",
        reason: SkipReason::BuildOutput,
    },
    IgnoreRule {
        name: "dist",
        reason: SkipReason::BuildOutput,
    },
    IgnoreRule {
        name: "build",
        reason: SkipReason::BuildOutput,
    },
    IgnoreRule {
        name: ".next",
        reason: SkipReason::BuildOutput,
    },
    IgnoreRule {
        name: ".nuxt",
        reason: SkipReason::BuildOutput,
    },
    IgnoreRule {
        name: ".svelte-kit",
        reason: SkipReason::BuildOutput,
    },
    IgnoreRule {
        name: ".output",
        reason: SkipReason::BuildOutput,
    },
    // CloudBase/CloudBase-style toolchains stage the admin console they generate
    // under `.tmp/` (`cloudcenter-*.js` here, minified webpack output). Measured
    // 2026-11-11 on the `app` mini-program: every remaining route finding and a
    // 26 MB report came from reads inside this tree — machine-written bundles,
    // not the project's source. The name is the tool's own dotted directory,
    // rebuilt by running the tool again.
    IgnoreRule {
        name: ".tmp",
        reason: SkipReason::BuildOutput,
    },
    // A tool's run output. `Dream-RSI/open-dream-rsi` keeps every agent run
    // under `.runtime/runs/<id>/`, including the HTML and JS each run renders;
    // measured 2026-11-03, 115 of that project's 122 findings were anchors
    // inside this tree, every one of them a page the tool generated. The name
    // is the tool's own (a dotted directory), not one a project gives its
    // source, and the whole subtree is rebuilt by running the tool again.
    IgnoreRule {
        name: ".runtime",
        reason: SkipReason::BuildOutput,
    },
    IgnoreRule {
        name: "DerivedData",
        reason: SkipReason::BuildOutput,
    },
    // Caches.
    IgnoreRule {
        name: "__pycache__",
        reason: SkipReason::Cache,
    },
    IgnoreRule {
        name: ".pytest_cache",
        reason: SkipReason::Cache,
    },
    IgnoreRule {
        name: ".mypy_cache",
        reason: SkipReason::Cache,
    },
    IgnoreRule {
        name: ".ruff_cache",
        reason: SkipReason::Cache,
    },
    IgnoreRule {
        name: ".gradle",
        reason: SkipReason::Cache,
    },
    IgnoreRule {
        name: ".cache",
        reason: SkipReason::Cache,
    },
    IgnoreRule {
        name: "coverage",
        reason: SkipReason::Cache,
    },
    IgnoreRule {
        name: "htmlcov",
        reason: SkipReason::Cache,
    },
    IgnoreRule {
        name: ".nyc_output",
        reason: SkipReason::Cache,
    },
    // SURE's own cache, in the table for a reason none of the others have: see
    // [`SkipReason::SureCache`].
    IgnoreRule {
        name: crate::paths::PROJECT_CACHE_DIR,
        reason: SkipReason::SureCache,
    },
];

/// Names that are never a file a project keeps its own work in.
///
/// Short on purpose. A file is a thing a person may have written and named by
/// hand, so a name only qualifies if some *other* program is known to create it
/// without being asked.
pub const IGNORED_FILES: &[IgnoreRule] = &[
    // A `.git` file rather than a directory appears in a submodule and in a
    // linked worktree: it holds the path of the real repository. It is version
    // control's, not the project's.
    IgnoreRule {
        name: ".git",
        reason: SkipReason::VersionControl,
    },
    // The operating system's own droppings — the Finder's, Explorer's, and the
    // Windows thumbnail cache's. They are here so that one developer's machine
    // does not change what a project looks like to everybody else, which is
    // what a fingerprint has to be stable against.
    IgnoreRule {
        name: ".DS_Store",
        reason: SkipReason::Cache,
    },
    IgnoreRule {
        name: "Thumbs.db",
        reason: SkipReason::Cache,
    },
    IgnoreRule {
        name: "desktop.ini",
        reason: SkipReason::Cache,
    },
];

/// The table that applies to entries of this kind.
#[must_use]
pub const fn table_for(kind: EntryKind) -> &'static [IgnoreRule] {
    match kind {
        EntryKind::Directory => IGNORED_DIRECTORIES,
        EntryKind::File => IGNORED_FILES,
    }
}

/// The rule that applies to `name` when it is an entry of kind `kind`.
///
/// Links are not asked about. [`SkipReason::NotFollowed`] is the truthful
/// reason a link is not in the scan whatever it is called, and answering
/// "vendored" for a link named `node_modules` would describe a decision that
/// was not the one made.
#[must_use]
pub fn matching_rule(
    name: &str,
    kind: EntryKind,
    case: CaseSensitivity,
) -> Option<&'static IgnoreRule> {
    table_for(kind)
        .iter()
        .find(|rule| name_matches(rule.name, name, case))
}

/// The rule that leaves a whole path out, for a path from somewhere other than
/// the walk.
///
/// The walk applies a table to each name as it meets it, so a rule matching a
/// component leaves out everything below: it never lists `target/`, so it never
/// reaches `target/debug/app`. This answers the same question about a path that
/// arrived whole — from `git status`, which names files rather than walking to
/// them — and it answers it with the same tables and the same comparison, so a
/// file the walk would not have looked at is a file this says was left out.
///
/// Every component but the last is a directory by construction. The last is
/// whatever `kind` says, and the caller is the one that knows: the walk learns
/// it from the directory entry, and the fingerprint learns it from Git's mode
/// fields or from the filesystem. That distinction is why there are two tables
/// in the first place — see the module comment.
#[must_use]
pub fn left_out(
    path: &Path,
    kind: EntryKind,
    case: CaseSensitivity,
) -> Option<&'static IgnoreRule> {
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        let last = components.peek().is_none();
        let kind = if last { kind } else { EntryKind::Directory };
        // `.` and `..` are components of a path but not names of anything, and
        // no rule is spelled either way — `no_rule_is_empty_or_a_path` holds
        // that — so neither can match here.
        let rule = matching_rule(&component.as_os_str().to_string_lossy(), kind, case);
        if rule.is_some() {
            return rule;
        }
    }
    None
}

/// Whether an ignore rule's name matches a real directory entry's name.
///
/// Written out rather than using [`crate::paths::same_path_case`] because these
/// are single names and not paths: that function normalises components, folds
/// `..`, and reduces prefixes, all of which is right for a location and wrong
/// for a name. A file may legitimately be called `..`-something, and the two
/// must not be answered by the same code path.
#[must_use]
fn name_matches(rule: &str, name: &str, case: CaseSensitivity) -> bool {
    match case {
        CaseSensitivity::Sensitive => rule == name,
        CaseSensitivity::Insensitive => {
            if rule == name {
                return true;
            }
            // Only ASCII is folded. Every name in both tables is ASCII, so a
            // name that is not cannot become one by being folded — and the
            // Unicode folding rules are locale-dependent in a way that would
            // make the answer depend on the machine.
            rule.eq_ignore_ascii_case(name)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const INSENSITIVE: CaseSensitivity = CaseSensitivity::Insensitive;
    const SENSITIVE: CaseSensitivity = CaseSensitivity::Sensitive;
    const DIR: EntryKind = EntryKind::Directory;
    const FILE: EntryKind = EntryKind::File;

    #[test]
    fn every_reason_a_declared_ignore_can_have_has_at_least_one_rule() {
        // If a category had no rules, "ignores VCS/vendor/build/cache
        // appropriately" could be satisfied by naming a category that can never
        // occur.
        for reason in [
            SkipReason::VersionControl,
            SkipReason::Vendored,
            SkipReason::BuildOutput,
            SkipReason::Cache,
            SkipReason::SureCache,
        ] {
            assert!(
                IGNORED_DIRECTORIES.iter().any(|rule| rule.reason == reason),
                "no rule produces {reason:?}"
            );
        }
    }

    #[test]
    fn no_rule_carries_a_reason_that_is_a_loss() {
        // A name in a table means "this is never project content". A loss
        // reason means "something might have been missed". Putting one in a
        // table would silently reclassify a loss as declared scope.
        for rule in IGNORED_DIRECTORIES.iter().chain(IGNORED_FILES) {
            assert!(
                rule.reason.is_by_design(),
                "{} is in an ignore table with the loss reason {:?}",
                rule.name,
                rule.reason
            );
        }
    }

    #[test]
    fn no_two_rules_share_a_name_within_a_table() {
        // Otherwise which rule applies depends on table order, and a re-order
        // would change what SURE looks at.
        for table in [IGNORED_DIRECTORIES, IGNORED_FILES] {
            let mut names: Vec<&str> = table.iter().map(|rule| rule.name).collect();
            names.sort_unstable();
            let count = names.len();
            names.dedup();
            assert_eq!(
                names.len(),
                count,
                "two ignore rules in one table share a name"
            );
        }
    }

    #[test]
    fn no_rule_is_empty_or_a_path() {
        for rule in IGNORED_DIRECTORIES.iter().chain(IGNORED_FILES) {
            assert!(!rule.name.is_empty(), "a rule has an empty name");
            assert!(
                !rule.name.contains('/') && !rule.name.contains('\\'),
                "{} is a path, not a name — it could never match one directory entry",
                rule.name
            );
            assert!(
                rule.name != "." && rule.name != "..",
                "{} is a directory reference, not a name",
                rule.name
            );
        }
    }

    #[test]
    fn a_known_directory_name_matches() {
        let cases = [
            (".git", SkipReason::VersionControl),
            ("node_modules", SkipReason::Vendored),
            ("target", SkipReason::BuildOutput),
            ("__pycache__", SkipReason::Cache),
            // The Python environments and caches, which are the names a Python
            // project is most likely to have a directory of. Asserted by name
            // rather than left to the table's own iteration, because a rule that
            // was removed from the table would otherwise remove its own test.
            (".venv", SkipReason::Vendored),
            ("venv", SkipReason::Vendored),
            (".tox", SkipReason::Vendored),
            (".nox", SkipReason::Vendored),
            (".eggs", SkipReason::Vendored),
            (".pytest_cache", SkipReason::Cache),
            (".mypy_cache", SkipReason::Cache),
            // The tool's own run output (measured on Dream-RSI/open-dream-rsi,
            // 2026-11-03: most of its findings came from `.runtime/runs/**`).
            (".runtime", SkipReason::BuildOutput),
        ];
        for (name, reason) in cases {
            assert_eq!(
                matching_rule(name, DIR, INSENSITIVE).map(|rule| rule.reason),
                Some(reason),
                "{name}"
            );
        }
    }

    #[test]
    fn sure_own_cache_is_recognised_from_the_constant_that_names_it() {
        // Reached through the constant rather than by spelling `.sure` twice,
        // so the directory SURE writes into and the directory SURE skips
        // cannot drift apart.
        assert_eq!(
            matching_rule(crate::paths::PROJECT_CACHE_DIR, DIR, INSENSITIVE)
                .expect(".sure is in the table")
                .reason,
            SkipReason::SureCache
        );
    }

    #[test]
    fn a_name_that_is_both_a_tool_output_and_a_script_is_only_ignored_as_a_directory() {
        // The reason the tables are split. `build` at the root is a directory
        // of compiled output *and* a script somebody wrote by hand; skipping
        // the script would lose a file that is part of the project.
        for name in ["build", "target", "dist", "coverage", "vendor"] {
            assert!(
                matching_rule(name, DIR, INSENSITIVE).is_some(),
                "{name} must be left out as a directory"
            );
            assert!(
                matching_rule(name, FILE, INSENSITIVE).is_none(),
                "{name} must stay in the scan as a file — a person may have written it"
            );
        }
    }

    #[test]
    fn the_operating_systems_own_files_are_left_out_as_files() {
        for name in [".DS_Store", "Thumbs.db", "desktop.ini"] {
            assert_eq!(
                matching_rule(name, FILE, INSENSITIVE).map(|rule| rule.reason),
                Some(SkipReason::Cache),
                "{name}"
            );
        }
    }

    #[test]
    fn a_git_file_is_left_out_because_a_submodule_writes_one() {
        // A `.git` *file* is not a directory and is not a project file either:
        // it holds the path of the repository a submodule or linked worktree
        // belongs to.
        assert_eq!(
            matching_rule(".git", FILE, INSENSITIVE).map(|rule| rule.reason),
            Some(SkipReason::VersionControl)
        );
    }

    #[test]
    fn an_ordinary_name_does_not_match() {
        for name in [
            "src",
            "tests",
            "docs",
            "bin",
            "obj",
            "out",
            "third_party",
            "site",
            "packages",
            "lib",
            "assets",
            "scripts",
            "data",
        ] {
            for kind in [DIR, FILE] {
                assert!(
                    matching_rule(name, kind, INSENSITIVE).is_none(),
                    "{name} as {kind:?} must stay in the scan"
                );
            }
        }
    }

    #[test]
    fn a_near_miss_name_does_not_match() {
        // `node_modules_backup` is a directory the project made.
        for name in [
            "node_modules_backup",
            "my_node_modules",
            ".github",
            ".gitignore",
            ".gitattributes",
            "targets",
            "dist-old",
            "builder",
            // A plain `runtime/` is a directory a project may have written
            // itself; only the tool's dotted `.runtime` is its output.
            "runtime",
            "Cargo.toml",
            "build.rs",
        ] {
            for kind in [DIR, FILE] {
                assert!(
                    matching_rule(name, kind, INSENSITIVE).is_none(),
                    "{name} as {kind:?} matched"
                );
            }
        }
    }

    #[test]
    fn case_is_folded_only_where_the_platform_folds_it() {
        assert_eq!(
            matching_rule("NODE_MODULES", DIR, INSENSITIVE)
                .unwrap()
                .reason,
            SkipReason::Vendored
        );
        // On Windows these are the same directory; on Linux they are not, and
        // the Linux one is a directory the project made.
        assert!(matching_rule("NODE_MODULES", DIR, SENSITIVE).is_none());
        assert_eq!(
            matching_rule("node_modules", DIR, SENSITIVE)
                .unwrap()
                .reason,
            SkipReason::Vendored
        );
    }

    #[test]
    fn case_folding_does_not_reach_a_name_that_is_not_ascii() {
        // `İ` lowercases to two code points in some locales and one in others.
        // Every name in both tables is ASCII, so the only safe fold is the
        // ASCII one, and a name that is not ASCII is never a tool's directory.
        for name in [
            "Ｔarget",
            "Ｎode_modules",
            "venv\u{0130}",
            "DEskTOP.INI\u{0307}",
        ] {
            for kind in [DIR, FILE] {
                assert!(matching_rule(name, kind, INSENSITIVE).is_none(), "{name}");
            }
        }
    }

    #[test]
    fn the_fold_is_ascii_rather_than_the_one_unicode_defines() {
        // The test above cannot tell the two folds apart, and the reason is
        // worth knowing: no name in either table contains a letter that has a
        // non-ASCII character lowercasing to it. The kelvin sign is the only
        // Latin letter that does — `K` (U+212A) lowercases to `k` — and no rule
        // in these tables contains a `k`.
        //
        // So this test names the rule rather than looking it up. `name_matches`
        // is called with a rule that does contain one `k`, which is the only way
        // to see the difference; a test that went through `matching_rule` would
        // be testing these tables and not the fold.
        //
        // It matters because the moment somebody adds a rule for a cache named
        // `kotlin-build`, the ASCII restriction stops being a formality.
        let kelvin = "\u{212a}otlin-build";
        assert!(
            !name_matches("kotlin-build", kelvin, INSENSITIVE),
            "the kelvin sign folded to an ASCII k"
        );
        // And it is a fold and not a refusal to fold at all: the real spelling
        // still matches, and so does the ASCII spelling in another case.
        assert!(name_matches("kotlin-build", "kotlin-build", INSENSITIVE));
        assert!(name_matches("kotlin-build", "KOTLIN-BUILD", INSENSITIVE));
    }

    #[test]
    fn a_path_is_left_out_by_a_name_anywhere_in_it() {
        // The walk applies the tables as it descends, so it never reaches a
        // file under a directory it declined. This answers the same question
        // about a path that arrived whole, which is how the fingerprint sees
        // one.
        let cases = [
            ("target/debug/app", SkipReason::BuildOutput),
            (
                "packages/app/node_modules/left-pad/index.js",
                SkipReason::Vendored,
            ),
            (".sure/evidence/current.json", SkipReason::SureCache),
            ("src/__pycache__/mod.pyc", SkipReason::Cache),
        ];
        for (path, reason) in cases {
            assert_eq!(
                left_out(Path::new(path), FILE, INSENSITIVE).map(|rule| rule.reason),
                Some(reason),
                "{path}"
            );
        }
    }

    #[test]
    fn a_path_is_not_left_out_for_a_name_that_only_counts_as_a_directory() {
        // The tables are two, and applying the wrong one is how a hand-written
        // script called `build` gets dropped from a fingerprint. Every
        // component but the last is a directory; the last is what the caller
        // says it is.
        for name in ["build", "target", "dist", "vendor", "coverage"] {
            assert!(
                left_out(Path::new(name), FILE, INSENSITIVE).is_none(),
                "{name} as a file was left out"
            );
            assert!(
                left_out(Path::new(name), DIR, INSENSITIVE).is_some(),
                "{name} as a directory was kept"
            );
            // And as a component of something below it, it is a directory
            // however the caller describes what is at the end.
            assert!(
                left_out(Path::new(&format!("{name}/app.js")), FILE, INSENSITIVE).is_some(),
                "{name}/app.js was kept"
            );
        }
    }

    #[test]
    fn an_ordinary_path_is_kept_whole() {
        for path in [
            "src/main.rs",
            "packages/app/src/index.ts",
            "docs/architecture/RUST_DESIGN.md",
            "third_party/vendored.c",
        ] {
            assert!(
                left_out(Path::new(path), FILE, INSENSITIVE).is_none(),
                "{path} was left out"
            );
            assert!(
                left_out(Path::new(path), DIR, INSENSITIVE).is_none(),
                "{path} as a directory was left out"
            );
        }
    }

    #[test]
    fn the_case_rule_reaches_every_component_and_not_only_the_first() {
        // The rule is the platform's and applies at every level, so a path
        // through `NODE_MODULES` is the same question as one through
        // `node_modules` on the platforms where those are one directory.
        assert_eq!(
            left_out(
                Path::new("src/NODE_MODULES/pkg/index.js"),
                FILE,
                INSENSITIVE
            )
            .map(|rule| rule.reason),
            Some(SkipReason::Vendored)
        );
        assert!(
            left_out(Path::new("src/NODE_MODULES/pkg/index.js"), FILE, SENSITIVE).is_none(),
            "a case-sensitive platform must not fold this"
        );
    }

    #[test]
    fn a_path_that_climbs_out_of_itself_is_answered_rather_than_panicked_over() {
        // Not a path the walk can produce — its paths are built by joining one
        // name onto a path that is already inside. Git's are not, so this
        // function can be handed one, and a `..` component has to be a name
        // that matches nothing rather than a name that resolves to something.
        assert!(left_out(Path::new("../secrets/key.pem"), FILE, INSENSITIVE).is_none());
        assert!(left_out(Path::new("src/../src/main.rs"), FILE, INSENSITIVE).is_none());
        assert!(left_out(Path::new("./src/main.rs"), FILE, INSENSITIVE).is_none());
    }

    #[test]
    fn every_rule_is_reachable_by_its_own_name() {
        // Cross-check against a shadowed rule: comparing the reason alone would
        // not catch a duplicate name pointing at the same category, and the
        // whole rule does. The lookup is a linear scan today; a caller that
        // replaces it with an index has to keep this true.
        for (table, kind) in [(IGNORED_DIRECTORIES, DIR), (IGNORED_FILES, FILE)] {
            for rule in table {
                let found = matching_rule(rule.name, kind, INSENSITIVE)
                    .unwrap_or_else(|| panic!("{} does not resolve", rule.name));
                assert_eq!(found, rule, "{} resolves to a different rule", rule.name);
            }
        }
    }
}
