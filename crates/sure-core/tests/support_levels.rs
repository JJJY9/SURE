//! Support-level classification end to end, from the outside.
//!
//! `crate::support`'s own tests hold the rule's parts — the ordering, the fold,
//! the ceiling, the list. This file drives the whole thing through the public
//! API over real directories, which is where the parts have to add up to a
//! sentence a person can read and check.
//!
//! # What this file observes today
//!
//! `sure_core::support::CEILING` is [`SupportLevel::Generic`] since ADR 0017
//! (2026-10-23). A project discovery grades `generic` is reported at B with the
//! reason below; a project discovery grades `inspect_only` stays C because the
//! discovery, not the ceiling, set it. The tests assert the level *and* the
//! reason, so a reworded sentence or a moved ceiling fails here rather than
//! reaching a person unreviewed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use sure_core::discover::{DiscoverOptions, Discovery, discover};
use sure_core::support::{CEILING, classify};
use sure_core::vocabulary::{ProjectSupport, SupportLevel};

/// A directory under the workspace's git-ignored `target/tmp`.
///
/// The claiming rules live in `sure_testkit::scratch`, and the history that put
/// them there is this repository's: clearing a fixed path with
/// `let _ = remove_dir_all(..)` and then treating it as fresh fails on Windows,
/// and the test then describes a directory that was never emptied. So nothing
/// here is adopted — a directory is taken with `create_dir`, which fails when
/// the name is taken, and one that is already there is skipped rather than
/// entered — and the helper clears only directories carrying *its own*
/// process's id, which no live process can own.
struct Fixture {
    project: PathBuf,
}

impl Fixture {
    fn new(test: &str) -> Self {
        Self {
            project: sure_testkit::scratch::directory("support levels", test),
        }
    }

    fn write(&self, relative: &str, contents: &str) -> &Self {
        let full = self.project.join(relative);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
        }
        std::fs::write(&full, contents)
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", full.display()));
        self
    }

    fn discovery(&self) -> Discovery {
        discover(&self.project, &DiscoverOptions::default()).expect("discover")
    }
}

/// The level a project is classified at, with the reason it gives.
///
/// Every assertion in this file goes through here so that a test cannot look at
/// a level without also having the sentence that is supposed to justify it —
/// which is the failure mode `ProjectSupport`'s two fields exist to prevent.
fn classification(discovery: &Discovery) -> (SupportLevel, String) {
    let support: ProjectSupport = classify(discovery);
    assert!(
        support.is_recorded(),
        "classify must return an answer, not `unrecorded`: {}",
        support.reason
    );
    let level = support.level;
    assert!(
        support.reason.contains(level.as_str()),
        "the reason must name the level it is the reason for, and `{}` does not mention `{}`",
        support.reason,
        level.as_str()
    );
    (level, support.reason)
}

#[test]
fn a_project_sure_can_read_is_classified_generic_and_says_why() {
    let fixture = Fixture::new("rust-only");
    fixture.write(
        "Cargo.toml",
        "[package]\nname = \"shop\"\nversion = \"0.1.0\"\n",
    );
    let (level, reason) = classification(&fixture.discovery());

    assert_eq!(level, SupportLevel::Generic);
    assert_eq!(
        level, CEILING,
        "no project may be classified above the ceiling"
    );
    // The whole sentence, pinned. It is the one a user reads, it has to do three
    // things at once — name what was read and what it was graded, say what the
    // level means including the consent and startability caveats, and give the
    // answer — and a reworded one is meant to fail here rather than reach a
    // person unreviewed.
    assert_eq!(
        reason,
        "SURE read one stack here, rust, and graded it generic (B). So the project is at level B \
         (generic). SURE can find how this project is built and run when you allow it, and can run \
         approved generic checks, but does not understand everything about it. A check whose \
         command cannot be started is reported as not checked, not passed."
    );
}

#[test]
fn a_directory_sure_read_nothing_in_is_classified_inspect_only_without_claiming_it_is_empty() {
    let fixture = Fixture::new("empty");
    let (level, reason) = classification(&fixture.discovery());

    assert_eq!(level, SupportLevel::InspectOnly);
    // The two things this sentence has to carry: something was *looked for*,
    // named, so a reader can tell *looked and found none* from *did not look*;
    // and the walk saw the whole project, so "found nothing" is not a claim
    // about ground it never covered. (A walk that missed part of the project
    // adds a clause here — see `nothing_was_found`.)
    assert_eq!(
        reason,
        "SURE looked for JavaScript or TypeScript, Python, Rust, Go, .NET and Java here and \
         found nothing it reads. So the project is at level C (inspect_only). SURE can look at \
         this project's files, but cannot safely run it."
    );
}

#[test]
fn the_stack_that_sets_the_level_is_the_one_named() {
    // Node has a readable manifest, which discovery grades `generic`. Python
    // has only a `requirements.txt`, which it grades `inspect_only`. The
    // project's reading is therefore the weaker one, and the reason must name
    // python — the stack that set it — rather than the project's stacks.
    let fixture = Fixture::new("mixed");
    fixture
        .write("package.json", r#"{"name":"shop"}"#)
        .write("requirements.txt", "flask==3.0.0\n");
    let (level, reason) = classification(&fixture.discovery());

    assert_eq!(level, SupportLevel::InspectOnly);
    assert_eq!(
        reason,
        "SURE read 2 stacks here and graded the weakest of them — python — inspect_only (C). \
         So the project is at level C (inspect_only). SURE can look at this project's files, \
         but cannot safely run it."
    );
    assert!(
        !reason.contains("node"),
        "node was graded higher, so naming it here would point a reader at the wrong file: \
         {reason}"
    );
}

#[test]
fn a_project_whose_stacks_agree_is_described_as_having_graded_all_of_them() {
    // Two ecosystems, both with a readable manifest, so both are graded
    // `generic` and there is no weakest one to single out. This is the arm of
    // `what_was_read` that says *all of them*, and it is tested because the
    // other two arms name a **subset** — a version that named only the stacks
    // below the reading, or only the first of them, would read as though the
    // rest had been graded differently.
    let fixture = Fixture::new("both-generic");
    fixture.write("package.json", r#"{"name":"shop"}"#).write(
        "Cargo.toml",
        "[package]\nname = \"shop\"\nversion = \"0.1.0\"\n",
    );
    let (level, reason) = classification(&fixture.discovery());

    assert_eq!(level, SupportLevel::Generic);
    assert_eq!(
        reason,
        "SURE read 2 stacks here — node and rust — and graded all of them generic (B). So the \
         project is at level B (generic). SURE can find how this project is built and run when you \
         allow it, and can run approved generic checks, but does not understand everything about \
         it. A check whose command cannot be started is reported as not checked, not passed."
    );
}

#[test]
fn a_project_with_no_readable_manifest_is_not_reported_as_if_it_had_one() {
    // A lockfile is evidence that this is a Rust project and is not a
    // declaration of how it is built. Discovery already grades this
    // `inspect_only`; what is checked here is that the project-level answer
    // does not quietly become `generic` on the way through.
    let fixture = Fixture::new("lockfile-only");
    fixture.write("Cargo.lock", "version = 4\n");
    let (level, reason) = classification(&fixture.discovery());

    assert_eq!(level, SupportLevel::InspectOnly);
    assert_eq!(
        reason,
        "SURE read one stack here, rust, and graded it inspect_only (C). So the project is at \
         level C (inspect_only). SURE can look at this project's files, but cannot safely run it."
    );
    assert!(
        !reason.contains("would be level"),
        "nothing was capped here, so the reason must not talk about a ceiling that did not \
         apply: {reason}"
    );
}

#[test]
fn a_classification_survives_the_project_being_deleted() {
    // `classify` takes a `Discovery`, not a path: it is a view over what was
    // read and opens nothing. Deleting the project between the two calls is how
    // that stops being a claim in a comment — and it is not a hypothetical, a
    // report is routinely rendered after the directory has moved on.
    let fixture = Fixture::new("deleted");
    fixture.write(
        "Cargo.toml",
        "[package]\nname = \"shop\"\nversion = \"0.1.0\"\n",
    );
    let discovery = fixture.discovery();
    let before = classify(&discovery);

    std::fs::remove_dir_all(&fixture.project).expect("remove the fixture");

    assert_eq!(
        classify(&discovery),
        before,
        "the second classification differs, so it read something after all"
    );
}

#[test]
fn the_ceiling_is_a_level_a_report_can_explain() {
    // The constant is read by a report that has to tell a user why their project
    // is where it is. It is asserted here rather than left to the module comment
    // because a ceiling that is not a real level, or one with nothing to say for
    // itself, would be rendered as a bare word.
    assert!(
        SupportLevel::ALL.contains(&CEILING),
        "the ceiling must be one of the levels, not a value outside them"
    );
    assert!(
        !CEILING.plain_description().is_empty(),
        "the ceiling's level must have a sentence a user can read"
    );
}
