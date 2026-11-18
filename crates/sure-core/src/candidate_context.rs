//! Production-path/context filter for candidate scanner hits.
//!
//! `P6-T002`'s acceptance: Test/example/docs mocks are distinguished from likely
//! real user paths where possible.

use std::path::Path;

use crate::components::ComponentGraph;

/// Where a candidate pattern was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateContext {
    /// Found in a test file or test directory.
    Test,
    /// Found in an example file or example directory.
    Example,
    /// Found in documentation.
    Doc,
    /// Found in a mock, stub, or fixture file/directory.
    MockFixture,
    /// Found in likely production or product code.
    Product,
}

/// Classify a source file path by its likely role in the project.
///
/// Heuristics are conservative: a path is flagged as test/example/doc/mock only
/// when it is clearly in a conventional directory or has a conventional file
/// name. When uncertain, [`CandidateContext::Product`] is returned.
///
/// # Which separators this reads, and which it does not
///
/// **The argument is a `Path` SURE produced itself, not text that arrived from
/// outside the process.** Both call shapes in this crate are like that: the
/// candidate scanners hand over the entry [`Discovery`](crate::discover::Discovery)
/// walked, and the two detectors that classify a path they read out of a file
/// (`route_consistency`, `ui_action_bridge`) hand over text this crate rendered
/// with [`display_path`](crate::scan::display_path), which joins components with
/// `/` on every platform deliberately. So there is no ambiguity to resolve:
/// Windows treats `/` as a separator too, so a rendered path classifies the same
/// way on all three platforms, and a walked path cannot be read any way other
/// than the one the filesystem gave it.
///
/// **Text from a harness is the other case, and this function is deliberately
/// not where it is answered.** A harness may send either separator, and its
/// paths describe a machine that is not necessarily this one; `hook_protection`
/// states that rule and applies it (`folded`, which replaces `\` with `/` on
/// every platform) so that the reading happens once, at the boundary where the
/// text arrives. Folding here instead would be wrong in the other direction: on
/// Unix a backslash is an ordinary character in a file name, and a project with
/// a file genuinely called `tests\foo.rs` in its root would be classified as
/// living in a `tests/` directory that does not exist.
///
/// # What the answer costs a verdict
///
/// This classification becomes [`Reach`](crate::finding_gravity::Reach), and
/// `Reach` is the gate that decides the severity of every candidate found in the
/// file (`finding_gravity::gravity_of`): `NotProduction` returns `note` for every
/// gap kind, and `note` is what `is_informational` calls "too weak to show as
/// material". Reading a path the other way therefore moves a finding across the
/// line between two different sentences — an unfinished marker in a file read as
/// product is `non_blocking` and shown, and the same marker in a file read as a
/// test is `note` and not shown as material at all. That is the intended
/// direction (a mock in `tests/` must not become a claim about shipping code),
/// and it is also why a wrong answer here is not cosmetic in either direction:
/// it either invents a finding about test scaffolding or hides one about the
/// product.
///
/// `root` and `graph` are available for future component-aware heuristics;
/// the current implementation uses conventional directory and file-name patterns.
#[must_use]
pub fn classify_path(
    path: &Path,
    _root: &Path,
    _graph: Option<&ComponentGraph>,
) -> CandidateContext {
    // Check file name segments first (more specific than directory).
    if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
        for segment in file_name.split('.') {
            let lower = segment.to_lowercase();
            if lower == "test" || lower == "spec" || lower == "e2e" {
                return CandidateContext::Test;
            }
            if lower == "mock" || lower == "stub" {
                return CandidateContext::MockFixture;
            }
            // 前缀形式（`e2e-flow.js`、`mock_server.py`）：脚本目录里以
            // e2e/mock/stub + 分隔符命名的文件是测试工具链，不是生产代码。
            // 只认带 `-`/`_` 的前缀——`mockery.ts`、`e2early.ts` 这类普通
            // 单词不会被误判。
            if lower.starts_with("e2e-") || lower.starts_with("e2e_") {
                return CandidateContext::Test;
            }
            if lower.starts_with("mock-")
                || lower.starts_with("mock_")
                || lower.starts_with("stub-")
                || lower.starts_with("stub_")
            {
                return CandidateContext::MockFixture;
            }
        }
    }

    // Check each path component against conventional directory names.
    for component in path.components() {
        if let Some(name) = component.as_os_str().to_str() {
            let lower = name.to_lowercase();
            match lower.as_str() {
                "tests" | "test" | "__tests__" | "e2e" => return CandidateContext::Test,
                "examples" | "example" => return CandidateContext::Example,
                "docs" | "doc" => return CandidateContext::Doc,
                "fixtures" | "mocks" | "stubs" => return CandidateContext::MockFixture,
                _ => {}
            }
        }
    }

    CandidateContext::Product
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn classify(path: &str) -> CandidateContext {
        classify_path(Path::new(path), Path::new(""), None)
    }

    #[test]
    fn e2e_tooling_directories_and_names_are_test_context() {
        assert_eq!(classify("e2e/login.ts"), CandidateContext::Test);
        assert_eq!(classify("tests/e2e/login.ts"), CandidateContext::Test);
        assert_eq!(classify("scripts/e2e-flow.js"), CandidateContext::Test);
        assert_eq!(classify("scripts/e2e_reset.py"), CandidateContext::Test);
        assert_eq!(classify("app/login.e2e.ts"), CandidateContext::Test);
    }

    #[test]
    fn mock_or_stub_prefixed_tooling_names_are_fixtures() {
        assert_eq!(
            classify("scripts/mock-ui-regression.js"),
            CandidateContext::MockFixture
        );
        assert_eq!(
            classify("scripts/mock_server.py"),
            CandidateContext::MockFixture
        );
        assert_eq!(
            classify("tools/stub-handlers.ts"),
            CandidateContext::MockFixture
        );
    }

    #[test]
    fn ordinary_tooling_names_stay_product() {
        assert_eq!(classify("scripts/init-db.js"), CandidateContext::Product);
        assert_eq!(classify("scripts/build.js"), CandidateContext::Product);
        assert_eq!(classify("src/mockery.ts"), CandidateContext::Product);
        assert_eq!(classify("src/e2early.ts"), CandidateContext::Product);
    }

    #[test]
    fn tests_directories_are_test_context() {
        assert_eq!(classify("tests/foo.rs"), CandidateContext::Test);
        assert_eq!(classify("test/bar.js"), CandidateContext::Test);
        assert_eq!(classify("__tests__/baz.ts"), CandidateContext::Test);
    }

    #[test]
    fn examples_directories_are_example_context() {
        assert_eq!(classify("examples/demo.rs"), CandidateContext::Example);
        assert_eq!(classify("example/usage.js"), CandidateContext::Example);
    }

    #[test]
    fn docs_directories_are_doc_context() {
        assert_eq!(classify("docs/readme.md"), CandidateContext::Doc);
        assert_eq!(classify("doc/api.rst"), CandidateContext::Doc);
    }

    #[test]
    fn fixture_directories_are_mock_fixture_context() {
        assert_eq!(classify("fixtures/data.rs"), CandidateContext::MockFixture);
        assert_eq!(classify("mocks/server.js"), CandidateContext::MockFixture);
        assert_eq!(classify("stubs/impl.ts"), CandidateContext::MockFixture);
    }

    #[test]
    fn test_and_spec_file_names_are_test_context() {
        assert_eq!(classify("src/foo.test.js"), CandidateContext::Test);
        assert_eq!(classify("lib/bar.spec.rs"), CandidateContext::Test);
        assert_eq!(classify("app/baz.test.ts"), CandidateContext::Test);
    }

    #[test]
    fn mock_and_stub_file_names_are_mock_fixture_context() {
        assert_eq!(classify("src/foo.mock.js"), CandidateContext::MockFixture);
        assert_eq!(classify("lib/bar.stub.rs"), CandidateContext::MockFixture);
    }

    #[test]
    fn ordinary_src_or_app_is_product_context() {
        assert_eq!(classify("src/main.rs"), CandidateContext::Product);
        assert_eq!(classify("app/index.js"), CandidateContext::Product);
        assert_eq!(classify("lib/lib.rs"), CandidateContext::Product);
    }

    #[test]
    fn test_helper_in_src_remains_product() {
        assert_eq!(classify("src/test_helper.rs"), CandidateContext::Product);
        assert_eq!(classify("app/testing_utils.js"), CandidateContext::Product);
    }

    // The three inputs below are the same text read by two different parsers,
    // and the two parsers disagree about them on purpose — a backslash is a
    // separator on Windows and an ordinary character in a file name on Unix, and
    // `std::path::Path` is the thing that says which. Gating the assertions and
    // not the file: each platform asserts what its own `Path` does with this
    // text, so nothing is skipped and no assertion is made about a platform that
    // did not run. What the classifier is *given* in production is asserted
    // below, on every platform, because that shape does not depend on this one.
    #[cfg(windows)]
    #[test]
    fn windows_separators_are_read_as_separators() {
        assert_eq!(classify("tests\\foo.rs"), CandidateContext::Test);
        assert_eq!(classify("src\\main.rs"), CandidateContext::Product);
        assert_eq!(classify("src\\foo.test.js"), CandidateContext::Test);
    }

    #[cfg(not(windows))]
    #[test]
    fn a_backslash_is_a_file_name_here_and_not_a_separator() {
        // `tests\foo.rs` is one file called that, not a file in `tests/`, so
        // the directory names it looks like it contains do not classify it.
        assert_eq!(classify("tests\\foo.rs"), CandidateContext::Product);
        assert_eq!(classify("src\\main.rs"), CandidateContext::Product);
        // The file-name test still fires, because it is a test of the name and
        // not of the directories: this file is called `foo.test.js` whatever the
        // rest of it is.
        assert_eq!(classify("src\\foo.test.js"), CandidateContext::Test);
    }

    /// What the classifier is actually handed in this crate: a path from the
    /// discovery walk, or one this crate rendered with `display_path`, which
    /// joins components with `/` everywhere. Both are asserted on every platform
    /// because both have to classify the same way on every platform — this is
    /// the shape a verdict depends on, and it is the reason the platform split
    /// above is about `Path` and not about SURE's own reading of a path.
    #[test]
    fn the_path_shape_sure_produces_classifies_the_same_way_everywhere() {
        for (parts, expected) in [
            (vec!["tests", "foo.rs"], CandidateContext::Test),
            (vec!["src", "foo.test.js"], CandidateContext::Test),
            (
                vec!["app", "tests", "integration.rs"],
                CandidateContext::Test,
            ),
            (vec!["src", "main.rs"], CandidateContext::Product),
            (vec!["examples", "demo.rs"], CandidateContext::Example),
            (vec!["fixtures", "data.rs"], CandidateContext::MockFixture),
        ] {
            let walked: std::path::PathBuf = parts.iter().collect();
            let rendered = crate::scan::display_path(&walked);
            assert_eq!(
                classify(&rendered),
                expected,
                "display_path rendered {walked:?} as {rendered:?}"
            );
            assert_eq!(
                classify_path(&walked, Path::new(""), None),
                expected,
                "the walked path {walked:?} itself"
            );
        }
    }

    #[test]
    fn nested_conventional_directories_are_classified() {
        assert_eq!(
            classify("packages/app/tests/integration.rs"),
            CandidateContext::Test
        );
        assert_eq!(
            classify("packages/app/examples/hello.rs"),
            CandidateContext::Example
        );
        assert_eq!(
            classify("packages/app/docs/guide.md"),
            CandidateContext::Doc
        );
    }

    #[test]
    fn case_insensitive_matching() {
        assert_eq!(classify("TESTS/foo.rs"), CandidateContext::Test);
        assert_eq!(classify("src/FOO.TEST.JS"), CandidateContext::Test);
        assert_eq!(classify("Docs/Readme.md"), CandidateContext::Doc);
    }
}
