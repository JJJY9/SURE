//! What a Java project declares about itself.
//!
//! | File | What it answers |
//! |---|---|
//! | `pom.xml` | the project's coordinates, its packaging, and the modules it aggregates |
//! | `build.gradle`, `build.gradle.kts` | that the project is built by Gradle (presence only) |
//! | `settings.gradle`, `settings.gradle.kts` | the same (presence only) |
//! | `mvnw`, `mvnw.cmd`, `gradlew`, `gradlew.bat` | that the project ships its own wrapper (presence only) |
//!
//! **Only a Maven POM is read into a value.** A Gradle build script is code —
//! Groovy or Kotlin — and SURE does not execute or interpret build scripts, so a
//! Gradle project is reported at [`SupportLevel::InspectOnly`] with the sentence
//! that says why rather than with a guessed task list. The wrapper files are
//! recorded by existence only: which Maven or Gradle a wrapper downloads is a
//! question only the wrapper answers, and SURE does not run it to find out.
//!
//! A `pom.xml` is parsed as XML with a real parser, because a POM is XML and a
//! line-oriented reader would mis-read a file whose whole project element is on
//! one line. SURE reads the root `<project>` element's **direct children** only:
//! `groupId`, `artifactId`, `version`, `packaging` and `modules`. Everything
//! else — dependencies, plugins, properties, profiles, the parent's coordinates —
//! is left to Maven, which is where a resolver lives. A module declared inside a
//! profile is not expanded, because whether a profile is active is a decision
//! Maven makes from the environment and SURE does not make it for Maven.
//!
//! A `pom.xml` SURE cannot parse is [`Unread`] and the checks become missing
//! commands rather than guesses; a module directory with no readable `pom.xml`
//! is the same, one module at a time.

use std::path::{Path, PathBuf};

use sure_domain::vocabulary::SupportLevel;

use super::read::{self, Budget, Probe, ReadFile, UnreadReason};
use super::{DiscoverOptions, Ecosystem, EcosystemReport, Findings, Unread};
use crate::scan::Scan;

/// The manifest every Maven project has, relative to the project root.
pub const MAVEN_MANIFEST: &str = "pom.xml";

/// Gradle build scripts, recognised by existence only.
const GRADLE_BUILD_FILES: &[&str] = &["build.gradle", "build.gradle.kts"];

/// Gradle settings files, recognised by existence only.
const GRADLE_SETTINGS_FILES: &[&str] = &["settings.gradle", "settings.gradle.kts"];

/// Wrapper scripts, recognised by existence only.
///
/// `mvnw`/`mvnw.cmd` is Maven's, `gradlew`/`gradlew.bat` is Gradle's. The
/// extension differs by platform and both are in the table rather than one
/// being derived from the host, because a repository is shared between platforms
/// and a finding about which wrapper it carries must not depend on who looked.
const WRAPPERS: &[&str] = &["mvnw", "mvnw.cmd", "gradlew", "gradlew.bat"];

/// Which build tool a Java project uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaBuild {
    /// Apache Maven: a `pom.xml` SURE reads.
    Maven,
    /// Gradle: build scripts SURE records but does not read.
    Gradle,
}

impl JavaBuild {
    /// The stable name, used in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Maven => "maven",
            Self::Gradle => "gradle",
        }
    }
}

/// The directives this module reads from `pom.xml`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MavenManifest {
    /// The `groupId` directly under `<project>`, verbatim.
    pub group_id: Option<String>,
    /// The `artifactId` directly under `<project>`, verbatim.
    pub artifact_id: Option<String>,
    /// The `version` directly under `<project>`, verbatim.
    pub version: Option<String>,
    /// The `packaging` directly under `<project>`, verbatim.
    pub packaging: Option<String>,
    /// The `modules` entries, relative to the project root, deduplicated.
    pub modules: Vec<PathBuf>,
}

/// One module a POM's `<modules>` names, and whether its `pom.xml` was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MavenModule {
    /// The directory named by `<module>`, relative to the project root.
    pub path: PathBuf,
    /// The parsed module manifest, when SURE read it.
    pub manifest: Option<MavenManifest>,
    /// Why the module manifest could not be read, when it was there.
    pub unread: Option<UnreadReason>,
}

impl MavenModule {
    /// Whether this module's `pom.xml` was read into a value.
    #[must_use]
    pub const fn manifest_read(&self) -> bool {
        self.manifest.is_some()
    }
}

/// What discovery found for Java, and what it could read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaProject {
    /// Which build tool the project uses.
    pub build: JavaBuild,
    /// The parsed Maven manifest, when SURE read it.
    pub manifest: Option<MavenManifest>,
    /// Why the Maven manifest could not be read, when it was there.
    pub unread: Option<UnreadReason>,
    /// The modules the POM's `<modules>` names, in declaration order.
    pub modules: Vec<MavenModule>,
    /// The wrapper script that is present, if one is.
    pub wrapper: Option<&'static str>,
    /// The Gradle build and settings files that are present, in table order.
    pub gradle_files: Vec<&'static str>,
}

impl JavaProject {
    /// Whether a Maven manifest was read into a value.
    #[must_use]
    pub const fn manifest_read(&self) -> bool {
        self.manifest.is_some()
    }
}

pub(super) fn look(
    root: &Path,
    scan: &Scan,
    options: &DiscoverOptions,
    budget: &mut Budget,
    unread: &mut Vec<Unread>,
) -> Option<EcosystemReport> {
    let tree = read::Tree::of(scan, options.scan.case);
    let pom_path = Path::new(MAVEN_MANIFEST);
    let pom_there = matches!(tree.probe(pom_path), Probe::File(_));
    let mut gradle_files: Vec<&'static str> = GRADLE_BUILD_FILES
        .iter()
        .chain(GRADLE_SETTINGS_FILES)
        .copied()
        .filter(|name| matches!(tree.probe(Path::new(name)), Probe::File(_)))
        .collect();
    let wrapper = WRAPPERS
        .iter()
        .copied()
        .find(|name| matches!(tree.probe(Path::new(name)), Probe::File(_)));
    if !pom_there && gradle_files.is_empty() && wrapper.is_none() {
        return None;
    }

    // A POM is the manifest SURE reads, so it decides the build tool. Without
    // one, a Maven wrapper still says Maven; otherwise the Gradle markers do.
    let maven_wrapper = matches!(wrapper, Some("mvnw" | "mvnw.cmd"));
    let build = if pom_there || maven_wrapper {
        JavaBuild::Maven
    } else {
        JavaBuild::Gradle
    };

    let mut found_by = Vec::new();
    if pom_there {
        found_by.push(pom_path.to_path_buf());
    }

    let (manifest, unread_reason) = if build == JavaBuild::Maven && pom_there {
        match read::read_text_file(root, tree.probe(pom_path), options, budget) {
            ReadFile::Parsed(value) => match parse_manifest(value.as_str().unwrap_or_default()) {
                Ok(manifest) => (Some(manifest), None),
                Err(reason) => {
                    unread.push(Unread {
                        path: pom_path.to_path_buf(),
                        reason: reason.clone(),
                    });
                    (None, Some(reason))
                }
            },
            ReadFile::Unread(reason) => {
                unread.push(Unread {
                    path: pom_path.to_path_buf(),
                    reason: reason.clone(),
                });
                (None, Some(reason))
            }
            ReadFile::Absent => (None, None),
        }
    } else {
        (None, None)
    };

    let mut modules = Vec::new();
    if let Some(manifest) = &manifest {
        for path in &manifest.modules {
            modules.push(read_module(root, &tree, path, options, budget, unread));
        }
        for module in &modules {
            found_by.push(module.path.join(MAVEN_MANIFEST));
        }
    }

    if build == JavaBuild::Maven {
        gradle_files.clear();
    } else {
        found_by.extend(gradle_files.iter().map(PathBuf::from));
    }
    if let Some(wrapper) = wrapper {
        found_by.push(PathBuf::from(wrapper));
    }

    let readable_modules = modules
        .iter()
        .filter(|module| module.manifest_read())
        .count();
    let level = if manifest.is_some() {
        SupportLevel::Generic
    } else {
        SupportLevel::InspectOnly
    };
    let reason = if manifest.is_some() {
        if manifest
            .as_ref()
            .is_some_and(|manifest| !manifest.modules.is_empty())
        {
            if readable_modules == 0 {
                "SURE read pom.xml but could not read any of the module pom.xml files it \
                 names, so it plans Maven's commands for whatever the reactor can still read."
            } else {
                "SURE read pom.xml and the module pom.xml files it names, so it can plan \
                 Maven's own test and package commands for the reactor when you allow them."
            }
        } else {
            "SURE read pom.xml, so it can plan Maven's own test and package commands when \
             you allow them."
        }
    } else if unread_reason.is_some() {
        "SURE found a pom.xml it could not read, so it cannot plan Maven's commands."
    } else if build == JavaBuild::Gradle {
        "SURE found a Gradle build script. A Gradle build script is code, and SURE does not \
         execute or interpret build scripts, so it cannot plan Gradle's tasks."
    } else {
        "SURE found a Maven wrapper but no pom.xml it can read, so it cannot plan the \
         project's commands."
    };

    Some(EcosystemReport {
        ecosystem: Ecosystem::Java,
        level,
        reason: reason.to_owned(),
        found_by,
        findings: Findings::Java(Box::new(JavaProject {
            build,
            manifest,
            unread: unread_reason,
            modules,
            wrapper,
            gradle_files,
        })),
    })
}

/// Read one module's `pom.xml`, if it has one.
fn read_module(
    root: &Path,
    tree: &read::Tree<'_>,
    path: &Path,
    options: &DiscoverOptions,
    budget: &mut Budget,
    unread: &mut Vec<Unread>,
) -> MavenModule {
    let manifest_path = path.join(MAVEN_MANIFEST);
    match read::read_text_file(root, tree.probe(&manifest_path), options, budget) {
        ReadFile::Parsed(value) => match parse_manifest(value.as_str().unwrap_or_default()) {
            Ok(manifest) => MavenModule {
                path: path.to_path_buf(),
                manifest: Some(manifest),
                unread: None,
            },
            Err(reason) => {
                unread.push(Unread {
                    path: manifest_path,
                    reason: reason.clone(),
                });
                MavenModule {
                    path: path.to_path_buf(),
                    manifest: None,
                    unread: Some(reason),
                }
            }
        },
        ReadFile::Unread(reason) => {
            unread.push(Unread {
                path: manifest_path,
                reason: reason.clone(),
            });
            MavenModule {
                path: path.to_path_buf(),
                manifest: None,
                unread: Some(reason),
            }
        }
        ReadFile::Absent => MavenModule {
            path: path.to_path_buf(),
            manifest: None,
            unread: None,
        },
    }
}

/// Read the root `<project>` element's direct children.
///
/// Namespaces are ignored on purpose: a POM's default namespace is
/// `http://maven.apache.org/POM/4.0.0`, but a POM with a different or missing
/// one is still a POM to Maven, and refusing it here would turn a Maven question
/// into SURE's. The element names compared are the local names, which is what
/// the POM schema means by them.
fn parse_manifest(text: &str) -> Result<MavenManifest, UnreadReason> {
    let document = roxmltree::Document::parse(text).map_err(|error| UnreadReason::NotParsed {
        detail: error.to_string(),
    })?;
    let root = document.root_element();
    if root.tag_name().name() != "project" {
        return Err(UnreadReason::WrongShape {
            found: "an XML document whose root element is not <project>",
        });
    }
    let mut manifest = MavenManifest::default();
    for child in root.children().filter(roxmltree::Node::is_element) {
        match child.tag_name().name() {
            "groupId" => manifest.group_id = text_of(child),
            "artifactId" => manifest.artifact_id = text_of(child),
            "version" => manifest.version = text_of(child),
            "packaging" => manifest.packaging = text_of(child),
            "modules" => {
                for module in child
                    .children()
                    .filter(|node| node.is_element() && node.tag_name().name() == "module")
                {
                    if let Some(path) = text_of(module).and_then(|text| module_path(&text))
                        && !manifest.modules.contains(&path)
                    {
                        manifest.modules.push(path);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(manifest)
}

/// A direct child's text, trimmed, when it has any.
fn text_of(node: roxmltree::Node<'_, '_>) -> Option<String> {
    node.text()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// A `<module>` entry as a path inside the project root.
///
/// The same rule `go.work`'s `use` paths get: a component path must stay inside
/// the project root, so absolute paths and paths containing `..` are not
/// followed. Maven would accept both; SURE's scope is the checked project.
fn module_path(text: &str) -> Option<PathBuf> {
    let raw = text.trim();
    if raw.is_empty() {
        return None;
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        return None;
    }
    let mut cleaned = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => return None,
            other => cleaned.push(other.as_os_str()),
        }
    }
    if cleaned.as_os_str().is_empty() {
        Some(PathBuf::from("."))
    } else {
        Some(cleaned)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_project_coordinates_and_modules() {
        let manifest = parse_manifest(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <properties><java.version>17</java.version></properties>
  <modules>
    <module>./core</module>
    <module>web</module>
  </modules>
</project>
"#,
        )
        .expect("a POM parses");
        assert_eq!(manifest.group_id.as_deref(), Some("com.example"));
        assert_eq!(manifest.artifact_id.as_deref(), Some("app"));
        assert_eq!(manifest.version.as_deref(), Some("1.0.0"));
        assert_eq!(manifest.packaging.as_deref(), Some("pom"));
        assert_eq!(
            manifest.modules,
            vec![PathBuf::from("core"), PathBuf::from("web")]
        );
    }

    #[test]
    fn a_pom_on_one_line_is_read() {
        let manifest = parse_manifest(
            "<project><groupId>g</groupId><artifactId>a</artifactId><modules><module>m</module></modules></project>",
        )
        .expect("a one-line POM parses");
        assert_eq!(manifest.group_id.as_deref(), Some("g"));
        assert_eq!(manifest.modules, vec![PathBuf::from("m")]);
    }

    #[test]
    fn a_module_outside_the_root_is_ignored() {
        let manifest = parse_manifest(
            "<project><modules><module>../outside</module><module>inside</module></modules></project>",
        )
        .expect("a POM parses");
        assert_eq!(manifest.modules, vec![PathBuf::from("inside")]);
    }

    #[test]
    fn a_document_whose_root_is_not_a_project_is_the_wrong_shape() {
        let reason = parse_manifest("<html><body/></html>").expect_err("not a POM");
        assert!(matches!(reason, UnreadReason::WrongShape { .. }));
    }

    #[test]
    fn malformed_xml_is_not_parsed() {
        let reason = parse_manifest("<project><groupId>g</project>").expect_err("not XML");
        assert!(matches!(reason, UnreadReason::NotParsed { .. }));
    }

    #[test]
    fn modules_declared_in_a_profile_are_not_expanded() {
        let manifest = parse_manifest(
            "<project><profiles><profile><modules><module>extra</module></modules></profile></profiles></project>",
        )
        .expect("a POM parses");
        assert!(manifest.modules.is_empty());
    }
}
