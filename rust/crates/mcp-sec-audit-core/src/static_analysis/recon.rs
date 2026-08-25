use std::collections::{BTreeMap, BTreeSet};

use crate::model::Fact;

/// Per-language set of top-level package roots, derived from `Fact::Import`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PackageInventory {
    packages: BTreeMap<String, BTreeSet<String>>,
}

impl PackageInventory {
    pub(crate) fn packages_for(&self, language: &str) -> Option<&BTreeSet<String>> {
        self.packages.get(language)
    }

    /// Total number of distinct package roots across all languages.
    pub(crate) fn len(&self) -> usize {
        self.packages.values().map(BTreeSet::len).sum()
    }
}

/// First path segment of a package name, using the language's separator.
fn package_root<'a>(name: &'a str, language: &str) -> &'a str {
    if language == "rust" {
        name.split("::").next().unwrap_or(name)
    } else {
        name.split('.').next().unwrap_or(name)
    }
}

/// Derive the set of imported top-level packages from import facts.
pub(crate) fn collect_packages(facts: &[Fact]) -> PackageInventory {
    let mut packages: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for fact in facts {
        let Fact::Import(import) = fact else { continue };
        let root = package_root(&import.module, &import.language);
        if root.is_empty() || root.starts_with('.') {
            continue; // skip empty and relative imports ("./x", "../x")
        }
        packages
            .entry(import.language.clone())
            .or_default()
            .insert(root.to_string());
    }
    PackageInventory { packages }
}

#[cfg(test)]
mod tests {
    use crate::model::{Fact, FactBase, ImportFact, ImportKind};

    use super::*;

    fn import(language: &str, module: &str) -> Fact {
        Fact::Import(ImportFact {
            base: FactBase {
                id: format!("import:{language}:{module}"),
                file: "f".to_string(),
                line: 1,
                extractor: "test".to_string(),
            },
            language: language.to_string(),
            module: module.to_string(),
            imported_name: None,
            alias: None,
            kind: ImportKind::Import,
        })
    }

    #[test]
    fn collects_package_roots_across_languages() {
        let facts = vec![
            import("python", "subprocess"),
            import("python", "os.path"),
            import("python", "openpyxl"),
            import("javascript", "child_process"),
            import("javascript", "xlsx"),
            import("rust", "std::process::Command"),
        ];
        let inv = collect_packages(&facts);
        assert_eq!(inv.len(), 6);
        assert!(inv.packages_for("python").unwrap().contains("subprocess"));
        assert!(inv.packages_for("python").unwrap().contains("os"));
        assert!(inv.packages_for("python").unwrap().contains("openpyxl"));
        assert!(
            inv.packages_for("javascript")
                .unwrap()
                .contains("child_process")
        );
        assert!(inv.packages_for("javascript").unwrap().contains("xlsx"));
        assert!(inv.packages_for("rust").unwrap().contains("std"));
        assert!(inv.packages_for("go").is_none());
    }

    #[test]
    fn skips_relative_imports() {
        let facts = vec![import("javascript", "./local"), import("javascript", "fs")];
        let inv = collect_packages(&facts);
        assert_eq!(inv.len(), 1);
        assert!(inv.packages_for("javascript").unwrap().contains("fs"));
    }
}
