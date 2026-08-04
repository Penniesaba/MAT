use std::collections::BTreeMap;
use swc_core::ecma::ast::{
    ImportDecl, ObjectPatProp, Pat, PropName, VarDeclarator,
};

use crate::model::{Fact, FactBase, ImportFact, ImportKind};

// --- ESM Import Handling ---

pub(crate) fn extract_esm_import(
    n: &ImportDecl,
    file: &str,
    line: u32,
    extractor_name: &str,
    facts: &mut Vec<Fact>,
    import_aliases: &mut BTreeMap<String, String>,
) {
    let module = n.src.value.to_string();

    for specifier in &n.specifiers {
        match specifier {
            swc_core::ecma::ast::ImportSpecifier::Named(named) => {
                // For `import { readFile as rf } from "fs"`, SWC sets:
                //   named.local    = rf       (local binding)
                //   named.imported = readFile (exported name)
                // Record imported_name = exported name and alias = local binding,
                // and map local binding -> "module.exported_name" in import_aliases.
                let local_binding = named.local.sym.to_string();
                let (imported_name, alias) = match &named.imported {
                    Some(imported) => {
                        let exported = match imported {
                            swc_core::ecma::ast::ModuleExportName::Ident(id) => id.sym.to_string(),
                            swc_core::ecma::ast::ModuleExportName::Str(s) => s.value.to_string(),
                        };
                        (exported, Some(local_binding.clone()))
                    }
                    None => (local_binding.clone(), None),
                };
                let kind = if alias.is_some() {
                    ImportKind::EsmImportAs
                } else {
                    ImportKind::EsmNamedImport
                };
                import_aliases.insert(local_binding, format!("{module}.{imported_name}"));

                facts.push(Fact::Import(ImportFact {
                    base: FactBase {
                        id: format!("import:{file}:{line}:{module}.{imported_name}"),
                        file: file.to_string(),
                        line,
                        extractor: extractor_name.to_string(),
                    },
                    language: "javascript".to_string(),
                    module: module.clone(),
                    imported_name: Some(imported_name),
                    alias,
                    kind,
                }));
            }
            swc_core::ecma::ast::ImportSpecifier::Default(default) => {
                let name = default.local.sym.to_string();
                import_aliases.insert(name.clone(), module.clone());

                facts.push(Fact::Import(ImportFact {
                    base: FactBase {
                        id: format!("import:{file}:{line}:{module}"),
                        file: file.to_string(),
                        line,
                        extractor: extractor_name.to_string(),
                    },
                    language: "javascript".to_string(),
                    module: module.clone(),
                    imported_name: None,
                    alias: Some(name),
                    kind: ImportKind::EsmImport,
                }));
            }
            swc_core::ecma::ast::ImportSpecifier::Namespace(ns) => {
                let name = ns.local.sym.to_string();
                import_aliases.insert(name.clone(), format!("{module}.*"));

                facts.push(Fact::Import(ImportFact {
                    base: FactBase {
                        id: format!("import:{file}:{line}:{module}.*"),
                        file: file.to_string(),
                        line,
                        extractor: extractor_name.to_string(),
                    },
                    language: "javascript".to_string(),
                    module: module.clone(),
                    imported_name: Some("*".to_string()),
                    alias: Some(name),
                    kind: ImportKind::EsmImportAs,
                }));
            }
        }
    }
}

// --- CJS require() Handling ---

pub(crate) fn extract_destructured_require(
    n: &VarDeclarator,
    module_name: &str,
    file: &str,
    line: u32,
    extractor_name: &str,
    facts: &mut Vec<Fact>,
    require_aliases: &mut BTreeMap<String, String>,
) {
    // Handle const { readFile, writeFile: wf } = require("fs")
    let Pat::Object(obj) = &n.name else {
        return;
    };

    for prop in &obj.props {
        match prop {
            ObjectPatProp::KeyValue(kv) => {
                let key = match &kv.key {
                    PropName::Ident(id) => id.sym.to_string(),
                    PropName::Str(s) => s.value.to_string(),
                    _ => continue,
                };
                let value_name = match kv.value.as_ref() {
                    Pat::Ident(id) => id.id.sym.to_string(),
                    _ => continue,
                };
                let alias = if key != value_name {
                    Some(value_name.clone())
                } else {
                    None
                };
                require_aliases.insert(value_name.clone(), format!("{module_name}.{key}"));

                facts.push(Fact::Import(ImportFact {
                    base: FactBase {
                        id: format!("import:{file}:{line}:{module_name}.{key}"),
                        file: file.to_string(),
                        line,
                        extractor: extractor_name.to_string(),
                    },
                    language: "javascript".to_string(),
                    module: module_name.to_string(),
                    imported_name: Some(key),
                    alias,
                    kind: ImportKind::RequireDestructure,
                }));
            }
            ObjectPatProp::Assign(assign) => {
                let name = assign.key.id.sym.to_string();
                require_aliases.insert(name.clone(), format!("{module_name}.{name}"));

                facts.push(Fact::Import(ImportFact {
                    base: FactBase {
                        id: format!("import:{file}:{line}:{module_name}.{name}"),
                        file: file.to_string(),
                        line,
                        extractor: extractor_name.to_string(),
                    },
                    language: "javascript".to_string(),
                    module: module_name.to_string(),
                    imported_name: Some(name),
                    alias: None,
                    kind: ImportKind::RequireDestructure,
                }));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::model::ImportKind;

    // NOTE: these tests will be enabled after JsTsFactExtractor is fully wired in Task 8.
    // For now, verify compilation with a placeholder test.
    #[test]
    fn esm_import_kinds_exist_in_model() {
        // Verify the JS/TS-specific ImportKind variants exist
        assert_eq!(
            serde_json::to_value(ImportKind::EsmImport).unwrap(),
            serde_json::json!("esm_import")
        );
        assert_eq!(
            serde_json::to_value(ImportKind::Require).unwrap(),
            serde_json::json!("require")
        );
        assert_eq!(
            serde_json::to_value(ImportKind::RequireDestructure).unwrap(),
            serde_json::json!("require_destructure")
        );
        assert_eq!(
            serde_json::to_value(ImportKind::EsmNamedImport).unwrap(),
            serde_json::json!("esm_named_import")
        );
    }
}
