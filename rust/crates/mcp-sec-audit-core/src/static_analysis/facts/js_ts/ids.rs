use std::path::Path;

/// Build a JS/TS function ID in the format: javascript:<rel_path>:<qualified_name>
pub(crate) fn make_js_ts_function_id(root: &Path, file: &Path, qualified_name: &str) -> String {
    let rel = file
        .strip_prefix(root)
        .unwrap_or(file)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    format!("javascript:{rel}:{qualified_name}")
}
