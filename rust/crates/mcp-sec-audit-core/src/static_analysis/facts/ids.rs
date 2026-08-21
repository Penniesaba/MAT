use std::path::Path;

fn rel_posix(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn make_fact_id(type_prefix: &str, root: &Path, file: &Path, qualifier: &str) -> String {
    format!("{type_prefix}:{}:{qualifier}", rel_posix(root, file))
}

pub fn make_function_id(language: &str, root: &Path, file: &Path, name: &str) -> String {
    make_fact_id(language, root, file, name)
}

pub fn make_import_id(root: &Path, file: &Path, line: u32, imported: &str) -> String {
    format!("import:{}:{line}:{imported}", rel_posix(root, file))
}

pub fn make_entrypoint_id(root: &Path, file: &Path, name: &str) -> String {
    make_fact_id("entry", root, file, name)
}

pub fn make_call_id(root: &Path, file: &Path, line: u32, column: u32) -> String {
    format!("call:{}:{line}:{column}", rel_posix(root, file))
}

pub fn make_sink_id(category: &str, root: &Path, file: &Path, line: u32) -> String {
    format!("sink:{category}:{}:{line}", rel_posix(root, file))
}

pub fn make_sanitizer_id(root: &Path, file: &Path, line: u32, callee: &str) -> String {
    let safe = callee.replace(['.', ':', '/'], "_");
    format!("sanitizer:{}:{line}:{safe}", rel_posix(root, file))
}

pub fn make_source_id(root: &Path, file: &Path, function_name: &str, param_name: &str) -> String {
    format!(
        "source:{}:{function_name}:{param_name}",
        rel_posix(root, file)
    )
}

pub fn make_assign_id(root: &Path, file: &Path, line: u32, target: &str) -> String {
    format!("assign:{}:{line}:{target}", rel_posix(root, file))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn ids_match_legacy_python_format() {
        let root = Path::new("/repo");
        let file = Path::new("/repo/src/server.py");

        assert_eq!(
            make_function_id("python", root, file, "tool_handler"),
            "python:src/server.py:tool_handler"
        );
        assert_eq!(
            make_import_id(root, file, 3, "subprocess"),
            "import:src/server.py:3:subprocess"
        );
        assert_eq!(
            make_entrypoint_id(root, file, "tool_handler"),
            "entry:src/server.py:tool_handler"
        );
        assert_eq!(make_call_id(root, file, 8, 4), "call:src/server.py:8:4");
        assert_eq!(
            make_sink_id("rce", root, file, 8),
            "sink:rce:src/server.py:8"
        );
        assert_eq!(
            make_source_id(root, file, "tool_handler", "command"),
            "source:src/server.py:tool_handler:command"
        );
        assert_eq!(
            make_assign_id(root, file, 7, "runner"),
            "assign:src/server.py:7:runner"
        );
    }
}
