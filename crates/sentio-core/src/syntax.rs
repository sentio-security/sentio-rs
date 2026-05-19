use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

pub struct ParsedFile {
    pub path: PathBuf,
    pub source: String,
    pub syntax: syn::File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParseFailure {
    pub path: String,
    pub message: String,
}

pub struct SyntaxReport {
    pub files: Vec<ParsedFile>,
    pub parse_failures: Vec<ParseFailure>,
}

pub fn parse_rust_files<I>(paths: I) -> SyntaxReport
where
    I: IntoIterator<Item = PathBuf>,
{
    let mut files = Vec::new();
    let mut parse_failures = Vec::new();

    for path in paths {
        match parse_rust_file(&path) {
            Ok(file) => files.push(file),
            Err(failure) => parse_failures.push(failure),
        }
    }

    SyntaxReport {
        files,
        parse_failures,
    }
}

pub fn parse_rust_file(path: &Path) -> Result<ParsedFile, ParseFailure> {
    let source = fs::read_to_string(path).map_err(|error| ParseFailure {
        path: path.display().to_string(),
        message: format!("failed to read file: {error}"),
    })?;

    parse_source(path, source)
}

fn parse_source(path: &Path, source: String) -> Result<ParsedFile, ParseFailure> {
    let syntax = syn::parse_file(&source).map_err(|error| ParseFailure {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;

    Ok(ParsedFile {
        path: path.to_path_buf(),
        source,
        syntax,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_rust_source() {
        let path = Path::new("program/src/lib.rs");
        let parsed = parse_source(path, "fn main() {}".to_string()).expect("source should parse");

        assert_eq!(parsed.path, path);
        assert_eq!(parsed.syntax.items.len(), 1);
        assert_eq!(parsed.source, "fn main() {}");
    }

    #[test]
    fn reports_invalid_rust_source() {
        let path = Path::new("program/src/lib.rs");
        let failure = match parse_source(path, "fn main( {".to_string()) {
            Ok(_) => panic!("source should fail"),
            Err(failure) => failure,
        };

        assert_eq!(failure.path, "program/src/lib.rs");
        assert!(!failure.message.is_empty());
    }
}
