use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceLocation {
    pub path: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileLocation {
    pub path: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    pub location: SourceLocation,
    pub help: Option<String>,
    pub suppressed: bool,
}
