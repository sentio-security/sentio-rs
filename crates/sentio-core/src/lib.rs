pub mod finding;
pub mod registry;
pub mod scanner;
pub mod syntax;

pub use finding::{Finding, Severity, SourceLocation};
pub use registry::{Rule, RuleCatalog, RuleId};
pub use scanner::{ScanOptions, ScanResult, Scanner};
pub use syntax::{ParseFailure, ParsedFile, SyntaxReport};