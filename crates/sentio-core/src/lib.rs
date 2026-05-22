pub mod ast_index;
pub mod anchor_accounts;
pub mod finding;
pub mod registry;
pub mod rules;
pub mod scanner;
pub mod syntax;

pub use ast_index::{collect_ast_index, AstAttr, AstField, AstIndex, AstSpan, AstStruct};
pub use anchor_accounts::{
    collect_anchor_accounts_index, AnchorAccountsField, AnchorAccountsIndex,
    AnchorAccountsStruct, AnchorConstraint, AnchorConstraintKind, AnchorFieldConstraints,
    AnchorFieldType, AnchorFieldTypeKind, AnchorTypeWrapper, AnchorTypeWrapperKind,
};
pub use finding::{Finding, FileLocation, Severity, SourceLocation};
pub use registry::{Rule, RuleCatalog, RuleId};
pub use rules::{RuleContext, RuleMetadata, RuleMatch, RuleRegistry, RuleSeverity, SuppressionSet};
pub use scanner::{ScanOptions, ScanResult, Scanner};
pub use syntax::{ParseFailure, ParsedFile, SyntaxReport};
