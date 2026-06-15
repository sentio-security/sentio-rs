pub mod anchor_accounts;
pub mod ast_index;
pub mod finding;
pub mod instruction_analysis;
pub mod registry;
pub mod rules;
pub mod scanner;
pub mod syntax;

pub use anchor_accounts::{
    collect_anchor_accounts_index, AnchorAccountsField, AnchorAccountsIndex, AnchorAccountsStruct,
    AnchorConstraint, AnchorConstraintKind, AnchorFieldConstraints, AnchorFieldType,
    AnchorFieldTypeKind, AnchorTypeWrapper, AnchorTypeWrapperKind,
};
pub use ast_index::{collect_ast_index, AstAttr, AstField, AstIndex, AstSpan, AstStruct};
pub use finding::{FileLocation, Finding, Severity, SourceLocation};
pub use instruction_analysis::{
    collect_instruction_index, CallEvidence, CallKind, GuardEvidence, GuardKind,
    InstructionFunction, InstructionIndex, WriteEvidence,
};
pub use registry::{Rule, RuleCatalog, RuleId};
pub use rules::{RuleContext, RuleMatch, RuleMetadata, RuleRegistry, RuleSeverity, SuppressionSet};
pub use scanner::{ScanOptions, ScanResult, Scanner};
pub use syntax::{ParseFailure, ParsedFile, SyntaxReport};
