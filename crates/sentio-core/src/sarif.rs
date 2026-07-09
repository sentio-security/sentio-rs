//! SARIF 2.1.0 export for GitHub Code Scanning and other consumers.

use crate::finding::{Finding, Severity};
use crate::rules::RuleRegistry;
use crate::scanner::ScanResult;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: &'static str,
    pub version: &'static str,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDriver {
    pub name: &'static str,
    pub version: String,
    pub information_uri: &'static str,
    pub rules: Vec<SarifReportingDescriptor>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReportingDescriptor {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
    pub full_description: SarifMessage,
    pub help: SarifMessage,
    pub default_configuration: SarifReportingConfig,
    pub properties: SarifRuleProperties,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifReportingConfig {
    pub level: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRuleProperties {
    pub tags: Vec<&'static str>,
    pub precision: &'static str,
    pub problem_severity: &'static str,
    #[serde(rename = "security-severity")]
    pub security_severity: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub level: &'static str,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    pub start_line: usize,
    pub start_column: usize,
}

#[derive(Debug, Serialize)]
pub struct SarifMessage {
    pub text: String,
}

/// Build a SARIF log from a scan result and the active rule registry.
pub fn build_sarif(result: &ScanResult, registry: &RuleRegistry, tool_version: &str) -> SarifLog {
    let mut rules_by_id: BTreeMap<String, SarifReportingDescriptor> = BTreeMap::new();

    for rule in registry.all() {
        let meta = rule.metadata();
        let level = severity_to_sarif_level(crate::rules::convert_severity(meta.severity));
        rules_by_id.insert(
            meta.id.to_string(),
            SarifReportingDescriptor {
                id: meta.id.to_string(),
                name: meta.title.to_string(),
                short_description: SarifMessage {
                    text: meta.title.to_string(),
                },
                full_description: SarifMessage {
                    text: meta.description.to_string(),
                },
                help: SarifMessage {
                    text: meta.fix_guidance.to_string(),
                },
                default_configuration: SarifReportingConfig { level },
                properties: SarifRuleProperties {
                    tags: vec!["security", "solana", "anchor"],
                    precision: "high",
                    problem_severity: severity_label(crate::rules::convert_severity(meta.severity)),
                    security_severity: security_severity_score(crate::rules::convert_severity(
                        meta.severity,
                    )),
                },
            },
        );
    }

    // Ensure any finding whose rule isn't in the registry still has a descriptor.
    for finding in &result.findings {
        rules_by_id
            .entry(finding.rule_id.clone())
            .or_insert_with(|| SarifReportingDescriptor {
                id: finding.rule_id.clone(),
                name: finding.rule_id.clone(),
                short_description: SarifMessage {
                    text: finding.message.clone(),
                },
                full_description: SarifMessage {
                    text: finding.message.clone(),
                },
                help: SarifMessage {
                    text: finding.help.clone().unwrap_or_default(),
                },
                default_configuration: SarifReportingConfig {
                    level: severity_to_sarif_level(finding.severity),
                },
                properties: SarifRuleProperties {
                    tags: vec!["security", "solana", "anchor"],
                    precision: "high",
                    problem_severity: severity_label(finding.severity),
                    security_severity: security_severity_score(finding.severity),
                },
            });
    }

    let results = result
        .findings
        .iter()
        .map(finding_to_sarif_result)
        .collect();

    SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "sentio",
                    version: tool_version.to_string(),
                    information_uri: "https://github.com/sentio-security/sentio-rs",
                    rules: rules_by_id.into_values().collect(),
                },
            },
            results,
        }],
    }
}

pub fn to_sarif_json(
    result: &ScanResult,
    registry: &RuleRegistry,
    tool_version: &str,
) -> Result<String, String> {
    let log = build_sarif(result, registry, tool_version);
    serde_json::to_string_pretty(&log).map_err(|e| e.to_string())
}

fn finding_to_sarif_result(finding: &Finding) -> SarifResult {
    SarifResult {
        rule_id: finding.rule_id.clone(),
        level: severity_to_sarif_level(finding.severity),
        message: SarifMessage {
            text: finding.message.clone(),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: finding.location.path.replace('\\', "/"),
                },
                region: SarifRegion {
                    start_line: finding.location.line.max(1),
                    start_column: finding.location.column.max(1),
                },
            },
        }],
    }
}

fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    }
}

/// GitHub Code Scanning security-severity (CVSS-like 0.0–10.0 string).
fn security_severity_score(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.0",
        Severity::High => "7.0",
        Severity::Medium => "5.0",
        Severity::Low => "3.0",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::SourceLocation;
    use crate::scanner::ScanResult;

    #[test]
    fn builds_valid_sarif_shape() {
        let result = ScanResult {
            findings: vec![Finding {
                rule_id: "SW001".to_string(),
                severity: Severity::Critical,
                message: "missing signer".to_string(),
                location: SourceLocation {
                    path: "src/lib.rs".to_string(),
                    line: 10,
                    column: 5,
                },
                help: Some("use Signer".to_string()),
                suppressed: false,
            }],
            files_scanned: 1,
            files_parsed: 1,
            parse_failures: vec![],
            baselined_count: 0,
        };

        let registry = RuleRegistry::baseline();
        let json = to_sarif_json(&result, &registry, "0.3.0").expect("sarif json");
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["results"][0]["ruleId"], "SW001");
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
                ["startLine"],
            10
        );
        assert!(!value["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}
