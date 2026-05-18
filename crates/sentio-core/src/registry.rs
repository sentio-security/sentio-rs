#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuleId(pub &'static str);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: RuleId,
    pub title: &'static str,
    pub default_enabled: bool,
}

#[derive(Debug, Default)]
pub struct RuleCatalog {
    rules: Vec<Rule>,
}

impl RuleCatalog {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn all(&self) -> &[Rule] {
        &self.rules
    }
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            id: RuleId("SW000"),
            title: "placeholder rule",
            default_enabled: true,
        }
    }
}

impl RuleCatalog {
    pub fn baseline() -> Self {
        Self::new(vec![
            Rule {
                id: RuleId("SW011"),
                title: "AccountInfo used for data account",
                default_enabled: true,
            },
            Rule {
                id: RuleId("SW013"),
                title: "Missing seeds and bump on PDA",
                default_enabled: true,
            },
            Rule {
                id: RuleId("SW017"),
                title: "init_if_needed usage",
                default_enabled: true,
            },
            Rule {
                id: RuleId("SW019"),
                title: "Missing realloc::zero = true",
                default_enabled: true,
            },
            Rule {
                id: RuleId("SW021"),
                title: "AccountInfo as CPI target program",
                default_enabled: true,
            },
        ])
    }
}
