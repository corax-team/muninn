use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub title: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub logsource: LogSource,
    pub detection: Detection,
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_level() -> String {
    "medium".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogSource {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    #[serde(default)]
    pub condition: ConditionValue,
    #[serde(flatten)]
    pub selections: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionValue {
    Single(String),
    List(Vec<String>),
}

impl Default for ConditionValue {
    fn default() -> Self {
        ConditionValue::Single(String::new())
    }
}

impl ConditionValue {
    pub fn as_vec(&self) -> Vec<&str> {
        match self {
            ConditionValue::Single(s) => vec![s.as_str()],
            ConditionValue::List(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

pub fn load_rules(path: &Path) -> Result<Vec<Rule>> {
    if path.is_dir() {
        load_directory(path)
    } else {
        load_yaml_file(path).map(|r| vec![r])
    }
}

fn load_directory(dir: &Path) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let p = entry.path();
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "yml" || ext == "yaml" {
            match load_yaml_file(p) {
                Ok(rule) => rules.push(rule),
                Err(e) => log::debug!("Skipping {:?}: {}", p, e),
            }
        }
    }
    log::info!("Loaded {} SIGMA rules from {:?}", rules.len(), dir);
    Ok(rules)
}

fn load_yaml_file(path: &Path) -> Result<Rule> {
    let content = std::fs::read_to_string(path).context(format!("Failed to read {:?}", path))?;
    let rule: Rule =
        serde_yaml::from_str(&content).context(format!("Failed to parse {:?}", path))?;
    Ok(rule)
}
