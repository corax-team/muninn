use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};

// Muninn bundled rules from corax-team repository (includes SigmaHQ + custom APT rules)
const MUNINN_RULES_URL: &str =
    "https://github.com/corax-team/muninn/releases/latest/download/sigma_rules.zip";
// SigmaHQ upstream rulesets (fallback / specific subsets)
const SIGMA_CORE_URL: &str =
    "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip";
const SIGMA_CORE_PLUS_URL: &str =
    "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core+.zip";
const SIGMA_ALL_URL: &str =
    "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip";
const SIGMA_EMERGING_URL: &str =
    "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_emerging_threats_addon.zip";

#[derive(Debug, Clone, Copy)]
pub enum RuleSet {
    Muninn,
    Core,
    CorePlus,
    All,
    Emerging,
}

impl RuleSet {
    pub fn from_name(name: &str) -> Result<Self> {
        match name.to_lowercase().as_str() {
            "muninn" | "default" => Ok(RuleSet::Muninn),
            "core" => Ok(RuleSet::Core),
            "core+" | "coreplus" | "core-plus" => Ok(RuleSet::CorePlus),
            "all" => Ok(RuleSet::All),
            "emerging" | "emerging-threats" => Ok(RuleSet::Emerging),
            _ => bail!(
                "Unknown ruleset: '{}'. Available: muninn (default), core, core+, all, emerging",
                name
            ),
        }
    }

    pub fn url(&self) -> &'static str {
        match self {
            RuleSet::Muninn => MUNINN_RULES_URL,
            RuleSet::Core => SIGMA_CORE_URL,
            RuleSet::CorePlus => SIGMA_CORE_PLUS_URL,
            RuleSet::All => SIGMA_ALL_URL,
            RuleSet::Emerging => SIGMA_EMERGING_URL,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            RuleSet::Muninn => "Muninn Rules (SigmaHQ + APT)",
            RuleSet::Core => "SigmaHQ Core",
            RuleSet::CorePlus => "SigmaHQ Core+",
            RuleSet::All => "SigmaHQ All Rules",
            RuleSet::Emerging => "SigmaHQ Emerging Threats",
        }
    }
}

pub struct DownloadResult {
    pub rules_count: usize,
    pub output_dir: PathBuf,
    pub bytes_downloaded: usize,
}

/// Download and extract SIGMA rules from SigmaHQ GitHub releases.
pub fn download_rules(ruleset: RuleSet, output_dir: &Path) -> Result<DownloadResult> {
    let url = ruleset.url();

    // Download zip into memory
    let resp = ureq::get(url)
        .call()
        .context(format!("Failed to download from {}", url))?;

    let content_length = resp
        .header("Content-Length")
        .and_then(|h| h.parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = Vec::with_capacity(content_length.max(1024 * 1024));
    resp.into_reader()
        .take(200 * 1024 * 1024) // 200MB max
        .read_to_end(&mut body)
        .context("Failed to read response body")?;

    let bytes_downloaded = body.len();

    // Create output directory
    std::fs::create_dir_all(output_dir)
        .context(format!("Failed to create directory {:?}", output_dir))?;

    // Extract YAML files from zip
    let cursor = std::io::Cursor::new(&body);
    let mut archive = zip::ZipArchive::new(cursor).context("Failed to open zip archive")?;

    let mut rules_count = 0;

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .context(format!("Failed to read zip entry {}", i))?;

        let name = file.name().to_string();

        // Only extract .yml files (SIGMA rules)
        if !name.ends_with(".yml") && !name.ends_with(".yaml") {
            continue;
        }

        // Determine output path, preserving directory structure
        let relative = normalize_zip_path(&name);
        let out_path = output_dir.join(&relative);

        // Create parent directories
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Extract file
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        std::fs::write(&out_path, &contents)?;
        rules_count += 1;
    }

    Ok(DownloadResult {
        rules_count,
        output_dir: output_dir.to_path_buf(),
        bytes_downloaded,
    })
}

/// Normalize zip entry paths: strip leading archive directory prefix.
fn normalize_zip_path(path: &str) -> String {
    // SigmaHQ zips often have a top-level dir like "sigma-master/"
    // Strip it to get cleaner output
    let parts: Vec<&str> = path.splitn(2, '/').collect();
    if parts.len() == 2 && !parts[1].is_empty() {
        parts[1].to_string()
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ruleset_from_name() {
        assert!(matches!(RuleSet::from_name("muninn"), Ok(RuleSet::Muninn)));
        assert!(matches!(RuleSet::from_name("default"), Ok(RuleSet::Muninn)));
        assert!(matches!(RuleSet::from_name("core"), Ok(RuleSet::Core)));
        assert!(matches!(RuleSet::from_name("all"), Ok(RuleSet::All)));
        assert!(matches!(RuleSet::from_name("core+"), Ok(RuleSet::CorePlus)));
        assert!(matches!(
            RuleSet::from_name("emerging"),
            Ok(RuleSet::Emerging)
        ));
        assert!(RuleSet::from_name("invalid").is_err());
    }

    #[test]
    fn test_normalize_zip_path() {
        assert_eq!(
            normalize_zip_path("sigma-master/rules/windows/test.yml"),
            "rules/windows/test.yml"
        );
        assert_eq!(normalize_zip_path("test.yml"), "test.yml");
    }
}
