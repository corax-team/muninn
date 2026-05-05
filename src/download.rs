use anyhow::{Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Single source of truth for Muninn rules: our curated `sigma_rules.zip`
/// asset attached to every release on github.com/corax-team/muninn.
/// It already bundles a SigmaHQ snapshot, the corax-team APT additions and
/// the 193 Hayabusa-native rules. We deliberately removed the upstream
/// SigmaHQ-direct download paths in v0.7.5 — keeping a single distribution
/// channel makes versioning, license attribution and false-positive
/// curation deterministic for end users.
const MUNINN_RULES_URL: &str =
    "https://github.com/corax-team/muninn/releases/latest/download/sigma_rules.zip";

pub struct DownloadResult {
    pub rules_count: usize,
    pub output_dir: PathBuf,
    pub bytes_downloaded: usize,
}

/// Download the latest curated Muninn ruleset and extract it into
/// `output_dir`. Existing files inside `output_dir` are kept; new rules
/// are added and same-named ones get overwritten with the upstream
/// version. Removed upstream rules are NOT pruned automatically.
pub fn download_rules(output_dir: &Path) -> Result<DownloadResult> {
    let url = MUNINN_RULES_URL;

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

/// Public display name kept for CLI banners — single ruleset, single name.
pub fn display_name() -> &'static str {
    "Muninn Rules (SigmaHQ snapshot + Corax APT + Hayabusa-native)"
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
    fn test_normalize_zip_path() {
        assert_eq!(
            normalize_zip_path("sigma-master/rules/windows/test.yml"),
            "rules/windows/test.yml"
        );
        assert_eq!(normalize_zip_path("test.yml"), "test.yml");
    }

    #[test]
    fn test_display_name() {
        assert!(display_name().contains("Muninn"));
    }
}
