//! Archive extraction support for compressed log files.
//!
//! Supports `.zip`, `.gz`, `.bz2`, `.tar.gz`, `.tgz`, `.rar`, and `.7z` formats.
//! Gated behind the `archive` feature flag.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Check if a path is a supported archive format.
pub fn is_archive(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Check compound extensions first
    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        return true;
    }

    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase()
            .as_str(),
        "zip" | "gz" | "bz2" | "rar" | "7z"
    )
}

/// Extract an archive to a temporary directory, returning the temp dir handle
/// and a list of extracted file paths.
///
/// The caller must keep the returned `TempDir` alive for as long as the
/// extracted files are needed; dropping it removes the directory.
pub fn extract_to_temp(path: &Path) -> Result<(tempfile::TempDir, Vec<PathBuf>)> {
    extract_to_temp_with_password(path, None)
}

pub fn extract_to_temp_with_password(
    path: &Path,
    password: Option<&str>,
) -> Result<(tempfile::TempDir, Vec<PathBuf>)> {
    let tmp = tempfile::tempdir().context("failed to create temp directory")?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    let files = if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        extract_tar_gz(path, tmp.path())?
    } else {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase()
            .as_str()
        {
            "zip" => extract_zip(path, tmp.path(), password)?,
            "gz" => extract_single_gz(path, tmp.path())?,
            "bz2" => extract_single_bz2(path, tmp.path())?,
            "rar" => extract_rar(path, tmp.path(), password)?,
            "7z" => extract_7z(path, tmp.path(), password)?,
            other => bail!("unsupported archive extension: {}", other),
        }
    };

    Ok((tmp, files))
}

/// Decompress a single `.gz` file entirely into memory.
pub fn decompress_gz(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut decoder = flate2::read::GzDecoder::new(file);
    let mut buf = Vec::new();
    decoder
        .read_to_end(&mut buf)
        .with_context(|| format!("failed to decompress {}", path.display()))?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn extract_zip(path: &Path, dest: &Path, password: Option<&str>) -> Result<Vec<PathBuf>> {
    let file = File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("failed to read zip archive {}", path.display()))?;

    let mut extracted = Vec::new();

    for i in 0..archive.len() {
        let mut entry = if let Some(pw) = password {
            archive
                .by_index_decrypt(i, pw.as_bytes())
                .map_err(|e| anyhow::anyhow!("zip decrypt error: {}", e))?
        } else {
            archive.by_index(i)?
        };
        let entry_path = match entry.enclosed_name() {
            Some(p) => p.to_owned(),
            None => continue, // skip entries with unsafe paths
        };

        let out_path = dest.join(&entry_path);

        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut out_file = File::create(&out_path)?;
            io::copy(&mut entry, &mut out_file)?;
            extracted.push(out_path);
        }
    }

    Ok(extracted)
}

fn extract_tar_gz(path: &Path, dest: &Path) -> Result<Vec<PathBuf>> {
    let file = File::open(path)?;
    let gz = flate2::read::GzDecoder::new(file);
    extract_tar(gz, dest, path)
}

fn extract_tar<R: Read>(reader: R, dest: &Path, source: &Path) -> Result<Vec<PathBuf>> {
    let mut archive = tar::Archive::new(reader);
    let mut extracted = Vec::new();

    for entry in archive
        .entries()
        .with_context(|| format!("failed to read tar entries from {}", source.display()))?
    {
        let mut entry = entry?;
        let entry_path = entry.path()?.to_path_buf();
        let out_path = dest.join(&entry_path);

        if !out_path.starts_with(dest) {
            log::warn!("Skipping path-traversal entry: {:?}", entry_path);
            continue;
        }

        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            entry.unpack(&out_path)?;
            extracted.push(out_path);
        }
    }

    Ok(extracted)
}

fn extract_single_gz(path: &Path, dest: &Path) -> Result<Vec<PathBuf>> {
    let data = decompress_gz(path)?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("decompressed");
    let out_path = dest.join(stem);
    std::fs::write(&out_path, &data)?;
    Ok(vec![out_path])
}

fn extract_single_bz2(path: &Path, dest: &Path) -> Result<Vec<PathBuf>> {
    let file = File::open(path)?;
    let mut decoder = bzip2::read::BzDecoder::new(file);
    let mut buf = Vec::new();
    decoder
        .read_to_end(&mut buf)
        .with_context(|| format!("failed to decompress {}", path.display()))?;

    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("decompressed");
    let out_path = dest.join(stem);
    std::fs::write(&out_path, &buf)?;
    Ok(vec![out_path])
}

fn extract_rar(path: &Path, dest: &Path, password: Option<&str>) -> Result<Vec<PathBuf>> {
    let path_str = path.to_string_lossy();
    let mut archive = if let Some(pw) = password {
        unrar::Archive::with_password(&*path_str, pw.as_bytes())
            .open_for_processing()
            .map_err(|e| anyhow::anyhow!("failed to open RAR archive {}: {}", path.display(), e))?
    } else {
        unrar::Archive::new(&*path_str)
            .open_for_processing()
            .map_err(|e| anyhow::anyhow!("failed to open RAR archive {}: {}", path.display(), e))?
    };

    let mut extracted = Vec::new();

    let canonical_dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());

    while let Some(header) = archive
        .read_header()
        .map_err(|e| anyhow::anyhow!("failed to read RAR header: {}", e))?
    {
        let (entry_path, is_file, is_dir) = {
            let entry = header.entry();
            (
                entry.filename.clone(),
                entry.is_file(),
                entry.is_directory(),
            )
        };

        let out_path = dest.join(&entry_path);

        // Path traversal protection
        if !out_path.starts_with(dest) {
            log::warn!("Skipping path-traversal entry in RAR: {:?}", entry_path);
            archive = header
                .skip()
                .map_err(|e| anyhow::anyhow!("failed to skip RAR entry: {}", e))?;
            continue;
        }

        if is_file {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            archive = header.extract_to(&out_path).map_err(|e| {
                anyhow::anyhow!(
                    "failed to extract RAR entry {}: {}",
                    entry_path.display(),
                    e
                )
            })?;
            // Verify the extracted file is within dest (post-extraction check)
            if let Ok(canon) = out_path.canonicalize() {
                if !canon.starts_with(&canonical_dest) {
                    log::warn!(
                        "Removing path-traversal file extracted from RAR: {:?}",
                        entry_path
                    );
                    let _ = std::fs::remove_file(&canon);
                    continue;
                }
            }
            extracted.push(out_path);
        } else {
            if is_dir {
                std::fs::create_dir_all(&out_path)?;
            }
            archive = header
                .skip()
                .map_err(|e| anyhow::anyhow!("failed to skip RAR entry: {}", e))?;
        }
    }

    Ok(extracted)
}

fn extract_7z(path: &Path, dest: &Path, password: Option<&str>) -> Result<Vec<PathBuf>> {
    if let Some(pw) = password {
        sevenz_rust::decompress_file_with_password(path, dest, pw.into())
            .with_context(|| format!("failed to decompress 7z archive {}", path.display()))?;
    } else {
        sevenz_rust::decompress_file(path, dest)
            .with_context(|| format!("failed to decompress 7z archive {}", path.display()))?;
    }

    // Walk the output directory to collect extracted file paths,
    // with path traversal protection
    let canonical_dest = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());
    let mut extracted = Vec::new();

    for entry in walkdir::WalkDir::new(dest)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let entry_path = entry.path();
        if entry_path.is_file() {
            let canon = entry_path
                .canonicalize()
                .unwrap_or_else(|_| entry_path.to_path_buf());
            if canon.starts_with(&canonical_dest) {
                extracted.push(entry_path.to_path_buf());
            } else {
                log::warn!(
                    "Skipping path-traversal file in 7z extraction: {:?}",
                    entry_path
                );
                let _ = std::fs::remove_file(&canon);
            }
        }
    }

    Ok(extracted)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_archive_zip() {
        assert!(is_archive(Path::new("logs.zip")));
    }

    #[test]
    fn test_is_archive_gz() {
        assert!(is_archive(Path::new("access.log.gz")));
    }

    #[test]
    fn test_is_archive_bz2() {
        assert!(is_archive(Path::new("syslog.bz2")));
    }

    #[test]
    fn test_is_archive_tar_gz() {
        assert!(is_archive(Path::new("logs.tar.gz")));
    }

    #[test]
    fn test_is_archive_tgz() {
        assert!(is_archive(Path::new("bundle.tgz")));
    }

    #[test]
    fn test_is_archive_negative() {
        assert!(!is_archive(Path::new("readme.txt")));
        assert!(!is_archive(Path::new("data.json")));
        assert!(!is_archive(Path::new("events.evtx")));
        assert!(!is_archive(Path::new("no_extension")));
    }

    #[test]
    fn test_is_archive_rar() {
        assert!(is_archive(Path::new("logs.rar")));
    }

    #[test]
    fn test_is_archive_7z() {
        assert!(is_archive(Path::new("logs.7z")));
    }

    #[test]
    fn test_is_archive_case_insensitive() {
        assert!(is_archive(Path::new("LOGS.ZIP")));
        assert!(is_archive(Path::new("data.GZ")));
        assert!(is_archive(Path::new("archive.TAR.GZ")));
        assert!(is_archive(Path::new("LOGS.RAR")));
        assert!(is_archive(Path::new("ARCHIVE.7Z")));
    }

    #[test]
    fn test_gz_roundtrip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let original = b"hello world, this is a test log line\n";

        // Compress in memory
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        // Write compressed data to a temp file
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &compressed).unwrap();

        // Decompress and verify
        let decompressed = decompress_gz(tmp.path()).unwrap();
        assert_eq!(decompressed, original);
    }
}
