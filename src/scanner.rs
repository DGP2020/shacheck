use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;
use crate::error::FsimError;
use crate::hasher::compute_sha256;

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub path: String,
    pub hash: String,
    pub size_bytes: i64,
    pub modified_time: i64,
}

pub fn scan_directory(root: &Path, records: &mut Vec<FileRecord>) -> Result<(), FsimError> {
    if !root.exists() {
        return Err(FsimError::InvalidPath(root.to_string_lossy().to_string()));
    }

    if root.is_dir() {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                scan_directory(&path, records)?;
            } else {
                let metadata = entry.metadata()?;
                let modified = metadata
                    .modified()?
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);

                let path_str = path.to_string_lossy().to_string();
                let hash = compute_sha256(&path_str)?;

                records.push(FileRecord {
                    path: path_str,
                    hash,
                    size_bytes: metadata.len() as i64,
                    modified_time: modified,
                });
            }
        }
    }
    Ok(())
}
