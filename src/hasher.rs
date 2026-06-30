use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use crate::error::FsimError;

pub fn compute_sha256(file_path: &str) -> Result<String, FsimError> {
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536]; // 64KB buffer chunks

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash_result = hasher.finalize();
    Ok(format!("{:x}", hash_result))
}
