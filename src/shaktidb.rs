use postgres::{Client, NoTls};
use crate::error::FsimError;
use crate::scanner::FileRecord;
use crate::audit_log;
use crate::sensitive_paths;

pub struct ShaktiDbClient {
    pub client: Client,
}

impl ShaktiDbClient {
    /// Connects to ShaktiDB via the standard PostgreSQL wire protocol
    pub fn connect(connection_string: &str) -> Result<Self, FsimError> {
        let client = Client::connect(connection_string, NoTls)?;
        Ok(Self { client })
    }

    /// Initializes all required tables inside ShaktiDB
    pub fn initialize_schema(&mut self) -> Result<(), FsimError> {
        // Baseline integrity table
        self.client.batch_execute("
            CREATE TABLE IF NOT EXISTS file_integrity_baseline (
                path          TEXT PRIMARY KEY,
                hash          TEXT NOT NULL,
                size_bytes    BIGINT NOT NULL,
                modified_time BIGINT NOT NULL
            );
        ")?;

        // Audit log table (LRU-capped)
        audit_log::initialize_audit_log_schema(&mut self.client)?;

        // Sensitive paths table (seeded with defaults)
        sensitive_paths::initialize_sensitive_paths_schema(&mut self.client)?;

        Ok(())
    }

    /// Saves or updates the current state as the baseline
    pub fn save_baseline(&mut self, records: &[FileRecord]) -> Result<(), FsimError> {
        let mut transaction = self.client.transaction()?;
        for record in records {
            transaction.execute(
                "INSERT INTO file_integrity_baseline (path, hash, size_bytes, modified_time)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (path) DO UPDATE
                 SET hash          = EXCLUDED.hash,
                     size_bytes    = EXCLUDED.size_bytes,
                     modified_time = EXCLUDED.modified_time",
                &[&record.path, &record.hash, &record.size_bytes, &record.modified_time],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Retrieves the stored baseline for anomaly comparison
    pub fn get_baseline(&mut self) -> Result<Vec<FileRecord>, FsimError> {
        let rows = self.client.query(
            "SELECT path, hash, size_bytes, modified_time FROM file_integrity_baseline",
            &[],
        )?;

        Ok(rows
            .iter()
            .map(|row| FileRecord {
                path: row.get(0),
                hash: row.get(1),
                size_bytes: row.get(2),
                modified_time: row.get(3),
            })
            .collect())
    }
}
