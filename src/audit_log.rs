use postgres::Client;
use crate::error::FsimError;

/// Maximum number of audit log entries to retain (LRU eviction)
const MAX_LOG_ENTRIES: i64 = 100_000;

/// Approximate maximum log size in bytes (64 MB)
const MAX_LOG_SIZE_BYTES: i64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum ChangeType {
    Modified,
    New,
    Deleted,
}

impl ChangeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangeType::Modified => "MODIFIED",
            ChangeType::New => "NEW",
            ChangeType::Deleted => "DELETED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub path: String,
    pub change_type: ChangeType,
    pub is_sensitive: bool,
}

/// Initializes the audit_log table in ShaktiDB
pub fn initialize_audit_log_schema(client: &mut Client) -> Result<(), FsimError> {
    client.batch_execute("
        CREATE TABLE IF NOT EXISTS audit_log (
            id          BIGSERIAL PRIMARY KEY,
            path        TEXT NOT NULL,
            change_type TEXT NOT NULL,
            is_sensitive BOOLEAN NOT NULL DEFAULT FALSE,
            detected_at BIGINT NOT NULL,
            size_bytes  BIGINT NOT NULL DEFAULT 0
        );
    ")?;
    Ok(())
}

/// Persists a batch of audit events and enforces LRU eviction
pub fn persist_audit_events(client: &mut Client, events: &[AuditEvent]) -> Result<(), FsimError> {
    if events.is_empty() {
        return Ok(());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut transaction = client.transaction()?;

    for event in events {
        // Estimate row size: path length + fixed overhead (~128 bytes)
        let estimated_row_size = (event.path.len() as i64) + 128;

        transaction.execute(
            "INSERT INTO audit_log (path, change_type, is_sensitive, detected_at, size_bytes)
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &event.path,
                &event.change_type.as_str(),
                &event.is_sensitive,
                &now,
                &estimated_row_size,
            ],
        )?;
    }

    transaction.commit()?;

    // LRU eviction: enforce row count cap
    client.execute(
        "DELETE FROM audit_log
         WHERE id IN (
             SELECT id FROM audit_log
             ORDER BY detected_at ASC
             LIMIT GREATEST(0, (SELECT COUNT(*) FROM audit_log) - $1)
         )",
        &[&MAX_LOG_ENTRIES],
    )?;

    // LRU eviction: enforce size cap
    client.execute(
        "DELETE FROM audit_log
         WHERE id IN (
             SELECT id FROM (
                 SELECT id,
                        SUM(size_bytes) OVER (ORDER BY detected_at DESC) AS running_total
                 FROM audit_log
             ) ranked
             WHERE running_total > $1
         )",
        &[&MAX_LOG_SIZE_BYTES],
    )?;

    Ok(())
}
