use postgres::Client;
use crate::error::FsimError;

/// Hardcoded defaults loaded on first run if the table is empty
const DEFAULT_SENSITIVE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssh",
    "/etc/crontab",
    "/etc/cron.d",
    "/var/log",
    "/audit",
    "/boot",
];

/// Initializes the sensitive_paths table and seeds defaults if empty
pub fn initialize_sensitive_paths_schema(client: &mut Client) -> Result<(), FsimError> {
    client.batch_execute("
        CREATE TABLE IF NOT EXISTS sensitive_paths (
            path TEXT PRIMARY KEY
        );
    ")?;

    // Seed defaults only if the table is currently empty
    let count: i64 = client
        .query_one("SELECT COUNT(*) FROM sensitive_paths", &[])?
        .get(0);

    if count == 0 {
        let mut tx = client.transaction()?;
        for path in DEFAULT_SENSITIVE_PATHS {
            tx.execute(
                "INSERT INTO sensitive_paths (path) VALUES ($1) ON CONFLICT DO NOTHING",
                &[path],
            )?;
        }
        tx.commit()?;
        println!("[*] Seeded {} default sensitive paths.", DEFAULT_SENSITIVE_PATHS.len());
    }

    Ok(())
}

/// Returns all currently registered sensitive paths
pub fn get_sensitive_paths(client: &mut Client) -> Result<Vec<String>, FsimError> {
    let rows = client.query("SELECT path FROM sensitive_paths ORDER BY path ASC", &[])?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// Adds a new sensitive path; returns false if it already existed
pub fn add_sensitive_path(client: &mut Client, path: &str) -> Result<bool, FsimError> {
    let rows_affected = client.execute(
        "INSERT INTO sensitive_paths (path) VALUES ($1) ON CONFLICT DO NOTHING",
        &[&path],
    )?;
    Ok(rows_affected > 0)
}

/// Removes a sensitive path; returns false if it was not present
pub fn remove_sensitive_path(client: &mut Client, path: &str) -> Result<bool, FsimError> {
    let rows_affected = client.execute(
        "DELETE FROM sensitive_paths WHERE path = $1",
        &[&path],
    )?;
    Ok(rows_affected > 0)
}

/// Returns true if the given file path starts with any registered sensitive path
pub fn is_sensitive(file_path: &str, sensitive_paths: &[String]) -> bool {
    sensitive_paths
        .iter()
        .any(|sensitive| file_path.starts_with(sensitive.as_str()))
}
