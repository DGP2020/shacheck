use notify_rust::{Notification, Urgency};
use std::collections::HashSet;
use crate::audit_log::{AuditEvent, ChangeType};
use crate::error::FsimError;

/// Sends at most two bundled desktop notifications per audit run:
///   - One Critical notification for sensitive path anomalies (if any)
///   - One Normal notification for all other anomalies (if any)
///
/// Bodies summarise affected parent directories to avoid per-file spam.
pub fn send_bundled_notifications(events: &[AuditEvent]) -> Result<(), FsimError> {
    let critical_events: Vec<&AuditEvent> = events.iter().filter(|e| e.is_sensitive).collect();
    let normal_events: Vec<&AuditEvent> = events.iter().filter(|e| !e.is_sensitive).collect();

    if !critical_events.is_empty() {
        let summary = build_summary(&critical_events);
        Notification::new()
            .summary(&format!(
                "⚠ CRITICAL: {} sensitive file anomal{}",
                critical_events.len(),
                if critical_events.len() == 1 { "y" } else { "ies" }
            ))
            .body(&summary)
            .urgency(Urgency::Critical)
            .icon("security-high")
            .show()
            .map_err(|e| FsimError::Notification(e.to_string()))?;
    }

    if !normal_events.is_empty() {
        let summary = build_summary(&normal_events);
        Notification::new()
            .summary(&format!(
                "shakti_fsim: {} filesystem anomal{}",
                normal_events.len(),
                if normal_events.len() == 1 { "y" } else { "ies" }
            ))
            .body(&summary)
            .urgency(Urgency::Normal)
            .icon("dialog-warning")
            .show()
            .map_err(|e| FsimError::Notification(e.to_string()))?;
    }

    Ok(())
}

/// Builds a compact summary string grouping events by parent directory.
/// Example: "3 changes in /etc, /var/log\n  • 2 MODIFIED, 1 DELETED"
fn build_summary(events: &[&AuditEvent]) -> String {
    // Collect unique parent directories
    let dirs: HashSet<String> = events
        .iter()
        .map(|e| {
            std::path::Path::new(&e.path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| e.path.clone())
        })
        .collect();

    let mut sorted_dirs: Vec<String> = dirs.into_iter().collect();
    sorted_dirs.sort();

    // Count by change type
    let modified = events.iter().filter(|e| e.change_type == ChangeType::Modified).count();
    let new_files = events.iter().filter(|e| e.change_type == ChangeType::New).count();
    let deleted = events.iter().filter(|e| e.change_type == ChangeType::Deleted).count();

    let mut type_parts = Vec::new();
    if modified > 0 { type_parts.push(format!("{} MODIFIED", modified)); }
    if new_files > 0 { type_parts.push(format!("{} NEW", new_files)); }
    if deleted > 0  { type_parts.push(format!("{} DELETED", deleted)); }

    format!(
        "Affected: {}\n{}",
        sorted_dirs.join(", "),
        type_parts.join(" | ")
    )
}
