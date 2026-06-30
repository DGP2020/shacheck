pub fn get_man_page() -> &'static str {
    r#".TH SHAKTI_FSIM 1 "JUNE 2026" "v0.1.0" "User Commands"
.SH NAME
shakti_fsim \- File System Integrity Monitor backed by ShaktiDB
.SH SYNOPSIS
.B shakti_fsim
[\fB\-d\fR|\fB\-\-db\fR \fIURI\fR] \fBSUBCOMMAND\fR [\fIOPTIONS\fR]
.SH DESCRIPTION
.B shakti_fsim
is a defensive cybersecurity CLI tool designed to crawl directories, compute
cryptographic SHA-256 baselines, and store them securely in a ShaktiDB
(PostgreSQL-compatible) instance. It detects unauthorized modifications,
zero-day payloads, and file tampering, and fires desktop notifications via
libnotify when anomalies are found.
.PP
Audit events are persisted to ShaktiDB with LRU eviction (capped at 100,000
rows or 64 MB, whichever is reached first). Sensitive paths receive
.B Critical
urgency desktop notifications; all other anomalies receive
.B Normal
urgency notifications. Both are bundled — one notification per urgency level
per run — to prevent desktop spam.
.SH GLOBAL OPTIONS
.TP
.BR \-d ", " \-\-db " " \fICONN_STR\fR
Set the ShaktiDB connection string.
.br
Default: \fBpostgresql://postgres:postgres@localhost:5432/shaktidb\fR
.SH SUBCOMMANDS
.SS baseline \-t <target_dir>
Crawls the target directory recursively, computes SHA-256 hashes for every
file, and stores the result as the known-good integrity baseline in ShaktiDB.
Re-running this command updates the baseline in place (UPSERT).
.TP
.BR \-t ", " \-\-target " " \fIDIR\fR
Path to the directory to baseline (required).
.SS check \-t <target_dir>
Scans the target directory and compares results against the stored ShaktiDB
baseline. Outputs an audit report to stdout and persists each anomaly event
to the ShaktiDB audit log. Fires desktop notifications on completion.
.TP
.BR \-t ", " \-\-target " " \fIDIR\fR
Path to the directory to audit (required).
.PP
Exit codes: 0 = secure (no anomalies), 1 = anomalies detected or fatal error.
.SS paths list
Prints all currently registered sensitive paths from ShaktiDB.
.SS paths add <path>
Registers a new sensitive path in ShaktiDB. Files under this path will trigger
.B Critical
urgency desktop notifications when modified, added, or deleted.
.TP
.I path
Absolute path prefix to mark as sensitive (e.g. /etc/cron.d).
.SS paths remove <path>
Removes a path from the sensitive paths registry in ShaktiDB. Reverts to
.B Normal
notification urgency for that path on future audits.
.TP
.I path
Absolute path prefix to deregister.
.SS man
Prints this manual page in raw troff/man format to stdout. Pipe to
.B man \-l \-
to render it in a pager:
.PP
.RS
shakti_fsim man | man -l -
.RE
.SH DEFAULT SENSITIVE PATHS
On first run the following paths are seeded automatically:
.PP
.RS
/etc/passwd, /etc/shadow, /etc/sudoers, /etc/sudoers.d,
/etc/ssh, /etc/crontab, /etc/cron.d, /var/log, /audit, /boot
.RE
.PP
These can be extended or reduced using the
.B paths add
and
.B paths remove
subcommands.
.SH AUDIT LOG
Every anomaly detected by
.B check
is written to the
.B audit_log
table in ShaktiDB. Rows are evicted LRU-style when either limit is exceeded:
.RS
.IP \(bu 2
100,000 total rows
.IP \(bu 2
64 MB total estimated size
.RE
.SH EXAMPLES
.TP
Establish a baseline for /etc:
.B shakti_fsim \-\-db "postgresql://user:pass@127.0.0.1/sdb" baseline \-t /etc
.TP
Audit /etc for tampering:
.B shakti_fsim check \-t /etc
.TP
List all sensitive paths:
.B shakti_fsim paths list
.TP
Add a custom sensitive path:
.B shakti_fsim paths add /opt/app/config
.TP
Remove a sensitive path:
.B shakti_fsim paths remove /boot
.TP
Render this manual page:
.B shakti_fsim man | man \-l \-
.SH DESKTOP NOTIFICATIONS
Requires a running notification daemon (e.g.
.BR dunst ", " mako ", " xfce4-notifyd ).
Notifications use the
.B libnotify
D-Bus interface via the
.B notify-rust
crate. Two notifications may appear per
.B check
run:
.RS
.IP \(bu 2
.B Critical
\(em sensitive path anomalies. Grouped by parent directory.
.IP \(bu 2
.B Normal
\(em all other filesystem anomalies. Grouped by parent directory.
.RE
.SH AUTHOR
Written by an Undergraduate Blue Team Specialist."#
}
