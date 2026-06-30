# shakti_fsim

A Blue Team File System Integrity Monitor for Linux, backed by **ShaktiDB** (a PostgreSQL-compatible database).

`shakti_fsim` crawls a directory, hashes every file with SHA-256, and stores the result as a known-good baseline. On later runs it re-scans the same directory and flags anything **modified**, **new**, or **deleted** — with extra-loud desktop alerts when the change touches a sensitive system path like `/etc/passwd` or `/etc/shadow`.

## Features

- Recursive directory hashing (SHA-256)
- Baseline storage and drift detection via ShaktiDB
- Persistent audit log with automatic LRU eviction (capped at 100,000 events or 64 MB, whichever comes first)
- Configurable sensitive-path registry, seeded with common system files
- Bundled desktop notifications via `libnotify` — **Critical** urgency for sensitive paths, **Normal** for everything else, grouped by directory to avoid spam
- Built-in `man` page

## Requirements

- Linux (uses `libnotify` for desktop alerts)
- [Rust toolchain](https://rustup.rs/) (stable, 2021 edition or later)
- A running ShaktiDB / PostgreSQL-compatible instance
- A notification daemon for desktop alerts (e.g. `dunst`, `mako`, or your desktop environment's built-in one — GNOME, KDE, and XFCE all ship one by default)

## Installation

Clone the repository and build with Cargo:

```bash
git clone https://github.com/<your-username>/shakti_fsim.git
cd shakti_fsim
cargo build --release
```

The compiled binary will be at `target/release/shakti_fsim`. Optionally install it to your PATH:

```bash
cargo install --path .
```

## Database Setup

`shakti_fsim` connects to any PostgreSQL wire-compatible database (ShaktiDB or vanilla PostgreSQL). Tables are created automatically on first run — no manual schema setup required.

By default it connects to:

```
postgresql://postgres:postgres@localhost:5432/shaktidb
```

Override this with `-d` / `--db` on any command, or by creating the database ahead of time:

```bash
createdb shaktidb
```

## Usage

### 1. Establish a baseline

Scan a directory and record its current state as "known good":

```bash
shakti_fsim --db "postgresql://user:pass@127.0.0.1/shaktidb" baseline -t /etc
```

Re-running `baseline` on the same target updates the existing baseline.

### 2. Audit for drift

Compare the current filesystem state against the stored baseline:

```bash
shakti_fsim check -t /etc
```

Example output:

```
-------------------- AUDIT REPORT --------------------
[!] MODIFIED: /etc/passwd (hash mismatch)
[?] UNTRACKED/NEW: /etc/newfile.conf
[-] DELETED: /etc/old.conf (missing from disk)
------------------------------------------------------
[!] Status: CRITICAL. 1 sensitive + 2 other anomalies detected!
```

Every anomaly is written to the ShaktiDB audit log, and a desktop notification is fired summarizing the changes. Exit code is `0` if no anomalies were found, `1` otherwise — useful for cron jobs or CI checks.

### 3. Manage sensitive paths

Files under these paths trigger **Critical** urgency notifications instead of Normal.

```bash
# List current sensitive paths
shakti_fsim paths list

# Add a custom sensitive path
shakti_fsim paths add /opt/app/config

# Remove a path from the registry
shakti_fsim paths remove /boot
```

Defaults seeded on first run: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d`, `/etc/ssh`, `/etc/crontab`, `/etc/cron.d`, `/var/log`, `/audit`, `/boot`.

### 4. View the manual

```bash
shakti_fsim man | man -l -
```

## Automating Audits

To run periodic checks via cron, e.g. every 15 minutes:

```cron
*/15 * * * * /usr/local/bin/shakti_fsim check -t /etc >> /var/log/shakti_fsim.log 2>&1
```

Desktop notifications require an active user session with a notification daemon running (D-Bus session bus), so cron jobs running as a system service may not show GUI alerts — the audit log in ShaktiDB and exit code remain the reliable signal in that case.

## Project Structure

```
src/
├── main.rs             CLI entry point and command dispatch
├── scanner.rs           Recursive directory walker and hashing
├── hasher.rs             SHA-256 file hashing
├── shaktidb.rs           ShaktiDB connection and schema management
├── audit_log.rs          Audit log persistence with LRU eviction
├── sensitive_paths.rs     Sensitive path registry
├── notifier.rs            Bundled desktop notifications
├── error.rs               Unified error type
└── manual.rs              Man page content
```

MIT License
