mod audit_log;
mod error;
mod hasher;
mod manual;
mod notifier;
mod scanner;
mod sensitive_paths;
mod shaktidb;

use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::Path;
use std::process::exit;

use audit_log::{AuditEvent, ChangeType};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "shakti_fsim")]
#[command(about = "ShaktiDB-backed File System Integrity Monitor", long_about = None)]
struct Cli {
    /// ShaktiDB (PostgreSQL wire-compatible) connection string
    #[arg(
        short,
        long,
        default_value = "postgresql://postgres:postgres@localhost:5432/shaktidb"
    )]
    db: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new baseline and store it in ShaktiDB
    Baseline {
        /// Target directory path to baseline
        #[arg(short, long)]
        target: String,
    },

    /// Audit a directory against the stored ShaktiDB baseline
    Check {
        /// Target directory path to verify
        #[arg(short, long)]
        target: String,
    },

    /// Manage sensitive paths that trigger Critical notifications
    Paths {
        #[command(subcommand)]
        action: PathsAction,
    },

    /// Print the Unix Manual (man) page
    Man,
}

#[derive(Subcommand)]
enum PathsAction {
    /// List all registered sensitive paths
    List,
    /// Add a sensitive path
    Add {
        /// Absolute path prefix to mark as sensitive
        path: String,
    },
    /// Remove a sensitive path
    Remove {
        /// Absolute path prefix to deregister
        path: String,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    // Man page is DB-independent — handle immediately
    if let Commands::Man = cli.command {
        println!("{}", manual::get_man_page());
        exit(0);
    }

    // Connect to ShaktiDB
    println!("[*] Connecting to ShaktiDB backend...");
    let mut db = match shaktidb::ShaktiDbClient::connect(&cli.db) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] Fatal DB connection failure: {}", e);
            exit(1);
        }
    };

    if let Err(e) = db.initialize_schema() {
        eprintln!("[-] Failed to initialize ShaktiDB schema: {}", e);
        exit(1);
    }

    match cli.command {
        // ----------------------------------------------------------------
        // baseline
        // ----------------------------------------------------------------
        Commands::Baseline { target } => {
            println!("[*] Initializing baseline scan on: {}", target);
            let mut records = Vec::new();
            if let Err(e) = scanner::scan_directory(Path::new(&target), &mut records) {
                eprintln!("[-] Scan failed: {}", e);
                exit(1);
            }

            println!("[*] Found {} files. Saving to ShaktiDB...", records.len());
            if let Err(e) = db.save_baseline(&records) {
                eprintln!("[-] Failed to persist baseline: {}", e);
                exit(1);
            }
            println!("[+] Baseline successfully locked in ShaktiDB.");
        }

        // ----------------------------------------------------------------
        // check
        // ----------------------------------------------------------------
        Commands::Check { target } => {
            // Fetch baseline
            println!("[*] Fetching known-good baseline from ShaktiDB...");
            let baseline_records = match db.get_baseline() {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[-] Failed to fetch baseline: {}", e);
                    exit(1);
                }
            };

            let baseline_map: HashMap<String, scanner::FileRecord> = baseline_records
                .into_iter()
                .map(|r| (r.path.clone(), r))
                .collect();

            // Fetch sensitive paths
            let sensitive = match sensitive_paths::get_sensitive_paths(&mut db.client) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[-] Failed to load sensitive paths: {}", e);
                    exit(1);
                }
            };

            // Scan current state
            println!("[*] Scanning filesystem target: {}...", target);
            let mut current_records = Vec::new();
            if let Err(e) = scanner::scan_directory(Path::new(&target), &mut current_records) {
                eprintln!("[-] Scan failed: {}", e);
                exit(1);
            }

            // Compare and collect anomalies
            println!("\n-------------------- AUDIT REPORT --------------------");
            let mut anomalies: Vec<AuditEvent> = Vec::new();
            let mut current_map: HashMap<String, scanner::FileRecord> = HashMap::new();

            for rec in current_records {
                current_map.insert(rec.path.clone(), rec.clone());

                match baseline_map.get(&rec.path) {
                    Some(baseline_rec) if baseline_rec.hash != rec.hash => {
                        let is_sensitive = sensitive_paths::is_sensitive(&rec.path, &sensitive);
                        println!("[!] MODIFIED: {} (hash mismatch)", rec.path);
                        anomalies.push(AuditEvent {
                            path: rec.path,
                            change_type: ChangeType::Modified,
                            is_sensitive,
                        });
                    }
                    None => {
                        let is_sensitive = sensitive_paths::is_sensitive(&rec.path, &sensitive);
                        println!("[?] UNTRACKED/NEW: {}", rec.path);
                        anomalies.push(AuditEvent {
                            path: rec.path,
                            change_type: ChangeType::New,
                            is_sensitive,
                        });
                    }
                    _ => {} // hash matches — file is clean
                }
            }

            // Detect deletions
            for (path, _) in &baseline_map {
                if !current_map.contains_key(path) {
                    let is_sensitive = sensitive_paths::is_sensitive(path, &sensitive);
                    println!("[-] DELETED: {} (missing from disk)", path);
                    anomalies.push(AuditEvent {
                        path: path.clone(),
                        change_type: ChangeType::Deleted,
                        is_sensitive,
                    });
                }
            }

            println!("------------------------------------------------------");

            // Persist audit events to ShaktiDB (LRU-capped)
            if !anomalies.is_empty() {
                if let Err(e) = audit_log::persist_audit_events(&mut db.client, &anomalies) {
                    eprintln!("[!] Warning: failed to persist audit log: {}", e);
                    // Non-fatal — continue to notification and exit code
                }
            }

            // Fire bundled desktop notifications
            if !anomalies.is_empty() {
                if let Err(e) = notifier::send_bundled_notifications(&anomalies) {
                    eprintln!("[!] Warning: desktop notification failed: {}", e);
                }
            }

            // Final status
            if anomalies.is_empty() {
                println!("[+] Status: SECURE. No filesystem anomalies detected.");
                exit(0);
            } else {
                let critical = anomalies.iter().filter(|e| e.is_sensitive).count();
                let normal = anomalies.len() - critical;
                if critical > 0 {
                    println!(
                        "[!] Status: CRITICAL. {} sensitive + {} other anomalies detected!",
                        critical, normal
                    );
                } else {
                    println!(
                        "[!] Status: WARNING. {} filesystem anomalies detected.",
                        normal
                    );
                }
                exit(1);
            }
        }

        // ----------------------------------------------------------------
        // paths
        // ----------------------------------------------------------------
        Commands::Paths { action } => match action {
            PathsAction::List => {
                match sensitive_paths::get_sensitive_paths(&mut db.client) {
                    Ok(paths) if paths.is_empty() => {
                        println!("[*] No sensitive paths registered.");
                    }
                    Ok(paths) => {
                        println!("[*] Registered sensitive paths ({}):", paths.len());
                        for p in paths {
                            println!("    {}", p);
                        }
                    }
                    Err(e) => {
                        eprintln!("[-] Failed to list paths: {}", e);
                        exit(1);
                    }
                }
            }

            PathsAction::Add { path } => {
                match sensitive_paths::add_sensitive_path(&mut db.client, &path) {
                    Ok(true) => println!("[+] Added sensitive path: {}", path),
                    Ok(false) => println!("[*] Path already registered: {}", path),
                    Err(e) => {
                        eprintln!("[-] Failed to add path: {}", e);
                        exit(1);
                    }
                }
            }

            PathsAction::Remove { path } => {
                match sensitive_paths::remove_sensitive_path(&mut db.client, &path) {
                    Ok(true) => println!("[+] Removed sensitive path: {}", path),
                    Ok(false) => println!("[*] Path not found in registry: {}", path),
                    Err(e) => {
                        eprintln!("[-] Failed to remove path: {}", e);
                        exit(1);
                    }
                }
            }
        },

        Commands::Man => unreachable!(),
    }
}
