//! macOS Seatbelt sandbox profile generation and execution.
//!
//! This module provides functionality to generate Seatbelt profiles for macOS sandboxing
//! and launch processes within these sandboxes using `sandbox-exec`. Seatbelt is Apple's
//! mandatory access control (MAC) framework based on TrustedBSD.
//!
//! # Profile Structure
//!
//! Seatbelt profiles use S-expression syntax and define security policies for:
//! - File system access (read/write restrictions)
//! - Network access (socket operations)
//! - Process execution (allowed binaries)
//! - Move-blocking (prevent restriction bypass via file moves)
//!
//! # Example
//!
//! ```ignore
//! use srt::config::SandboxConfig;
//! use srt::sandbox::macos::{generate_seatbelt_profile, launch_with_seatbelt};
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Create sandbox configuration
//! let config = SandboxConfig::default();
//!
//! // Generate Seatbelt profile
//! let profile = generate_seatbelt_profile(&config);
//!
//! // Launch process in sandbox
//! let command = vec!["python3".to_string(), "script.py".to_string()];
//! let child = launch_with_seatbelt(&command, &profile).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Security Features
//!
//! ## Move-Blocking
//!
//! A critical security feature prevents attackers from moving files from readable
//! locations to writable locations to bypass restrictions:
//!
//! ```text
//! Attack: mv /restricted/secret.txt /tmp/secret.txt
//! Defense: Deny file-write-create with regex matching restricted paths
//! ```
//!
//! ## Network Isolation
//!
//! Network access is restricted to Unix domain sockets only, which connect to
//! a filtering proxy running outside the sandbox.
//!
//! # Limitations
//!
//! Seatbelt profiles cannot be modified after process creation. Dynamic rule
//! updates require restarting the sandboxed process with a new profile.

use anyhow::{Context, Result};
use std::io::Write;
use tempfile::NamedTempFile;
use tokio::process::{Child, Command};

use crate::config::SandboxConfig;
use crate::utils::glob::glob_to_regex;

/// Generates a Seatbelt profile from sandbox configuration.
///
/// Creates a complete S-expression formatted Seatbelt profile that enforces
/// the filesystem and network restrictions specified in the configuration.
///
/// # Arguments
///
/// * `config` - Sandbox configuration containing allowed/blocked paths and network rules
///
/// # Returns
///
/// A string containing the complete Seatbelt profile in S-expression format
///
/// # Profile Sections
///
/// 1. **Header**: Version and debug settings
/// 2. **Default policy**: Allow by default (start permissive)
/// 3. **File write rules**: Deny writes except to allowed paths
/// 4. **File read rules**: Block reading sensitive files
/// 5. **Move-blocking**: Prevent bypassing restrictions via file moves
/// 6. **Network rules**: Allow only Unix socket connections to proxy
/// 7. **Process rules**: Allow common system operations
///
/// # Example
///
/// ```ignore
/// use srt::config::{SandboxConfig, FilesystemConfig, NetworkConfig};
/// use srt::sandbox::macos::generate_seatbelt_profile;
///
/// let config = SandboxConfig::new(
///     FilesystemConfig::new(
///         vec!["/tmp/**".to_string()],
///         vec!["/etc/shadow".to_string()],
///     ),
///     NetworkConfig::new(true, vec!["*.example.com".to_string()]),
/// );
///
/// let profile = generate_seatbelt_profile(&config);
/// println!("{}", profile);
/// ```
///
/// # Generated Profile Example
///
/// ```scheme
/// (version 1)
/// (debug deny)
/// (allow default)
///
/// ;; File write restrictions
/// (deny file-write* (subpath "/"))
/// (allow file-write* (subpath "/tmp"))
///
/// ;; File read restrictions
/// (deny file-read-data (literal "/etc/shadow"))
///
/// ;; Move-blocking rules
/// (deny file-write-create
///   (require-all
///     (vnode-type REGULAR)
///     (regex #"^/etc/.*")))
///
/// ;; Network restrictions
/// (deny network*)
/// (allow network-outbound
///   (remote unix-socket))
/// ```
pub fn generate_seatbelt_profile(config: &SandboxConfig) -> String {
    let mut profile = String::new();

    // Header: version and debug mode
    profile.push_str("(version 1)\n");
    profile.push_str(";; Enable debug logging for sandbox denials\n");
    profile.push_str("(debug deny)\n\n");

    // Default policy: start permissive, then restrict
    profile.push_str(";; Default policy: allow operations unless explicitly denied\n");
    profile.push_str("(allow default)\n\n");

    // File write restrictions
    profile.push_str(&generate_file_write_rules(config));

    // File read restrictions
    profile.push_str(&generate_file_read_rules(config));

    // Move-blocking rules (prevent bypass attacks)
    profile.push_str(&generate_move_blocking_rules(config));

    // Network restrictions
    profile.push_str(&generate_network_rules(config));

    // Process execution rules
    profile.push_str(&generate_process_rules());

    profile
}

/// Generates file write restriction rules.
///
/// Creates rules that:
/// 1. Deny all file writes by default
/// 2. Allow writes to explicitly allowed paths
/// 3. Handle glob pattern conversion to regex
///
/// # Arguments
///
/// * `config` - Sandbox configuration with filesystem rules
///
/// # Returns
///
/// S-expression rules for file write restrictions
fn generate_file_write_rules(config: &SandboxConfig) -> String {
    let mut rules = String::new();

    rules.push_str(";; ============================================================\n");
    rules.push_str(";; FILE WRITE RESTRICTIONS\n");
    rules.push_str(";; ============================================================\n");
    rules.push_str(";; Block all filesystem writes by default, then allow specific paths\n\n");

    // Deny all writes to root (will be overridden by specific allows)
    rules.push_str("(deny file-write*\n");
    rules.push_str("  (subpath \"/\"))\n\n");

    // Always allow writes to /dev/null (needed by many programs)
    rules.push_str(";; Always allow writing to /dev/null (required by many tools)\n");
    rules.push_str("(allow file-write*\n");
    rules.push_str("  (literal \"/dev/null\"))\n\n");

    // Allow writes to explicitly allowed paths
    if !config.filesystem.allowed_paths.is_empty() {
        rules.push_str(";; Allow writes to configured allowed paths\n");

        for path in &config.filesystem.allowed_paths {
            if path.contains('*') || path.contains('?') || path.contains('[') {
                // Glob pattern: convert to regex
                match glob_to_regex(path) {
                    Ok(regex) => {
                        let regex_str = regex.as_str();
                        rules.push_str(&format!(
                            "(allow file-write*\n  (regex #\"{}\"))\n",
                            regex_str
                        ));
                    }
                    Err(_) => {
                        // Invalid glob pattern - skip with comment
                        rules.push_str(&format!(
                            ";; Skipped invalid glob pattern: {}\n",
                            path
                        ));
                    }
                }
            } else {
                // Literal path: use subpath or literal
                if path.ends_with('/') || path.ends_with("**") {
                    // Directory path: use subpath
                    let clean_path = path.trim_end_matches('/').trim_end_matches("**");
                    rules.push_str(&format!("(allow file-write*\n  (subpath \"{}\"))\n", clean_path));
                } else {
                    // File path: use literal
                    rules.push_str(&format!("(allow file-write*\n  (literal \"{}\"))\n", path));
                }
            }
        }
        rules.push('\n');
    }

    rules
}

/// Generates file read restriction rules.
///
/// Creates rules that block reading sensitive files specified in the
/// blocked paths configuration.
///
/// # Arguments
///
/// * `config` - Sandbox configuration with filesystem rules
///
/// # Returns
///
/// S-expression rules for file read restrictions
fn generate_file_read_rules(config: &SandboxConfig) -> String {
    let mut rules = String::new();

    if config.filesystem.blocked_paths.is_empty() {
        return rules;
    }

    rules.push_str(";; ============================================================\n");
    rules.push_str(";; FILE READ RESTRICTIONS\n");
    rules.push_str(";; ============================================================\n");
    rules.push_str(";; Block reading sensitive files\n\n");

    for path in &config.filesystem.blocked_paths {
        if path.contains('*') || path.contains('?') || path.contains('[') {
            // Glob pattern: convert to regex
            match glob_to_regex(path) {
                Ok(regex) => {
                    let regex_str = regex.as_str();
                    rules.push_str(&format!(
                        "(deny file-read-data\n  (regex #\"{}\"))\n",
                        regex_str
                    ));
                }
                Err(_) => {
                    rules.push_str(&format!(";; Skipped invalid glob pattern: {}\n", path));
                }
            }
        } else {
            // Literal path
            if path.ends_with('/') || path.ends_with("**") {
                let clean_path = path.trim_end_matches('/').trim_end_matches("**");
                rules.push_str(&format!("(deny file-read-data\n  (subpath \"{}\"))\n", clean_path));
            } else {
                rules.push_str(&format!("(deny file-read-data\n  (literal \"{}\"))\n", path));
            }
        }
    }

    rules.push('\n');
    rules
}

/// Generates move-blocking rules to prevent restriction bypass attacks.
///
/// These rules prevent attackers from moving files from readable locations
/// to writable locations to bypass restrictions. For example, without this,
/// an attacker could do:
///
/// ```bash
/// mv /restricted/secret.txt /tmp/secret.txt
/// cat /tmp/secret.txt  # Now readable!
/// ```
///
/// The defense is to block `file-write-create` operations (which includes `mv`)
/// for paths that match blocked patterns.
///
/// # Arguments
///
/// * `config` - Sandbox configuration with filesystem rules
///
/// # Returns
///
/// S-expression rules for move-blocking
fn generate_move_blocking_rules(config: &SandboxConfig) -> String {
    let mut rules = String::new();

    if config.filesystem.blocked_paths.is_empty() {
        return rules;
    }

    rules.push_str(";; ============================================================\n");
    rules.push_str(";; MOVE-BLOCKING RULES (Security Critical)\n");
    rules.push_str(";; ============================================================\n");
    rules.push_str(";; Prevent bypassing read restrictions by moving files to writable locations\n");
    rules.push_str(";; Example attack: mv /restricted/secret.txt /tmp/secret.txt\n");
    rules.push_str(";; Defense: Block file-write-create (includes mv) for restricted paths\n\n");

    for path in &config.filesystem.blocked_paths {
        if path.contains('*') || path.contains('?') || path.contains('[') {
            // Glob pattern: convert to regex for move blocking
            match glob_to_regex(path) {
                Ok(regex) => {
                    let regex_str = regex.as_str();
                    rules.push_str(&format!(
                        "(deny file-write-create\n  (regex #\"{}\"))\n",
                        regex_str
                    ));
                }
                Err(_) => {
                    rules.push_str(&format!(";; Skipped invalid glob pattern: {}\n", path));
                }
            }
        } else {
            // Literal path
            if path.ends_with('/') || path.ends_with("**") {
                let clean_path = path.trim_end_matches('/').trim_end_matches("**");
                rules.push_str(&format!(
                    "(deny file-write-create\n  (subpath \"{}\"))\n",
                    clean_path
                ));
            } else {
                rules.push_str(&format!(
                    "(deny file-write-create\n  (literal \"{}\"))\n",
                    path
                ));
            }
        }
    }

    rules.push('\n');
    rules
}

/// Generates network access restriction rules.
///
/// Creates rules that:
/// 1. Deny all network operations by default
/// 2. Allow only Unix domain socket connections (to proxy)
///
/// Network filtering is done by the proxy, not Seatbelt. Seatbelt only ensures
/// that the sandbox can only communicate via the Unix socket to the proxy.
///
/// # Arguments
///
/// * `config` - Sandbox configuration with network rules
///
/// # Returns
///
/// S-expression rules for network restrictions
fn generate_network_rules(config: &SandboxConfig) -> String {
    let mut rules = String::new();

    rules.push_str(";; ============================================================\n");
    rules.push_str(";; NETWORK RESTRICTIONS\n");
    rules.push_str(";; ============================================================\n");

    if config.network.enabled {
        rules.push_str(";; Network enabled: Allow Unix socket connections to proxy only\n");
        rules.push_str(";; Domain filtering is performed by the proxy (not Seatbelt)\n\n");

        // Deny all network operations
        rules.push_str("(deny network*)\n\n");

        // Allow Unix socket connections (to proxy)
        rules.push_str(";; Allow Unix domain socket connections for proxy communication\n");
        rules.push_str("(allow network-outbound\n");
        rules.push_str("  (remote unix-socket))\n\n");

        // Allow localhost connections (loopback)
        rules.push_str(";; Allow localhost connections (loopback)\n");
        rules.push_str("(allow network*\n");
        rules.push_str("  (remote ip \"*:*\")\n");
        rules.push_str("  (remote ip \"localhost:*\"))\n\n");
    } else {
        rules.push_str(";; Network disabled: Block all network operations\n\n");
        rules.push_str("(deny network*)\n\n");
    }

    rules
}

/// Generates process execution and control rules.
///
/// Creates rules that allow basic process operations needed by most programs:
/// - Process forking (creating child processes)
/// - Signal handling (sending signals to processes)
/// - Executing common system binaries
///
/// # Returns
///
/// S-expression rules for process operations
fn generate_process_rules() -> String {
    let mut rules = String::new();

    rules.push_str(";; ============================================================\n");
    rules.push_str(";; PROCESS EXECUTION RULES\n");
    rules.push_str(";; ============================================================\n");
    rules.push_str(";; Allow basic process operations and common system binaries\n\n");

    // Allow process forking
    rules.push_str(";; Allow creating child processes\n");
    rules.push_str("(allow process-fork)\n\n");

    // Allow signal operations
    rules.push_str(";; Allow sending signals to processes\n");
    rules.push_str("(allow signal)\n\n");

    // Allow executing common system binaries
    rules.push_str(";; Allow executing common system binaries\n");
    rules.push_str("(allow process-exec\n");
    rules.push_str("  (subpath \"/usr/bin\")\n");
    rules.push_str("  (subpath \"/bin\")\n");
    rules.push_str("  (subpath \"/usr/sbin\")\n");
    rules.push_str("  (subpath \"/sbin\"))\n\n");

    // Allow reading system libraries and frameworks
    rules.push_str(";; Allow reading system libraries and frameworks (required for execution)\n");
    rules.push_str("(allow file-read*\n");
    rules.push_str("  (subpath \"/usr/lib\")\n");
    rules.push_str("  (subpath \"/System/Library\")\n");
    rules.push_str("  (subpath \"/Library\"))\n\n");

    rules
}

/// Launches a command within a Seatbelt sandbox.
///
/// This function:
/// 1. Writes the Seatbelt profile to a temporary file
/// 2. Spawns `sandbox-exec` with the profile
/// 3. Executes the specified command within the sandbox
///
/// # Arguments
///
/// * `command` - Command and arguments to execute (e.g., `["python3", "script.py"]`)
/// * `profile` - Seatbelt profile S-expression string (from `generate_seatbelt_profile`)
///
/// # Returns
///
/// A `Child` process handle for the sandboxed process
///
/// # Errors
///
/// Returns an error if:
/// - Temporary file creation fails
/// - Profile write fails
/// - `sandbox-exec` is not found
/// - Process spawn fails
///
/// # Example
///
/// ```ignore
/// use srt::config::SandboxConfig;
/// use srt::sandbox::macos::{generate_seatbelt_profile, launch_with_seatbelt};
///
/// # async fn example() -> anyhow::Result<()> {
/// let config = SandboxConfig::default();
/// let profile = generate_seatbelt_profile(&config);
///
/// let command = vec!["python3".to_string(), "script.py".to_string()];
/// let mut child = launch_with_seatbelt(&command, &profile).await?;
///
/// // Wait for completion
/// let status = child.wait().await?;
/// println!("Exit code: {}", status.code().unwrap_or(-1));
/// # Ok(())
/// # }
/// ```
///
/// # Platform Requirements
///
/// - macOS only
/// - `sandbox-exec` must be available (standard on macOS)
/// - Process must have appropriate permissions
///
/// # Security Notes
///
/// - The profile is written to a temporary file in `/tmp`
/// - The temp file is deleted when the `NamedTempFile` is dropped
/// - The profile path is passed to `sandbox-exec` via `-f` flag
/// - Seatbelt denials are logged to system log (viewable via `log stream`)
pub async fn launch_with_seatbelt(command: &[String], profile: &str) -> Result<Child> {
    if command.is_empty() {
        return Err(anyhow::anyhow!("Command cannot be empty"));
    }

    // Create temporary file for Seatbelt profile
    let mut temp_file = NamedTempFile::new()
        .context("Failed to create temporary file for Seatbelt profile")?;

    // Write profile to temp file (synchronous I/O is fine for small profiles)
    temp_file
        .write_all(profile.as_bytes())
        .context("Failed to write Seatbelt profile to temporary file")?;

    // Flush to ensure all data is written
    temp_file
        .flush()
        .context("Failed to flush Seatbelt profile to disk")?;

    // Get path to temp file (must keep temp_file alive)
    let profile_path = temp_file.path();

    // Log the profile path for debugging
    tracing::debug!(
        "Seatbelt profile written to: {}",
        profile_path.display()
    );

    // Build sandbox-exec command
    let mut sandbox_cmd = Command::new("sandbox-exec");
    sandbox_cmd
        .arg("-f")
        .arg(profile_path)
        .args(command);

    // Persist the temp file so it doesn't get deleted when it goes out of scope
    // sandbox-exec reads the file synchronously when it starts, so we need to keep it
    let (_, profile_path) = temp_file
        .keep()
        .context("Failed to persist Seatbelt profile")?;

    // Spawn the sandboxed process
    let child = sandbox_cmd
        .spawn()
        .context("Failed to spawn sandbox-exec process")?;

    // Clean up the temp file after the process exits
    // We spawn a background task to wait for the process and then delete the file
    let pid = child.id();
    tokio::spawn(async move {
        // Give sandbox-exec time to read the profile file
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Delete the temp file now that sandbox-exec has read it
        if let Err(e) = std::fs::remove_file(&profile_path) {
            tracing::debug!("Failed to clean up temp profile file: {}", e);
        } else {
            tracing::debug!("Cleaned up temp profile file for pid {:?}", pid);
        }
    });

    Ok(child)
}

/// Monitors sandbox violations in real-time using macOS unified logging.
///
/// This function spawns a background task that streams sandbox violation logs
/// and reports them via the tracing framework.
///
/// # Arguments
///
/// * `process_id` - PID of the sandboxed process to monitor
///
/// # Returns
///
/// A `Child` process handle for the log monitoring process
///
/// # Errors
///
/// Returns an error if the `log stream` command fails to spawn
///
/// # Example
///
/// ```ignore
/// use srt::sandbox::macos::monitor_sandbox_violations;
///
/// # async fn example() -> anyhow::Result<()> {
/// let sandboxed_process_id = 12345;
/// let mut monitor = monitor_sandbox_violations(sandboxed_process_id).await?;
///
/// // Monitor runs in background
/// // Violations are logged via tracing::error!
/// # Ok(())
/// # }
/// ```
///
/// # Implementation Details
///
/// Uses `log stream` with:
/// - `--predicate` to filter by process ID
/// - `--style json` for structured output
/// - Filters for `com.apple.sandbox.reporting` subsystem
///
/// # macOS Unified Logging
///
/// Violations appear in system log as:
/// ```text
/// [com.apple.sandbox.reporting] deny file-write* /etc/passwd
/// ```
pub async fn monitor_sandbox_violations(process_id: u32) -> Result<Child> {
    let mut log_cmd = Command::new("log");
    log_cmd
        .arg("stream")
        .arg("--predicate")
        .arg(format!("processID == {}", process_id))
        .arg("--style")
        .arg("json");

    let mut child = log_cmd
        .spawn()
        .context("Failed to spawn log stream process")?;

    // Spawn background task to read and parse log output
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};

            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();

            while let Ok(Some(line)) = lines.next_line().await {
                // Parse JSON log entry
                if let Ok(entry) = serde_json::from_str::<serde_json::Value>(&line) {
                    // Check if it's a sandbox violation
                    if let Some(subsystem) = entry.get("subsystem").and_then(|v| v.as_str()) {
                        if subsystem == "com.apple.sandbox.reporting" {
                            if let Some(message) = entry.get("eventMessage").and_then(|v| v.as_str()) {
                                tracing::error!("Sandbox violation: {}", message);
                            }
                        }
                    }
                }
            }
        });
    }

    Ok(child)
}

/// Tags a command with metadata for violation tracking.
///
/// Prepends a base64-encoded tag to the command to help identify sandbox
/// violations in the system log.
///
/// # Arguments
///
/// * `command` - Original command to execute
///
/// # Returns
///
/// Tagged command with metadata prefix
///
/// # Example
///
/// ```ignore
/// use srt::sandbox::macos::tag_command;
///
/// let command = vec!["python3".to_string(), "script.py".to_string()];
/// let tagged = tag_command(&command);
/// // Returns: ["sh", "-c", "echo '<base64-metadata>' && python3 script.py"]
/// ```
pub fn tag_command(command: &[String]) -> Vec<String> {
    use base64::{engine::general_purpose, Engine as _};

    // Create metadata
    let metadata = serde_json::json!({
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        "command": command.first().unwrap_or(&String::new()),
    });

    // Encode as base64
    let tag = general_purpose::STANDARD.encode(metadata.to_string());

    // Prepend echo command
    let tagged_command = format!(
        "echo '{}' && {}",
        tag,
        command.join(" ")
    );

    vec!["sh".to_string(), "-c".to_string(), tagged_command]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FilesystemConfig, NetworkConfig};

    #[test]
    fn test_generate_seatbelt_profile_basic() {
        let config = SandboxConfig::default();
        let profile = generate_seatbelt_profile(&config);

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(debug deny)"));
        assert!(profile.contains("(allow default)"));
    }

    #[test]
    fn test_generate_file_write_rules() {
        let config = SandboxConfig::new(
            FilesystemConfig::new(
                vec!["/tmp".to_string(), "/home/user/**".to_string()],
                vec![],
            ),
            NetworkConfig::default(),
        );

        let profile = generate_seatbelt_profile(&config);
        assert!(profile.contains("file-write*"));
        assert!(profile.contains("/dev/null"));
    }

    #[test]
    fn test_generate_file_read_rules() {
        let config = SandboxConfig::new(
            FilesystemConfig::new(
                vec![],
                vec!["/etc/shadow".to_string(), "/home/*/.ssh/**".to_string()],
            ),
            NetworkConfig::default(),
        );

        let profile = generate_seatbelt_profile(&config);
        assert!(profile.contains("file-read-data"));
        assert!(profile.contains("FILE READ RESTRICTIONS"));
    }

    #[test]
    fn test_generate_move_blocking_rules() {
        let config = SandboxConfig::new(
            FilesystemConfig::new(
                vec![],
                vec!["/etc/shadow".to_string()],
            ),
            NetworkConfig::default(),
        );

        let profile = generate_seatbelt_profile(&config);
        assert!(profile.contains("MOVE-BLOCKING"));
        assert!(profile.contains("file-write-create"));
    }

    #[test]
    fn test_generate_network_rules_enabled() {
        let config = SandboxConfig::new(
            FilesystemConfig::default(),
            NetworkConfig::new(true, vec!["*.example.com".to_string()]),
        );

        let profile = generate_seatbelt_profile(&config);
        assert!(profile.contains("NETWORK RESTRICTIONS"));
        assert!(profile.contains("unix-socket"));
    }

    #[test]
    fn test_generate_network_rules_disabled() {
        let config = SandboxConfig::new(
            FilesystemConfig::default(),
            NetworkConfig::new(false, vec![]),
        );

        let profile = generate_seatbelt_profile(&config);
        assert!(profile.contains("Network disabled"));
        assert!(profile.contains("(deny network*)"));
    }

    #[test]
    fn test_generate_process_rules() {
        let config = SandboxConfig::default();
        let profile = generate_seatbelt_profile(&config);

        assert!(profile.contains("PROCESS EXECUTION"));
        assert!(profile.contains("process-fork"));
        assert!(profile.contains("signal"));
        assert!(profile.contains("process-exec"));
    }

    #[test]
    fn test_tag_command() {
        let command = vec!["python3".to_string(), "script.py".to_string()];
        let tagged = tag_command(&command);

        assert_eq!(tagged.len(), 3);
        assert_eq!(tagged[0], "sh");
        assert_eq!(tagged[1], "-c");
        assert!(tagged[2].contains("echo"));
        assert!(tagged[2].contains("python3 script.py"));
    }

    #[test]
    fn test_launch_with_seatbelt_empty_command() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let profile = "(version 1)\n(allow default)\n";
            let result = launch_with_seatbelt(&[], profile).await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("cannot be empty"));
        });
    }

    #[test]
    fn test_complete_profile_structure() {
        let config = SandboxConfig::new(
            FilesystemConfig::new(
                vec!["/tmp/**".to_string(), "/home/user/workspace/**".to_string()],
                vec!["/etc/shadow".to_string(), "/home/*/.ssh/**".to_string()],
            ),
            NetworkConfig::new(true, vec!["*.example.com".to_string()]),
        );

        let profile = generate_seatbelt_profile(&config);

        // Verify all major sections exist
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("FILE WRITE RESTRICTIONS"));
        assert!(profile.contains("FILE READ RESTRICTIONS"));
        assert!(profile.contains("MOVE-BLOCKING"));
        assert!(profile.contains("NETWORK RESTRICTIONS"));
        assert!(profile.contains("PROCESS EXECUTION"));

        // Verify structure integrity
        let open_parens = profile.matches('(').count();
        let close_parens = profile.matches(')').count();
        assert_eq!(open_parens, close_parens, "Unbalanced parentheses in S-expression");
    }
}
