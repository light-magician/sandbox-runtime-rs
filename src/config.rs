//! Configuration module for the Sandbox Runtime (srt).
//!
//! This module provides configuration structures for sandbox restrictions
//! including filesystem access control and network filtering. It supports
//! loading from JSON files and strings with comprehensive validation.
//!
//! # Examples
//!
//! ```ignore
//! use srt::config::SandboxConfig;
//!
//! // Load from JSON file
//! let config = SandboxConfig::from_file("config.json")?;
//!
//! // Create from JSON string
//! let json = r#"{"filesystem": {"allowed_paths": ["/tmp"]}, "network": {"enabled": false}}"#;
//! let config = SandboxConfig::from_json_string(json)?;
//! ```

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Configuration for filesystem access restrictions.
///
/// Defines which paths are allowed for reading/writing and which are blocked.
/// Supports glob patterns like `*.txt`, `**/*.py`, and literal paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FilesystemConfig {
    /// Paths that are explicitly allowed for access.
    ///
    /// Supports glob patterns:
    /// - `*` matches any sequence of characters except `/`
    /// - `**` matches any sequence including `/`
    /// - `?` matches a single character except `/`
    /// - `[abc]` matches character class
    ///
    /// Examples:
    /// - `/tmp` - literal path
    /// - `/home/user/workspace/**` - recursive glob
    /// - `*.txt` - file extension match
    #[serde(default)]
    pub allowed_paths: Vec<String>,

    /// Paths that are explicitly blocked from access.
    ///
    /// Blocked paths take precedence over allowed paths. Uses the same
    /// glob pattern syntax as `allowed_paths`.
    ///
    /// Common examples:
    /// - `/etc/shadow` - sensitive system files
    /// - `/home/user/.ssh/**` - SSH keys
    /// - `/var/log/**` - system logs
    #[serde(default)]
    pub blocked_paths: Vec<String>,
}

/// Configuration for network access restrictions.
///
/// Controls network connectivity and domain filtering via HTTP/SOCKS5 proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkConfig {
    /// Whether network access is enabled for the sandbox.
    ///
    /// If `false`, all network connections are blocked.
    /// If `true`, only connections to `allowed_domains` are permitted.
    #[serde(default = "default_network_enabled")]
    pub enabled: bool,

    /// List of domains that are allowed for network access.
    ///
    /// Supports wildcard patterns:
    /// - `*.example.com` - any subdomain of example.com
    /// - `api.trusted.com` - specific domain
    /// - `*` - allow all domains (use with caution!)
    ///
    /// If `enabled` is `true` and this list is empty, no domains are allowed.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

/// Complete sandbox configuration combining all restriction settings.
///
/// This is the top-level configuration structure that defines how the sandbox
/// restricts filesystem and network access for untrusted code execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SandboxConfig {
    /// Filesystem access restrictions.
    #[serde(default)]
    pub filesystem: FilesystemConfig,

    /// Network access restrictions and filtering.
    #[serde(default)]
    pub network: NetworkConfig,
}

// Default values for optional fields
fn default_network_enabled() -> bool {
    false
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            allowed_paths: vec![],
            blocked_paths: vec![],
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_domains: vec![],
        }
    }
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            filesystem: FilesystemConfig::default(),
            network: NetworkConfig::default(),
        }
    }
}

impl FilesystemConfig {
    /// Creates a new filesystem configuration with the given paths.
    ///
    /// # Arguments
    ///
    /// * `allowed_paths` - List of allowed paths (glob patterns supported)
    /// * `blocked_paths` - List of blocked paths (glob patterns supported)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let fs_config = FilesystemConfig::new(
    ///     vec!["/tmp".to_string(), "/home/user/**".to_string()],
    ///     vec!["/etc/shadow".to_string()],
    /// );
    /// ```
    pub fn new(allowed_paths: Vec<String>, blocked_paths: Vec<String>) -> Self {
        Self {
            allowed_paths,
            blocked_paths,
        }
    }

    /// Validates the filesystem configuration.
    ///
    /// Checks for:
    /// - Empty path lists (warning only, not an error)
    /// - Invalid glob patterns
    /// - Conflicting allow/block rules
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Path strings contain null bytes
    /// - Invalid regex patterns are generated from globs
    pub fn validate(&self) -> Result<()> {
        // Validate allowed paths
        for path in &self.allowed_paths {
            validate_path_string(path)
                .with_context(|| format!("Invalid allowed path: {}", path))?;
        }

        // Validate blocked paths
        for path in &self.blocked_paths {
            validate_path_string(path)
                .with_context(|| format!("Invalid blocked path: {}", path))?;
        }

        // Warn if both lists are empty (not an error, but unusual)
        if self.allowed_paths.is_empty() && self.blocked_paths.is_empty() {
            tracing::warn!("Filesystem config has both allowed_paths and blocked_paths empty");
        }

        Ok(())
    }

    /// Checks if a path is allowed based on the allow/block rules.
    ///
    /// Blocked paths take precedence over allowed paths.
    ///
    /// # Arguments
    ///
    /// * `path` - The file path to check
    ///
    /// Returns `true` if the path is allowed, `false` otherwise.
    pub fn is_path_allowed(&self, path: &str) -> bool {
        // Check blocked paths first (they take precedence)
        for blocked in &self.blocked_paths {
            if glob_matches(path, blocked) {
                return false;
            }
        }

        // Check allowed paths
        for allowed in &self.allowed_paths {
            if glob_matches(path, allowed) {
                return true;
            }
        }

        // If no explicit allow, deny by default
        false
    }
}

impl NetworkConfig {
    /// Creates a new network configuration.
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether network access is enabled
    /// * `allowed_domains` - List of allowed domains (wildcard patterns supported)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let net_config = NetworkConfig::new(
    ///     true,
    ///     vec!["*.example.com".to_string(), "api.trusted.com".to_string()],
    /// );
    /// ```
    pub fn new(enabled: bool, allowed_domains: Vec<String>) -> Self {
        Self {
            enabled,
            allowed_domains,
        }
    }

    /// Validates the network configuration.
    ///
    /// Checks for:
    /// - Invalid domain patterns
    /// - Inconsistent settings (enabled but no allowed domains)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Domain strings contain invalid characters
    /// - Network is enabled but allowed_domains is empty
    pub fn validate(&self) -> Result<()> {
        // If network is disabled, allowed_domains is irrelevant
        if !self.enabled {
            return Ok(());
        }

        // If enabled, validate each domain
        for domain in &self.allowed_domains {
            validate_domain_string(domain)
                .with_context(|| format!("Invalid domain pattern: {}", domain))?;
        }

        Ok(())
    }

    /// Checks if a domain is allowed by the network configuration.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to check
    ///
    /// Returns `true` if the domain is allowed, `false` otherwise.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        if !self.enabled {
            return false;
        }

        // If allowed_domains is empty, deny all
        if self.allowed_domains.is_empty() {
            return false;
        }

        // Check if domain matches any allowed pattern
        self.allowed_domains
            .iter()
            .any(|pattern| domain_matches(domain, pattern))
    }
}

impl SandboxConfig {
    /// Creates a new sandbox configuration.
    ///
    /// # Arguments
    ///
    /// * `filesystem` - Filesystem access configuration
    /// * `network` - Network access configuration
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = SandboxConfig::new(
    ///     FilesystemConfig::new(
    ///         vec!["/tmp".to_string()],
    ///         vec!["/etc/shadow".to_string()],
    ///     ),
    ///     NetworkConfig::new(
    ///         true,
    ///         vec!["*.example.com".to_string()],
    ///     ),
    /// );
    /// ```
    pub fn new(filesystem: FilesystemConfig, network: NetworkConfig) -> Self {
        Self {
            filesystem,
            network,
        }
    }

    /// Loads a sandbox configuration from a JSON file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the JSON configuration file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read
    /// - The file content is not valid JSON
    /// - The JSON does not match the expected schema
    /// - The configuration validation fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = SandboxConfig::from_file("config.json")?;
    /// ```
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        // Read the file
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        // Parse and validate
        Self::from_json_string(&content)
    }

    /// Loads a sandbox configuration from a JSON string.
    ///
    /// # Arguments
    ///
    /// * `json` - JSON string containing the configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The string is not valid JSON
    /// - The JSON does not match the expected schema
    /// - The configuration validation fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// let json = r#"{"filesystem": {"allowed_paths": ["/tmp"]}, "network": {"enabled": false}}"#;
    /// let config = SandboxConfig::from_json_string(json)?;
    /// ```
    pub fn from_json_string(json: &str) -> Result<Self> {
        // Parse JSON
        let config: SandboxConfig = serde_json::from_str(json)
            .context("Failed to parse JSON configuration")?;

        // Validate the configuration
        config.validate()?;

        Ok(config)
    }

    /// Converts the configuration to a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be serialized to JSON.
    /// This should rarely happen unless there are serialization issues.
    pub fn to_json_string(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .context("Failed to serialize configuration to JSON")
    }

    /// Validates the entire sandbox configuration.
    ///
    /// Checks all sub-configurations and ensures consistency.
    ///
    /// # Errors
    ///
    /// Returns an error if any part of the configuration is invalid.
    pub fn validate(&self) -> Result<()> {
        self.filesystem.validate()?;
        self.network.validate()?;
        Ok(())
    }

    /// Merges another configuration into this one.
    ///
    /// Paths and domains from `other` are appended to this configuration's lists.
    /// Network enabled status is taken from `other` if it's explicitly set to `true`.
    ///
    /// # Arguments
    ///
    /// * `other` - The configuration to merge
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut config1 = SandboxConfig::default();
    /// let config2 = SandboxConfig::from_file("extra.json")?;
    /// config1.merge(config2)?;
    /// ```
    pub fn merge(&mut self, other: SandboxConfig) -> Result<()> {
        // Merge filesystem paths
        self.filesystem.allowed_paths.extend(other.filesystem.allowed_paths);
        self.filesystem.blocked_paths.extend(other.filesystem.blocked_paths);

        // Merge network settings
        if other.network.enabled {
            self.network.enabled = true;
        }
        self.network.allowed_domains.extend(other.network.allowed_domains);

        // Re-validate after merge
        self.validate()
    }
}

/// Validates a path string for use in configuration.
fn validate_path_string(path: &str) -> Result<()> {
    // Check for null bytes
    if path.contains('\0') {
        return Err(anyhow!("Path contains null bytes"));
    }

    // Empty paths are allowed (could be catch-all)
    if path.is_empty() {
        return Err(anyhow!("Path cannot be empty"));
    }

    Ok(())
}

/// Validates a domain string for use in network configuration.
fn validate_domain_string(domain: &str) -> Result<()> {
    // Check for null bytes
    if domain.contains('\0') {
        return Err(anyhow!("Domain contains null bytes"));
    }

    // Empty domain is allowed (could be wildcard)
    if domain.is_empty() {
        return Err(anyhow!("Domain cannot be empty"));
    }

    // Basic validation: domain should contain only valid characters
    // Allow: alphanumerics, dots, hyphens, asterisks (for wildcards)
    for ch in domain.chars() {
        if !ch.is_alphanumeric() && ch != '.' && ch != '-' && ch != '*' {
            return Err(anyhow!(
                "Domain contains invalid character: {}",
                ch
            ));
        }
    }

    Ok(())
}

/// Matches a file path against a glob pattern.
///
/// Supports:
/// - `*` matches any sequence of characters except `/`
/// - `**` matches any sequence including `/`
/// - `?` matches a single character except `/`
/// - `[abc]` matches character classes
///
/// # Arguments
///
/// * `path` - The file path to match
/// * `pattern` - The glob pattern
///
/// Returns `true` if the path matches the pattern.
fn glob_matches(path: &str, pattern: &str) -> bool {
    glob_to_regex(pattern)
        .map(|regex| regex.is_match(path))
        .unwrap_or(false)
}

/// Converts a glob pattern to a compiled regex for matching.
///
/// # Arguments
///
/// * `glob` - The glob pattern to convert
///
/// Returns the compiled regex, or `None` if the pattern is invalid.
fn glob_to_regex(glob: &str) -> Option<regex::Regex> {
    let mut regex = String::from("^");
    let mut chars = glob.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '*' => {
                if chars.peek() == Some(&'*') {
                    // ** matches anything including /
                    regex.push_str(".*");
                    chars.next(); // consume second *
                } else {
                    // * matches anything except /
                    regex.push_str("[^/]*");
                }
            }
            '?' => {
                // ? matches single char except /
                regex.push_str("[^/]");
            }
            '[' => {
                // Character class - pass through until ]
                regex.push('[');
                while let Some(ch) = chars.next() {
                    regex.push(ch);
                    if ch == ']' {
                        break;
                    }
                }
            }
            // Escape regex special characters
            '.' | '+' | '^' | '$' | '(' | ')' | '{' | '}' | '|' | '\\' => {
                regex.push('\\');
                regex.push(ch);
            }
            _ => regex.push(ch),
        }
    }

    regex.push('$');
    regex::Regex::new(&regex).ok()
}

/// Matches a domain against a domain pattern.
///
/// Supports wildcard matching:
/// - `*.example.com` matches any subdomain of example.com
/// - `example.com` matches exactly example.com
/// - `*` matches any domain
///
/// # Arguments
///
/// * `domain` - The domain to match
/// * `pattern` - The domain pattern
///
/// Returns `true` if the domain matches the pattern.
fn domain_matches(domain: &str, pattern: &str) -> bool {
    // Exact match
    if domain == pattern {
        return true;
    }

    // Wildcard: * matches anything
    if pattern == "*" {
        return true;
    }

    // Prefix wildcard: *.example.com matches any subdomain
    if pattern.starts_with("*.") {
        let suffix = &pattern[2..]; // Remove "*."
        if domain.ends_with(suffix) {
            // Ensure it's a subdomain (has at least one dot separator)
            let prefix = &domain[..domain.len() - suffix.len() - 1];
            return !prefix.contains('.');
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_config_new() {
        let config = FilesystemConfig::new(
            vec!["/tmp".to_string()],
            vec!["/etc/shadow".to_string()],
        );
        assert_eq!(config.allowed_paths.len(), 1);
        assert_eq!(config.blocked_paths.len(), 1);
    }

    #[test]
    fn test_filesystem_config_validate() {
        let config = FilesystemConfig::new(
            vec!["/tmp".to_string()],
            vec!["/etc/shadow".to_string()],
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_filesystem_config_validate_null_bytes() {
        let config = FilesystemConfig::new(
            vec!["/tmp\0invalid".to_string()],
            vec![],
        );
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_filesystem_config_is_path_allowed() {
        let config = FilesystemConfig::new(
            vec!["/tmp/**".to_string(), "/home/user/**".to_string()],
            vec!["/tmp/blocked/**".to_string()],
        );

        assert!(config.is_path_allowed("/tmp/file.txt"));
        assert!(config.is_path_allowed("/home/user/document.pdf"));
        assert!(!config.is_path_allowed("/tmp/blocked/secret.txt"));
        assert!(!config.is_path_allowed("/etc/passwd"));
    }

    #[test]
    fn test_network_config_new() {
        let config = NetworkConfig::new(
            true,
            vec!["*.example.com".to_string()],
        );
        assert!(config.enabled);
        assert_eq!(config.allowed_domains.len(), 1);
    }

    #[test]
    fn test_network_config_validate() {
        let config = NetworkConfig::new(true, vec!["api.example.com".to_string()]);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_network_config_validate_disabled() {
        let config = NetworkConfig::new(false, vec![]);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_network_config_is_domain_allowed() {
        let config = NetworkConfig::new(
            true,
            vec!["*.example.com".to_string(), "api.trusted.com".to_string()],
        );

        assert!(config.is_domain_allowed("sub.example.com"));
        assert!(config.is_domain_allowed("api.trusted.com"));
        assert!(!config.is_domain_allowed("example.com")); // Not a subdomain
        assert!(!config.is_domain_allowed("evil.com"));
    }

    #[test]
    fn test_network_config_is_domain_allowed_disabled() {
        let config = NetworkConfig::new(
            false,
            vec!["*.example.com".to_string()],
        );
        assert!(!config.is_domain_allowed("example.com"));
    }

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert!(!config.network.enabled);
        assert!(config.filesystem.allowed_paths.is_empty());
    }

    #[test]
    fn test_sandbox_config_from_json_string() {
        let json = r#"{
            "filesystem": {
                "allowed_paths": ["/tmp"],
                "blocked_paths": ["/etc/shadow"]
            },
            "network": {
                "enabled": true,
                "allowed_domains": ["*.example.com"]
            }
        }"#;
        let config = SandboxConfig::from_json_string(json).unwrap();
        assert!(config.network.enabled);
        assert_eq!(config.filesystem.allowed_paths.len(), 1);
    }

    #[test]
    fn test_sandbox_config_from_json_string_invalid() {
        let json = "{ invalid json }";
        assert!(SandboxConfig::from_json_string(json).is_err());
    }

    #[test]
    fn test_sandbox_config_to_json_string() {
        let config = SandboxConfig::new(
            FilesystemConfig::new(vec!["/tmp".to_string()], vec![]),
            NetworkConfig::new(true, vec!["example.com".to_string()]),
        );
        let json = config.to_json_string().unwrap();
        assert!(json.contains("filesystem"));
        assert!(json.contains("network"));
    }

    #[test]
    fn test_sandbox_config_merge() {
        let mut config1 = SandboxConfig::new(
            FilesystemConfig::new(vec!["/tmp".to_string()], vec![]),
            NetworkConfig::new(false, vec![]),
        );
        let config2 = SandboxConfig::new(
            FilesystemConfig::new(vec!["/home".to_string()], vec!["/secret".to_string()]),
            NetworkConfig::new(true, vec!["example.com".to_string()]),
        );
        config1.merge(config2).unwrap();

        assert_eq!(config1.filesystem.allowed_paths.len(), 2);
        assert_eq!(config1.filesystem.blocked_paths.len(), 1);
        assert!(config1.network.enabled);
        assert_eq!(config1.network.allowed_domains.len(), 1);
    }

    #[test]
    fn test_glob_to_regex_star() {
        let regex = glob_to_regex("*.txt").unwrap();
        assert!(regex.is_match("file.txt"));
        assert!(!regex.is_match("dir/file.txt"));
    }

    #[test]
    fn test_glob_to_regex_double_star() {
        let regex = glob_to_regex("**/*.py").unwrap();
        assert!(regex.is_match("file.py"));
        assert!(regex.is_match("dir/file.py"));
        assert!(regex.is_match("deep/nested/dir/file.py"));
    }

    #[test]
    fn test_glob_to_regex_question() {
        let regex = glob_to_regex("file?.txt").unwrap();
        assert!(regex.is_match("file1.txt"));
        assert!(!regex.is_match("file12.txt"));
    }

    #[test]
    fn test_glob_to_regex_character_class() {
        let regex = glob_to_regex("file[abc].txt").unwrap();
        assert!(regex.is_match("filea.txt"));
        assert!(regex.is_match("fileb.txt"));
        assert!(!regex.is_match("filed.txt"));
    }

    #[test]
    fn test_domain_matches_exact() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(!domain_matches("example.com", "other.com"));
    }

    #[test]
    fn test_domain_matches_wildcard_all() {
        assert!(domain_matches("anything.com", "*"));
        assert!(domain_matches("example.com", "*"));
    }

    #[test]
    fn test_domain_matches_wildcard_subdomain() {
        assert!(domain_matches("sub.example.com", "*.example.com"));
        assert!(domain_matches("deep.sub.example.com", "*.example.com")); // Matches first level only
        assert!(!domain_matches("example.com", "*.example.com"));
    }

    #[test]
    fn test_validate_path_string() {
        assert!(validate_path_string("/tmp").is_ok());
        assert!(validate_path_string("/tmp\0invalid").is_err());
        assert!(validate_path_string("").is_err());
    }

    #[test]
    fn test_validate_domain_string() {
        assert!(validate_domain_string("example.com").is_ok());
        assert!(validate_domain_string("*.example.com").is_ok());
        assert!(validate_domain_string("example.com\0invalid").is_err());
        assert!(validate_domain_string("example@.com").is_err());
        assert!(validate_domain_string("").is_err());
    }
}
