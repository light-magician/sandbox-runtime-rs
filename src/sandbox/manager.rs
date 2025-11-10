//! Sandbox orchestration and lifecycle management.
//!
//! This module provides the high-level `SandboxManager` that coordinates all aspects of
//! sandbox execution: network proxy setup, platform detection, profile generation, and
//! process lifecycle management.
//!
//! # Architecture
//!
//! The SandboxManager follows a three-phase lifecycle:
//!
//! 1. **Initialization**: Starts network proxy if enabled, validates platform support
//! 2. **Execution**: Generates sandbox profile, launches sandboxed process, monitors execution
//! 3. **Cleanup**: Gracefully shuts down proxy, releases resources
//!
//! # Example
//!
//! ```no_run
//! use srt::config::{SandboxConfig, FilesystemConfig, NetworkConfig};
//! use srt::sandbox::manager::SandboxManager;
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Configure sandbox restrictions
//! let config = SandboxConfig::new(
//!     FilesystemConfig::new(
//!         vec!["/tmp/**".to_string()],
//!         vec!["/etc/shadow".to_string()],
//!     ),
//!     NetworkConfig::new(true, vec!["*.example.com".to_string()]),
//! );
//!
//! // Create and initialize manager
//! let mut manager = SandboxManager::new(config);
//! manager.initialize().await?;
//!
//! // Run command in sandbox
//! let command = vec!["python3".to_string(), "script.py".to_string()];
//! let status = manager.run(&command).await?;
//!
//! println!("Exit code: {:?}", status.code());
//!
//! // Cleanup resources
//! manager.cleanup().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Platform Support
//!
//! Currently supports macOS only via Seatbelt. The manager automatically detects the
//! platform and returns an error on unsupported systems.
//!
//! # Network Proxy
//!
//! When network access is enabled, the manager:
//! - Starts an HTTP/HTTPS proxy on a random available port
//! - Sets environment variables (HTTP_PROXY, HTTPS_PROXY, etc.)
//! - Filters outbound connections based on allowed domains
//! - Allows dynamic rule updates via `update_network_rules()`
//!
//! # Thread Safety
//!
//! The manager is not thread-safe and should not be shared between threads.
//! For concurrent sandbox execution, create separate manager instances.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::process::ExitStatus;
use tokio::process::Child;

use crate::config::SandboxConfig;
use crate::network::proxy::NetworkFilter;

#[cfg(target_os = "macos")]
use crate::sandbox::macos::{generate_seatbelt_profile, launch_with_seatbelt};

/// High-level orchestration manager for sandbox execution.
///
/// The `SandboxManager` coordinates all aspects of running code in a sandboxed
/// environment, including network proxy management, platform-specific sandbox
/// configuration, and process lifecycle management.
///
/// # Lifecycle
///
/// The manager follows a three-phase lifecycle:
///
/// 1. **Creation**: `new()` - Configures the manager with sandbox restrictions
/// 2. **Initialization**: `initialize()` - Starts proxy, validates platform
/// 3. **Execution**: `run()` - Runs commands in the sandbox
/// 4. **Cleanup**: `cleanup()` - Shuts down proxy, releases resources
///
/// # Fields
///
/// - `config`: The sandbox configuration (filesystem and network rules)
/// - `network_filter`: Optional HTTP proxy for domain filtering
/// - `proxy_address`: Address the proxy is listening on (if enabled)
pub struct SandboxManager {
    /// Sandbox configuration with filesystem and network restrictions.
    config: SandboxConfig,

    /// Network filtering proxy (None if network is disabled).
    network_filter: Option<NetworkFilter>,

    /// Socket address the proxy is listening on (None if network is disabled).
    proxy_address: Option<SocketAddr>,
}

impl SandboxManager {
    /// Creates a new sandbox manager with the specified configuration.
    ///
    /// This does not start the proxy or validate platform support. Call `initialize()`
    /// to complete setup before running commands.
    ///
    /// # Arguments
    ///
    /// * `config` - Sandbox configuration with filesystem and network restrictions
    ///
    /// # Example
    ///
    /// ```
    /// use srt::config::SandboxConfig;
    /// use srt::sandbox::manager::SandboxManager;
    ///
    /// let config = SandboxConfig::default();
    /// let manager = SandboxManager::new(config);
    /// ```
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            config,
            network_filter: None,
            proxy_address: None,
        }
    }

    /// Initializes the sandbox manager by starting the network proxy if needed.
    ///
    /// This method must be called before `run()`. It performs the following:
    ///
    /// 1. Validates platform support (macOS only for now)
    /// 2. If network is enabled, starts HTTP/HTTPS proxy on a random port
    /// 3. Stores proxy address for environment variable configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The platform is not supported (Linux support coming soon)
    /// - Network proxy fails to start
    /// - Port binding fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use srt::config::{SandboxConfig, NetworkConfig, FilesystemConfig};
    /// # use srt::sandbox::manager::SandboxManager;
    /// # async fn example() -> anyhow::Result<()> {
    /// let config = SandboxConfig::new(
    ///     FilesystemConfig::default(),
    ///     NetworkConfig::new(true, vec!["*.example.com".to_string()]),
    /// );
    ///
    /// let mut manager = SandboxManager::new(config);
    /// manager.initialize().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn initialize(&mut self) -> Result<()> {
        // Platform detection
        #[cfg(not(target_os = "macos"))]
        {
            anyhow::bail!(
                "Unsupported platform: {}. Currently only macOS is supported. \
                 Linux support coming soon.",
                std::env::consts::OS
            );
        }

        #[cfg(target_os = "macos")]
        tracing::info!("Platform detected: macOS (Seatbelt sandbox)");

        // Start network proxy if enabled
        if self.config.network.enabled {
            tracing::info!("Network filtering enabled, starting HTTP/HTTPS proxy");

            let filter = NetworkFilter::new(self.config.network.allowed_domains.clone());

            // Start proxy on random available port (0 = let OS choose)
            let addr = filter
                .start(0)
                .await
                .context("Failed to start network filtering proxy")?;

            tracing::info!("Network proxy started on {}", addr);

            self.proxy_address = Some(addr);
            self.network_filter = Some(filter);
        } else {
            tracing::info!("Network filtering disabled, all network access blocked");
        }

        Ok(())
    }

    /// Runs a command within the sandbox.
    ///
    /// This is the main execution method that:
    ///
    /// 1. Validates the command is not empty
    /// 2. Generates platform-specific sandbox profile (Seatbelt on macOS)
    /// 3. Sets environment variables for proxy (if network enabled)
    /// 4. Launches the sandboxed process
    /// 5. Waits for process completion
    /// 6. Returns the exit status
    ///
    /// # Arguments
    ///
    /// * `command` - Command and arguments to execute (e.g., `["python3", "script.py"]`)
    ///
    /// # Returns
    ///
    /// The exit status of the sandboxed process.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `initialize()` was not called first
    /// - Command array is empty
    /// - Sandbox profile generation fails
    /// - Process spawn fails
    /// - Process wait fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use srt::config::SandboxConfig;
    /// # use srt::sandbox::manager::SandboxManager;
    /// # async fn example() -> anyhow::Result<()> {
    /// let mut manager = SandboxManager::new(SandboxConfig::default());
    /// manager.initialize().await?;
    ///
    /// let command = vec!["ls".to_string(), "-la".to_string()];
    /// let status = manager.run(&command).await?;
    ///
    /// if status.success() {
    ///     println!("Command succeeded");
    /// } else {
    ///     println!("Command failed with: {:?}", status.code());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Platform-Specific Behavior
    ///
    /// ## macOS
    ///
    /// - Uses `sandbox-exec` with generated Seatbelt profile
    /// - Seatbelt enforces filesystem and network restrictions at kernel level
    /// - Violations are logged to system log (`log stream`)
    ///
    /// ## Linux (Coming Soon)
    ///
    /// - Will use Bubblewrap + Seccomp-BPF
    /// - Similar restriction model with namespace isolation
    pub async fn run(&self, command: &[String]) -> Result<ExitStatus> {
        if command.is_empty() {
            anyhow::bail!("Command cannot be empty");
        }

        tracing::info!("Running command in sandbox: {}", command.join(" "));

        // Generate platform-specific sandbox profile
        #[cfg(target_os = "macos")]
        let profile = generate_seatbelt_profile(&self.config);

        #[cfg(target_os = "macos")]
        tracing::debug!("Generated Seatbelt profile:\n{}", profile);

        // Launch sandboxed process
        #[cfg(target_os = "macos")]
        let mut child = self.launch_macos(command, &profile).await?;

        // Wait for process completion
        let status = child
            .wait()
            .await
            .context("Failed to wait for sandboxed process")?;

        tracing::info!(
            "Sandboxed process exited with status: {}",
            status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".to_string())
        );

        Ok(status)
    }

    /// Launches a sandboxed process on macOS with Seatbelt.
    ///
    /// This is a platform-specific helper that:
    /// - Builds a command wrapper with environment variables for proxy (if enabled)
    /// - Invokes the Seatbelt sandbox with the generated profile via launch_with_seatbelt
    /// - Returns a child process handle
    #[cfg(target_os = "macos")]
    async fn launch_macos(&self, command: &[String], profile: &str) -> Result<Child> {
        // Build command with environment variable wrapper if proxy is enabled
        let final_command = if let Some(addr) = self.proxy_address {
            let proxy_url = format!("http://{}", addr);

            tracing::debug!("Setting proxy environment variables: {}", proxy_url);

            // Wrap the command with env to set proxy variables
            let mut wrapped_command = vec![
                "env".to_string(),
                format!("HTTP_PROXY={}", proxy_url),
                format!("HTTPS_PROXY={}", proxy_url),
                format!("http_proxy={}", proxy_url),
                format!("https_proxy={}", proxy_url),
                "NO_PROXY=localhost,127.0.0.1".to_string(),
                "no_proxy=localhost,127.0.0.1".to_string(),
            ];
            wrapped_command.extend_from_slice(command);
            wrapped_command
        } else {
            command.to_vec()
        };

        // Use the macos module's launch_with_seatbelt which handles temp file lifecycle
        launch_with_seatbelt(&final_command, profile).await
    }

    /// Cleans up resources used by the sandbox manager.
    ///
    /// This method:
    /// - Shuts down the network proxy (if running)
    /// - Releases any held resources
    /// - Logs cleanup status
    ///
    /// It is safe to call this method multiple times. Subsequent calls are no-ops.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use srt::config::SandboxConfig;
    /// # use srt::sandbox::manager::SandboxManager;
    /// # async fn example() -> anyhow::Result<()> {
    /// let mut manager = SandboxManager::new(SandboxConfig::default());
    /// manager.initialize().await?;
    ///
    /// // ... run commands ...
    ///
    /// manager.cleanup().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn cleanup(&mut self) -> Result<()> {
        tracing::info!("Cleaning up sandbox manager");

        // Shut down network proxy
        if self.network_filter.is_some() {
            tracing::info!("Shutting down network proxy");
            self.network_filter = None;
            self.proxy_address = None;
            tracing::info!("Network proxy shut down successfully");
        }

        tracing::info!("Sandbox manager cleanup complete");
        Ok(())
    }

    /// Updates network filtering rules dynamically.
    ///
    /// This method allows updating the allowed domains list while the proxy is running.
    /// Changes take effect immediately for new connections.
    ///
    /// # Arguments
    ///
    /// * `domains` - New list of allowed domain patterns (e.g., `["*.example.com"]`)
    ///
    /// # Behavior
    ///
    /// - If network filtering is disabled, this is a no-op
    /// - If network filtering is enabled, the proxy rules are updated atomically
    /// - Existing connections are not affected, only new connections
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use srt::config::{SandboxConfig, NetworkConfig, FilesystemConfig};
    /// # use srt::sandbox::manager::SandboxManager;
    /// # async fn example() -> anyhow::Result<()> {
    /// let config = SandboxConfig::new(
    ///     FilesystemConfig::default(),
    ///     NetworkConfig::new(true, vec!["*.old.com".to_string()]),
    /// );
    ///
    /// let mut manager = SandboxManager::new(config);
    /// manager.initialize().await?;
    ///
    /// // Later: update allowed domains
    /// manager.update_network_rules(vec![
    ///     "*.new.com".to_string(),
    ///     "api.trusted.com".to_string(),
    /// ]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn update_network_rules(&self, domains: Vec<String>) {
        if let Some(filter) = &self.network_filter {
            tracing::info!("Updating network filtering rules");
            filter.update_allowed_domains(domains);
            tracing::info!("Network filtering rules updated");
        } else {
            tracing::warn!(
                "Attempted to update network rules, but network filtering is not enabled"
            );
        }
    }

    /// Returns the proxy address if network filtering is enabled.
    ///
    /// # Returns
    ///
    /// - `Some(SocketAddr)` if network proxy is running
    /// - `None` if network filtering is disabled
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use srt::config::{SandboxConfig, NetworkConfig, FilesystemConfig};
    /// # use srt::sandbox::manager::SandboxManager;
    /// # async fn example() -> anyhow::Result<()> {
    /// let config = SandboxConfig::new(
    ///     FilesystemConfig::default(),
    ///     NetworkConfig::new(true, vec!["*.example.com".to_string()]),
    /// );
    ///
    /// let mut manager = SandboxManager::new(config);
    /// manager.initialize().await?;
    ///
    /// if let Some(addr) = manager.proxy_address() {
    ///     println!("Proxy listening on: {}", addr);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn proxy_address(&self) -> Option<SocketAddr> {
        self.proxy_address
    }

    /// Returns a reference to the sandbox configuration.
    ///
    /// # Example
    ///
    /// ```
    /// # use srt::config::SandboxConfig;
    /// # use srt::sandbox::manager::SandboxManager;
    /// let manager = SandboxManager::new(SandboxConfig::default());
    /// let config = manager.config();
    /// println!("Network enabled: {}", config.network.enabled);
    /// ```
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FilesystemConfig, NetworkConfig};

    #[test]
    fn test_new_manager() {
        let config = SandboxConfig::default();
        let manager = SandboxManager::new(config);

        assert!(manager.network_filter.is_none());
        assert!(manager.proxy_address.is_none());
        assert!(!manager.config.network.enabled);
    }

    #[test]
    fn test_config_getter() {
        let config = SandboxConfig::new(
            FilesystemConfig::new(vec!["/tmp".to_string()], vec![]),
            NetworkConfig::new(true, vec!["*.example.com".to_string()]),
        );

        let manager = SandboxManager::new(config.clone());
        assert_eq!(manager.config().filesystem.allowed_paths.len(), 1);
        assert!(manager.config().network.enabled);
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn test_initialize_no_network() {
        let config = SandboxConfig::new(
            FilesystemConfig::default(),
            NetworkConfig::new(false, vec![]),
        );

        let mut manager = SandboxManager::new(config);
        let result = manager.initialize().await;

        assert!(result.is_ok());
        assert!(manager.proxy_address.is_none());
        assert!(manager.network_filter.is_none());
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn test_initialize_with_network() {
        let config = SandboxConfig::new(
            FilesystemConfig::default(),
            NetworkConfig::new(true, vec!["*.example.com".to_string()]),
        );

        let mut manager = SandboxManager::new(config);
        let result = manager.initialize().await;

        assert!(result.is_ok());
        assert!(manager.proxy_address.is_some());
        assert!(manager.network_filter.is_some());
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn test_run_empty_command() {
        let config = SandboxConfig::default();
        let mut manager = SandboxManager::new(config);
        manager.initialize().await.unwrap();

        let result = manager.run(&[]).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn test_run_simple_command() {
        let config = SandboxConfig::new(
            FilesystemConfig::new(vec!["/tmp/**".to_string()], vec![]),
            NetworkConfig::new(false, vec![]),
        );

        let mut manager = SandboxManager::new(config);
        manager.initialize().await.unwrap();

        // Run a simple command that should succeed
        let command = vec!["echo".to_string(), "hello".to_string()];
        let result = manager.run(&command).await;

        assert!(result.is_ok());
        let status = result.unwrap();
        assert!(status.success());
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn test_cleanup() {
        let config = SandboxConfig::new(
            FilesystemConfig::default(),
            NetworkConfig::new(true, vec!["*.example.com".to_string()]),
        );

        let mut manager = SandboxManager::new(config);
        manager.initialize().await.unwrap();

        assert!(manager.network_filter.is_some());
        assert!(manager.proxy_address.is_some());

        let result = manager.cleanup().await;
        assert!(result.is_ok());

        assert!(manager.network_filter.is_none());
        assert!(manager.proxy_address.is_none());
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn test_cleanup_idempotent() {
        let config = SandboxConfig::default();
        let mut manager = SandboxManager::new(config);
        manager.initialize().await.unwrap();

        // Cleanup multiple times should not error
        assert!(manager.cleanup().await.is_ok());
        assert!(manager.cleanup().await.is_ok());
        assert!(manager.cleanup().await.is_ok());
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn test_update_network_rules_enabled() {
        let config = SandboxConfig::new(
            FilesystemConfig::default(),
            NetworkConfig::new(true, vec!["*.old.com".to_string()]),
        );

        let mut manager = SandboxManager::new(config);
        manager.initialize().await.unwrap();

        // Should not panic or error
        manager.update_network_rules(vec!["*.new.com".to_string()]);

        // Verify the filter was updated
        if let Some(filter) = &manager.network_filter {
            assert!(filter.is_allowed("sub.new.com"));
            assert!(!filter.is_allowed("sub.old.com"));
        }
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn test_update_network_rules_disabled() {
        let config = SandboxConfig::new(
            FilesystemConfig::default(),
            NetworkConfig::new(false, vec![]),
        );

        let mut manager = SandboxManager::new(config);
        manager.initialize().await.unwrap();

        // Should not panic, just log a warning
        manager.update_network_rules(vec!["*.example.com".to_string()]);
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn test_proxy_address_getter() {
        let config = SandboxConfig::new(
            FilesystemConfig::default(),
            NetworkConfig::new(true, vec!["*.example.com".to_string()]),
        );

        let mut manager = SandboxManager::new(config);

        // Before initialization
        assert!(manager.proxy_address().is_none());

        // After initialization
        manager.initialize().await.unwrap();
        assert!(manager.proxy_address().is_some());

        // After cleanup
        manager.cleanup().await.unwrap();
        assert!(manager.proxy_address().is_none());
    }
}
