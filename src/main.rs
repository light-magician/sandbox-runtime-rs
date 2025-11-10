//! Sandbox Runtime (srt) - CLI entry point
//!
//! Command-line interface for executing untrusted code in isolated environments.
//! Provides filesystem restrictions, network filtering, and syscall blocking
//! for cross-platform process isolation on macOS and Linux.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use srt::config::SandboxConfig;
use srt::sandbox::manager::SandboxManager;

/// Sandbox Runtime - Run commands in isolated environments
///
/// Execute untrusted code with configurable filesystem and network restrictions.
/// Supports Seatbelt sandboxing on macOS and Bubblewrap + Seccomp on Linux.
///
/// # Examples
///
/// Run a command with default restrictions:
///     srt "python script.py"
///
/// With custom settings:
///     srt --settings ./sandbox.json "node app.js"
///
/// With debug logging:
///     srt --debug "curl https://example.com"
#[derive(Parser, Debug)]
#[command(name = "srt")]
#[command(about = "Sandbox Runtime - Run commands in isolated environments")]
#[command(version)]
#[command(author = "Anthropic")]
pub struct Cli {
    /// The command to run in the sandbox
    ///
    /// Provide the command and all arguments as a single string.
    /// The first element is treated as the executable, and remaining elements
    /// are passed as arguments.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,

    /// Path to settings JSON file
    ///
    /// If provided, loads sandbox configuration from this JSON file.
    /// See README for JSON schema and examples.
    ///
    /// If not provided, uses default configuration (network disabled,
    /// filesystem access unrestricted).
    #[arg(long, short = 's')]
    settings: Option<PathBuf>,

    /// Enable debug logging
    ///
    /// When enabled, prints detailed debug information to stderr including:
    /// - Generated Seatbelt/Bubblewrap profiles
    /// - Network filtering decisions
    /// - Process lifecycle events
    #[arg(long, short = 'd')]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    initialize_logging(cli.debug)?;

    // Load configuration from file or use defaults
    let config = if let Some(settings_path) = cli.settings {
        tracing::info!("Loading configuration from: {}", settings_path.display());
        SandboxConfig::from_file(&settings_path)?
    } else {
        tracing::info!("Using default sandbox configuration");
        SandboxConfig::default()
    };

    // Validate configuration
    config.validate()?;

    // Create sandbox manager
    let mut manager = SandboxManager::new(config);

    // Initialize manager (starts network proxy if enabled)
    manager.initialize().await?;

    // Run the sandboxed command
    let exit_status = manager.run(&cli.command).await?;

    // Cleanup resources
    manager.cleanup().await?;

    // Exit with the sandboxed process's exit code
    std::process::exit(exit_status.code().unwrap_or(1));
}

/// Initializes the logging system.
///
/// Sets up tracing subscriber with appropriate log level:
/// - `debug=true`: TRACE level for verbose output
/// - `debug=false`: INFO level for standard operation
///
/// Respects the `RUST_LOG` environment variable for fine-grained control.
///
/// # Arguments
///
/// * `debug` - Enable debug (TRACE) level logging
///
/// # Errors
///
/// Returns an error if the logging subscriber fails to initialize.
fn initialize_logging(debug: bool) -> Result<()> {
    let log_level = if debug { "debug" } else { "info" };

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .with_thread_ids(false)
        .with_level(true)
        .init();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing_simple() {
        let args = vec!["srt", "echo", "hello"];
        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(cli.command, vec!["echo", "hello"]);
        assert!(cli.settings.is_none());
        assert!(!cli.debug);
    }

    #[test]
    fn test_cli_parsing_with_settings() {
        let args = vec!["srt", "--settings", "config.json", "ls", "-la"];
        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(cli.command, vec!["ls", "-la"]);
        assert_eq!(cli.settings, Some(PathBuf::from("config.json")));
        assert!(!cli.debug);
    }

    #[test]
    fn test_cli_parsing_with_debug() {
        let args = vec!["srt", "--debug", "python", "script.py"];
        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(cli.command, vec!["python", "script.py"]);
        assert!(cli.debug);
    }

    #[test]
    fn test_cli_parsing_all_options() {
        let args = vec!["srt", "-s", "sandbox.json", "-d", "curl", "https://example.com"];
        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(cli.command, vec!["curl", "https://example.com"]);
        assert_eq!(cli.settings, Some(PathBuf::from("sandbox.json")));
        assert!(cli.debug);
    }

    #[test]
    fn test_cli_parsing_short_options() {
        let args = vec!["srt", "-s", "config.json", "-d", "bash", "-c", "echo test"];
        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(cli.command, vec!["bash", "-c", "echo test"]);
        assert!(cli.debug);
    }

    #[test]
    fn test_cli_command_required() {
        let args = vec!["srt"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_command_with_flags() {
        let args = vec!["srt", "python", "-u", "-c", "print('test')"];
        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(cli.command, vec!["python", "-u", "-c", "print('test')"]);
    }
}
