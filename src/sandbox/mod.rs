//! Sandbox runtime module for cross-platform process isolation.
//!
//! This module provides platform-specific sandbox implementations:
//! - **macOS**: Seatbelt profiles via `sandbox-exec`
//! - **Linux**: Bubblewrap + Seccomp-BPF (future implementation)
//!
//! # Platform Support
//!
//! The sandbox module automatically detects the platform and uses the
//! appropriate isolation mechanism:
//!
//! | Platform | Technology | Implementation |
//! |----------|-----------|----------------|
//! | macOS | Seatbelt (TrustedBSD MAC) | `macos::launch_with_seatbelt` |
//! | Linux | Bubblewrap + Seccomp | `linux::launch_with_bubblewrap` (TBD) |
//!
//! # Example
//!
//! ```ignore
//! use srt::config::SandboxConfig;
//! use srt::sandbox::macos::{generate_seatbelt_profile, launch_with_seatbelt};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = SandboxConfig::default();
//!
//! #[cfg(target_os = "macos")]
//! {
//!     let profile = generate_seatbelt_profile(&config);
//!     let command = vec!["python3".to_string(), "script.py".to_string()];
//!     let child = launch_with_seatbelt(&command, &profile).await?;
//! }
//! # Ok(())
//! # }
//! ```

#[cfg(target_os = "macos")]
pub mod macos;

// Orchestration layer for sandbox execution
pub mod manager;

// Future Linux implementation
// #[cfg(target_os = "linux")]
// pub mod linux;
