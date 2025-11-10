//! Sandbox Runtime (srt) - Cross-platform process isolation framework
//!
//! A Rust implementation of the Anthropic Sandbox Runtime, providing
//! filesystem restrictions, network filtering, and syscall blocking
//! for untrusted code execution on macOS and Linux.

pub mod config;
pub mod network;
pub mod sandbox;
pub mod utils;
