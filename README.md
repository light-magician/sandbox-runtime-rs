# Sandbox Runtime (Rust)

[![CI](https://github.com/light-magician/sandbox-runtime-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/light-magician/sandbox-runtime-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A lightweight sandboxing tool for enforcing filesystem and network restrictions on arbitrary processes at the OS level, without requiring a container.

`srt` uses native OS sandboxing primitives (`sandbox-exec` on macOS) and proxy-based network filtering. It can be used to sandbox the behaviour of agents, local MCP servers, bash commands and arbitrary processes.

This is a Rust implementation of [Anthropic's Sandbox Runtime](https://github.com/anthropics/sandbox-runtime). The original TypeScript implementation is available in the `typescript/` directory.

**Repository:** https://github.com/light-magician/sandbox-runtime-rs

> **Experimental Port**
>
> This is an experimental Rust port of the original TypeScript implementation. While it offers performance improvements, the TypeScript version in `typescript/` is more mature and supports both macOS and Linux. This Rust version currently only supports macOS

## Installation

```bash
cargo install --path .
```

## Basic Usage

```bash
# Network restrictions
$ srt "curl anthropic.com"
Running: curl anthropic.com
<html>...</html>  # Request succeeds

$ srt "curl example.com"
Running: curl example.com
Connection blocked by network allowlist  # Request blocked

# Filesystem restrictions
$ srt "cat README.md"
Running: cat README.md
# Sandbox Runtime...  # Current directory access allowed

$ srt "cat ~/.ssh/id_rsa"
Running: cat ~/.ssh/id_rsa
cat: /Users/user/.ssh/id_rsa: Operation not permitted  # Specific file blocked
```

## Overview

This package provides a standalone sandbox implementation that can be used as both a CLI tool and a library. It's designed with a **secure-by-default** philosophy tailored for common developer use cases: processes start with minimal access, and you explicitly poke only the holes you need.

**Key capabilities:**

- **Network restrictions**: Control which hosts/domains can be accessed via HTTP/HTTPS
- **Filesystem restrictions**: Control which files/directories can be read/written (defaulting to allowing writes to the current working directory)

## How It Works

The sandbox uses OS-level primitives to enforce restrictions that apply to the entire process tree:

- **macOS**: Uses `sandbox-exec` with dynamically generated [Seatbelt profiles](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf)

### Dual Isolation Model

Both filesystem and network isolation are required for effective sandboxing. Without network isolation, a compromised process could exfiltrate SSH keys or other sensitive files. Without filesystem isolation, a process could escape the sandbox and gain unrestricted network access.

**Filesystem Isolation** enforces read and write restrictions:

- **Read**: By default, read access is allowed everywhere. You can deny specific paths (e.g., blocking `~/.ssh`)
- **Write**: By default, write access is only allowed in the current working directory. You can allow additional paths (e.g., `/tmp`), and deny within allowed paths

**Network Isolation** routes all traffic through a proxy server running on the host:

- **macOS**: The Seatbelt profile allows communication only to a specific localhost port. The proxy listens on this port, creating a controlled channel for all network access

HTTP/HTTPS traffic is mediated by the proxy, which enforces your domain allowlists and denylists.

For more details on sandboxing, see:
- [Claude Code Sandboxing Documentation](https://docs.claude.com/en/docs/claude-code/sandboxing)
- [Beyond Permission Prompts: Making Claude Code More Secure and Autonomous](https://www.anthropic.com/engineering/claude-code-sandboxing)

## Architecture

```
src/
├── main.rs                   # CLI entrypoint (srt command)
├── lib.rs                    # Library exports
├── config.rs                 # Config structs
├── sandbox/
│   ├── mod.rs               # Platform abstraction
│   ├── macos.rs             # Seatbelt implementation
│   └── manager.rs           # Orchestration
├── network/
│   ├── mod.rs               # Network module
│   └── proxy.rs             # HTTP/HTTPS proxy for network filtering
└── utils/
    ├── mod.rs               # Utilities module
    └── glob.rs              # Pattern matching
```

## Usage

### As a CLI tool

The `srt` command wraps any command with security boundaries:

```bash
# Run a command in the sandbox
srt echo "hello world"

# With debug logging
srt --debug curl https://example.com

# Specify custom settings file
srt --settings /path/to/srt-settings.json npm install
```

## Configuration

### Settings File Location

By default, the sandbox runtime looks for configuration at `~/.srt-settings.json`. You can specify a custom path using the `--settings` flag:

```bash
srt --settings /path/to/srt-settings.json <command>
```

### Complete Configuration Example

```json
{
  "network": {
    "allowedDomains": [
      "github.com",
      "*.github.com",
      "npmjs.org",
      "*.npmjs.org"
    ],
    "deniedDomains": [
      "malicious.com"
    ]
  },
  "filesystem": {
    "denyRead": [
      "~/.ssh"
    ],
    "allowWrite": [
      ".",
      "src/",
      "test/",
      "/tmp"
    ],
    "denyWrite": [
      ".env",
      "config/production.json"
    ]
  }
}
```

### Configuration Options

#### Network Configuration

- `network.allowedDomains` - Array of allowed domains (supports wildcards like `*.example.com`)
- `network.deniedDomains` - Array of denied domains (takes precedence over allowedDomains)

#### Filesystem Configuration

- `filesystem.denyRead` - Array of paths to deny read access
- `filesystem.allowWrite` - Array of paths to allow write access (default: current working directory only)
- `filesystem.denyWrite` - Array of paths to deny write access (takes precedence over allowWrite)

**Path Syntax:**

Paths support git-style glob patterns, similar to `.gitignore` syntax:

- `*` - Matches any characters except `/` (e.g., `*.ts` matches `foo.ts` but not `foo/bar.ts`)
- `**` - Matches any characters including `/` (e.g., `src/**/*.ts` matches all `.ts` files in `src/`)
- `?` - Matches any single character except `/` (e.g., `file?.txt` matches `file1.txt`)
- `[abc]` - Matches any character in the set (e.g., `file[0-9].txt` matches `file3.txt`)

Examples:
- `"allowWrite": ["src/"]` - Allow write to entire `src/` directory
- `"allowWrite": ["src/**/*.ts"]` - Allow write to all `.ts` files in `src/` and subdirectories
- `"denyRead": ["~/.ssh"]` - Deny read to SSH directory
- `"denyWrite": [".env"]` - Deny write to `.env` file (even if current directory is allowed)

**Path notes:**
- Paths can be absolute (e.g., `/home/user/.ssh`) or relative to the current working directory (e.g., `./src`)
- `~` expands to the user's home directory

### Common Configuration Recipes

**Allow GitHub access** (all necessary endpoints):
```json
{
  "network": {
    "allowedDomains": [
      "github.com",
      "*.github.com",
      "api.github.com"
    ],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": [],
    "allowWrite": ["."],
    "denyWrite": []
  }
}
```

**Restrict to specific directories:**
```json
{
  "network": {
    "allowedDomains": [],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": ["~/.ssh"],
    "allowWrite": [".", "src/", "test/"],
    "denyWrite": [".env", "secrets/"]
  }
}
```

## Platform Support

- **macOS**: Uses `sandbox-exec` with custom profiles (no additional dependencies)
- **Linux**: Not yet supported (planned)
- **Windows**: Not supported

## Performance Characteristics

The Rust implementation exhibits different performance characteristics compared to the TypeScript implementation due to architectural differences (compiled native binary vs. interpreted JavaScript with JIT compilation).

### Measured Metrics

The following measurements were taken on macOS (Apple Silicon) running simple commands through the sandbox:

| Metric | TypeScript | Rust | Notes |
|--------|-----------|------|-------|
| **Startup Time** | ~50-100ms | ~16ms | Time to initialize sandbox and execute simple command |
| **Memory Usage** | ~30-50 MB | ~4.5 MB | Peak RSS during execution |
| **Binary Size** | ~40 MB | 3.8 MB | Rust: release binary; TypeScript: node_modules + bundled code |

### Methodology Notes

These measurements represent initial observations and should be interpreted with the following considerations:

- **Startup time**: Measured via repeated execution of `echo "hello"` through the sandbox (100 iterations)
- **Memory usage**: Measured via system monitoring tools during execution
- **Binary size**: TypeScript includes Node.js dependency chain; Rust is a single static binary
- **Workload dependency**: Performance characteristics may vary significantly based on the sandboxed workload
- **Platform specificity**: Measurements taken on macOS ARM64; results may differ on other platforms

### Limitations

The current performance measurements are informal observations rather than rigorous benchmarks. For production use cases, we recommend:

1. Conducting application-specific benchmarking with your actual workloads
2. Measuring end-to-end latency including network proxy overhead
3. Profiling memory usage patterns over extended runtime periods
4. Testing with realistic filesystem and network access patterns

### Establishing Rigorous Benchmarks

To establish scientifically valid performance benchmarks, the following methodology should be implemented:

#### 1. Benchmark Suite Design

A proper benchmark suite should include:

- **Microbenchmarks**: Isolated measurements of specific operations
  - Sandbox initialization time
  - Process spawn overhead
  - Network proxy latency per request
  - Filesystem access overhead per operation

- **Macrobenchmarks**: Real-world representative workloads
  - Running a Node.js application through the sandbox
  - Git operations (clone, fetch, push)
  - Package manager operations (npm install, cargo build)
  - Multi-process workloads

#### 2. Measurement Tools

- **Time measurements**: Use `hyperfine` for statistical analysis of command execution times
  ```bash
  hyperfine --warmup 3 --runs 100 'srt echo "hello"'
  ```

- **Memory profiling**: Use system tools for memory measurement
  - macOS: `/usr/bin/time -l` or `leaks`
  - Linux: `/usr/bin/time -v` or `valgrind --tool=massif`

- **System tracing**: Use platform-specific profiling tools
  - macOS: `instruments` or `dtrace`
  - Linux: `perf` or `bpftrace`

#### 3. Statistical Rigor

- Run each benchmark multiple times (minimum 30-100 iterations)
- Calculate mean, median, standard deviation, and confidence intervals
- Control for system load (run on idle system)
- Report system specifications (CPU, RAM, OS version)

#### 4. Comparison Fairness

When comparing implementations:
- Use equivalent configurations
- Test with identical workloads
- Measure on the same hardware
- Account for warmup effects (JIT compilation, disk caching)
- Report both cold-start and warm-run performance

#### 5. Current Status

**Not yet implemented**: Formal benchmarking infrastructure is not currently in place. The measurements reported above are preliminary observations. Contributions to establish a rigorous benchmark suite are welcome.

## Development

```bash
# Install dependencies
cargo build

# Build the project
cargo build --release

# Run tests
cargo test

# Type checking (with clippy)
cargo clippy

# Format code
cargo fmt
```

### Continuous Integration

The project uses GitHub Actions for automated testing and quality assurance. On every push and pull request, the following checks are performed:

#### Test Suite (`ci.yml`)

- **Test Matrix**: Tests run on macOS with stable and beta Rust toolchains
- **Unit Tests**: All unit tests are executed with `cargo test --verbose --all-features`
- **Doc Tests**: Documentation examples are validated with `cargo test --doc`
- **Formatting**: Code formatting is checked with `rustfmt`
- **Linting**: Code quality is verified with `clippy` (warnings treated as errors)
- **Build Verification**: Release binaries are built for both x86_64 and aarch64 architectures
- **Security Audit**: Dependencies are scanned for known vulnerabilities with `cargo-audit`
- **Code Coverage**: Test coverage is measured with `cargo-tarpaulin` (uploaded to Codecov)

#### Release Workflow (`release.yml`)

Triggered when version tags (e.g., `v1.0.0`) are pushed:

- Builds release binaries for both macOS architectures
- Strips debug symbols for smaller binary size
- Creates compressed archives with SHA-256 checksums
- Publishes release artifacts to GitHub Releases

#### Local CI Simulation

To run the same checks locally before pushing:

```bash
# Run all tests
cargo test --all-features --verbose

# Check formatting
cargo fmt --all -- --check

# Run clippy with the same strictness as CI
cargo clippy --all-targets --all-features -- -D warnings

# Build for release
cargo build --release

# Security audit
cargo install cargo-audit
cargo audit

# Code coverage (requires cargo-tarpaulin)
cargo install cargo-tarpaulin
cargo tarpaulin --verbose --all-features --workspace --timeout 120
```

## Implementation Details

### Network Isolation Architecture

The sandbox runs an HTTP proxy server on the host machine that filters all network requests based on permission rules:

1. **HTTP/HTTPS Traffic**: An HTTP proxy server intercepts requests and validates them against allowed/denied domains
2. **Permission Enforcement**: The proxy enforces the configuration rules

The Seatbelt profile allows communication only to specific localhost ports where the proxy listens. All other network access is blocked.

### Filesystem Isolation

Filesystem restrictions are enforced at the OS level using `sandbox-exec` with dynamically generated Seatbelt profiles that specify allowed read/write paths.

**Default filesystem permissions:**

- **Read**: Allowed everywhere by default. You can deny specific paths using deny rules
  - Example: Deny reading `~/.ssh` to block access to SSH keys

- **Write**: Only allowed in the current working directory by default. You can:
  - Allow additional paths using allow rules (e.g., allow `/tmp`)
  - Deny specific paths within allowed directories (e.g., deny `.env` even though `.` is allowed)

This model lets you start with broad read access but tightly controlled write access, then refine both as needed.

### Security Limitations

* **Network Sandboxing Limitations**: The network filtering system operates by restricting the domains that processes are allowed to connect to. It does not otherwise inspect the traffic passing through the proxy and users are responsible for ensuring they only allow trusted domains in their policy.

  Users should be aware of potential risks that come from allowing broad domains like `github.com` that may allow for data exfiltration.

* **Filesystem Permission Escalation**: Overly broad filesystem write permissions can enable privilege escalation attacks. Allowing writes to directories containing executables in `$PATH`, system configuration directories, or user shell configuration files (`.bashrc`, `.zshrc`) can lead to code execution in different security contexts when other users or system processes access these files.

## License

MIT License

**Original TypeScript Implementation:**
Copyright (c) 2024 Anthropic, Inc.

**Rust Port:**
Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Acknowledgments

Based on the original TypeScript implementation by Anthropic, Inc.
