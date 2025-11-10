//! Glob pattern matching utilities for sandboxing.
//!
//! This module provides functions to convert glob patterns (used in filesystem rules)
//! into compiled regular expressions for efficient matching.
//!
//! Supported glob syntax:
//! - `*` - Matches any characters except `/` (single path component)
//! - `**` - Matches any characters including `/` (multiple path components)
//! - `?` - Matches exactly one character except `/`
//! - `[...]` - Character class (passed through to regex)
//! - `{a,b,c}` - Brace expansion (matches any of the comma-separated alternatives)
//! - All other characters are escaped as regex literals
//!
//! # Examples
//!
//! ```
//! use srt::utils::glob::glob_to_regex;
//!
//! # fn main() -> anyhow::Result<()> {
//! // Single-level glob
//! let re = glob_to_regex("*.txt")?;
//! assert!(re.is_match("file.txt"));
//! assert!(!re.is_match("dir/file.txt"));
//!
//! // Multi-level glob with ** followed by /
//! let re = glob_to_regex("**/*.py")?;
//! assert!(re.is_match("main.py")); // **/ matches zero or more directories
//! assert!(re.is_match("src/main.py"));
//! assert!(re.is_match("src/sub/test.py"));
//!
//! // Double asterisk with slash (matches zero or more path components)
//! let re = glob_to_regex("**/main.rs")?;
//! assert!(re.is_match("main.rs")); // **/ matches zero directories
//! assert!(re.is_match("src/main.rs"));
//!
//! // Character class
//! let re = glob_to_regex("src/[abc]*.js")?;
//! assert!(re.is_match("src/app.js"));
//! assert!(re.is_match("src/config.js"));
//! assert!(!re.is_match("src/main.js"));
//! # Ok(())
//! # }
//! ```

use anyhow::{anyhow, Result};
use regex::Regex;

/// Converts a glob pattern to a compiled regular expression.
///
/// This function implements glob pattern matching as used in the Anthropic
/// Sandbox Runtime for path matching in filesystem rules.
///
/// # Arguments
///
/// * `glob` - A glob pattern string
///
/// # Returns
///
/// A compiled `Regex` that matches paths conforming to the glob pattern,
/// or an error if regex compilation fails.
///
/// # Pattern Syntax
///
/// - `*` matches any sequence of characters except `/` (single path component)
/// - `**` matches any sequence of characters including `/` (multiple components)
/// - `?` matches exactly one character except `/`
/// - `[abc]` matches any character in the character class
/// - `[a-z]` matches any character in the range
/// - `{a,b,c}` matches any of the comma-separated alternatives (brace expansion)
/// - All other characters are treated as literals (regex special chars are escaped)
///
/// # Examples
///
/// ```
/// use srt::utils::glob::glob_to_regex;
///
/// # fn main() -> anyhow::Result<()> {
/// // Basic wildcard
/// let re = glob_to_regex("*.txt")?;
/// assert!(re.is_match("file.txt"));
/// assert!(!re.is_match("dir/file.txt")); // * doesn't match /
///
/// // Double asterisk for deep matching
/// let re = glob_to_regex("src/**/*.py")?;
/// assert!(re.is_match("src/test.py"));
/// assert!(re.is_match("src/utils/helpers.py"));
/// assert!(re.is_match("src/deep/nested/module.py"));
///
/// // Double asterisk with slash matches zero or more path components
/// let re = glob_to_regex("**/test.rs")?;
/// assert!(re.is_match("test.rs")); // **/ matches zero directories
/// assert!(re.is_match("src/test.rs"));
/// assert!(re.is_match("src/nested/test.rs"));
///
/// // Question mark for single character
/// let re = glob_to_regex("file?.txt")?;
/// assert!(re.is_match("file1.txt"));
/// assert!(!re.is_match("file/.txt")); // ? doesn't match /
/// assert!(!re.is_match("file12.txt")); // ? matches exactly one
/// # Ok(())
/// # }
/// ```
pub fn glob_to_regex(glob: &str) -> Result<Regex> {
    let regex_str = glob_to_regex_string(glob)?;
    Regex::new(&regex_str).map_err(|e| anyhow!("Failed to compile glob pattern to regex: {}", e))
}

/// Converts a glob pattern to a regex pattern string.
///
/// This is the core implementation that processes the glob pattern character
/// by character and builds up the equivalent regex pattern.
///
/// # Arguments
///
/// * `glob` - A glob pattern string
///
/// # Returns
///
/// A regex pattern string (without compilation), or an error if the pattern
/// contains invalid character classes.
///
/// # Implementation Details
///
/// The algorithm iterates through the glob pattern:
/// 1. For `*` characters:
///    - Check if followed by another `*` (lookahead)
///    - `**/` becomes `(?:.*/)?` (optionally matches any path with trailing `/`)
///    - `**` (not followed by `/`) becomes `.*` (matches anything including `/`)
///    - Single `*` becomes `[^/]*` (matches anything except `/`)
/// 2. For `?` characters: becomes `[^/]` (single non-slash char)
/// 3. For `[` characters: find the matching `]` and pass the class through
/// 4. For `{` characters: find the matching `}`, split by `,`, and convert to `(?:alt1|alt2|...)`
/// 5. For all other characters: escape them for regex safety
///
/// The result is wrapped with `^` and `$` anchors to match the entire path.
fn glob_to_regex_string(glob: &str) -> Result<String> {
    let mut regex = String::from("^");
    let glob_bytes = glob.as_bytes();
    let mut i = 0;

    while i < glob_bytes.len() {
        let char = glob_bytes[i] as char;

        match char {
            '*' => {
                // Check for double asterisk
                if i + 1 < glob_bytes.len() && glob_bytes[i + 1] as char == '*' {
                    // Check if ** is followed by /
                    if i + 2 < glob_bytes.len() && glob_bytes[i + 2] as char == '/' {
                        // **/ should match zero or more directories
                        // (?:.*/)?  means: optionally match any characters followed by /
                        regex.push_str("(?:.*/)?");
                        i += 3; // Skip **, and /
                    } else {
                        // ** without / matches anything including /
                        regex.push_str(".*");
                        i += 2;
                    }
                } else {
                    // Single * matches anything except /
                    regex.push_str("[^/]*");
                    i += 1;
                }
            }
            '?' => {
                // ? matches single character except /
                regex.push_str("[^/]");
                i += 1;
            }
            '[' => {
                // Character class: find closing ] and pass through
                if let Some(close_idx) = glob[i..].find(']') {
                    let class = &glob[i..i + close_idx + 1];
                    regex.push_str(class);
                    i += close_idx + 1;
                } else {
                    return Err(anyhow!(
                        "Unclosed character class '[' at position {} in glob pattern: {}",
                        i,
                        glob
                    ));
                }
            }
            '{' => {
                // Brace expansion: convert {a,b,c} to (?:a|b|c)
                if let Some(close_idx) = glob[i..].find('}') {
                    let content = &glob[i + 1..i + close_idx];
                    let alternatives: Vec<&str> = content.split(',').collect();

                    // Build regex alternation: (?:alt1|alt2|...)
                    regex.push_str("(?:");
                    for (idx, alt) in alternatives.iter().enumerate() {
                        if idx > 0 {
                            regex.push('|');
                        }
                        // Escape each alternative to handle regex special chars
                        let escaped = regex::escape(alt);
                        regex.push_str(&escaped);
                    }
                    regex.push(')');

                    i += close_idx + 1;
                } else {
                    return Err(anyhow!(
                        "Unclosed brace expansion '{{' at position {} in glob pattern: {}",
                        i,
                        glob
                    ));
                }
            }
            _ => {
                // Escape regex special characters
                let escaped = regex::escape(&char.to_string());
                regex.push_str(&escaped);
                i += 1;
            }
        }
    }

    regex.push('$');
    Ok(regex)
}

/// Checks if a path matches a glob pattern without compiling to regex.
///
/// This is a convenience function that combines `glob_to_regex` and matching
/// in one operation. Use this when you only need to test a single path.
///
/// For multiple matches against the same pattern, compile the regex once
/// and reuse it.
///
/// # Arguments
///
/// * `glob` - A glob pattern string
/// * `path` - A filesystem path to test
///
/// # Returns
///
/// `true` if the path matches the glob pattern, `false` otherwise.
/// Returns `false` if the glob pattern is invalid.
///
/// # Examples
///
/// ```
/// use srt::utils::glob::matches_glob;
///
/// assert!(matches_glob("*.txt", "file.txt").unwrap_or(false));
/// assert!(!matches_glob("*.txt", "file.rs").unwrap_or(false));
/// assert!(matches_glob("**/*.rs", "src/main.rs").unwrap_or(false));
/// ```
pub fn matches_glob(glob: &str, path: &str) -> Result<bool> {
    let regex = glob_to_regex(glob)?;
    Ok(regex.is_match(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_literal_pattern() -> Result<()> {
        let re = glob_to_regex("file.txt")?;
        assert!(re.is_match("file.txt"));
        assert!(!re.is_match("file.rs"));
        assert!(!re.is_match("dir/file.txt"));
        Ok(())
    }

    #[test]
    fn test_single_asterisk() -> Result<()> {
        let re = glob_to_regex("*.txt")?;
        assert!(re.is_match("file.txt"));
        assert!(re.is_match("test.txt"));
        assert!(!re.is_match("file.rs"));
        assert!(!re.is_match("dir/file.txt")); // * doesn't match /
        Ok(())
    }

    #[test]
    fn test_double_asterisk() -> Result<()> {
        let re = glob_to_regex("**/*.py")?;
        assert!(re.is_match("script.py")); // **/ matches zero directories
        assert!(re.is_match("src.py")); // **/ matches zero directories
        assert!(re.is_match("src/main.py"));
        assert!(re.is_match("src/utils/helpers.py"));
        Ok(())
    }

    #[test]
    fn test_double_asterisk_at_start() -> Result<()> {
        // **/pattern matches zero or more directories
        let re = glob_to_regex("**/test.rs")?;
        assert!(re.is_match("test.rs")); // **/ matches zero directories
        assert!(re.is_match("src/test.rs"));
        assert!(re.is_match("src/deep/nested/test.rs"));
        assert!(!re.is_match("test.ts"));
        Ok(())
    }

    #[test]
    fn test_question_mark() -> Result<()> {
        let re = glob_to_regex("file?.txt")?;
        assert!(re.is_match("file1.txt"));
        assert!(re.is_match("fileA.txt"));
        assert!(!re.is_match("file.txt")); // ? requires exactly one char
        assert!(!re.is_match("file12.txt"));
        assert!(!re.is_match("file/.txt")); // ? doesn't match /
        Ok(())
    }

    #[test]
    fn test_character_class() -> Result<()> {
        let re = glob_to_regex("src/[abc]*.js")?;
        assert!(re.is_match("src/app.js"));
        assert!(re.is_match("src/config.js"));
        assert!(re.is_match("src/bootstrap.js"));
        assert!(!re.is_match("src/main.js"));
        assert!(!re.is_match("src/test.js"));
        Ok(())
    }

    #[test]
    fn test_character_class_range() -> Result<()> {
        let re = glob_to_regex("[a-z]*.txt")?;
        assert!(re.is_match("abc.txt"));
        assert!(re.is_match("file.txt"));
        assert!(!re.is_match("ABC.txt"));
        assert!(!re.is_match("123.txt"));
        Ok(())
    }

    #[test]
    fn test_regex_special_chars_escaped() -> Result<()> {
        let re = glob_to_regex("test.txt")?;
        assert!(re.is_match("test.txt"));
        assert!(!re.is_match("testXtxt")); // . should not match any char
        Ok(())
    }

    #[test]
    fn test_complex_pattern() -> Result<()> {
        let re = glob_to_regex("src/**/[abc]*.{js,ts}")?;
        assert!(re.is_match("src/app.js"));
        assert!(re.is_match("src/utils/config.ts"));
        assert!(re.is_match("src/deep/nested/bootstrap.js"));
        assert!(!re.is_match("src/main.js")); // 'm' not in [abc]
        assert!(!re.is_match("src/app.rs")); // .rs doesn't match {js,ts}
        Ok(())
    }

    #[test]
    fn test_unclosed_character_class() {
        let result = glob_to_regex_string("file[abc");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unclosed character class"));
    }

    #[test]
    fn test_brace_expansion_simple() -> Result<()> {
        let re = glob_to_regex("*.{js,ts}")?;
        assert!(re.is_match("app.js"));
        assert!(re.is_match("config.ts"));
        assert!(!re.is_match("main.rs"));
        assert!(!re.is_match("test.py"));
        Ok(())
    }

    #[test]
    fn test_brace_expansion_multiple_alternatives() -> Result<()> {
        let re = glob_to_regex("*.{html,css,js,ts}")?;
        assert!(re.is_match("index.html"));
        assert!(re.is_match("styles.css"));
        assert!(re.is_match("app.js"));
        assert!(re.is_match("types.ts"));
        assert!(!re.is_match("main.rs"));
        Ok(())
    }

    #[test]
    fn test_brace_expansion_with_path() -> Result<()> {
        let re = glob_to_regex("src/*.{py,java}")?;
        assert!(re.is_match("src/main.py"));
        assert!(re.is_match("src/Main.java"));
        assert!(!re.is_match("src/main.rs"));
        assert!(!re.is_match("test/main.py")); // Wrong directory
        Ok(())
    }

    #[test]
    fn test_brace_expansion_special_chars() -> Result<()> {
        // Test that special regex chars in alternatives are escaped
        let re = glob_to_regex("*.{c++,c}")?;
        assert!(re.is_match("main.c++"));
        assert!(re.is_match("util.c"));
        assert!(!re.is_match("main.cpp"));
        Ok(())
    }

    #[test]
    fn test_unclosed_brace_expansion() {
        let result = glob_to_regex_string("*.{js,ts");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unclosed brace expansion"));
    }

    #[test]
    fn test_empty_pattern() -> Result<()> {
        let re = glob_to_regex("")?;
        assert!(re.is_match(""));
        assert!(!re.is_match("anything"));
        Ok(())
    }

    #[test]
    fn test_matches_glob_convenience() -> Result<()> {
        assert!(matches_glob("*.txt", "file.txt")?);
        assert!(!matches_glob("*.txt", "file.rs")?);
        assert!(matches_glob("**/*.py", "src/main.py")?);
        Ok(())
    }

    #[test]
    fn test_path_with_slashes() -> Result<()> {
        let re = glob_to_regex("src/*/test.rs")?;
        assert!(re.is_match("src/utils/test.rs"));
        assert!(!re.is_match("src/deep/nested/test.rs")); // * doesn't match /
        Ok(())
    }

    #[test]
    fn test_multiple_wildcards() -> Result<()> {
        let re = glob_to_regex("*.min.*.js")?;
        assert!(re.is_match("app.min.prod.js"));
        assert!(re.is_match("lib.min.bundle.js"));
        assert!(!re.is_match("app.js"));
        assert!(!re.is_match("app.min.js")); // Missing the second *
        Ok(())
    }

    #[test]
    fn test_seatbelt_use_cases() -> Result<()> {
        // macOS Seatbelt profile regex patterns

        // Allow /Users/user/workspace/** for write access
        let re = glob_to_regex("/Users/*/workspace/**")?;
        assert!(re.is_match("/Users/alice/workspace/file.txt"));
        assert!(re.is_match("/Users/bob/workspace/src/main.py"));
        assert!(!re.is_match("/Users/alice/other/file.txt"));

        // Block /home/user/.ssh/**
        let re = glob_to_regex("/home/*/.ssh/**")?;
        assert!(re.is_match("/home/alice/.ssh/id_rsa"));
        assert!(re.is_match("/home/alice/.ssh/config"));
        assert!(!re.is_match("/home/alice/.config/ssh"));

        // Allow /etc/config*.json files
        let re = glob_to_regex("/etc/config*.json")?;
        assert!(re.is_match("/etc/config.json"));
        assert!(re.is_match("/etc/config-prod.json"));
        assert!(!re.is_match("/etc/config.yaml"));

        Ok(())
    }

    #[test]
    fn test_edge_case_consecutive_asterisks() -> Result<()> {
        // *** should be interpreted as ** followed by *
        let re = glob_to_regex("***")?;
        // ** matches anything (incl /), then * matches anything except /
        assert!(re.is_match("anything"));
        assert!(re.is_match("any/thing"));
        Ok(())
    }

    #[test]
    fn test_tilde_not_special() -> Result<()> {
        // ~ should be literal, not expanded
        let re = glob_to_regex("~/*.txt")?;
        assert!(re.is_match("~/file.txt"));
        assert!(!re.is_match("home/user/file.txt"));
        Ok(())
    }

    #[test]
    fn test_leading_slash() -> Result<()> {
        // Absolute paths
        let re = glob_to_regex("/var/log/*.log")?;
        assert!(re.is_match("/var/log/system.log"));
        assert!(re.is_match("/var/log/auth.log"));
        assert!(!re.is_match("/var/log/syslog")); // Doesn't end with .log
        assert!(!re.is_match("var/log/system.log")); // Missing leading /
        Ok(())
    }
}
