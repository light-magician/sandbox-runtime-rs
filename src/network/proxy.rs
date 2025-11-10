//! Network proxy module for domain-based filtering.
//!
//! This module provides an HTTP/HTTPS proxy server that filters outbound connections
//! based on configurable domain allowlists with wildcard pattern support.
//!
//! # Features
//!
//! - HTTP/1.1 proxy for plain HTTP requests (GET, POST, etc.)
//! - HTTPS tunneling via CONNECT method
//! - Thread-safe dynamic domain rule updates
//! - Wildcard pattern matching (e.g., `*.example.com`)
//! - Domain blocking with 403 Forbidden responses
//!
//! # Example
//!
//! ```no_run
//! use srt::network::proxy::NetworkFilter;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let filter = NetworkFilter::new(vec![
//!         "*.example.com".to_string(),
//!         "api.trusted.com".to_string(),
//!     ]);
//!
//!     let addr = filter.start(8080).await?;
//!     println!("Proxy listening on {}", addr);
//!
//!     // Update rules dynamically
//!     filter.update_allowed_domains(vec!["*.newdomain.com".to_string()]);
//!
//!     Ok(())
//! }
//! ```

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::{TcpListener, TcpStream};

/// HTTP proxy server with domain-based filtering.
///
/// The `NetworkFilter` struct maintains a thread-safe list of allowed domains
/// and provides an HTTP/HTTPS proxy that filters connections based on these rules.
#[derive(Clone)]
pub struct NetworkFilter {
    /// Thread-safe allowed domain patterns with wildcard support.
    allowed_domains: Arc<RwLock<Vec<String>>>,
}

impl NetworkFilter {
    /// Creates a new network filter with the specified allowed domains.
    ///
    /// # Arguments
    ///
    /// * `allowed_domains` - List of domain patterns (supports wildcards like `*.example.com`)
    ///
    /// # Example
    ///
    /// ```
    /// use srt::network::proxy::NetworkFilter;
    ///
    /// let filter = NetworkFilter::new(vec![
    ///     "*.example.com".to_string(),
    ///     "api.service.com".to_string(),
    /// ]);
    /// ```
    pub fn new(allowed_domains: Vec<String>) -> Self {
        Self {
            allowed_domains: Arc::new(RwLock::new(allowed_domains)),
        }
    }

    /// Starts the HTTP proxy server on the specified port.
    ///
    /// The server will listen on `127.0.0.1:<port>` and handle both HTTP
    /// and HTTPS (via CONNECT) requests.
    ///
    /// # Arguments
    ///
    /// * `port` - Port number to bind to (e.g., 8080)
    ///
    /// # Returns
    ///
    /// The actual `SocketAddr` the server is listening on.
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to bind to the port.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use srt::network::proxy::NetworkFilter;
    /// # #[tokio::main]
    /// # async fn main() -> anyhow::Result<()> {
    /// let filter = NetworkFilter::new(vec!["*.example.com".to_string()]);
    /// let addr = filter.start(8080).await?;
    /// println!("Listening on {}", addr);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start(&self, port: u16) -> Result<SocketAddr> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(addr)
            .await
            .context("Failed to bind proxy server")?;

        let local_addr = listener.local_addr()?;

        let filter = self.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let filter = filter.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, filter).await {
                                tracing::debug!("Connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to accept connection: {}", e);
                    }
                }
            }
        });

        Ok(local_addr)
    }

    /// Updates the allowed domain patterns dynamically.
    ///
    /// This method can be called while the proxy is running. New rules
    /// take effect immediately for subsequent connections.
    ///
    /// # Arguments
    ///
    /// * `domains` - New list of allowed domain patterns
    ///
    /// # Example
    ///
    /// ```
    /// # use srt::network::proxy::NetworkFilter;
    /// let filter = NetworkFilter::new(vec!["*.old.com".to_string()]);
    /// filter.update_allowed_domains(vec![
    ///     "*.new.com".to_string(),
    ///     "api.service.com".to_string(),
    /// ]);
    /// ```
    pub fn update_allowed_domains(&self, domains: Vec<String>) {
        if let Ok(mut allowed) = self.allowed_domains.write() {
            *allowed = domains;
            tracing::info!("Updated allowed domains: {:?}", *allowed);
        }
    }

    /// Checks if a domain is allowed by the current filtering rules.
    ///
    /// Supports wildcard patterns:
    /// - `*.example.com` matches `sub.example.com`, `a.b.example.com`, etc.
    /// - `example.com` matches exactly `example.com`
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to check (hostname without port)
    ///
    /// # Returns
    ///
    /// `true` if the domain matches any allowed pattern, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// # use srt::network::proxy::NetworkFilter;
    /// let filter = NetworkFilter::new(vec!["*.example.com".to_string()]);
    /// assert!(filter.is_allowed("sub.example.com"));
    /// assert!(filter.is_allowed("a.b.example.com"));
    /// assert!(!filter.is_allowed("other.com"));
    /// ```
    pub fn is_allowed(&self, domain: &str) -> bool {
        let allowed = match self.allowed_domains.read() {
            Ok(guard) => guard,
            Err(_) => return false, // On lock poisoning, deny by default
        };

        // If no domains are configured, deny all
        if allowed.is_empty() {
            return false;
        }

        allowed
            .iter()
            .any(|pattern| matches_pattern(domain, pattern))
    }
}

/// Handles a single TCP connection to the proxy.
async fn handle_connection(stream: TcpStream, filter: NetworkFilter) -> Result<()> {
    let io = TokioIo::new(stream);

    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let filter = filter.clone();
                async move { handle_request(req, filter).await }
            }),
        )
        .with_upgrades()
        .await
        .context("Failed to serve connection")
}

/// Handles an individual HTTP request.
async fn handle_request(
    req: Request<Incoming>,
    filter: NetworkFilter,
) -> Result<Response<Full<Bytes>>> {
    let host = extract_host(&req).unwrap_or_default();

    // Check if domain is allowed
    if !filter.is_allowed(&host) {
        tracing::warn!("Blocked request to: {}", host);
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from(format!(
                "Domain blocked by proxy: {}\n",
                host
            ))))
            .unwrap());
    }

    tracing::debug!("Allowing request to: {}", host);

    match req.method() {
        &Method::CONNECT => handle_connect(req).await,
        _ => handle_http(req, &host).await,
    }
}

/// Handles HTTPS CONNECT tunneling.
///
/// Establishes a TCP tunnel between the client and the destination server
/// for end-to-end encrypted connections.
async fn handle_connect(req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    let uri = req.uri();
    let host_port = uri
        .authority()
        .context("Missing authority in CONNECT request")?
        .as_str();

    // Parse host:port
    let (host, port) = parse_host_port(host_port)?;

    tracing::debug!("CONNECT tunnel to {}:{}", host, port);

    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                // Connect to upstream server
                match TcpStream::connect((host.as_str(), port)).await {
                    Ok(mut upstream) => {
                        let mut upgraded = TokioIo::new(upgraded);

                        // Bidirectional copy
                        if let Err(e) =
                            tokio::io::copy_bidirectional(&mut upgraded, &mut upstream).await
                        {
                            tracing::debug!("Tunnel error: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to connect to {}:{}: {}", host, port, e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to upgrade connection: {}", e);
            }
        }
    });

    // Send 200 Connection Established
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

/// Handles plain HTTP requests (GET, POST, etc.).
async fn handle_http(req: Request<Incoming>, host: &str) -> Result<Response<Full<Bytes>>> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Build upstream URI
    let upstream_uri = build_upstream_uri(&uri, host)?;

    tracing::debug!("{} {}", method, upstream_uri);

    // Create HTTP client
    let client = Client::builder(TokioExecutor::new()).build_http();

    // Read request body
    let body_bytes = req
        .into_body()
        .collect()
        .await
        .context("Failed to read request body")?
        .to_bytes();

    // Forward request to upstream
    let upstream_req = Request::builder()
        .method(method)
        .uri(upstream_uri)
        .body(Full::new(body_bytes))
        .context("Failed to build upstream request")?;

    // Copy headers
    let mut upstream_req = upstream_req;
    *upstream_req.headers_mut() = headers;

    // Send request
    let upstream_res = client
        .request(upstream_req)
        .await
        .context("Failed to send upstream request")?;

    // Read response
    let status = upstream_res.status();
    let headers = upstream_res.headers().clone();
    let body_bytes = upstream_res
        .into_body()
        .collect()
        .await
        .context("Failed to read upstream response")?
        .to_bytes();

    // Build response
    let mut response = Response::builder()
        .status(status)
        .body(Full::new(body_bytes))
        .unwrap();

    *response.headers_mut() = headers;

    Ok(response)
}

/// Extracts the host from a request.
fn extract_host(req: &Request<Incoming>) -> Option<String> {
    // Try Host header first
    if let Some(host) = req.headers().get("host") {
        if let Ok(host_str) = host.to_str() {
            return Some(strip_port(host_str));
        }
    }

    // Fall back to URI authority
    req.uri().authority().map(|auth| strip_port(auth.as_str()))
}

/// Strips the port from a host:port string.
fn strip_port(host_port: &str) -> String {
    host_port.split(':').next().unwrap_or(host_port).to_string()
}

/// Parses "host:port" into separate components.
fn parse_host_port(host_port: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = host_port.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid host:port format: {}", host_port);
    }

    let host = parts[0].to_string();
    let port = parts[1].parse::<u16>().context("Invalid port number")?;

    Ok((host, port))
}

/// Builds an absolute URI for the upstream request.
fn build_upstream_uri(uri: &Uri, host: &str) -> Result<Uri> {
    let scheme = uri.scheme_str().unwrap_or("http");
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let uri_str = format!("{}://{}{}", scheme, host, path);
    uri_str.parse().context("Failed to parse upstream URI")
}

/// Checks if a domain matches a pattern with wildcard support.
///
/// Pattern rules:
/// - `*.example.com` matches any subdomain of `example.com`
/// - `example.com` matches exactly `example.com`
/// - Wildcards only supported at the start of the pattern
///
/// # Examples
///
/// ```
/// # use srt::network::proxy::matches_pattern;
/// assert!(matches_pattern("sub.example.com", "*.example.com"));
/// assert!(matches_pattern("a.b.example.com", "*.example.com"));
/// assert!(matches_pattern("example.com", "example.com"));
/// assert!(!matches_pattern("other.com", "*.example.com"));
/// ```
pub fn matches_pattern(domain: &str, pattern: &str) -> bool {
    if pattern.starts_with("*.") {
        // Wildcard pattern: *.example.com
        let base = &pattern[2..]; // Remove "*."

        // Match if domain ends with .base or equals base
        domain.ends_with(&format!(".{}", base)) || domain == base
    } else {
        // Exact match
        domain == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_pattern_wildcard() {
        assert!(matches_pattern("sub.example.com", "*.example.com"));
        assert!(matches_pattern("a.b.example.com", "*.example.com"));
        assert!(matches_pattern("deep.sub.example.com", "*.example.com"));
        assert!(matches_pattern("example.com", "*.example.com"));
        assert!(!matches_pattern("other.com", "*.example.com"));
        assert!(!matches_pattern("exampleXcom", "*.example.com"));
    }

    #[test]
    fn test_matches_pattern_exact() {
        assert!(matches_pattern("example.com", "example.com"));
        assert!(matches_pattern("api.service.com", "api.service.com"));
        assert!(!matches_pattern("sub.example.com", "example.com"));
        assert!(!matches_pattern("example.org", "example.com"));
    }

    #[test]
    fn test_is_allowed() {
        let filter = NetworkFilter::new(vec![
            "*.example.com".to_string(),
            "api.service.com".to_string(),
        ]);

        assert!(filter.is_allowed("sub.example.com"));
        assert!(filter.is_allowed("example.com"));
        assert!(filter.is_allowed("api.service.com"));
        assert!(!filter.is_allowed("other.com"));
        assert!(!filter.is_allowed("service.com"));
    }

    #[test]
    fn test_update_allowed_domains() {
        let filter = NetworkFilter::new(vec!["*.old.com".to_string()]);

        assert!(filter.is_allowed("sub.old.com"));
        assert!(!filter.is_allowed("sub.new.com"));

        filter.update_allowed_domains(vec!["*.new.com".to_string()]);

        assert!(!filter.is_allowed("sub.old.com"));
        assert!(filter.is_allowed("sub.new.com"));
    }

    #[test]
    fn test_strip_port() {
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("example.com:8080"), "example.com");
        assert_eq!(strip_port("localhost:3000"), "localhost");
    }

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("example.com:443").unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("localhost:8080").unwrap(),
            ("localhost".to_string(), 8080)
        );
        assert!(parse_host_port("invalid").is_err());
        assert!(parse_host_port("host:port:extra").is_err());
    }

    #[test]
    fn test_empty_allowlist() {
        let filter = NetworkFilter::new(vec![]);
        assert!(!filter.is_allowed("example.com"));
        assert!(!filter.is_allowed("any.domain.com"));
    }
}
