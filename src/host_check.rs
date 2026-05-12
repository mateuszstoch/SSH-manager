use std::net::TcpStream;
use std::time::Duration;

/// Reachability status for a single host.
#[derive(Debug, Clone, PartialEq)]
pub enum HostStatus {
    /// TCP handshake on the given port succeeded within the timeout.
    Reachable,
    /// Connection refused or timed out.
    Unreachable,
}

impl HostStatus {
    /// Returns a plain-ASCII label for use in terminal output.
    pub fn label(&self) -> &'static str {
        match self {
            HostStatus::Reachable => "[up]",
            HostStatus::Unreachable => "[down]",
        }
    }
}

// Connection timeout – short enough to keep `list` snappy.
const TIMEOUT: Duration = Duration::from_secs(2);

/// Checks a single host by attempting a TCP connect to `host:port`.
pub fn check_host(host: &str, port: u16) -> HostStatus {
    let addr = format!("{host}:{port}");
    match TcpStream::connect_timeout(&addr.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()), TIMEOUT) {
        Ok(_) => HostStatus::Reachable,
        Err(_) => HostStatus::Unreachable,
    }
}

/// Checks all hosts concurrently using `tokio::task::spawn_blocking` and returns
/// a `Vec<HostStatus>` in the same order as the input slice.
pub async fn check_all(hosts: &[(String, u16)]) -> Vec<HostStatus> {
    let handles: Vec<_> = hosts
        .iter()
        .map(|(host, port)| {
            let h = host.clone();
            let p = *port;
            tokio::task::spawn_blocking(move || check_host(&h, p))
        })
        .collect();

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        // Propagate panics as `Unreachable` rather than crashing the whole app.
        results.push(handle.await.unwrap_or(HostStatus::Unreachable));
    }
    results
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_strings_are_correct() {
        assert_eq!(HostStatus::Reachable.label(), "[up]");
        assert_eq!(HostStatus::Unreachable.label(), "[down]");
    }

    #[test]
    fn unreachable_host_returns_down_status() {
        // Port 1 on localhost is virtually never listening; expect a timeout/refused.
        let status = check_host("127.0.0.1", 1);
        assert_eq!(status, HostStatus::Unreachable);
    }

    #[test]
    fn invalid_address_is_handled_gracefully() {
        // An unparseable address must not panic – falls back to Unreachable.
        let status = check_host("not-a-valid-host-!@#", 22);
        assert_eq!(status, HostStatus::Unreachable);
    }
}

