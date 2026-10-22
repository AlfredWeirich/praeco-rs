//! # Connection Tracker
//!
//! Provides global and per-IP connection tracking with RAII guards to prevent
//! TCP socket exhaustion, file-descriptor leaks, and Slowloris-style denial of service.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Error returned when acquiring a connection permit fails due to configured limits.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AcquireError {
    /// The global server connection limit has been reached.
    #[error("Global connection limit reached ({current} >= {max})")]
    GlobalLimitReached { current: usize, max: usize },

    /// The per-IP connection limit has been reached for the specified client IP.
    #[error("Per-IP connection limit reached for {ip} ({current} >= {max})")]
    IpLimitReached { ip: IpAddr, current: u32, max: usize },
}

/// Tracks active connections globally and per client IP.
#[derive(Debug, Clone)]
pub struct ConnectionTracker {
    current_connections: Arc<AtomicUsize>,
    max_connections: usize,
    ip_counts: Arc<DashMap<IpAddr, u32>>,
    max_connections_per_ip: usize,
}

impl ConnectionTracker {
    /// Creates a new `ConnectionTracker` with the specified global and per-IP caps.
    pub fn new(max_connections: usize, max_connections_per_ip: usize) -> Self {
        Self {
            current_connections: Arc::new(AtomicUsize::new(0)),
            max_connections,
            ip_counts: Arc::new(DashMap::new()),
            max_connections_per_ip,
        }
    }

    /// Attempts to acquire a permit for an incoming connection.
    ///
    /// If successful, returns a [`ConnectionGuard`] which automatically releases
    /// the permits when dropped.
    pub fn acquire(&self, ip: Option<IpAddr>) -> Result<ConnectionGuard, AcquireError> {
        // 1. Check and increment global counter
        let current = self.current_connections.fetch_add(1, Ordering::SeqCst);
        if current >= self.max_connections {
            self.current_connections.fetch_sub(1, Ordering::SeqCst);
            return Err(AcquireError::GlobalLimitReached {
                current,
                max: self.max_connections,
            });
        }

        // 2. Check and increment per-IP counter (skipping unspecified addresses such as 0.0.0.0 from tunnels)
        if let Some(ip_addr) = ip {
            if !ip_addr.is_unspecified() {
                let mut entry = self.ip_counts.entry(ip_addr).or_insert(0);
                if *entry as usize >= self.max_connections_per_ip {
                    let cur_ip = *entry;
                    drop(entry);
                    self.current_connections.fetch_sub(1, Ordering::SeqCst);
                    return Err(AcquireError::IpLimitReached {
                        ip: ip_addr,
                        current: cur_ip,
                        max: self.max_connections_per_ip,
                    });
                }
                *entry += 1;
            }
        }

        Ok(ConnectionGuard {
            tracker: self.clone(),
            ip,
        })
    }

    /// Internal release function called by [`ConnectionGuard::drop`].
    fn release(&self, ip: Option<IpAddr>) {
        self.current_connections.fetch_sub(1, Ordering::SeqCst);
        if let Some(ip_addr) = ip {
            if !ip_addr.is_unspecified() {
                if let dashmap::mapref::entry::Entry::Occupied(mut occ) = self.ip_counts.entry(ip_addr) {
                    let count = occ.get_mut();
                    if *count <= 1 {
                        occ.remove();
                    } else {
                        *count -= 1;
                    }
                }
            }
        }
    }

    /// Returns the current number of active connections tracked across the server.
    pub fn current_connections(&self) -> usize {
        self.current_connections.load(Ordering::SeqCst)
    }

    /// Returns the active connection count for a specific IP address.
    pub fn connections_for_ip(&self, ip: &IpAddr) -> u32 {
        self.ip_counts.get(ip).map(|v| *v).unwrap_or(0)
    }

    /// Returns the configured global maximum number of connections.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Returns the configured maximum number of connections per IP address.
    pub fn max_connections_per_ip(&self) -> usize {
        self.max_connections_per_ip
    }
}

/// RAII guard that holds a connection permit. Decrements active counts upon drop.
#[derive(Debug)]
pub struct ConnectionGuard {
    tracker: ConnectionTracker,
    ip: Option<IpAddr>,
}

impl ConnectionGuard {
    /// Associates a resolved client IP with this active connection guard,
    /// checking and incrementing the per-IP connection limit.
    pub fn bind_ip(&mut self, ip: IpAddr) -> Result<(), AcquireError> {
        if ip.is_unspecified() || self.ip.is_some() {
            return Ok(());
        }
        let mut entry = self.tracker.ip_counts.entry(ip).or_insert(0);
        if *entry as usize >= self.tracker.max_connections_per_ip {
            let cur_ip = *entry;
            return Err(AcquireError::IpLimitReached {
                ip,
                current: cur_ip,
                max: self.tracker.max_connections_per_ip,
            });
        }
        *entry += 1;
        self.ip = Some(ip);
        Ok(())
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.tracker.release(self.ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_global_connection_limit() {
        let tracker = ConnectionTracker::new(2, 10);
        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();

        let g1 = tracker.acquire(Some(ip)).expect("first connection ok");
        assert_eq!(tracker.current_connections(), 1);

        let g2 = tracker.acquire(Some(ip)).expect("second connection ok");
        assert_eq!(tracker.current_connections(), 2);

        let g3_err = tracker.acquire(Some(ip)).expect_err("third connection should exceed global limit");
        assert_eq!(
            g3_err,
            AcquireError::GlobalLimitReached {
                current: 2,
                max: 2,
            }
        );
        assert_eq!(tracker.current_connections(), 2);

        drop(g1);
        assert_eq!(tracker.current_connections(), 1);

        let _g3_retry = tracker.acquire(Some(ip)).expect("should succeed after drop");
        assert_eq!(tracker.current_connections(), 2);

        drop(g2);
    }

    #[test]
    fn test_per_ip_connection_limit() {
        let tracker = ConnectionTracker::new(10, 2);
        let ip_a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let ip_b: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();

        let g_a1 = tracker.acquire(Some(ip_a)).expect("ip_a conn 1 ok");
        let _g_a2 = tracker.acquire(Some(ip_a)).expect("ip_a conn 2 ok");
        assert_eq!(tracker.connections_for_ip(&ip_a), 2);

        let g_a3_err = tracker.acquire(Some(ip_a)).expect_err("ip_a conn 3 should exceed per-ip limit");
        assert_eq!(
            g_a3_err,
            AcquireError::IpLimitReached {
                ip: ip_a,
                current: 2,
                max: 2,
            }
        );
        // Global count must be 2, not 3
        assert_eq!(tracker.current_connections(), 2);

        // Another IP can still connect
        let g_b1 = tracker.acquire(Some(ip_b)).expect("ip_b conn 1 ok");
        assert_eq!(tracker.connections_for_ip(&ip_b), 1);
        assert_eq!(tracker.current_connections(), 3);

        // Dropping one from IP A frees up quota for IP A
        drop(g_a1);
        assert_eq!(tracker.connections_for_ip(&ip_a), 1);
        assert_eq!(tracker.current_connections(), 2);

        let _g_a3_retry = tracker.acquire(Some(ip_a)).expect("ip_a retry ok after drop");
        assert_eq!(tracker.connections_for_ip(&ip_a), 2);

        drop(g_b1);
    }

    #[test]
    fn test_unspecified_ip_bypasses_per_ip_limit() {
        let tracker = ConnectionTracker::new(5, 1);
        let unspecified: IpAddr = Ipv4Addr::UNSPECIFIED.into(); // 0.0.0.0

        let g1 = tracker.acquire(Some(unspecified)).expect("unspecified 1 ok");
        let g2 = tracker.acquire(Some(unspecified)).expect("unspecified 2 ok despite per-ip limit 1");
        let g3 = tracker.acquire(None).expect("none IP ok");

        assert_eq!(tracker.current_connections(), 3);
        assert_eq!(tracker.connections_for_ip(&unspecified), 0);

        drop(g1);
        drop(g2);
        drop(g3);
        assert_eq!(tracker.current_connections(), 0);
    }

    #[test]
    fn test_dashmap_cleanup_on_zero() {
        let tracker = ConnectionTracker::new(10, 5);
        let ip: IpAddr = Ipv4Addr::new(172, 16, 0, 1).into();

        let g = tracker.acquire(Some(ip)).expect("conn ok");
        assert_eq!(tracker.connections_for_ip(&ip), 1);
        assert!(tracker.ip_counts.contains_key(&ip));

        drop(g);
        assert_eq!(tracker.connections_for_ip(&ip), 0);
        // The entry must be removed completely from DashMap to prevent memory growth
        assert!(!tracker.ip_counts.contains_key(&ip));
    }

    #[tokio::test]
    async fn test_concurrent_acquisitions() {
        let tracker = Arc::new(ConnectionTracker::new(50, 10));
        let mut handles = Vec::new();

        // Spawn 20 tasks per IP for 5 different IPs (total 100 attempts, max 50 global, max 10 per IP)
        for ip_idx in 0..5 {
            let ip: IpAddr = Ipv4Addr::new(10, 0, 0, ip_idx as u8 + 1).into();
            for _ in 0..20 {
                let tracker_clone = tracker.clone();
                handles.push(tokio::spawn(async move {
                    tracker_clone.acquire(Some(ip))
                }));
            }
        }

        let mut successful_guards = Vec::new();
        let mut global_rejected = 0;
        let mut ip_rejected = 0;

        for handle in handles {
            match handle.await.unwrap() {
                Ok(guard) => successful_guards.push(guard),
                Err(AcquireError::GlobalLimitReached { .. }) => global_rejected += 1,
                Err(AcquireError::IpLimitReached { .. }) => ip_rejected += 1,
            }
        }

        // At most 50 successful guards because global limit is 50
        assert!(successful_guards.len() <= 50);
        // And at most 10 per IP
        for ip_idx in 0..5 {
            let ip: IpAddr = Ipv4Addr::new(10, 0, 0, ip_idx as u8 + 1).into();
            assert!(tracker.connections_for_ip(&ip) <= 10);
        }
        assert_eq!(successful_guards.len() + global_rejected + ip_rejected, 100);

        // When all guards drop, count returns to 0
        drop(successful_guards);
        assert_eq!(tracker.current_connections(), 0);
        assert_eq!(tracker.ip_counts.len(), 0);
    }

    #[tokio::test]
    async fn test_tcp_accept_loop_per_ip_limit_rejection() {
        use tokio::net::{TcpListener, TcpStream};
        use tokio::io::AsyncReadExt;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Global limit = 5, per-IP limit = 1
        let tracker = Arc::new(ConnectionTracker::new(5, 1));
        let cancel_token = tokio_util::sync::CancellationToken::new();

        let cancel_clone = cancel_token.clone();
        let tracker_clone = tracker.clone();
        let server_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    res = listener.accept() => {
                        let (stream, peer_addr) = match res {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        let guard = match tracker_clone.acquire(Some(peer_addr.ip())) {
                            Ok(g) => g,
                            Err(_) => {
                                // Drop socket immediately on connection limit
                                drop(stream);
                                continue;
                            }
                        };
                        let conn_cancel = cancel_clone.child_token();
                        tokio::spawn(async move {
                            let _guard = guard;
                            let mut stream = stream;
                            let mut buf = [0u8; 1];
                            tokio::select! {
                                _ = conn_cancel.cancelled() => {},
                                _ = stream.read(&mut buf) => {},
                            }
                        });
                    }
                }
            }
        });

        // 1. First connection from 127.0.0.1 (per-IP limit = 1) -> accepted
        let client1 = TcpStream::connect(addr).await.expect("client1 connect");
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert_eq!(tracker.connections_for_ip(&addr.ip()), 1);

        // 2. Second connection from same IP -> server accepts, then drops because per-IP limit reached
        let mut client2 = TcpStream::connect(addr).await.expect("client2 connect");
        // Reading from client2 should immediately return EOF (0 bytes) because the server dropped it
        let mut buf = [0u8; 16];
        let n = client2.read(&mut buf).await.expect("client2 read");
        assert_eq!(n, 0, "client2 should receive EOF immediately because server dropped the connection");

        // Per-IP count must still be 1 (client1)
        assert_eq!(tracker.connections_for_ip(&addr.ip()), 1);

        // 3. Drop client1
        drop(client1);
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert_eq!(tracker.connections_for_ip(&addr.ip()), 0);

        // 4. Third connection can now succeed since slot is free
        let _client3 = TcpStream::connect(addr).await.expect("client3 connect");
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert_eq!(tracker.connections_for_ip(&addr.ip()), 1);

        cancel_token.cancel();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn test_tcp_accept_loop_global_limit_rejection() {
        use tokio::net::{TcpListener, TcpStream};
        use tokio::io::AsyncReadExt;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Global limit = 1, per-IP limit = 10
        let tracker = Arc::new(ConnectionTracker::new(1, 10));
        let cancel_token = tokio_util::sync::CancellationToken::new();

        let cancel_clone = cancel_token.clone();
        let tracker_clone = tracker.clone();
        let server_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    res = listener.accept() => {
                        let (stream, peer_addr) = match res {
                            Ok(v) => v,
                            Err(_) => break,
                        };
                        let guard = match tracker_clone.acquire(Some(peer_addr.ip())) {
                            Ok(g) => g,
                            Err(_) => {
                                drop(stream);
                                continue;
                            }
                        };
                        let conn_cancel = cancel_clone.child_token();
                        tokio::spawn(async move {
                            let _guard = guard;
                            let mut stream = stream;
                            let mut buf = [0u8; 1];
                            tokio::select! {
                                _ = conn_cancel.cancelled() => {},
                                _ = stream.read(&mut buf) => {},
                            }
                        });
                    }
                }
            }
        });

        // First connection succeeds
        let client1 = TcpStream::connect(addr).await.expect("client1 connect");
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert_eq!(tracker.current_connections(), 1);

        // Second connection is dropped because global limit (1) is reached
        let mut client2 = TcpStream::connect(addr).await.expect("client2 connect");
        let mut buf = [0u8; 16];
        let n = client2.read(&mut buf).await.expect("client2 read");
        assert_eq!(n, 0, "client2 should receive EOF immediately because global limit was reached");

        // After client1 drops, slot is free
        drop(client1);
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert_eq!(tracker.current_connections(), 0);

        let _client3 = TcpStream::connect(addr).await.expect("client3 connect");
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert_eq!(tracker.current_connections(), 1);

        cancel_token.cancel();
        let _ = server_task.await;
    }

    #[test]
    fn test_connection_guard_bind_ip() {
        let tracker = ConnectionTracker::new(10, 2);
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 5).into();

        // 1. Acquire permit with None (tunnel stream before reading PROXY header)
        let mut g1 = tracker.acquire(None).expect("global acquire ok");
        assert_eq!(tracker.current_connections(), 1);
        assert_eq!(tracker.connections_for_ip(&ip), 0);

        // 2. Bind IP after reading PROXY header
        g1.bind_ip(ip).expect("bind_ip 1 ok");
        assert_eq!(tracker.connections_for_ip(&ip), 1);

        // 3. Second connection from same IP
        let mut g2 = tracker.acquire(None).expect("global acquire ok");
        g2.bind_ip(ip).expect("bind_ip 2 ok");
        assert_eq!(tracker.connections_for_ip(&ip), 2);

        // 4. Third connection exceeds per-IP limit (2)
        let mut g3 = tracker.acquire(None).expect("global acquire ok");
        let err = g3.bind_ip(ip).expect_err("should reject third connection from same IP");
        assert!(matches!(err, AcquireError::IpLimitReached { .. }));

        // Dropping g3 releases global permit
        drop(g3);
        assert_eq!(tracker.current_connections(), 2);
        assert_eq!(tracker.connections_for_ip(&ip), 2);

        // Dropping g1 decrements both global and IP count
        drop(g1);
        assert_eq!(tracker.current_connections(), 1);
        assert_eq!(tracker.connections_for_ip(&ip), 1);

        drop(g2);
        assert_eq!(tracker.current_connections(), 0);
        assert_eq!(tracker.connections_for_ip(&ip), 0);
    }
}
