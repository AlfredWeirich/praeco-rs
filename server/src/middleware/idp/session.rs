//! # IdP QR-Code Session Store
//!
//! Manages short-lived authentication sessions for the DeviceAuth (QR Code) flow.

use common::Claims;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// Represents the current status of an authentication session.
#[derive(Debug, Clone)]
pub enum SessionStatus {
    /// The session has been created (e.g. QR code displayed) but not yet confirmed.
    Pending,
    /// The session has been successfully confirmed by a device holding a valid mTLS certificate.
    Confirmed(Claims),
}

/// An entry in the session store.
#[derive(Debug)]
struct SessionEntry {
    /// When this session was created (used for TTL expiration).
    created_at: Instant,
    /// The current status of the session.
    status: SessionStatus,
}

/// A thread-safe, fast concurrent store for short-lived IdP sessions.
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<DashMap<String, SessionEntry>>,
    ttl: Duration,
}

impl SessionStore {
    /// Creates a new SessionStore with the specified Time-To-Live (TTL) for sessions.
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    /// Creates a new pending session and returns its unique, random ID.
    pub fn create_session(&self) -> String {
        use rand::Rng;
        let mut rng = rand::rngs::OsRng;
        // Generate a random 32-character alphanumeric string for the session ID
        let mut session_id = String::with_capacity(32);
        const CHARSET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        for _ in 0..32 {
            let ch = CHARSET[rng.gen_range(0..CHARSET.len())] as char;
            session_id.push(ch);
        }

        self.sessions.insert(
            session_id.clone(),
            SessionEntry {
                created_at: Instant::now(),
                status: SessionStatus::Pending,
            },
        );

        trace!("Created new IdP session: {}", session_id);
        
        // Optionally trigger a cleanup of expired sessions
        self.cleanup_expired();

        session_id
    }

    /// Confirms a pending session, attaching the verified identity (Claims).
    /// Returns true if the session was successfully confirmed.
    pub fn confirm_session(&self, session_id: &str, claims: Claims) -> bool {
        if let Some(mut entry) = self.sessions.get_mut(session_id) {
            if entry.created_at.elapsed() > self.ttl {
                debug!("Attempted to confirm expired session: {}", session_id);
                return false;
            }
            entry.status = SessionStatus::Confirmed(claims);
            trace!("Confirmed IdP session: {}", session_id);
            true
        } else {
            false
        }
    }

    /// Retrieves the status of a session.
    /// If the session is confirmed, it is automatically removed from the store (One-Time-Use).
    pub fn get_and_consume(&self, session_id: &str) -> Option<SessionStatus> {
        // Atomically remove the session if it's Confirmed (or expired)
        if let Some((_, entry)) = self.sessions.remove_if(session_id, |_, entry| {
            entry.created_at.elapsed() > self.ttl || matches!(entry.status, SessionStatus::Confirmed(_))
        }) {
            if entry.created_at.elapsed() > self.ttl {
                None
            } else {
                Some(entry.status)
            }
        } else {
            // If it wasn't removed, it's either Pending (and not expired) or doesn't exist
            if let Some(entry) = self.sessions.get(session_id) {
                if entry.created_at.elapsed() > self.ttl {
                    None
                } else {
                    Some(entry.status.clone())
                }
            } else {
                None
            }
        }
    }

    /// Removes all expired sessions from the store.
    fn cleanup_expired(&self) {
        let ttl = self.ttl;
        self.sessions.retain(|_k, v| v.created_at.elapsed() <= ttl);
    }
}
