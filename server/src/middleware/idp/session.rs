//! # IdP QR-Code Session Store
//!
//! Manages short-lived authentication sessions for the DeviceAuth (QR Code) flow
//! with cryptographic browser binding (poll secret), user verification code (Quishing protection),
//! per-IP rate limiting, and bounded storage.

use common::Claims;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;

const MAX_LOGIN_REQUESTS_PER_MINUTE: u32 = 15;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const DEFAULT_MAX_ACTIVE_SESSIONS: usize = 5_000;
const CLEANUP_THROTTLE_INTERVAL: Duration = Duration::from_secs(10);
const MAX_CONFIRM_ATTEMPTS: u8 = 3;

/// Constant-time byte slice comparison to mitigate timing side-channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut res = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }
    res == 0
}

/// Generates a high-entropy 256-bit poll secret (URL-safe base64).
fn generate_poll_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generates a high-entropy 192-bit session ID (URL-safe base64).
fn generate_session_id() -> String {
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generates a human-readable 6-character user verification code formatted as `XXX-YYY`.
/// Omits easily confused characters (0/O, 1/I).
fn generate_user_code() -> String {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    const CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let mut code = String::with_capacity(7);
    for i in 0..6 {
        if i == 3 {
            code.push('-');
        }
        let ch = CHARSET[rng.gen_range(0..CHARSET.len())] as char;
        code.push(ch);
    }
    code
}

/// Public session information returned to the initiating browser upon `POST /auth/login`.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Public session ID (encoded in QR code).
    pub session_id: String,
    /// High-entropy secret known only to the initiating browser, required to poll status.
    pub poll_secret: String,
    /// Visual verification code displayed in browser and checked on device (Quishing protection).
    pub user_code: String,
}

/// Represents the current status of an authentication session.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionStatus {
    /// The session has been created but not yet confirmed by an authenticated device.
    Pending,
    /// The session has been successfully confirmed by a device holding a valid mTLS certificate.
    Confirmed(Claims),
}

/// Internal session entry.
#[derive(Debug)]
struct SessionEntry {
    created_at: Instant,
    poll_secret: String,
    user_code: String,
    failed_attempts: u8,
    aud: Option<String>,
    #[allow(dead_code)]
    client_ip: Option<IpAddr>,
    status: SessionStatus,
}

/// Errors when creating a new session.
#[derive(Debug, PartialEq, Eq)]
pub enum CreateSessionError {
    RateLimited,
    CapacityExceeded,
}

/// Errors when polling a session.
#[derive(Debug, PartialEq, Eq)]
pub enum PollError {
    NotFound,
    Unauthorized,
}

/// Errors when confirming a session.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfirmError {
    NotFound,
    Expired,
    InvalidUserCode,
    AlreadyConfirmed,
}

/// A thread-safe, concurrent store for short-lived IdP sessions.
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<DashMap<String, SessionEntry>>,
    ip_rate_limits: Arc<DashMap<IpAddr, (u32, Instant)>>,
    ttl: Duration,
    max_active_sessions: usize,
    last_cleanup: Arc<std::sync::Mutex<Instant>>,
}

impl SessionStore {
    /// Creates a new SessionStore with the specified Time-To-Live (TTL) for sessions.
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            ip_rate_limits: Arc::new(DashMap::new()),
            ttl: Duration::from_secs(ttl_seconds),
            max_active_sessions: DEFAULT_MAX_ACTIVE_SESSIONS,
            last_cleanup: Arc::new(std::sync::Mutex::new(Instant::now())),
        }
    }

    /// Creates a new pending session and returns its unique [`SessionInfo`].
    ///
    /// Enforces per-IP rate limiting and bounded store capacity.
    pub fn create_session(
        &self,
        client_ip: Option<IpAddr>,
        aud: Option<String>,
    ) -> Result<SessionInfo, CreateSessionError> {
        let client_ip = client_ip.map(common::canonical_client_ip);

        // 1. Throttled Cleanup
        self.maybe_cleanup_expired();

        // 2. IP Rate Limiting
        if let Some(ip) = client_ip {
            if !self.ip_rate_limits.contains_key(&ip)
                && self.ip_rate_limits.len() >= self.max_active_sessions * 2
            {
                self.cleanup_expired_force();
                if !self.ip_rate_limits.contains_key(&ip)
                    && self.ip_rate_limits.len() >= self.max_active_sessions * 2
                {
                    warn!("IdP IP rate limit table capacity reached");
                    return Err(CreateSessionError::CapacityExceeded);
                }
            }
            let mut rate_entry = self.ip_rate_limits.entry(ip).or_insert((0, Instant::now()));
            let (count, start) = rate_entry.value_mut();
            if start.elapsed() > RATE_LIMIT_WINDOW {
                *count = 1;
                *start = Instant::now();
            } else {
                *count += 1;
                if *count > MAX_LOGIN_REQUESTS_PER_MINUTE {
                    warn!("IdP rate limit exceeded for IP: {}", ip);
                    return Err(CreateSessionError::RateLimited);
                }
            }
        }

        // 3. Capacity Check
        if self.sessions.len() >= self.max_active_sessions {
            self.cleanup_expired_force();
            if self.sessions.len() >= self.max_active_sessions {
                warn!(
                    "IdP session store capacity reached ({} active sessions)",
                    self.sessions.len()
                );
                return Err(CreateSessionError::CapacityExceeded);
            }
        }

        let session_id = generate_session_id();
        let poll_secret = generate_poll_secret();
        let user_code = generate_user_code();

        self.sessions.insert(
            session_id.clone(),
            SessionEntry {
                created_at: Instant::now(),
                poll_secret: poll_secret.clone(),
                user_code: user_code.clone(),
                failed_attempts: 0,
                aud,
                client_ip,
                status: SessionStatus::Pending,
            },
        );

        trace!(
            "Created new IdP session: {} (user_code: {})",
            session_id, user_code
        );

        Ok(SessionInfo {
            session_id,
            poll_secret,
            user_code,
        })
    }

    /// Pre-validates that a pending session exists, is not expired, is not yet confirmed,
    /// and that the mandatory `user_code` matches (enforcing `MAX_CONFIRM_ATTEMPTS`).
    ///
    /// Called before triggering external Claims Webhooks so invalid/brute-force confirm
    /// requests never cause unnecessary backend load.
    pub fn verify_session_code(
        &self,
        session_id: &str,
        user_code: Option<&str>,
    ) -> Result<(), ConfirmError> {
        let mut entry = match self.sessions.get_mut(session_id) {
            Some(e) => e,
            None => return Err(ConfirmError::NotFound),
        };

        if entry.created_at.elapsed() > self.ttl {
            debug!("Attempted to confirm expired session: {}", session_id);
            drop(entry);
            self.sessions.remove(session_id);
            return Err(ConfirmError::Expired);
        }

        if matches!(entry.status, SessionStatus::Confirmed(_)) {
            return Err(ConfirmError::AlreadyConfirmed);
        }

        // Mandatory user_code verification (case-insensitive, ignoring optional dashes, constant-time)
        let code_matches = match user_code {
            Some(code) if !code.trim().is_empty() => {
                let clean_input: String = code
                    .chars()
                    .filter(|c| *c != '-')
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                let clean_expected: String = entry
                    .user_code
                    .chars()
                    .filter(|c| *c != '-')
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                constant_time_eq(clean_input.as_bytes(), clean_expected.as_bytes())
            }
            _ => false,
        };

        if !code_matches {
            entry.failed_attempts = entry.failed_attempts.saturating_add(1);
            let attempts = entry.failed_attempts;
            warn!(
                "Invalid or missing user_code for session {} (attempt {}/{})",
                session_id, attempts, MAX_CONFIRM_ATTEMPTS
            );
            if attempts >= MAX_CONFIRM_ATTEMPTS {
                warn!(
                    "Session {} invalidated after {} failed user_code attempts",
                    session_id, attempts
                );
                drop(entry);
                self.sessions.remove(session_id);
            }
            return Err(ConfirmError::InvalidUserCode);
        }

        Ok(())
    }

    /// Confirms a pending session, attaching the verified identity (`Claims`).
    /// The 6-character `user_code` is mandatory (fail-closed) and limited to `MAX_CONFIRM_ATTEMPTS` attempts.
    pub fn confirm_session(
        &self,
        session_id: &str,
        user_code: Option<&str>,
        mut claims: Claims,
    ) -> Result<(), ConfirmError> {
        self.verify_session_code(session_id, user_code)?;

        let mut entry = match self.sessions.get_mut(session_id) {
            Some(e) => e,
            None => return Err(ConfirmError::NotFound),
        };

        if matches!(entry.status, SessionStatus::Confirmed(_)) {
            return Err(ConfirmError::AlreadyConfirmed);
        }

        // If the session was initiated with a specific audience, preserve it
        if let Some(aud) = &entry.aud {
            claims.aud = Some(aud.clone());
        }

        entry.status = SessionStatus::Confirmed(claims);
        trace!("Confirmed IdP session: {}", session_id);
        Ok(())
    }

    /// Retrieves the status of a session, requiring the correct `poll_secret`.
    ///
    /// If the session is confirmed, it is atomically removed from the store (One-Time-Use).
    pub fn get_and_consume(
        &self,
        session_id: &str,
        poll_secret: &str,
    ) -> Result<SessionStatus, PollError> {
        let entry_ref = match self.sessions.get(session_id) {
            Some(e) => e,
            None => return Err(PollError::NotFound),
        };

        // Constant-time compare poll_secret to prevent timing leaks
        if !constant_time_eq(entry_ref.poll_secret.as_bytes(), poll_secret.as_bytes()) {
            warn!(
                "IdP status poll unauthorized: invalid poll_secret for session {}",
                session_id
            );
            return Err(PollError::Unauthorized);
        }

        // Check expiration
        if entry_ref.created_at.elapsed() > self.ttl {
            drop(entry_ref);
            self.sessions.remove(session_id);
            return Err(PollError::NotFound);
        }

        match &entry_ref.status {
            SessionStatus::Pending => Ok(SessionStatus::Pending),
            SessionStatus::Confirmed(_) => {
                drop(entry_ref);
                // Atomically consume the session if confirmed
                if let Some((_, entry)) = self.sessions.remove_if(session_id, |_, e| {
                    constant_time_eq(e.poll_secret.as_bytes(), poll_secret.as_bytes())
                        && matches!(e.status, SessionStatus::Confirmed(_))
                }) {
                    Ok(entry.status)
                } else {
                    Err(PollError::NotFound)
                }
            }
        }
    }

    /// Retrieves the user verification code for an active session (for device display).
    pub fn get_session_user_code(&self, session_id: &str) -> Option<String> {
        self.sessions.get(session_id).and_then(|entry| {
            if entry.created_at.elapsed() <= self.ttl {
                Some(entry.user_code.clone())
            } else {
                None
            }
        })
    }

    /// Throttled cleanup of expired sessions and stale IP rate-limiting records.
    fn maybe_cleanup_expired(&self) {
        if let Ok(mut last) = self.last_cleanup.try_lock() {
            if last.elapsed() >= CLEANUP_THROTTLE_INTERVAL {
                *last = Instant::now();
                drop(last);
                self.cleanup_expired_force();
            }
        }
    }

    /// Forcefully purges all expired sessions and rate limits.
    fn cleanup_expired_force(&self) {
        let ttl = self.ttl;
        self.sessions.retain(|_k, v| v.created_at.elapsed() <= ttl);
        self.ip_rate_limits
            .retain(|_k, (_count, start)| start.elapsed() <= RATE_LIMIT_WINDOW);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle_with_poll_secret() {
        let store = SessionStore::new(60);
        let info = store.create_session(None, Some("test-aud".to_string())).unwrap();

        assert!(!info.session_id.is_empty());
        assert!(!info.poll_secret.is_empty());
        assert_eq!(info.user_code.len(), 7); // XXX-YYY format

        // Poll without valid secret fails
        assert_eq!(
            store.get_and_consume(&info.session_id, "wrong_secret"),
            Err(PollError::Unauthorized)
        );

        // Poll with valid secret when pending returns Pending
        let status = store.get_and_consume(&info.session_id, &info.poll_secret).unwrap();
        assert!(matches!(status, SessionStatus::Pending));

        // Confirm session with valid user_code
        let claims = Claims {
            sub: "alice".to_string(),
            iss: "praeco-test".to_string(),
            aud: None,
            exp: 9999999999,
            oids: vec![],
            jti: None,
        };
        store
            .confirm_session(&info.session_id, Some(&info.user_code), claims)
            .unwrap();

        // Second confirm should fail (AlreadyConfirmed)
        let claims2 = Claims {
            sub: "alice".to_string(),
            iss: "praeco-test".to_string(),
            aud: None,
            exp: 9999999999,
            oids: vec![],
            jti: None,
        };
        assert_eq!(
            store.confirm_session(&info.session_id, Some(&info.user_code), claims2),
            Err(ConfirmError::AlreadyConfirmed)
        );

        // Poll with correct secret consumes Confirmed session
        let consumed = store.get_and_consume(&info.session_id, &info.poll_secret).unwrap();
        if let SessionStatus::Confirmed(c) = consumed {
            assert_eq!(c.sub, "alice");
            assert_eq!(c.aud, Some("test-aud".to_string()));
        } else {
            panic!("Expected confirmed status");
        }

        // Subsequent poll should fail with NotFound (One-Time-Use)
        assert_eq!(
            store.get_and_consume(&info.session_id, &info.poll_secret),
            Err(PollError::NotFound)
        );
    }

    #[test]
    fn test_user_code_verification_mismatch_and_missing_rejected() {
        let store = SessionStore::new(60);
        let info = store.create_session(None, None).unwrap();

        let claims = Claims {
            sub: "bob".to_string(),
            iss: "praeco-test".to_string(),
            aud: None,
            exp: 9999999999,
            oids: vec![],
            jti: None,
        };

        // 1. Missing user_code (None) is rejected (fail-closed)
        let res_missing = store.confirm_session(&info.session_id, None, claims.clone());
        assert_eq!(res_missing, Err(ConfirmError::InvalidUserCode));

        // 2. Mismatched user_code is rejected
        let res_wrong = store.confirm_session(&info.session_id, Some("WRONG1"), claims.clone());
        assert_eq!(res_wrong, Err(ConfirmError::InvalidUserCode));

        // 3. Valid user_code (even without dash or lowercase) succeeds on 3rd attempt
        let code_no_dash = info.user_code.replace('-', "").to_lowercase();
        let res_valid = store.confirm_session(&info.session_id, Some(&code_no_dash), claims);
        assert_eq!(res_valid, Ok(()));
    }

    #[test]
    fn test_user_code_brute_force_invalidates_session_after_max_attempts() {
        let store = SessionStore::new(60);
        let info = store.create_session(None, None).unwrap();

        let claims = Claims {
            sub: "attacker".to_string(),
            iss: "praeco-test".to_string(),
            aud: None,
            exp: 9999999999,
            oids: vec![],
            jti: None,
        };

        // 3 failed attempts invalidate the session
        for _ in 0..MAX_CONFIRM_ATTEMPTS {
            let res = store.confirm_session(&info.session_id, Some("BADCOD"), claims.clone());
            assert_eq!(res, Err(ConfirmError::InvalidUserCode));
        }

        // 4th attempt even with the valid user_code returns NotFound because session was removed
        let res_after = store.confirm_session(&info.session_id, Some(&info.user_code), claims);
        assert_eq!(res_after, Err(ConfirmError::NotFound));
    }

    #[test]
    fn test_ip_rate_limiting() {
        let store = SessionStore::new(60);
        let test_ip: IpAddr = "192.0.2.1".parse().unwrap();

        for _ in 0..MAX_LOGIN_REQUESTS_PER_MINUTE {
            assert!(store.create_session(Some(test_ip), None).is_ok());
        }

        // Next request from same IP should be rate limited
        let blocked = store.create_session(Some(test_ip), None);
        assert_eq!(blocked.unwrap_err(), CreateSessionError::RateLimited);

        // Different IP is not affected
        let other_ip: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(store.create_session(Some(other_ip), None).is_ok());
    }

    #[test]
    fn test_expired_session_handling() {
        let store = SessionStore::new(0); // TTL = 0 seconds (immediately expired)
        let info1 = store.create_session(None, None).unwrap();

        std::thread::sleep(Duration::from_millis(5));

        // get_and_consume removes and returns NotFound on expired
        assert_eq!(
            store.get_and_consume(&info1.session_id, &info1.poll_secret),
            Err(PollError::NotFound)
        );

        // A second session that is expired but not yet consumed returns Expired on confirm
        let info2 = store.create_session(None, None).unwrap();
        std::thread::sleep(Duration::from_millis(5));

        let claims = Claims {
            sub: "charlie".to_string(),
            iss: "praeco-test".to_string(),
            aud: None,
            exp: 9999999999,
            oids: vec![],
            jti: None,
        };
        assert_eq!(
            store.confirm_session(&info2.session_id, None, claims),
            Err(ConfirmError::Expired)
        );
    }
}
