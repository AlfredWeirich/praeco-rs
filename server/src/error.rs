//! # Unified Error Type
//!
//! This module defines [`SrvError`], the single error enum that flows through
//! the entire Tower service stack. By funnelling every error source into one
//! type, middleware layers and the router can use a uniform
//! `Result<…, SrvError>` without generic error proliferation.

use hyper::Error as HyperError;
use hyper_util::client::legacy::Error as HyperUtilError;
use std::convert::Infallible;

/// The central error enum for the server application.
///
/// All error variants are converted from their upstream types via [`From`]
/// implementations, so `?` works transparently across middleware boundaries.
///
/// # Variants
///
/// | Variant | Source |
/// |---------|--------|
/// | [`Infallible`](SrvError::Infallible) | Type-system only; never actually constructed at runtime. |
/// | [`Hyper`](SrvError::Hyper) | Errors from the Hyper HTTP engine (connection resets, protocol violations, …). |
/// | [`HyperUtil`](SrvError::HyperUtil) | Errors from the Hyper utility / legacy client layer. |
/// | [`Other`](SrvError::Other) | Catch-all for application-level errors expressed as plain strings. |
#[derive(Debug, thiserror::Error)]
pub enum SrvError {
    /// Errors originating from infallible operations.
    ///
    /// Required so that body types parameterised over `Infallible` can be
    /// mapped into `SrvError` without special-casing. Never triggered at
    /// runtime because `Infallible` has no inhabitants.
    #[error("Infallible: {0}")]
    Infallible(#[from] Infallible),

    /// Errors propagated from the Hyper HTTP core library.
    ///
    /// Typical causes: connection reset by peer, HTTP protocol violations,
    /// or timeout errors from the connection layer.
    #[error("Hyper: {0}")]
    Hyper(#[from] HyperError),

    /// Errors from the Hyper utility / legacy client components.
    ///
    /// Usually surfaced when the pooled reverse-proxy client fails to
    /// connect to an upstream backend.
    #[error("HyperUtil: {0}")]
    HyperUtil(#[from] HyperUtilError),

    /// Catch-all for internal or string-based application errors.
    ///
    /// Used for things like invalid URI construction, payload-limit
    /// violations, or decompression failures.
    #[error("Internal Error: {0}")]
    Other(String),
}

/// Convenience conversion so that any `String` can be turned into
/// [`SrvError::Other`] via `.into()` or `?`.
impl From<String> for SrvError {
    fn from(s: String) -> Self {
        SrvError::Other(s)
    }
}
