//! # Artificial Delay Middleware
//!
//! Introduces a configurable fixed delay before a service reports readiness.
//! This is useful for:
//! - **Load testing** – simulating slow backends.
//! - **Timeout verification** – ensuring client-side timeouts trigger correctly.
//! - **Back-pressure simulation** – seeing how the stack behaves when a layer
//!   is slow to accept work.
//!
//! The delay is injected in [`poll_ready`](tower::Service::poll_ready), **not**
//! in `call`, which means the service will hold off accepting the *next*
//! request until the sleep completes.

// === Standard Library ===
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

// === External Crates ===
use tokio::time::{self, Sleep};
use tower::{Layer, Service};

/// A Tower [`Layer`] that injects a fixed artificial delay before readiness.
///
/// Each cloned service receives its own independent sleep state, so the
/// delay applies per-clone (i.e. per-connection in the typical server setup).
#[derive(Clone)]
pub struct DelayLayer {
    /// How long to sleep before the service reports readiness.
    delay: Duration,
    /// Server name label for log output.
    server_name: &'static str,
}

impl DelayLayer {
    /// Creates a new `DelayLayer`.
    ///
    /// # Arguments
    ///
    /// * `delay`       – The duration to sleep before readiness.
    /// * `server_name` – A `'static` label for tracing output.
    pub fn new(delay: Duration, server_name: &'static str) -> Self {
        Self { delay, server_name }
    }
}

impl<S> Layer<S> for DelayLayer {
    type Service = DelayService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DelayService {
            inner,
            delay: self.delay,
            sleep: None,
            server_name: self.server_name,
        }
    }
}

/// Service wrapper that sleeps for a configured duration in `poll_ready`
/// before delegating to the inner service.
///
/// The sleep future is created lazily on the first `poll_ready` call and
/// cleared once it completes, so subsequent calls will start a new sleep.
pub struct DelayService<S> {
    /// The wrapped inner service.
    inner: S,
    /// The configured delay duration.
    delay: Duration,
    /// The currently active sleep future, if any.
    /// `None` means no sleep is in progress; the next `poll_ready` will
    /// create one.
    sleep: Option<Pin<Box<Sleep>>>,
    /// Server name label for log output.
    server_name: &'static str,
}

/// Manual [`Clone`] implementation: the `sleep` state is intentionally
/// **not** cloned — each clone starts fresh without an active delay,
/// preventing one connection's delay from leaking into another.
impl<S: Clone> Clone for DelayService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            delay: self.delay,
            sleep: None, // Don't clone sleep state!
            server_name: self.server_name,
        }
    }
}

impl<S, Request> Service<Request> for DelayService<S>
where
    S: Service<Request>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    /// Injects the delay before reporting readiness.
    ///
    /// 1. On first poll, creates a new [`Sleep`] future.
    /// 2. Polls the sleep; returns `Pending` until it completes.
    /// 3. Once the sleep elapses, clears it and delegates to the inner
    ///    service's `poll_ready`.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // If we haven't started sleeping yet, create a new Sleep.
        if self.sleep.is_none() {
            tracing::info!(
                "{}: Injecting a delay of {:?} before readiness",
                self.server_name,
                self.delay
            );
            self.sleep = Some(Box::pin(time::sleep(self.delay)));
        }

        // Now, poll the Sleep future.
        let sleep = self.sleep.as_mut().unwrap();
        if Pin::new(sleep).poll(cx).is_pending() {
            return Poll::Pending;
        }

        // Sleep is done, clear it for next time.
        self.sleep = None;

        // Now delegate to the inner service.
        self.inner.poll_ready(cx)
    }

    /// Forwards the request to the inner service without additional delay.
    ///
    /// The delay was already applied during `poll_ready`, so `call` simply
    /// delegates.
    fn call(&mut self, req: Request) -> Self::Future {
        tracing::info!("{}: Passing request through DelayLayer", self.server_name);
        self.inner.call(req)
    }
}
