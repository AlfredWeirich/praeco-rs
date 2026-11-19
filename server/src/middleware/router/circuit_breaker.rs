//! # 3-State Circuit Breaker & Outlier Detection for Upstream Nodes
//!
//! This module implements a lock-free, atomic **3-State Circuit Breaker**
//! (`Closed` $\rightarrow$ `Open` $\rightarrow$ `HalfOpen`) and **Outlier Detection**
//! for reverse-proxy upstream backends ([`UpstreamNode`](crate::configuration::UpstreamNode)).
//!
//! ## State Machine
//!
//! ```text
//!                     [consecutive_failures >= failure_threshold]
//!                      or hard connect/timeout failure
//!        ┌──────────┐ ──────────────────────────────────────────► ┌──────────┐
//!        │  Closed  │                                             │   Open   │
//!        │ (Normal) │ ◄───────────────────────┐                   │  (Dead)  │
//!        └──────────┘   [Probe 2xx/3xx/4xx]   │                   └──────────┘
//!                                             │                        │
//!                                        ┌──────────┐                  │
//!                                        │ HalfOpen │ ◄────────────────┘
//!                                        │ (1 Probe)│  [cooldown_seconds elapsed:
//!                                        └──────────┘   exactly 1 probe allowed]
//!                                             │
//!                                             └────────────────────────► (Back to Open on
//!                                                [Probe fails / 502-504]  probe failure)
//! ```
//!
//! ## Key Guarantees
//!
//! 1. **Outlier Detection (`502` / `503` / `504` & gRPC `UNAVAILABLE`)**:
//!    Upstream responses with `502 Bad Gateway`, `503 Service Unavailable`, or
//!    `504 Gateway Timeout` (as well as gRPC status `14 UNAVAILABLE`) are classified
//!    as outlier failures rather than healthy responses. They increment
//!    `consecutive_failures` and never falsely mark an unhealthy node as alive.
//! 2. **Thundering-Herd Prevention in `HalfOpen`**:
//!    When `cooldown_seconds` expires for an `Open` node, only **one** concurrent
//!    request wins the atomic transition to `HalfOpen` (`try_acquire_probe`). All
//!    other concurrent requests continue routing to healthy nodes until the single
//!    probe request proves the backend has recovered.
//! 3. **Fail-Safe Probe Guard**:
//!    If a `HalfOpen` probe request is aborted before receiving a response (e.g.,
//!    client disconnect), [`ProbeGuard`](crate::middleware::router::circuit_breaker::ProbeGuard)
//!    automatically reverts the circuit back to `Open` on drop so the node can never
//!    become permanently wedged in `HalfOpen`.
//! 4. **Bounded Retry Buffering (`max_retry_buffer_bytes`)**:
//!    Buffers request bodies for retryable requests only up to `max_retry_buffer_bytes`
//!    (default: 64 KiB). Larger payloads seamlessly spill over into streaming mode
//!    without buffering the entire body in RAM.

use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use hyper::{HeaderMap, StatusCode};
use pin_project::pin_project;

use crate::{SrvBody, SrvError, configuration::UpstreamNode};
use super::RequestBody;

/// Numeric representation of the 3 circuit breaker states stored in `UpstreamNode::circuit_state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitState {
    /// Normal operation: requests are routed freely to this node.
    Closed = 0,
    /// Tripped / Quarantined: node is excluded from routing until `cooldown_seconds` elapses.
    Open = 1,
    /// Recovery Probe: cooldown has elapsed and a single probe request is allowed to test recovery.
    HalfOpen = 2,
}

impl CircuitState {
    /// Converts a raw atomic `u8` value into a [`CircuitState`].
    #[inline]
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => Self::Open,
            2 => Self::HalfOpen,
            _ => Self::Closed,
        }
    }
}

/// Returns `true` if the HTTP status code indicates an upstream gateway/availability
/// failure (`502 Bad Gateway`, `503 Service Unavailable`, or `504 Gateway Timeout`).
#[inline]
pub fn is_outlier_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    )
}

/// Returns `true` if a gRPC response indicates an upstream availability failure,
/// either via HTTP status (`502`/`503`/`504`) or an initial `grpc-status: 14` (`UNAVAILABLE`) header.
#[inline]
pub fn is_grpc_outlier_response(status: StatusCode, headers: &HeaderMap) -> bool {
    if is_outlier_status(status) {
        return true;
    }
    if let Some(grpc_status) = headers.get("grpc-status").and_then(|v| v.to_str().ok()) {
        // gRPC status code 14 = UNAVAILABLE
        if grpc_status.trim() == "14" {
            return true;
        }
    }
    false
}

/// RAII guard for a `HalfOpen` probe request.
///
/// If the request task is dropped before calling [`ProbeGuard::complete`] (for example,
/// if the downstream client disconnects mid-flight), this guard resets the node's
/// `half_open_probe_in_flight` flag and reverts the circuit to `Open` so future
/// requests can probe again.
pub struct ProbeGuard<'a> {
    node: &'a UpstreamNode,
    is_probe: bool,
    captured_epoch: u64,
    completed: bool,
}

impl<'a> ProbeGuard<'a> {
    /// Creates a new `ProbeGuard` for the selected `UpstreamNode`.
    ///
    /// Automatically checks if the node's cooldown just elapsed and attempts to
    /// claim the single `HalfOpen` probe slot.
    pub fn new(node: &'a UpstreamNode, cooldown_seconds: u64) -> Self {
        if let Some(probe_epoch) = node.try_enter_half_open_probe_epoch(cooldown_seconds) {
            Self {
                node,
                is_probe: true,
                captured_epoch: probe_epoch,
                completed: false,
            }
        } else {
            Self {
                node,
                is_probe: false,
                captured_epoch: node.circuit_epoch.load(Ordering::Acquire),
                completed: false,
            }
        }
    }

    /// Returns the monotonic `circuit_epoch` captured when this request started
    /// (or entered `HalfOpen`).
    #[inline]
    pub fn epoch(&self) -> u64 {
        self.captured_epoch
    }

    /// Marks the request as having reached a definitive outcome (`record_success` or `record_failure`).
    #[inline]
    pub fn complete(&mut self) {
        self.completed = true;
    }
}

impl<'a> Drop for ProbeGuard<'a> {
    fn drop(&mut self) {
        if self.is_probe
            && !self.completed
            && self.node.circuit_epoch.load(Ordering::Acquire) == self.captured_epoch
        {
            // Probe was aborted mid-flight without a definitive upstream verdict:
            // revert the circuit from HalfOpen -> Open atomically if still in the same epoch.
            if self
                .node
                .circuit_state
                .compare_exchange(
                    CircuitState::HalfOpen as u8,
                    CircuitState::Open as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                self.node.circuit_epoch.fetch_add(1, Ordering::AcqRel);
                self.node
                    .half_open_probe_in_flight
                    .store(false, Ordering::Release);
            }
        }
    }
}

// ============================================================================
//  Bounded Retry Body Buffering (`max_retry_buffer_bytes`)
// ============================================================================

/// A streaming HTTP body that replays an already-read prefix (`Bytes`) followed
/// by the remaining unconsumed frames of the inner [`SrvBody`].
#[pin_project]
pub struct PrefixedStreamBody {
    prefix: Option<Bytes>,
    next_frame: Option<Frame<Bytes>>,
    #[pin]
    remaining: SrvBody,
}

impl Body for PrefixedStreamBody {
    type Data = Bytes;
    type Error = SrvError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        if let Some(bytes) = this.prefix.take()
            && !bytes.is_empty()
        {
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        if let Some(frame) = this.next_frame.take() {
            return Poll::Ready(Some(Ok(frame)));
        }
        this.remaining.poll_frame(cx)
    }
}

/// Reads `body` into a [`RequestBody::Buffered`] up to `max_buffer_bytes`.
///
/// - If the entire body fits within `max_buffer_bytes`, returns `Ok(RequestBody::Buffered(bytes))`
///   so the router can replay the body across retries.
/// - If the body exceeds `max_buffer_bytes`, stops buffering in RAM and returns
///   `Ok(RequestBody::Stream(...))` chaining the already-read prefix with the rest of `body`.
/// - Propagates client payload-limit or decompression-bomb errors as `Err(SrvError)`.
pub async fn buffer_body_up_to(
    mut body: SrvBody,
    max_buffer_bytes: usize,
) -> Result<RequestBody, SrvError> {
    let mut accumulated = BytesMut::new();

    while let Some(frame_res) = body.frame().await {
        let frame = frame_res?;
        if let Ok(data) = frame.into_data() {
            if accumulated.len().saturating_add(data.len()) > max_buffer_bytes {
                // Exceeded retry buffer cap: combine accumulated bytes + current chunk into prefix
                // and stream the rest without buffering the whole upload in RAM!
                accumulated.extend_from_slice(&data);
                let prefix = accumulated.freeze();
                let combined = PrefixedStreamBody {
                    prefix: Some(prefix),
                    next_frame: None,
                    remaining: body,
                };
                return Ok(RequestBody::Stream(combined.boxed()));
            }
            accumulated.extend_from_slice(&data);
        }
    }

    Ok(RequestBody::Buffered(accumulated.freeze()))
}

/// Buffers at most the first complete gRPC frame (up to `max_buffer_bytes`) and
/// checks non-blockingly whether the client closed the stream (`EOF`):
///
/// - Unary / server-streaming calls (1 frame followed by immediate `EOF`) return
///   [`RequestBody::Buffered`] so connect-time failover works seamlessly.
/// - Client-streaming / bidirectional gRPC calls (where the client keeps the
///   request stream open after frame 1) spill immediately into
///   [`RequestBody::Stream`] without waiting for `EOF`, preventing deadlocks.
pub async fn buffer_grpc_first_frame_or_stream(
    mut body: SrvBody,
    max_buffer_bytes: usize,
) -> Result<RequestBody, SrvError> {
    let mut accumulated = BytesMut::new();

    loop {
        if accumulated.len() >= 5 {
            let frame_len =
                u32::from_be_bytes([accumulated[1], accumulated[2], accumulated[3], accumulated[4]])
                    as usize;
            let first_frame_end = 5usize.saturating_add(frame_len);

            if first_frame_end > max_buffer_bytes || accumulated.len() > first_frame_end {
                let combined = PrefixedStreamBody {
                    prefix: Some(accumulated.freeze()),
                    next_frame: None,
                    remaining: body,
                };
                return Ok(RequestBody::Stream(combined.boxed()));
            }

            if accumulated.len() == first_frame_end {
                if body.is_end_stream() {
                    return Ok(RequestBody::Buffered(accumulated.freeze()));
                }
                let next = std::future::poll_fn(|cx| {
                    Poll::Ready(Pin::new(&mut body).poll_frame(cx))
                })
                .await;
                match next {
                    Poll::Ready(None) => {
                        return Ok(RequestBody::Buffered(accumulated.freeze()));
                    }
                    Poll::Ready(Some(Err(e))) => return Err(e),
                    Poll::Ready(Some(Ok(frame))) => {
                        if frame.is_data() && frame.data_ref().is_some_and(|d| d.is_empty()) {
                            continue;
                        }
                        let combined = PrefixedStreamBody {
                            prefix: Some(accumulated.freeze()),
                            next_frame: Some(frame),
                            remaining: body,
                        };
                        return Ok(RequestBody::Stream(combined.boxed()));
                    }
                    Poll::Pending => {
                        let combined = PrefixedStreamBody {
                            prefix: Some(accumulated.freeze()),
                            next_frame: None,
                            remaining: body,
                        };
                        return Ok(RequestBody::Stream(combined.boxed()));
                    }
                }
            }
        }

        match body.frame().await {
            None => return Ok(RequestBody::Buffered(accumulated.freeze())),
            Some(Err(e)) => return Err(e),
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    if accumulated.len().saturating_add(data.len()) > max_buffer_bytes {
                        accumulated.extend_from_slice(&data);
                        let combined = PrefixedStreamBody {
                            prefix: Some(accumulated.freeze()),
                            next_frame: None,
                            remaining: body,
                        };
                        return Ok(RequestBody::Stream(combined.boxed()));
                    }
                    accumulated.extend_from_slice(&data);
                }
                Err(non_data_frame) => {
                    let combined = PrefixedStreamBody {
                        prefix: Some(accumulated.freeze()),
                        next_frame: Some(non_data_frame),
                        remaining: body,
                    };
                    return Ok(RequestBody::Stream(combined.boxed()));
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::UpstreamNode;
    use hyper::Uri;

    #[test]
    fn test_circuit_breaker_closed_to_open_after_threshold() {
        let uri: Uri = "http://127.0.0.1:8080".parse().unwrap();
        let node = UpstreamNode::new(uri);
        assert_eq!(node.circuit_state(), CircuitState::Closed);
        assert!(node.is_available(10));

        // With threshold = 3: first two failures keep circuit Closed
        assert!(!node.record_failure(3));
        assert_eq!(node.circuit_state(), CircuitState::Closed);
        assert!(node.is_available(10));

        assert!(!node.record_failure(3));
        assert_eq!(node.circuit_state(), CircuitState::Closed);
        assert!(node.is_available(10));

        // 3rd consecutive failure trips circuit to Open!
        assert!(node.record_failure(3));
        assert_eq!(node.circuit_state(), CircuitState::Open);
        assert!(!node.is_available(10));
    }

    #[test]
    fn test_circuit_breaker_half_open_single_probe_and_recovery() {
        let uri: Uri = "http://127.0.0.1:8080".parse().unwrap();
        let node = UpstreamNode::new(uri);

        // Trip immediately
        node.mark_dead();
        assert_eq!(node.circuit_state(), CircuitState::Open);
        assert!(!node.is_available(10));

        // Simulate cooldown elapsed (15s ago > 10s cooldown)
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 15;
        node.last_failure_time.store(past, Ordering::Relaxed);

        // Node is eligible for a probe
        assert!(node.is_available(10));

        // First caller claims the HalfOpen probe slot
        assert!(node.try_enter_half_open_probe(10));
        assert_eq!(node.circuit_state(), CircuitState::HalfOpen);

        // Second concurrent caller MUST NOT be allowed while probe is in flight!
        assert!(!node.is_available(10));
        assert!(!node.try_enter_half_open_probe(10));

        // Probe succeeds -> circuit closes and node is available again
        node.record_success();
        assert_eq!(node.circuit_state(), CircuitState::Closed);
        assert!(node.is_available(10));
        assert_eq!(node.consecutive_failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_circuit_breaker_half_open_probe_failure_reopens_immediately() {
        let uri: Uri = "http://127.0.0.1:8080".parse().unwrap();
        let node = UpstreamNode::new(uri);
        node.mark_dead();

        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 15;
        node.last_failure_time.store(past, Ordering::Relaxed);

        assert!(node.try_enter_half_open_probe(10));
        assert_eq!(node.circuit_state(), CircuitState::HalfOpen);

        // Even if failure_threshold is 5, a single failure in HalfOpen must re-open immediately!
        assert!(node.record_failure(5));
        assert_eq!(node.circuit_state(), CircuitState::Open);
        assert!(!node.is_available(10));
    }

    #[test]
    fn test_circuit_breaker_late_success_does_not_close_open_or_corrupt_epoch() {
        let uri: Uri = "http://127.0.0.1:8080".parse().unwrap();
        let node = UpstreamNode::new(uri);
        let initial_epoch = node.circuit_epoch.load(Ordering::Acquire);

        // Trip circuit open
        node.mark_dead();
        assert_eq!(node.circuit_state(), CircuitState::Open);
        assert!(!node.is_available(10));

        // A late 2xx response must never close an Open circuit
        node.record_success();
        assert_eq!(node.circuit_state(), CircuitState::Open);
        assert!(!node.is_available(10));

        // Even once cooldown elapses and a new HalfOpen probe starts (new epoch),
        // an epoch-stamped late success from the earlier epoch must be ignored.
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 15;
        node.last_failure_time.store(past, Ordering::Relaxed);
        let guard = ProbeGuard::new(&node, 10);
        assert_eq!(node.circuit_state(), CircuitState::HalfOpen);
        assert_ne!(guard.epoch(), initial_epoch);

        node.record_success_with_epoch(initial_epoch);
        assert_eq!(node.circuit_state(), CircuitState::HalfOpen);

        // Dropping the uncompleted ProbeGuard reverts HalfOpen back to Open safely.
        drop(guard);
        assert_eq!(node.circuit_state(), CircuitState::Open);
    }

    #[tokio::test]
    async fn test_buffer_body_up_to_switches_to_stream_when_exceeded() {
        // 1. Small body (<= 64 bytes) stays Buffered
        let small_chunks = vec![
            Ok(Frame::data(Bytes::from_static(b"hello "))),
            Ok(Frame::data(Bytes::from_static(b"world"))),
        ];
        let small_body: SrvBody = http_body_util::StreamBody::new(futures_util::stream::iter(small_chunks)).boxed();
        match buffer_body_up_to(small_body, 64).await.unwrap() {
            RequestBody::Buffered(b) => assert_eq!(&b[..], b"hello world"),
            RequestBody::Stream(_) => panic!("Expected small body to be buffered"),
        }

        // 2. Large body (> 10 bytes) switches to Stream without losing any bytes
        let large_chunks = vec![
            Ok(Frame::data(Bytes::from_static(b"0123456789"))),
            Ok(Frame::data(Bytes::from_static(b"abcdef"))),
            Ok(Frame::data(Bytes::from_static(b"ghijkl"))),
        ];
        let large_body: SrvBody = http_body_util::StreamBody::new(futures_util::stream::iter(large_chunks)).boxed();
        match buffer_body_up_to(large_body, 10).await.unwrap() {
            RequestBody::Buffered(_) => panic!("Expected large body to switch to Stream"),
            RequestBody::Stream(stream_body) => {
                let collected = stream_body.collect().await.unwrap().to_bytes();
                assert_eq!(&collected[..], b"0123456789abcdefghijkl");
            }
        }
    }

    #[tokio::test]
    async fn test_buffer_grpc_first_frame_unary_vs_bidi_open_stream() {
        // 1. Unary gRPC call (1 frame + immediate EOF) -> Buffered for connect failover
        let mut unary_frame = vec![0u8, 0, 0, 0, 3];
        unary_frame.extend_from_slice(b"abc");
        let unary_body: SrvBody = http_body_util::Full::new(Bytes::from(unary_frame.clone()))
            .map_err(SrvError::from)
            .boxed();
        match buffer_grpc_first_frame_or_stream(unary_body, 1024).await.unwrap() {
            RequestBody::Buffered(b) => assert_eq!(&b[..], &unary_frame[..]),
            RequestBody::Stream(_) => panic!("Unary 1-frame gRPC body must stay Buffered"),
        }

        // 2. Open bidirectional stream (1st frame arrives, sender kept open) -> Stream immediately!
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, SrvError>>(4);
        tx.send(Ok(Frame::data(Bytes::from(unary_frame.clone()))))
            .await
            .unwrap();
        let stream = futures_util::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        let bidi_body: SrvBody = http_body_util::StreamBody::new(stream).boxed();

        // Must return immediately without waiting for EOF!
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            buffer_grpc_first_frame_or_stream(bidi_body, 1024),
        )
        .await
        .expect("bidi stream must not block waiting for EOF")
        .unwrap();

        match res {
            RequestBody::Buffered(_) => panic!("Open bidi gRPC body must switch to Stream"),
            RequestBody::Stream(mut stream_body) => {
                // First frame is readable immediately while tx is still open
                let first = stream_body.frame().await.unwrap().unwrap().into_data().unwrap();
                assert_eq!(&first[..], &unary_frame[..]);

                // Subsequent frame sent later on the bidi stream arrives intact
                tx.send(Ok(Frame::data(Bytes::from_static(b"second"))))
                    .await
                    .unwrap();
                drop(tx);
                let second = stream_body.frame().await.unwrap().unwrap().into_data().unwrap();
                assert_eq!(&second[..], b"second");
            }
        }
    }
}
