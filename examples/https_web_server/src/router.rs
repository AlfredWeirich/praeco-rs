//! Lightweight, composable HTTP endpoint router for embedding `praeco-rs`.
//!
//! Uses `matchit` per HTTP method so endpoint handlers can be written as plain
//! `async fn`s outside `main()` and registered declaratively.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, header};
use praeco_rs::{BoxCloneSyncServiceExt, BoxedCloneService, ServiceRespBody, SrvBody, SrvError};
use serde::Serialize;

type BoxHandlerFuture =
    Pin<Box<dyn Future<Output = Result<Response<ServiceRespBody>, SrvError>> + Send>>;
type BoxedHandler = Arc<dyn Fn(Request<SrvBody>) -> BoxHandlerFuture + Send + Sync>;

/// Path parameters extracted by `matchit` (e.g. `{id}`) and attached to
/// `req.extensions()` before the endpoint handler is invoked.
#[derive(Clone, Debug, Default)]
pub struct PathParams(HashMap<String, String>);

impl PathParams {
    /// Returns the captured parameter value for `key`, if present.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
}

/// Method-aware HTTP router that compiles into Praeco's [`BoxedCloneService`].
#[derive(Clone, Default)]
pub struct WebRouter {
    routes: HashMap<Method, matchit::Router<BoxedHandler>>,
}

impl WebRouter {
    /// Creates an empty router.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an `async fn` handler for the given HTTP `method` and `path` pattern.
    ///
    /// Supports `matchit` placeholders such as `"/users/{id}"` or `"/files/{*rest}"`.
    pub fn route<F, Fut>(mut self, method: Method, path: &str, handler: F) -> anyhow::Result<Self>
    where
        F: Fn(Request<SrvBody>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Response<ServiceRespBody>, SrvError>> + Send + 'static,
    {
        let boxed: BoxedHandler = Arc::new(move |req| Box::pin(handler(req)));
        self.routes
            .entry(method)
            .or_default()
            .insert(path, boxed)
            .map_err(|err| anyhow::anyhow!("Invalid route '{path}': {err}"))?;
        Ok(self)
    }

    /// Converts this router into a [`BoxedCloneService`] compatible with
    /// [`praeco_rs::build_service_stack_with_base`].
    pub fn into_service(self) -> BoxedCloneService {
        let routes = Arc::new(self.routes);
        tower::service_fn(move |mut req: Request<SrvBody>| {
            let routes = Arc::clone(&routes);
            async move {
                let method = req.method().clone();
                let path = req.uri().path().to_owned();

                if let Some(router) = routes.get(&method)
                    && let Ok(matched) = router.at(&path)
                {
                    let params: HashMap<String, String> = matched
                        .params
                        .iter()
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect();
                    let handler = Arc::clone(matched.value);
                    req.extensions_mut().insert(PathParams(params));
                    return handler(req).await;
                }

                // Check if another HTTP method matches the same path -> 405 Method Not Allowed
                let mut allowed: Vec<&str> = routes
                    .iter()
                    .filter(|(m, _)| *m != method)
                    .filter_map(|(m, router)| router.at(&path).ok().map(|_| m.as_str()))
                    .collect();

                if !allowed.is_empty() {
                    allowed.sort_unstable();
                    let allow_header = allowed.join(", ");
                    return build_text_response_with_header(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "Method Not Allowed\n",
                        header::ALLOW,
                        &allow_header,
                    );
                }

                text_response(StatusCode::NOT_FOUND, "Not Found\n")
            }
        })
        .boxed_clone_sync()
    }
}

/// Builds a plain-text HTTP response without panicking.
pub fn text_response(
    status: StatusCode,
    body: impl Into<Bytes>,
) -> Result<Response<ServiceRespBody>, SrvError> {
    let boxed = Full::new(body.into()).map_err(SrvError::from).boxed();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(boxed)
        .map_err(|e| SrvError::Other(e.to_string()))
}

/// Builds a JSON HTTP response from any `serde::Serialize` payload.
pub fn json_response<T: Serialize>(
    status: StatusCode,
    payload: &T,
) -> Result<Response<ServiceRespBody>, SrvError> {
    let bytes = serde_json::to_vec(payload).map_err(|e| SrvError::Other(e.to_string()))?;
    let boxed = Full::new(Bytes::from(bytes))
        .map_err(SrvError::from)
        .boxed();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(boxed)
        .map_err(|e| SrvError::Other(e.to_string()))
}

fn build_text_response_with_header(
    status: StatusCode,
    body: &'static str,
    header_name: header::HeaderName,
    header_val: &str,
) -> Result<Response<ServiceRespBody>, SrvError> {
    let boxed = Full::new(Bytes::from_static(body.as_bytes()))
        .map_err(SrvError::from)
        .boxed();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header_name, header_val)
        .body(boxed)
        .map_err(|e| SrvError::Other(e.to_string()))
}
