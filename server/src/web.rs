//! # Embedded Web Router & Extractors (`web` feature)
//!
//! Lightweight, composable HTTP endpoint router and Axum-style extractors for
//! applications embedding `praeco-rs` via [`crate::build_service_stack_with_base`].
//!
//! ## Highlights
//!
//! - **Composable handlers:** Write plain `async fn`s accepting 0–4 extractors
//!   ([`Query<T>`], [`Path<T>`], [`PathParams`], [`Json<T>`], [`TraceId`], or raw
//!   `Request<SrvBody>`) and returning any [`IntoResponse`] value (`Json<T>`,
//!   `String`, `&'static str`, `(StatusCode, T)`, `Result<T, E>`, ...).
//! - **Single source of truth for WAF rules:** Every registered route records its
//!   `Inspection`-layer allowlist rule automatically (or via `*_with_waf`), and
//!   [`WebRouter::allowed_pathes`] produces the matching [`AllowedPathes`] config.

use std::collections::HashMap;
use std::fmt::Display;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Method, Request, Response, StatusCode, header};
use serde::{Serialize, de::DeserializeOwned};

use crate::configuration::AllowedPathes;
use crate::{BoxCloneSyncServiceExt, BoxedCloneService, ServiceRespBody, SrvBody, SrvError};

type BoxHandlerFuture =
    Pin<Box<dyn Future<Output = Result<Response<ServiceRespBody>, SrvError>> + Send>>;
type BoxedHandler = Arc<dyn Fn(Request<SrvBody>) -> BoxHandlerFuture + Send + Sync>;

/// Boxed future returned by asynchronous request extractors ([`FromRequest`]).
pub type BoxExtractFuture<T> = Pin<Box<dyn Future<Output = Result<T, ExtractError>> + Send>>;

/// Errors returned when constructing or registering routes on a [`WebRouter`].
#[derive(Debug, thiserror::Error)]
pub enum WebRouterError {
    /// Failed to insert a route pattern into the underlying `matchit` radix tree.
    #[error("Invalid route '{path}': {source}")]
    InvalidRoute {
        /// The route path that failed validation.
        path: String,
        /// Underlying `matchit` error.
        #[source]
        source: matchit::InsertError,
    },
}

// ============================================================================
//  Rejections & Responses
// ============================================================================

/// HTTP error response returned when a request extractor rejects client input.
#[derive(Debug, Clone)]
pub struct Rejection {
    status: StatusCode,
    message: String,
}

impl Rejection {
    /// Creates a new rejection with the given HTTP status code and plain-text message.
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// Returns the HTTP status code of this rejection.
    pub fn status(&self) -> StatusCode {
        self.status
    }
}

/// Error produced during request extraction.
///
/// Separates client-facing HTTP [`Rejection`]s (e.g. `400 Bad Request`) from
/// transport/middleware [`SrvError`]s (e.g. `413 Payload Too Large` from `MaxPayload`).
#[derive(Debug)]
pub enum ExtractError {
    /// Client-facing HTTP rejection converted directly into a response.
    Rejection(Rejection),
    /// Server/transport error propagated back up the Tower stack.
    Server(SrvError),
}

impl From<Rejection> for ExtractError {
    fn from(value: Rejection) -> Self {
        Self::Rejection(value)
    }
}

impl From<SrvError> for ExtractError {
    fn from(value: SrvError) -> Self {
        Self::Server(value)
    }
}

/// Converts a handler's return value into an HTTP response for the Praeco stack.
pub trait IntoResponse {
    /// Converts `self` into a [`Response<ServiceRespBody>`] or propagates a [`SrvError`].
    fn into_response(self) -> Result<Response<ServiceRespBody>, SrvError>;
}

impl IntoResponse for Response<ServiceRespBody> {
    fn into_response(self) -> Result<Response<ServiceRespBody>, SrvError> {
        Ok(self)
    }
}

impl IntoResponse for SrvError {
    fn into_response(self) -> Result<Response<ServiceRespBody>, SrvError> {
        Err(self)
    }
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Result<Response<ServiceRespBody>, SrvError> {
        text_response(self.status, self.message)
    }
}

impl IntoResponse for ExtractError {
    fn into_response(self) -> Result<Response<ServiceRespBody>, SrvError> {
        match self {
            Self::Rejection(r) => r.into_response(),
            Self::Server(e) => Err(e),
        }
    }
}

impl IntoResponse for &'static str {
    fn into_response(self) -> Result<Response<ServiceRespBody>, SrvError> {
        text_response(StatusCode::OK, Bytes::from_static(self.as_bytes()))
    }
}

impl IntoResponse for String {
    fn into_response(self) -> Result<Response<ServiceRespBody>, SrvError> {
        text_response(StatusCode::OK, self)
    }
}

impl IntoResponse for StatusCode {
    fn into_response(self) -> Result<Response<ServiceRespBody>, SrvError> {
        let body = Empty::<Bytes>::new().map_err(SrvError::from).boxed();
        Response::builder()
            .status(self)
            .body(body)
            .map_err(|e| SrvError::Other(e.to_string()))
    }
}

impl<T: IntoResponse> IntoResponse for (StatusCode, T) {
    fn into_response(self) -> Result<Response<ServiceRespBody>, SrvError> {
        let mut resp = self.1.into_response()?;
        *resp.status_mut() = self.0;
        Ok(resp)
    }
}

impl<T: IntoResponse, E: IntoResponse> IntoResponse for Result<T, E> {
    fn into_response(self) -> Result<Response<ServiceRespBody>, SrvError> {
        match self {
            Ok(v) => v.into_response(),
            Err(e) => e.into_response(),
        }
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

// ============================================================================
//  Request Extractors
// ============================================================================

/// Extracts a typed value from the non-body parts of an incoming request
/// (URI, query string, headers, extensions) without consuming the body.
pub trait FromRequestParts: Sized {
    /// Extracts `Self` from `req`, or returns a [`Rejection`].
    fn from_request_parts(req: &Request<SrvBody>) -> Result<Self, Rejection>;
}

/// Extracts a typed value from an incoming request, optionally consuming the body.
///
/// Always placed as the **last** argument in multi-argument handlers.
pub trait FromRequest: Sized {
    /// Asynchronously extracts `Self` from `req`.
    fn from_request(req: Request<SrvBody>) -> BoxExtractFuture<Self>;
}

impl FromRequest for Request<SrvBody> {
    fn from_request(req: Request<SrvBody>) -> BoxExtractFuture<Self> {
        Box::pin(std::future::ready(Ok(req)))
    }
}

/// Path parameters captured by `matchit` (e.g. `{id}`) and attached to
/// `req.extensions()` before the endpoint handler is invoked.
#[derive(Clone, Debug, Default)]
pub struct PathParams(HashMap<String, String>);

impl PathParams {
    /// Returns the captured parameter value for `key`, if present.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Returns the number of captured path parameters.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if no path parameters were captured.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromRequestParts for PathParams {
    fn from_request_parts(req: &Request<SrvBody>) -> Result<Self, Rejection> {
        Ok(req.extensions().get::<Self>().cloned().unwrap_or_default())
    }
}

impl FromRequest for PathParams {
    fn from_request(req: Request<SrvBody>) -> BoxExtractFuture<Self> {
        Box::pin(std::future::ready(
            Self::from_request_parts(&req).map_err(ExtractError::from),
        ))
    }
}

/// Extractor for a single typed path parameter (e.g. `"/users/{id}"` -> `Path<String>` or `Path<u64>`).
///
/// For routes with multiple path parameters, use [`PathParams`] instead.
#[derive(Clone, Debug)]
pub struct Path<T>(pub T);

impl<T> FromRequestParts for Path<T>
where
    T: FromStr,
    T::Err: Display,
{
    fn from_request_parts(req: &Request<SrvBody>) -> Result<Self, Rejection> {
        let Some(params) = req.extensions().get::<PathParams>() else {
            return Err(Rejection::new(
                StatusCode::BAD_REQUEST,
                "Missing path parameters\n",
            ));
        };

        if params.0.len() != 1 {
            return Err(Rejection::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Path<T> expects exactly 1 path parameter, found {} (use PathParams for multi-parameter routes)\n",
                    params.0.len()
                ),
            ));
        }

        let Some((key, raw)) = params.0.iter().next() else {
            return Err(Rejection::new(
                StatusCode::BAD_REQUEST,
                "Missing path parameter\n",
            ));
        };

        raw.parse::<T>().map(Path).map_err(|err| {
            Rejection::new(
                StatusCode::BAD_REQUEST,
                format!("Invalid path parameter '{key}': {err}\n"),
            )
        })
    }
}

impl<T> FromRequest for Path<T>
where
    T: FromStr + Send + 'static,
    T::Err: Display,
{
    fn from_request(req: Request<SrvBody>) -> BoxExtractFuture<Self> {
        Box::pin(std::future::ready(
            Self::from_request_parts(&req).map_err(ExtractError::from),
        ))
    }
}

/// Extractor that deserializes URL query parameters (`?key=value&...`) via
/// `serde_urlencoded` into any `serde::Deserialize` struct.
///
/// Combine with Rust struct destructuring in the handler signature to inject
/// fields directly as typed local variables without procedural macros:
///
/// ```rust
/// # use praeco_rs::web::Query;
/// # use serde::Deserialize;
/// #[derive(Deserialize)]
/// struct GreetQuery { user_name: String, age: Option<u8> }
///
/// async fn greet(Query(GreetQuery { user_name, age }): Query<GreetQuery>) -> String {
///     format!("Hello {user_name} ({age:?})")
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Query<T>(pub T);

impl<T: DeserializeOwned> FromRequestParts for Query<T> {
    fn from_request_parts(req: &Request<SrvBody>) -> Result<Self, Rejection> {
        let raw_query = req.uri().query().unwrap_or("");
        serde_urlencoded::from_str(raw_query)
            .map(Query)
            .map_err(|err| {
                Rejection::new(
                    StatusCode::BAD_REQUEST,
                    format!("Invalid query parameters: {err}\n"),
                )
            })
    }
}

impl<T: DeserializeOwned + Send + 'static> FromRequest for Query<T> {
    fn from_request(req: Request<SrvBody>) -> BoxExtractFuture<Self> {
        Box::pin(std::future::ready(
            Self::from_request_parts(&req).map_err(ExtractError::from),
        ))
    }
}

/// Extractor for the `x-trace-id` header propagated by Praeco's `TraceId` layer.
#[derive(Clone, Debug)]
pub struct TraceId(pub Option<String>);

impl FromRequestParts for TraceId {
    fn from_request_parts(req: &Request<SrvBody>) -> Result<Self, Rejection> {
        let value = req
            .headers()
            .get("x-trace-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        Ok(Self(value))
    }
}

impl FromRequest for TraceId {
    fn from_request(req: Request<SrvBody>) -> BoxExtractFuture<Self> {
        Box::pin(std::future::ready(
            Self::from_request_parts(&req).map_err(ExtractError::from),
        ))
    }
}

/// JSON wrapper serving as both a **request body extractor** ([`FromRequest`])
/// and a **response type** ([`IntoResponse`]).
///
/// As a request extractor, reads the body (bounded by Praeco's `MaxPayload` and
/// `Decompression` layers) and deserializes JSON with `serde_json`, returning
/// `400 Bad Request` for malformed JSON.
#[derive(Clone, Debug)]
pub struct Json<T>(pub T);

impl<T: DeserializeOwned + Send + 'static> FromRequest for Json<T> {
    fn from_request(req: Request<SrvBody>) -> BoxExtractFuture<Self> {
        Box::pin(async move {
            let body_bytes = req.collect().await.map_err(ExtractError::Server)?.to_bytes();
            serde_json::from_slice(&body_bytes).map(Json).map_err(|err| {
                ExtractError::Rejection(Rejection::new(
                    StatusCode::BAD_REQUEST,
                    format!("Invalid JSON payload: {err}\n"),
                ))
            })
        })
    }
}

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Result<Response<ServiceRespBody>, SrvError> {
        json_response(StatusCode::OK, &self.0)
    }
}

// ============================================================================
//  Handler Trait (0..=4 Extractors)
// ============================================================================

/// Trait implemented by async endpoint handlers accepting 0–4 extractors and
/// returning any [`IntoResponse`] value.
pub trait Handler<T>: Send + Sync + 'static {
    /// Runs request extraction, invokes the handler, and converts its result into a response.
    fn call(&self, req: Request<SrvBody>) -> BoxHandlerFuture;
}

impl<F, Fut, Res> Handler<()> for F
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Res> + Send + 'static,
    Res: IntoResponse,
{
    fn call(&self, _req: Request<SrvBody>) -> BoxHandlerFuture {
        let fut = self();
        Box::pin(async move { fut.await.into_response() })
    }
}

macro_rules! impl_handler {
    ( [$($part:ident : $part_var:ident),*], $last:ident : $last_var:ident ) => {
        impl<F, Fut, Res, $($part,)* $last> Handler<($($part,)* $last,)> for F
        where
            F: Fn($($part,)* $last) -> Fut + Send + Sync + Clone + 'static,
            Fut: Future<Output = Res> + Send + 'static,
            Res: IntoResponse,
            $($part: FromRequestParts + Send + 'static,)*
            $last: FromRequest + Send + 'static,
        {
            fn call(&self, req: Request<SrvBody>) -> BoxHandlerFuture {
                $(
                    let $part_var = match $part::from_request_parts(&req) {
                        Ok(val) => val,
                        Err(rejection) => return Box::pin(async move { rejection.into_response() }),
                    };
                )*
                let handler = self.clone();
                Box::pin(async move {
                    let $last_var = match $last::from_request(req).await {
                        Ok(val) => val,
                        Err(err) => return err.into_response(),
                    };
                    handler($($part_var,)* $last_var).await.into_response()
                })
            }
        }
    };
}

impl_handler!([], T1: t1);
impl_handler!([T1: t1], T2: t2);
impl_handler!([T1: t1, T2: t2], T3: t3);
impl_handler!([T1: t1, T2: t2, T3: t3], T4: t4);

// ============================================================================
//  WebRouter
// ============================================================================

/// Method-aware HTTP router that compiles into Praeco's [`BoxedCloneService`]
/// and tracks WAF allowlist rules for the `Inspection` middleware.
#[derive(Clone, Default)]
pub struct WebRouter {
    routes: HashMap<Method, matchit::Router<BoxedHandler>>,
    waf_rules: HashMap<Method, HashMap<String, Vec<String>>>,
}

impl WebRouter {
    /// Creates an empty router.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a handler for `method` and `path` and derives a default WAF
    /// allowlist rule for [`Self::allowed_pathes`].
    ///
    /// - Static paths (e.g. `"/healthz"`) get an exact anchored regex (`"^/healthz$"`).
    /// - Paths containing `matchit` placeholders (`{id}` / `{*rest}`) get a prefix
    ///   key and non-empty segment regex. For stricter validation or query-string
    ///   rules, prefer [`Self::route_with_waf`] / [`Self::get_with_waf`].
    pub fn route<H, T>(
        self,
        method: Method,
        path: &str,
        handler: H,
    ) -> Result<Self, WebRouterError>
    where
        H: Handler<T>,
    {
        let (waf_key, waf_regex) = derive_default_waf_rule(path);
        self.route_with_waf(method, path, &waf_key, &waf_regex, handler)
    }

    /// Registers a handler for `method` and `path` together with an explicit
    /// `Inspection`-layer WAF allowlist entry (`waf_key` -> `waf_regex`).
    pub fn route_with_waf<H, T>(
        mut self,
        method: Method,
        path: &str,
        waf_key: &str,
        waf_regex: &str,
        handler: H,
    ) -> Result<Self, WebRouterError>
    where
        H: Handler<T>,
    {
        let boxed: BoxedHandler = Arc::new(move |req| handler.call(req));
        self.routes
            .entry(method.clone())
            .or_default()
            .insert(path, boxed)
            .map_err(|source| WebRouterError::InvalidRoute {
                path: path.to_owned(),
                source,
            })?;

        self.waf_rules
            .entry(method)
            .or_default()
            .entry(waf_key.to_owned())
            .or_default()
            .push(waf_regex.to_owned());

        Ok(self)
    }

    /// Shorthand for registering a `GET` route with an auto-derived WAF rule.
    pub fn get<H, T>(self, path: &str, handler: H) -> Result<Self, WebRouterError>
    where
        H: Handler<T>,
    {
        self.route(Method::GET, path, handler)
    }

    /// Shorthand for registering a `GET` route with an explicit WAF rule.
    pub fn get_with_waf<H, T>(
        self,
        path: &str,
        waf_key: &str,
        waf_regex: &str,
        handler: H,
    ) -> Result<Self, WebRouterError>
    where
        H: Handler<T>,
    {
        self.route_with_waf(Method::GET, path, waf_key, waf_regex, handler)
    }

    /// Shorthand for registering a `POST` route with an auto-derived WAF rule.
    pub fn post<H, T>(self, path: &str, handler: H) -> Result<Self, WebRouterError>
    where
        H: Handler<T>,
    {
        self.route(Method::POST, path, handler)
    }

    /// Shorthand for registering a `POST` route with an explicit WAF rule.
    pub fn post_with_waf<H, T>(
        self,
        path: &str,
        waf_key: &str,
        waf_regex: &str,
        handler: H,
    ) -> Result<Self, WebRouterError>
    where
        H: Handler<T>,
    {
        self.route_with_waf(Method::POST, path, waf_key, waf_regex, handler)
    }

    /// Shorthand for registering a `PUT` route with an auto-derived WAF rule.
    pub fn put<H, T>(self, path: &str, handler: H) -> Result<Self, WebRouterError>
    where
        H: Handler<T>,
    {
        self.route(Method::PUT, path, handler)
    }

    /// Shorthand for registering a `DELETE` route with an auto-derived WAF rule.
    pub fn delete<H, T>(self, path: &str, handler: H) -> Result<Self, WebRouterError>
    where
        H: Handler<T>,
    {
        self.route(Method::DELETE, path, handler)
    }

    /// Shorthand for registering a `PATCH` route with an auto-derived WAF rule.
    pub fn patch<H, T>(self, path: &str, handler: H) -> Result<Self, WebRouterError>
    where
        H: Handler<T>,
    {
        self.route(Method::PATCH, path, handler)
    }

    /// Builds an [`AllowedPathes`] WAF allowlist covering all routes registered
    /// on this router, ready to attach to `ServerConfig::allowed_pathes`.
    pub fn allowed_pathes(&self) -> AllowedPathes {
        AllowedPathes {
            get: self.waf_rules.get(&Method::GET).cloned(),
            post: self.waf_rules.get(&Method::POST).cloned(),
            put: self.waf_rules.get(&Method::PUT).cloned(),
            delete: self.waf_rules.get(&Method::DELETE).cloned(),
            patch: self.waf_rules.get(&Method::PATCH).cloned(),
            head: self.waf_rules.get(&Method::HEAD).cloned(),
        }
    }

    /// Converts this router into a [`BoxedCloneService`] compatible with
    /// [`crate::build_service_stack_with_base`].
    pub fn into_service(self) -> BoxedCloneService {
        let routes = Arc::new(self.routes);
        tower::service_fn(move |mut req: Request<SrvBody>| {
            let routes = Arc::clone(&routes);
            async move {
                let matched_route = routes
                    .get(req.method())
                    .and_then(|router| router.at(req.uri().path()).ok())
                    .map(|matched| {
                        let params: HashMap<String, String> = matched
                            .params
                            .iter()
                            .map(|(k, v)| (k.to_owned(), v.to_owned()))
                            .collect();
                        (Arc::clone(matched.value), params)
                    });

                if let Some((handler, params)) = matched_route {
                    req.extensions_mut().insert(PathParams(params));
                    return handler(req).await;
                }

                // Check if another HTTP method matches the same path -> 405 Method Not Allowed
                let method = req.method();
                let path = req.uri().path();
                let mut allowed: Vec<&str> = routes
                    .iter()
                    .filter(|(m, _)| *m != method)
                    .filter_map(|(m, router)| router.at(path).ok().map(|_| m.as_str()))
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

/// Derives a default `(waf_key, waf_regex)` pair from a `matchit` route pattern.
fn derive_default_waf_rule(path: &str) -> (String, String) {
    let Some(first_brace) = path.find('{') else {
        return (path.to_owned(), format!("^{}$", regex::escape(path)));
    };

    let waf_key = format!("{}*", &path[..first_brace]);
    let mut pattern = String::from("^");
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        pattern.push_str(&regex::escape(&rest[..open]));
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            pattern.push_str(&regex::escape(&rest[open..]));
            rest = "";
            break;
        };
        let placeholder = &after_open[..close];
        if placeholder.starts_with('*') {
            pattern.push_str(".+");
        } else {
            pattern.push_str("[^/]+");
        }
        rest = &after_open[close + 1..];
    }
    pattern.push_str(&regex::escape(rest));
    pattern.push('$');

    (waf_key, pattern)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use tower::ServiceExt;

    fn make_req(method: Method, uri: &str, body: Option<&'static [u8]>) -> Request<SrvBody> {
        let srv_body = match body {
            Some(bytes) => Full::new(Bytes::from_static(bytes))
                .map_err(SrvError::from)
                .boxed(),
            None => Empty::<Bytes>::new().map_err(SrvError::from).boxed(),
        };
        Request::builder()
            .method(method)
            .uri(uri)
            .body(srv_body)
            .expect("valid request")
    }

    #[derive(Deserialize)]
    struct ItemQuery {
        name: String,
        count: Option<u32>,
    }

    #[derive(Deserialize, Serialize)]
    struct EchoBody {
        msg: String,
    }

    #[tokio::test]
    async fn test_extractors_and_into_response() -> Result<(), Box<dyn std::error::Error>> {
        async fn ping() -> &'static str {
            "pong"
        }

        async fn get_item(Path(id): Path<u64>, Query(ItemQuery { name, count }): Query<ItemQuery>) -> String {
            format!("{id}:{name}:{}", count.unwrap_or(0))
        }

        async fn echo(Json(body): Json<EchoBody>) -> (StatusCode, Json<EchoBody>) {
            (StatusCode::CREATED, Json(body))
        }

        let router = WebRouter::new()
            .get("/ping", ping)?
            .get("/items/{id}", get_item)?
            .post("/echo", echo)?;

        let allowed = router.allowed_pathes();
        assert!(allowed.get.as_ref().is_some_and(|m| m.contains_key("/ping")));
        assert!(allowed.get.as_ref().is_some_and(|m| m.contains_key("/items/*")));
        assert!(allowed.post.as_ref().is_some_and(|m| m.contains_key("/echo")));

        let svc = router.into_service();

        let res = svc.clone().oneshot(make_req(Method::GET, "/ping", None)).await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.collect().await?.to_bytes(), Bytes::from_static(b"pong"));

        let res = svc
            .clone()
            .oneshot(make_req(Method::GET, "/items/7?name=widget&count=3", None))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.collect().await?.to_bytes(), Bytes::from_static(b"7:widget:3"));

        let res = svc
            .clone()
            .oneshot(make_req(Method::GET, "/items/not-a-number?name=widget", None))
            .await?;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let res = svc
            .clone()
            .oneshot(make_req(Method::POST, "/echo", Some(br#"{"msg":"hi"}"#)))
            .await?;
        assert_eq!(res.status(), StatusCode::CREATED);
        let parsed: serde_json::Value = serde_json::from_slice(&res.collect().await?.to_bytes())?;
        assert_eq!(parsed["msg"], "hi");

        let res = svc
            .clone()
            .oneshot(make_req(Method::POST, "/echo", Some(b"not-json")))
            .await?;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Method mismatch on an existing route path returns 405 with sorted Allow header
        let res_405 = svc
            .clone()
            .oneshot(make_req(Method::DELETE, "/ping", None))
            .await?;
        assert_eq!(res_405.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            res_405.headers().get(header::ALLOW).and_then(|v| v.to_str().ok()),
            Some("GET")
        );

        let res_404 = svc
            .oneshot(make_req(Method::GET, "/missing", None))
            .await?;
        assert_eq!(res_404.status(), StatusCode::NOT_FOUND);

        Ok(())
    }
}
