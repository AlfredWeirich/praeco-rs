//! HTTP endpoint handlers and request/response DTOs for the embedded HTTPS web server.

use hyper::Request;
use praeco_rs::{
    SrvBody,
    web::{ClientOids, ClientSan, Json, JwtClaims, Path, Query, TraceId, UserRoles},
};
use serde::{Deserialize, Serialize};

// ============================================================================
//  Request / Response DTOs
// ============================================================================

/// Response payload for `GET /healthz`.
#[derive(Serialize)]
pub struct HealthPayload {
    pub status: &'static str,
    pub protocol_hint: &'static str,
}

/// Response payload for `GET /users/{id}`.
#[derive(Serialize)]
pub struct UserPayload {
    pub id: String,
    pub name: String,
    pub trace_id: Option<String>,
}

/// Query parameters for `GET /greet?user_name=alice` (with optional `&age=17`).
#[derive(Deserialize)]
pub struct GreetQuery {
    pub user_name: String,
    pub age: Option<u8>,
}

/// Response payload for `GET /greet`.
#[derive(Serialize)]
pub struct GreetPayload {
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age: Option<u8>,
    pub greeting: String,
}

/// Response payload for `POST /api/echo`.
#[derive(Serialize)]
pub struct EchoPayload {
    pub body: serde_json::Value,
    pub trace_id: Option<String>,
}

/// Response payload for `GET /whoami` exposing caller identity and mapped OID roles.
#[derive(Serialize)]
pub struct WhoAmIPayload {
    pub roles: Vec<String>,
    pub oids: Vec<String>,
    pub san: Option<String>,
    pub jwt_sub: Option<String>,
}

/// Response payload for `GET /admin/stats` (restricted to the `"Admin"` role via `RbacLayer`).
#[derive(Serialize)]
pub struct AdminStatsPayload {
    pub status: &'static str,
    pub roles: Vec<String>,
    pub trace_id: Option<String>,
}

// ============================================================================
//  Endpoint Handlers
// ============================================================================

/// `GET /` — Welcome response showing HTTP version and Trace ID.
pub async fn index(TraceId(trace_id): TraceId, req: Request<SrvBody>) -> String {
    let version = req.version();
    let trace = trace_id.as_deref().unwrap_or("<none>");
    format!("Hallo von praeco-rs ({version:?}, x-trace-id={trace})!\n")
}

/// `GET /healthz` — Liveness probe returning JSON.
pub async fn healthz() -> Json<HealthPayload> {
    Json(HealthPayload {
        status: "ok",
        protocol_hint: "HTTP/1.1 + HTTP/2 + HTTP/3 (QUIC)",
    })
}

/// `GET /users/{id}` — Demonstrates typed [`Path`] + [`TraceId`] extractors.
pub async fn get_user(Path(id): Path<String>, TraceId(trace_id): TraceId) -> Json<UserPayload> {
    Json(UserPayload {
        name: format!("User {id}"),
        id,
        trace_id,
    })
}

/// `GET /greet?user_name=alice[&age=17]` — Demonstrates [`Query`] extraction with
/// struct destructuring so `user_name` and `age` are injected as typed variables.
pub async fn greet(
    Query(GreetQuery { user_name, age }): Query<GreetQuery>,
) -> Json<GreetPayload> {
    let greeting = match age {
        Some(years) => format!("Hallo {user_name} ({years} Jahre)!"),
        None => format!("Hallo {user_name}!"),
    };
    Json(GreetPayload {
        user_name,
        age,
        greeting,
    })
}

/// `POST /api/echo` — Demonstrates async [`Json`] body extraction + [`TraceId`].
pub async fn echo_json(
    TraceId(trace_id): TraceId,
    Json(body): Json<serde_json::Value>,
) -> Json<EchoPayload> {
    Json(EchoPayload { body, trace_id })
}

/// `GET /whoami` — Returns resolved roles, OID suffixes, mTLS SAN, and JWT subject (if any).
pub async fn whoami(
    UserRoles(roles): UserRoles,
    ClientOids(oids): ClientOids,
    ClientSan(san): ClientSan,
    JwtClaims(claims): JwtClaims,
) -> Json<WhoAmIPayload> {
    Json(WhoAmIPayload {
        roles: roles.into_iter().map(|r| r.0).collect(),
        oids,
        san,
        jwt_sub: claims.map(|c| c.sub),
    })
}

/// `GET /admin/stats` — Protected endpoint requiring `"Admin"` role via `RbacLayer`.
pub async fn admin_stats(UserRoles(roles): UserRoles, TraceId(trace_id): TraceId) -> Json<AdminStatsPayload> {
    Json(AdminStatsPayload {
        status: "admin-ok",
        roles: roles.into_iter().map(|r| r.0).collect(),
        trace_id,
    })
}
