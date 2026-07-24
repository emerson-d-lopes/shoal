use crate::auth;
use crate::db::{Db, Op};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, Uri},
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures::stream::Stream;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

pub const MAX_BATCH: usize = 1000;
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Abuse guards. Defaults are far above what a personal sync client
/// generates; they exist so a leaked URL or runaway client cannot fill the
/// disk or monopolize the server.
#[derive(Clone, Copy)]
pub struct Limits {
    /// Authenticated requests per pubkey per minute (fixed window).
    pub requests_per_minute: u32,
    /// Total stored ops per user; pushes that would exceed it are rejected.
    pub max_ops_per_user: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            requests_per_minute: 120,
            max_ops_per_user: 1_000_000,
        }
    }
}

impl Limits {
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            requests_per_minute: std::env::var("SHOAL_RATE_PER_MIN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d.requests_per_minute),
            max_ops_per_user: std::env::var("SHOAL_MAX_OPS_PER_USER")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(d.max_ops_per_user),
        }
    }
}

pub struct AppState {
    pub db: Db,
    pub limits: Limits,
    /// Per-user poke channels. Lazily created, never removed; a personal
    /// server has a handful of users at most.
    pokes: Mutex<HashMap<String, broadcast::Sender<i64>>>,
    /// pubkey -> (window start minute, requests in window).
    rate: Mutex<HashMap<String, (u64, u32)>>,
}

impl AppState {
    pub fn new(db: Db) -> Self {
        Self::with_limits(db, Limits::default())
    }

    pub fn with_limits(db: Db, limits: Limits) -> Self {
        Self {
            db,
            limits,
            pokes: Mutex::new(HashMap::new()),
            rate: Mutex::new(HashMap::new()),
        }
    }

    /// Fixed-window rate check; true = allowed. Entries are tiny and per
    /// legitimate user, so the map is never cleaned.
    fn allow(&self, pubkey: &str) -> bool {
        let minute = now_secs() as u64 / 60;
        let mut rate = self.rate.lock().unwrap();
        let entry = rate.entry(pubkey.to_string()).or_insert((minute, 0));
        if entry.0 != minute {
            *entry = (minute, 0);
        }
        entry.1 += 1;
        entry.1 <= self.limits.requests_per_minute
    }

    fn poke_channel(&self, pubkey: &str) -> broadcast::Sender<i64> {
        self.pokes
            .lock()
            .unwrap()
            .entry(pubkey.to_string())
            .or_insert_with(|| broadcast::channel(16).0)
            .clone()
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { Json(json!({"status": "ok"})) }))
        .route("/v1/ops", post(push_ops).get(pull_ops))
        .route("/v1/poke", get(poke))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({"error": msg.into()}))).into_response()
}

// A ready-to-return Response in Err is the point here; boxing it would only
// move the size elsewhere for three call sites.
#[allow(clippy::result_large_err)]
fn authenticate(
    headers: &HeaderMap,
    method: &str,
    uri: &Uri,
    body: &[u8],
) -> Result<String, Response> {
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| uri.path());
    auth::verify(headers, method, path_and_query, body, now_secs())
        .map_err(|e| err(StatusCode::UNAUTHORIZED, e.message()))
}

#[derive(Deserialize)]
struct PushBody {
    ops: Vec<Op>,
}

async fn push_ops(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> Response {
    let pubkey = match authenticate(&headers, "POST", &uri, &body) {
        Ok(pk) => pk,
        Err(resp) => return resp,
    };
    if !state.allow(&pubkey) {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }

    let parsed: PushBody = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("invalid body: {e}")),
    };
    if parsed.ops.is_empty() {
        return err(StatusCode::BAD_REQUEST, "empty batch");
    }
    if parsed.ops.len() > MAX_BATCH {
        return err(
            StatusCode::BAD_REQUEST,
            format!("batch exceeds {MAX_BATCH} ops"),
        );
    }
    for op in &parsed.ops {
        if op.payload.len() > MAX_PAYLOAD_BYTES {
            return err(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("payload exceeds {MAX_PAYLOAD_BYTES} bytes"),
            );
        }
        if op.op_id.is_empty()
            || op.collection.is_empty()
            || op.record_id.is_empty()
            || op.hlc.is_empty()
        {
            return err(StatusCode::BAD_REQUEST, "op with empty required field");
        }
    }

    let result = {
        let state = state.clone();
        let pubkey = pubkey.clone();
        let ops = parsed.ops;
        tokio::task::spawn_blocking(move || {
            let stored = state.db.user_op_count(&pubkey)?;
            if stored + ops.len() as i64 > state.limits.max_ops_per_user {
                return Ok(None);
            }
            state.db.push(&pubkey, &ops, now_secs()).map(Some)
        })
        .await
    };
    match result {
        Ok(Ok(None)) => err(
            StatusCode::INSUFFICIENT_STORAGE,
            "per-user op limit reached; contact the server operator",
        ),
        Ok(Ok(Some(r))) => {
            if r.appended > 0 {
                // Best-effort: receivers may be absent; that's fine.
                let _ = state.poke_channel(&pubkey).send(r.head);
            }
            let results: Vec<_> = r
                .results
                .iter()
                .map(|(op_id, seq)| json!({"op_id": op_id, "seq": seq}))
                .collect();
            Json(json!({"results": results, "head": r.head})).into_response()
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "push failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
        }
        Err(e) => {
            tracing::error!(error = %e, "push task panicked");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

#[derive(Deserialize)]
struct PullParams {
    #[serde(default)]
    since: i64,
    collection: Option<String>,
    limit: Option<i64>,
}

async fn pull_ops(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    Query(params): Query<PullParams>,
) -> Response {
    let pubkey = match authenticate(&headers, "GET", &uri, b"") {
        Ok(pk) => pk,
        Err(resp) => return resp,
    };
    if !state.allow(&pubkey) {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }

    let limit = params.limit.unwrap_or(500).clamp(1, 1000);
    let result = {
        let state = state.clone();
        let pubkey = pubkey.clone();
        tokio::task::spawn_blocking(move || {
            state
                .db
                .pull(&pubkey, params.since, params.collection.as_deref(), limit)
        })
        .await
    };
    match result {
        Ok(Ok((ops, head))) => Json(json!({"ops": ops, "head": head})).into_response(),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "pull failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
        }
        Err(e) => {
            tracing::error!(error = %e, "pull task panicked");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

async fn poke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>>, Response> {
    let pubkey = authenticate(&headers, "GET", &uri, b"")?;
    let rx = state.poke_channel(&pubkey).subscribe();

    let stream = futures::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(head) => {
                    let event = Event::default()
                        .event("poke")
                        .data(json!({"head": head}).to_string());
                    return Some((Ok(event), rx));
                }
                // Lagged: we only care about the latest head; keep reading.
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(30))))
}
