use crate::auth;
use crate::db::{Caps, Db, Op, PushOutcome, StoreOp};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::sse::{Event, KeepAlive, Sse},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures::stream::Stream;
use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

pub const MAX_BATCH: usize = 1000;
/// Default ceiling on one op's decrypted-size-equivalent, measured on the
/// decoded payload rather than its base64 form. Operators raise it with
/// `SHOAL_MAX_PAYLOAD_BYTES` for apps whose records are legitimately large
/// (embedded images); clients must set `maxPayloadBytes` to match.
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
/// Ceiling on a whole request body. A batch of maximum-size ops hits this
/// first, so in practice it is the body limit that bounds a push and
/// `MAX_PAYLOAD_BYTES` that bounds a single oversized record. Clients keep
/// batches under this with their own byte budget; the limit here is the
/// backstop for clients that do not.
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Beyond these sizes the bookkeeping maps are swept. Both are far above the
/// number of live entries a real deployment produces; they exist because a
/// public-facing server can be handed unlimited distinct public keys.
const MAX_RATE_ENTRIES: usize = 4096;
const MAX_POKE_ENTRIES: usize = 1024;

/// Abuse guards. Defaults are far above what a personal sync client
/// generates; they exist so a leaked URL or runaway client cannot fill the
/// disk or monopolize the server.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Authenticated requests per pubkey per minute (fixed window).
    pub requests_per_minute: u32,
    /// Total stored ops per user; pushes that would exceed it are rejected.
    pub max_ops_per_user: i64,
    /// Distinct users the server will ever create. 0 means unlimited.
    pub max_users: i64,
    /// Stored ops across all users. 0 means unlimited.
    pub max_total_ops: i64,
    /// Concurrent SSE streams one user may hold open.
    pub max_streams_per_user: usize,
    /// Largest accepted op payload, measured after base64 decoding.
    pub max_payload_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            requests_per_minute: 120,
            max_ops_per_user: 1_000_000,
            max_users: 0,
            max_total_ops: 0,
            max_streams_per_user: 8,
            max_payload_bytes: MAX_PAYLOAD_BYTES,
        }
    }
}

fn env_parsed<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

impl Limits {
    pub fn from_env() -> Self {
        let d = Self::default();
        Self {
            requests_per_minute: env_parsed("SHOAL_RATE_PER_MIN", d.requests_per_minute),
            max_ops_per_user: env_parsed("SHOAL_MAX_OPS_PER_USER", d.max_ops_per_user),
            max_users: env_parsed("SHOAL_MAX_USERS", d.max_users),
            max_total_ops: env_parsed("SHOAL_MAX_TOTAL_OPS", d.max_total_ops),
            max_streams_per_user: env_parsed("SHOAL_MAX_STREAMS_PER_USER", d.max_streams_per_user),
            max_payload_bytes: env_parsed("SHOAL_MAX_PAYLOAD_BYTES", d.max_payload_bytes),
        }
    }

    fn caps(&self) -> Caps {
        Caps {
            max_ops_per_user: self.max_ops_per_user,
            max_total_ops: self.max_total_ops,
            max_users: self.max_users,
        }
    }
}

/// Which public keys the server will serve.
///
/// A valid signature proves possession of a key, not that the key is one the
/// operator meant to host. Generating a keypair is free, so without an
/// allowlist every per-user limit is per-identity rather than per-person and
/// bounds nothing. An empty allowlist keeps the original open behaviour, in
/// which case `Limits::max_users` and `max_total_ops` are the only ceilings.
#[derive(Clone, Debug, Default)]
pub struct Access {
    allowed: Option<HashSet<String>>,
}

impl Access {
    pub fn open() -> Self {
        Self { allowed: None }
    }

    pub fn allowlist<I: IntoIterator<Item = String>>(keys: I) -> Self {
        let set: HashSet<String> = keys
            .into_iter()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .collect();
        if set.is_empty() {
            Self::open()
        } else {
            Self { allowed: Some(set) }
        }
    }

    pub fn from_env() -> Self {
        match std::env::var("SHOAL_ALLOWED_PUBKEYS") {
            Ok(v) => Self::allowlist(v.split(',').map(|s| s.trim().to_string())),
            Err(_) => Self::open(),
        }
    }

    pub fn is_open(&self) -> bool {
        self.allowed.is_none()
    }

    pub fn permits(&self, pubkey: &str) -> bool {
        match &self.allowed {
            None => true,
            Some(set) => set.contains(pubkey),
        }
    }
}

pub struct AppState {
    pub db: Db,
    pub limits: Limits,
    pub access: Access,
    /// Per-user poke channels, swept of unsubscribed entries once the map
    /// grows past `MAX_POKE_ENTRIES`.
    pokes: Mutex<HashMap<String, broadcast::Sender<i64>>>,
    /// pubkey -> (window start minute, requests in window).
    rate: Mutex<HashMap<String, (u64, u32)>>,
    /// pubkey -> open SSE streams.
    streams: Mutex<HashMap<String, usize>>,
}

impl AppState {
    pub fn new(db: Db) -> Self {
        Self::with_limits(db, Limits::default())
    }

    pub fn with_limits(db: Db, limits: Limits) -> Self {
        Self::with_access(db, limits, Access::open())
    }

    pub fn with_access(db: Db, limits: Limits, access: Access) -> Self {
        Self {
            db,
            limits,
            access,
            pokes: Mutex::new(HashMap::new()),
            rate: Mutex::new(HashMap::new()),
            streams: Mutex::new(HashMap::new()),
        }
    }

    /// Fixed-window rate check; true = allowed.
    fn allow(&self, pubkey: &str) -> bool {
        let minute = now_secs().unsigned_abs() / 60;
        let mut rate = self.rate.lock().unwrap();
        // Entries only matter for the window they name, so anything older is
        // dead weight and can go whenever the map gets large.
        if rate.len() > MAX_RATE_ENTRIES {
            rate.retain(|_, (window, _)| *window >= minute);
        }
        let entry = rate.entry(pubkey.to_string()).or_insert((minute, 0));
        if entry.0 != minute {
            *entry = (minute, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= self.limits.requests_per_minute
    }

    fn poke_channel(&self, pubkey: &str) -> broadcast::Sender<i64> {
        let mut pokes = self.pokes.lock().unwrap();
        if pokes.len() > MAX_POKE_ENTRIES {
            pokes.retain(|_, tx| tx.receiver_count() > 0);
        }
        pokes
            .entry(pubkey.to_string())
            .or_insert_with(|| broadcast::channel(16).0)
            .clone()
    }

    /// Reserves one SSE slot, or returns None when the user is at their cap.
    fn acquire_stream(self: &Arc<Self>, pubkey: &str) -> Option<StreamGuard> {
        let mut streams = self.streams.lock().unwrap();
        let slot = streams.entry(pubkey.to_string()).or_insert(0);
        if *slot >= self.limits.max_streams_per_user {
            return None;
        }
        *slot += 1;
        Some(StreamGuard {
            state: self.clone(),
            pubkey: pubkey.to_string(),
        })
    }
}

/// Releases an SSE slot when the stream is dropped, however it ended.
struct StreamGuard {
    state: Arc<AppState>,
    pubkey: String,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let mut streams = self.state.streams.lock().unwrap();
        if let Some(slot) = streams.get_mut(&self.pubkey) {
            *slot = slot.saturating_sub(1);
            if *slot == 0 {
                streams.remove(&self.pubkey);
            }
        }
    }
}

/// Browser clients send `X-Shoal-*` headers, which are never simple headers,
/// so every cross-origin request is preceded by a preflight. Without this
/// layer the preflight hits the router and is answered with 405.
///
/// Requests carry no cookies and no ambient authority: authentication is a
/// per-request ed25519 signature over the method, path, timestamp, and body
/// hash. An attacker's page cannot produce one, so a permissive origin
/// default does not grant it anything.
pub fn cors_layer(origins: &str) -> CorsLayer {
    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            header::ACCEPT,
            HeaderName::from_static("x-shoal-pubkey"),
            HeaderName::from_static("x-shoal-timestamp"),
            HeaderName::from_static("x-shoal-signature"),
        ])
        .max_age(Duration::from_secs(86_400));

    let trimmed = origins.trim();
    if trimmed.is_empty() || trimmed == "*" {
        return layer.allow_origin(Any);
    }
    let list: Vec<HeaderValue> = trimmed
        .split(',')
        .filter_map(|o| HeaderValue::from_str(o.trim()).ok())
        .collect();
    if list.is_empty() {
        layer.allow_origin(Any)
    } else {
        layer.allow_origin(AllowOrigin::list(list))
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    router_with_cors(
        state,
        cors_layer(&std::env::var("SHOAL_ALLOWED_ORIGINS").unwrap_or_else(|_| "*".into())),
    )
}

pub fn router_with_cors(state: Arc<AppState>, cors: CorsLayer) -> Router {
    Router::new()
        .route("/healthz", get(|| async { Json(json!({"status": "ok"})) }))
        .route("/v1/ops", post(push_ops).get(pull_ops))
        .route("/v1/compact", post(compact_ops))
        .route("/v1/poke", get(poke))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        // Outermost, so a preflight is answered here instead of reaching the
        // routes, which have no OPTIONS handler.
        .layer(cors)
        .with_state(state)
}

fn now_secs() -> i64 {
    // A clock before the epoch would otherwise panic on every request. Such a
    // clock fails the skew check anyway, so 0 is a safe reading.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({"error": msg.into()}))).into_response()
}

// A ready-to-return Response in Err is the point here; boxing it would only
// move the size elsewhere for three call sites.
#[allow(clippy::result_large_err)]
fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    uri: &Uri,
    body: &[u8],
) -> Result<String, Response> {
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| uri.path());
    let pubkey = auth::verify(headers, method, path_and_query, body, now_secs())
        .map_err(|e| err(StatusCode::UNAUTHORIZED, e.message()))?;
    if !state.access.permits(&pubkey) {
        return Err(err(
            StatusCode::FORBIDDEN,
            "public key is not allowed on this server",
        ));
    }
    Ok(pubkey)
}

#[derive(Deserialize)]
struct PushBody {
    ops: Vec<Op>,
}

/// Validates a batch and decodes payloads, so nothing malformed is stored.
#[allow(clippy::result_large_err)]
fn prepare_batch(ops: Vec<Op>, max_payload_bytes: usize) -> Result<Vec<StoreOp>, Response> {
    if ops.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "empty batch"));
    }
    if ops.len() > MAX_BATCH {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("batch exceeds {MAX_BATCH} ops"),
        ));
    }
    let mut prepared = Vec::with_capacity(ops.len());
    for op in ops {
        if op.op_id.is_empty()
            || op.collection.is_empty()
            || op.record_id.is_empty()
            || op.hlc.is_empty()
        {
            return Err(err(StatusCode::BAD_REQUEST, "op with empty required field"));
        }
        let op_id = op.op_id.clone();
        let stored = op.into_store().ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                format!("op {op_id} has a payload that is not valid base64"),
            )
        })?;
        if stored.payload.len() > max_payload_bytes {
            return Err(err(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("payload exceeds {max_payload_bytes} bytes"),
            ));
        }
        prepared.push(stored);
    }
    Ok(prepared)
}

async fn push_ops(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> Response {
    let pubkey = match authenticate(&state, &headers, "POST", &uri, &body) {
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
    let ops = match prepare_batch(parsed.ops, state.limits.max_payload_bytes) {
        Ok(ops) => ops,
        Err(resp) => return resp,
    };

    let caps = state.limits.caps();
    let result = {
        let state = state.clone();
        let pubkey = pubkey.clone();
        tokio::task::spawn_blocking(move || state.db.push(&pubkey, &ops, now_secs(), caps)).await
    };
    match result {
        Ok(Ok(PushOutcome::UserOpCap)) => err(
            StatusCode::INSUFFICIENT_STORAGE,
            "per-user op limit reached; contact the server operator",
        ),
        Ok(Ok(PushOutcome::TotalOpCap)) => err(
            StatusCode::INSUFFICIENT_STORAGE,
            "server storage limit reached; contact the server operator",
        ),
        Ok(Ok(PushOutcome::UserCap)) => err(
            StatusCode::FORBIDDEN,
            "server is not accepting new users; contact the server operator",
        ),
        Ok(Ok(PushOutcome::Stored(r))) => {
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
struct CompactBody {
    collection: String,
    /// Only ops at or below this seq are considered. Clients pass their own
    /// pull cursor, so they never ask to compact anything they have not seen.
    through: i64,
}

/// Drops ops superseded by a later write to the same record.
///
/// Scoped to one collection by design: an app merged as append-only would be
/// damaged by this, and only the client knows which strategy a collection
/// uses. See `Db::compact` for why removing them cannot change any client's
/// converged state.
async fn compact_ops(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> Response {
    let pubkey = match authenticate(&state, &headers, "POST", &uri, &body) {
        Ok(pk) => pk,
        Err(resp) => return resp,
    };
    if !state.allow(&pubkey) {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }

    let parsed: CompactBody = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("invalid body: {e}")),
    };
    if parsed.collection.is_empty() {
        return err(StatusCode::BAD_REQUEST, "collection is required");
    }
    if parsed.through < 0 {
        return err(StatusCode::BAD_REQUEST, "through must not be negative");
    }

    let result = tokio::task::spawn_blocking({
        let state = state.clone();
        let pubkey = pubkey.clone();
        move || {
            state
                .db
                .compact(&pubkey, &parsed.collection, parsed.through)
        }
    })
    .await;

    match result {
        Ok(Ok(r)) => {
            tracing::info!(removed = r.removed, remaining = r.remaining, "compacted");
            Json(json!({"removed": r.removed, "remaining": r.remaining, "head": r.head}))
                .into_response()
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "compaction failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "storage error")
        }
        Err(e) => {
            tracing::error!(error = %e, "compaction task panicked");
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
    let pubkey = match authenticate(&state, &headers, "GET", &uri, b"") {
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
    let pubkey = authenticate(&state, &headers, "GET", &uri, b"")?;
    if !state.allow(&pubkey) {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded"));
    }
    // Held for the life of the stream; dropping it frees the slot.
    let guard = state.acquire_stream(&pubkey).ok_or_else(|| {
        err(
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "at most {} concurrent poke streams per user",
                state.limits.max_streams_per_user
            ),
        )
    })?;
    let rx = state.poke_channel(&pubkey).subscribe();

    let stream = futures::stream::unfold((rx, guard), |(mut rx, guard)| async move {
        loop {
            match rx.recv().await {
                Ok(head) => {
                    let event = Event::default()
                        .event("poke")
                        .data(json!({"head": head}).to_string());
                    return Some((Ok(event), (rx, guard)));
                }
                // Lagged: we only care about the latest head; keep reading.
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(30))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_stays_open() {
        let access = Access::allowlist(["".to_string(), "  ".to_string()]);
        assert!(access.is_open());
        assert!(access.permits("anything"));
    }

    #[test]
    fn allowlist_admits_only_listed_keys() {
        let access = Access::allowlist(["alice".to_string(), " bob ".to_string()]);
        assert!(!access.is_open());
        assert!(access.permits("alice"));
        // Entries are trimmed when the list is built.
        assert!(access.permits("bob"));
        assert!(!access.permits("carol"));
    }

    #[test]
    fn rate_window_resets_and_map_is_swept() {
        let state = Arc::new(AppState::with_limits(
            Db::open_in_memory().unwrap(),
            Limits {
                requests_per_minute: 2,
                ..Limits::default()
            },
        ));
        assert!(state.allow("alice"));
        assert!(state.allow("alice"));
        assert!(!state.allow("alice"), "third request in the window is over");

        // A stale window from a key that will never return must not pin memory.
        {
            let mut rate = state.rate.lock().unwrap();
            for i in 0..=MAX_RATE_ENTRIES {
                rate.insert(format!("stale{i}"), (0, 1));
            }
        }
        state.allow("bob");
        let rate = state.rate.lock().unwrap();
        assert!(
            rate.len() < MAX_RATE_ENTRIES,
            "stale windows should have been swept, got {}",
            rate.len()
        );
    }

    #[test]
    fn stream_slots_are_capped_and_released() {
        let state = Arc::new(AppState::with_limits(
            Db::open_in_memory().unwrap(),
            Limits {
                max_streams_per_user: 2,
                ..Limits::default()
            },
        ));
        let a = state.acquire_stream("alice").unwrap();
        let b = state.acquire_stream("alice").unwrap();
        assert!(state.acquire_stream("alice").is_none(), "third is refused");
        // A different user has their own budget.
        assert!(state.acquire_stream("bob").is_some());

        drop(a);
        assert!(state.acquire_stream("alice").is_some(), "slot was released");
        drop(b);
    }

    #[test]
    fn oversized_payload_is_measured_after_decoding() {
        // Base64 inflates by 4/3, so a payload that is over the limit encoded
        // but under it decoded has to be accepted.
        let raw = vec![0u8; MAX_PAYLOAD_BYTES - 16];
        let op = Op {
            op_id: "a".into(),
            collection: "mnemonic".into(),
            record_id: "card/1".into(),
            hlc: "h".into(),
            payload: crate::db::encode_payload(&raw),
        };
        assert!(op.payload.len() > MAX_PAYLOAD_BYTES, "encoded form is over");
        assert!(
            prepare_batch(vec![op], MAX_PAYLOAD_BYTES).is_ok(),
            "decoded form is under"
        );

        let too_big = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let op = Op {
            op_id: "b".into(),
            collection: "mnemonic".into(),
            record_id: "card/1".into(),
            hlc: "h".into(),
            payload: crate::db::encode_payload(&too_big),
        };
        assert!(prepare_batch(vec![op], MAX_PAYLOAD_BYTES).is_err());
    }

    #[test]
    fn payload_cap_is_configurable() {
        // An op over the default cap is accepted by a server configured with a
        // larger one, and refused by the default.
        let raw = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let op = Op {
            op_id: "a".into(),
            collection: "scalidraw".into(),
            record_id: "file/img1".into(),
            hlc: "h".into(),
            payload: crate::db::encode_payload(&raw),
        };
        assert!(prepare_batch(vec![op.clone()], MAX_PAYLOAD_BYTES).is_err());
        assert!(prepare_batch(vec![op], 4 * 1024 * 1024).is_ok());
    }

    #[test]
    fn malformed_base64_is_rejected() {
        let op = Op {
            op_id: "a".into(),
            collection: "mnemonic".into(),
            record_id: "card/1".into(),
            hlc: "h".into(),
            payload: "not valid base64!!!".into(),
        };
        assert!(prepare_batch(vec![op], MAX_PAYLOAD_BYTES).is_err());
    }
}
