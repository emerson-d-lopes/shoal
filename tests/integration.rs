use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use shoal::db::Db;
use shoal::server::{cors_layer, router_with_cors, Access, AppState, Limits};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

struct Client {
    key: SigningKey,
    http: reqwest::Client,
    base: String,
}

impl Client {
    fn new(seed: u8, base: &str) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
            http: reqwest::Client::new(),
            base: base.to_string(),
        }
    }

    fn headers(&self, method: &str, path_and_query: &str, body: &[u8]) -> Vec<(String, String)> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let msg = shoal::auth::signing_message(method, path_and_query, &ts, body);
        let sig = self.key.sign(&msg);
        vec![
            (
                "x-shoal-pubkey".into(),
                B64.encode(self.key.verifying_key().as_bytes()),
            ),
            ("x-shoal-timestamp".into(), ts),
            ("x-shoal-signature".into(), B64.encode(sig.to_bytes())),
        ]
    }

    async fn push(&self, ops: Value) -> (u16, Value) {
        let body = json!({ "ops": ops }).to_string();
        let path = "/v1/ops";
        let mut req = self
            .http
            .post(format!("{}{}", self.base, path))
            .body(body.clone());
        for (k, v) in self.headers("POST", path, body.as_bytes()) {
            req = req.header(k, v);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn pull(&self, query: &str) -> (u16, Value) {
        let path = format!("/v1/ops?{query}");
        let mut req = self.http.get(format!("{}{}", self.base, path));
        for (k, v) in self.headers("GET", &path, b"") {
            req = req.header(k, v);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }
}

async fn spawn_server() -> String {
    spawn_server_with(Limits::default()).await
}

async fn spawn_server_with(limits: Limits) -> String {
    spawn_server_with_access(limits, Access::open()).await
}

async fn spawn_server_with_access(limits: Limits, access: Access) -> String {
    let state = Arc::new(AppState::with_access(
        Db::open_in_memory().unwrap(),
        limits,
        access,
    ));
    // The CORS policy is passed explicitly rather than read from the
    // environment, so tests do not depend on ambient configuration.
    let app = router_with_cors(state, cors_layer("*"));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn pubkey_of(seed: u8) -> String {
    B64.encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .as_bytes(),
    )
}

fn op(op_id: &str, record_id: &str, hlc: &str) -> Value {
    json!({
        "op_id": op_id,
        "collection": "mnemonic",
        "record_id": record_id,
        "hlc": hlc,
        "payload": B64.encode(b"ciphertext-placeholder"),
    })
}

#[tokio::test]
async fn push_pull_roundtrip_two_devices() {
    let base = spawn_server().await;
    // Same user (same seed) on two "devices".
    let device_a = Client::new(1, &base);
    let device_b = Client::new(1, &base);

    let (status, resp) = device_a
        .push(json!([
            op("op-1", "playlist/aaa", "01-a"),
            op("op-2", "playlist/bbb", "02-a")
        ]))
        .await;
    assert_eq!(status, 200, "{resp}");
    assert_eq!(resp["head"], 2);

    let (status, resp) = device_b.pull("since=0").await;
    assert_eq!(status, 200);
    assert_eq!(resp["ops"].as_array().unwrap().len(), 2);
    assert_eq!(resp["head"], 2);
    assert_eq!(resp["ops"][0]["record_id"], "playlist/aaa");

    // Device B pushes, device A pulls from its cursor.
    let (status, _) = device_b
        .push(json!([op("op-3", "playlist/aaa", "03-b")]))
        .await;
    assert_eq!(status, 200);
    let (_, resp) = device_a.pull("since=2").await;
    let ops = resp["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["op_id"], "op-3");
}

#[tokio::test]
async fn push_is_idempotent() {
    let base = spawn_server().await;
    let c = Client::new(2, &base);

    let (_, first) = c.push(json!([op("dup-1", "r/1", "01")])).await;
    let seq_first = first["results"][0]["seq"].as_i64().unwrap();

    let (_, second) = c
        .push(json!([op("dup-1", "r/1", "01"), op("new-1", "r/2", "02")]))
        .await;
    assert_eq!(second["results"][0]["seq"].as_i64().unwrap(), seq_first);
    assert_eq!(second["head"], 2);
}

#[tokio::test]
async fn users_are_isolated() {
    let base = spawn_server().await;
    let alice = Client::new(3, &base);
    let mallory = Client::new(4, &base);

    alice.push(json!([op("a-1", "r/1", "01")])).await;
    let (status, resp) = mallory.pull("since=0").await;
    assert_eq!(status, 200);
    assert_eq!(
        resp["ops"].as_array().unwrap().len(),
        0,
        "must not see another user's ops"
    );
}

#[tokio::test]
async fn collection_filter() {
    let base = spawn_server().await;
    let c = Client::new(5, &base);

    let mut mixed = op("m-1", "r/1", "01");
    mixed["collection"] = json!("habits");
    c.push(json!([mixed, op("t-1", "r/2", "02")])).await;

    let (_, resp) = c.pull("since=0&collection=mnemonic").await;
    let ops = resp["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["collection"], "mnemonic");
    // head is the user's global head, not per-collection.
    assert_eq!(resp["head"], 2);
}

#[tokio::test]
async fn rejects_bad_signature_and_missing_auth() {
    let base = spawn_server().await;
    let c = Client::new(6, &base);

    // Missing headers entirely.
    let resp = reqwest::Client::new()
        .get(format!("{base}/v1/ops?since=0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);

    // Signature over different body.
    let body = json!({"ops": [op("x-1", "r/1", "01")]}).to_string();
    let mut req = reqwest::Client::new()
        .post(format!("{base}/v1/ops"))
        .body(body);
    for (k, v) in c.headers("POST", "/v1/ops", b"different-body") {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status().as_u16(), 401);
}

#[tokio::test]
async fn rate_limit_returns_429() {
    let base = spawn_server_with(Limits {
        requests_per_minute: 3,
        ..Limits::default()
    })
    .await;
    let c = Client::new(8, &base);

    let mut last = 0;
    for i in 0..5 {
        let (status, _) = c.push(json!([op(&format!("r-{i}"), "r/1", "01")])).await;
        last = status;
    }
    assert_eq!(last, 429);
}

#[tokio::test]
async fn op_cap_returns_507_and_stores_nothing_past_cap() {
    let base = spawn_server_with(Limits {
        max_ops_per_user: 2,
        ..Limits::default()
    })
    .await;
    let c = Client::new(9, &base);

    let (status, _) = c
        .push(json!([op("c-1", "r/1", "01"), op("c-2", "r/2", "02")]))
        .await;
    assert_eq!(status, 200);

    let (status, _) = c.push(json!([op("c-3", "r/3", "03")])).await;
    assert_eq!(status, 507);

    let (_, resp) = c.pull("since=0").await;
    assert_eq!(resp["ops"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn rejects_oversized_and_empty_batches() {
    let base = spawn_server().await;
    let c = Client::new(7, &base);

    let (status, _) = c.push(json!([])).await;
    assert_eq!(status, 400);

    let big: Vec<Value> = (0..1001)
        .map(|i| op(&format!("b-{i}"), "r/1", "01"))
        .collect();
    let (status, _) = c.push(json!(big)).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn payload_survives_the_round_trip() {
    let base = spawn_server().await;
    let c = Client::new(20, &base);

    // Bytes that are not valid UTF-8, which is what real ciphertext looks like.
    let raw: Vec<u8> = vec![0, 1, 2, 200, 255, 128, 64];
    let mut o = op("p-1", "r/1", "01");
    o["payload"] = json!(B64.encode(&raw));
    let (status, _) = c.push(json!([o])).await;
    assert_eq!(status, 200);

    let (_, resp) = c.pull("since=0").await;
    let got = resp["ops"][0]["payload"].as_str().unwrap();
    assert_eq!(B64.decode(got).unwrap(), raw);
}

#[tokio::test]
async fn rejects_payload_that_is_not_base64() {
    let base = spawn_server().await;
    let c = Client::new(21, &base);

    let mut o = op("bad-1", "r/1", "01");
    o["payload"] = json!("this is not base64 !!!");
    let (status, resp) = c.push(json!([o])).await;
    assert_eq!(status, 400, "{resp}");
}

#[tokio::test]
async fn preflight_is_answered_with_cors_headers() {
    let base = spawn_server().await;

    // Exactly what a browser sends before a cross-origin push. Without a CORS
    // layer this reaches the router, which has no OPTIONS handler, and 405s.
    let resp = reqwest::Client::new()
        .request(reqwest::Method::OPTIONS, format!("{base}/v1/ops"))
        .header("Origin", "https://app.example.com")
        .header("Access-Control-Request-Method", "POST")
        .header(
            "Access-Control-Request-Headers",
            "x-shoal-pubkey,x-shoal-timestamp,x-shoal-signature,content-type",
        )
        .send()
        .await
        .unwrap();

    assert!(
        resp.status().is_success(),
        "preflight should not be rejected, got {}",
        resp.status()
    );
    let headers = resp.headers();
    assert!(headers.contains_key("access-control-allow-origin"));
    let allowed = headers
        .get("access-control-allow-headers")
        .unwrap()
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    for required in [
        "x-shoal-pubkey",
        "x-shoal-timestamp",
        "x-shoal-signature",
        "content-type",
    ] {
        assert!(
            allowed.contains(required),
            "{required} missing from {allowed}"
        );
    }
}

#[tokio::test]
async fn allowlist_rejects_keys_it_does_not_name() {
    let base =
        spawn_server_with_access(Limits::default(), Access::allowlist([pubkey_of(30)])).await;

    let allowed = Client::new(30, &base);
    let (status, resp) = allowed.push(json!([op("ok-1", "r/1", "01")])).await;
    assert_eq!(status, 200, "{resp}");

    // A perfectly valid signature from a key the operator never listed.
    let stranger = Client::new(31, &base);
    let (status, _) = stranger.push(json!([op("no-1", "r/1", "01")])).await;
    assert_eq!(status, 403);
    let (status, _) = stranger.pull("since=0").await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn user_cap_stops_new_identities() {
    let base = spawn_server_with(Limits {
        max_users: 1,
        ..Limits::default()
    })
    .await;

    let first = Client::new(32, &base);
    let (status, _) = first.push(json!([op("u-1", "r/1", "01")])).await;
    assert_eq!(status, 200);

    // Second identity is refused even though its signature is valid.
    let second = Client::new(33, &base);
    let (status, _) = second.push(json!([op("u-2", "r/1", "01")])).await;
    assert_eq!(status, 403);

    // The existing user keeps working.
    let (status, _) = first.push(json!([op("u-3", "r/2", "02")])).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn total_op_cap_spans_users() {
    let base = spawn_server_with(Limits {
        max_total_ops: 2,
        ..Limits::default()
    })
    .await;

    let a = Client::new(34, &base);
    let b = Client::new(35, &base);
    assert_eq!(a.push(json!([op("t-1", "r/1", "01")])).await.0, 200);
    assert_eq!(b.push(json!([op("t-2", "r/1", "01")])).await.0, 200);

    let c = Client::new(36, &base);
    let (status, _) = c.push(json!([op("t-3", "r/1", "01")])).await;
    assert_eq!(status, 507, "global storage ceiling applies across users");
}

/// Opens an authenticated SSE stream and returns the response once headers
/// have arrived, which is after the handler has subscribed.
async fn open_poke(c: &Client, base: &str) -> reqwest::Response {
    let path = "/v1/poke";
    let mut req = reqwest::Client::new().get(format!("{base}{path}"));
    for (k, v) in c.headers("GET", path, b"") {
        req = req.header(k, v);
    }
    req.send().await.unwrap()
}

#[tokio::test]
async fn poke_emits_when_ops_land() {
    use futures::StreamExt;

    let base = spawn_server().await;
    let listener = Client::new(40, &base);
    let writer = Client::new(40, &base); // same user, second device

    let resp = open_poke(&listener, &base).await;
    assert_eq!(resp.status().as_u16(), 200);
    let mut stream = resp.bytes_stream();

    let (status, _) = writer.push(json!([op("k-1", "r/1", "01")])).await;
    assert_eq!(status, 200);

    let mut seen = String::new();
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(chunk) = stream.next().await {
            seen.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
            if seen.contains("event: poke") {
                return true;
            }
        }
        false
    })
    .await
    .expect("timed out waiting for a poke");

    assert!(read, "stream ended without a poke, saw: {seen}");
    assert!(
        seen.contains("\"head\":1"),
        "poke should carry head, got {seen}"
    );
}

#[tokio::test]
async fn poke_streams_are_capped_per_user() {
    let base = spawn_server_with(Limits {
        max_streams_per_user: 1,
        ..Limits::default()
    })
    .await;
    let c = Client::new(41, &base);

    let first = open_poke(&c, &base).await;
    assert_eq!(first.status().as_u16(), 200);

    let second = open_poke(&c, &base).await;
    assert_eq!(
        second.status().as_u16(),
        429,
        "a second concurrent stream should be refused"
    );

    // Dropping the first frees its slot for a reconnect.
    drop(first);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let third = open_poke(&c, &base).await;
    assert_eq!(third.status().as_u16(), 200);
}

#[tokio::test]
async fn poke_is_rate_limited_like_every_other_endpoint() {
    let base = spawn_server_with(Limits {
        requests_per_minute: 2,
        max_streams_per_user: 100,
        ..Limits::default()
    })
    .await;
    let c = Client::new(42, &base);

    let mut last = 0;
    let mut held = Vec::new();
    for _ in 0..4 {
        let resp = open_poke(&c, &base).await;
        last = resp.status().as_u16();
        held.push(resp);
    }
    assert_eq!(last, 429, "poke must consume the rate budget");
}

impl Client {
    async fn compact(&self, collection: &str, through: i64) -> (u16, Value) {
        let body = json!({ "collection": collection, "through": through }).to_string();
        let path = "/v1/compact";
        let mut req = self
            .http
            .post(format!("{}{}", self.base, path))
            .body(body.clone());
        for (k, v) in self.headers("POST", path, body.as_bytes()) {
            req = req.header(k, v);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }
}

#[tokio::test]
async fn compaction_drops_superseded_ops_over_http() {
    let base = spawn_server().await;
    let c = Client::new(50, &base);

    c.push(json!([
        op("s-1", "card/1", "0001"),
        op("s-2", "card/1", "0002"),
        op("s-3", "card/1", "0003"),
        op("s-4", "card/2", "0001"),
    ]))
    .await;

    let (status, resp) = c.compact("mnemonic", 4).await;
    assert_eq!(status, 200, "{resp}");
    assert_eq!(resp["removed"], 2);
    assert_eq!(resp["remaining"], 2);
    assert_eq!(resp["head"], 4, "head is unchanged by compaction");

    // A device syncing from scratch still sees the winner for every record.
    let (_, resp) = c.pull("since=0").await;
    let ops = resp["ops"].as_array().unwrap();
    assert_eq!(ops.len(), 2);
    assert_eq!(resp["head"], 4);
}

#[tokio::test]
async fn compaction_is_scoped_to_the_caller_and_collection() {
    let base = spawn_server().await;
    let alice = Client::new(51, &base);
    let bob = Client::new(52, &base);

    let mut other = op("x-1", "day/1", "0001");
    other["collection"] = json!("habits");
    let mut other2 = op("x-2", "day/1", "0002");
    other2["collection"] = json!("habits");

    alice
        .push(json!([
            op("a-1", "card/1", "0001"),
            op("a-2", "card/1", "0002"),
            other,
            other2
        ]))
        .await;
    bob.push(json!([
        op("b-1", "card/1", "0001"),
        op("b-2", "card/1", "0002")
    ]))
    .await;

    let (status, resp) = alice.compact("mnemonic", 4).await;
    assert_eq!(status, 200);
    assert_eq!(resp["removed"], 1);

    // The append-only neighbour is intact.
    let (_, habits) = alice.pull("since=0&collection=habits").await;
    assert_eq!(habits["ops"].as_array().unwrap().len(), 2);

    // Another user is untouched.
    let (_, bobs) = bob.pull("since=0").await;
    assert_eq!(bobs["ops"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn compaction_rejects_bad_input_and_missing_auth() {
    let base = spawn_server().await;
    let c = Client::new(53, &base);

    let (status, _) = c.compact("", 5).await;
    assert_eq!(status, 400, "collection is required");

    let (status, _) = c.compact("mnemonic", -1).await;
    assert_eq!(status, 400, "negative watermark");

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/compact"))
        .body(r#"{"collection":"mnemonic","through":1}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}

#[tokio::test]
async fn compaction_frees_room_against_the_op_cap() {
    let base = spawn_server_with(Limits {
        max_ops_per_user: 3,
        ..Limits::default()
    })
    .await;
    let c = Client::new(54, &base);

    c.push(json!([
        op("f-1", "card/1", "0001"),
        op("f-2", "card/1", "0002"),
        op("f-3", "card/1", "0003"),
    ]))
    .await;
    let (status, _) = c.push(json!([op("f-4", "card/2", "0004")])).await;
    assert_eq!(status, 507, "at the ceiling");

    c.compact("mnemonic", 3).await;

    let (status, _) = c.push(json!([op("f-4", "card/2", "0004")])).await;
    assert_eq!(status, 200, "compaction made real room");
}

#[tokio::test]
async fn poke_requires_authentication() {
    let base = spawn_server().await;
    let resp = reqwest::Client::new()
        .get(format!("{base}/v1/poke"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
}
