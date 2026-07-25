use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use shoal::db::Db;
use shoal::server::{router, AppState, Limits};
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
    let state = Arc::new(AppState::with_limits(Db::open_in_memory().unwrap(), limits));
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
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
