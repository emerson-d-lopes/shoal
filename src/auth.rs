use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub const MAX_CLOCK_SKEW_SECS: i64 = 300;

#[derive(Debug, PartialEq)]
pub enum AuthError {
    MissingHeader(&'static str),
    BadEncoding,
    SkewedTimestamp,
    BadSignature,
}

impl AuthError {
    pub fn message(&self) -> String {
        match self {
            AuthError::MissingHeader(h) => format!("missing header: {h}"),
            AuthError::BadEncoding => "malformed auth header".into(),
            AuthError::SkewedTimestamp => "timestamp outside allowed window".into(),
            AuthError::BadSignature => "signature verification failed".into(),
        }
    }
}

/// The signed message is:
///   method \n path-with-query \n timestamp \n hex(sha256(body))
pub fn signing_message(method: &str, path_and_query: &str, timestamp: &str, body: &[u8]) -> Vec<u8> {
    let body_hash = hex(&Sha256::digest(body));
    format!("{method}\n{path_and_query}\n{timestamp}\n{body_hash}").into_bytes()
}

/// Verifies request auth headers. Returns the caller's pubkey (base64url) on
/// success. `now` is unix seconds, injected for testability.
pub fn verify(
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    now: i64,
) -> Result<String, AuthError> {
    let get = |name: &'static str| -> Result<&str, AuthError> {
        headers
            .get(name)
            .ok_or(AuthError::MissingHeader(name))?
            .to_str()
            .map_err(|_| AuthError::BadEncoding)
    };
    let pubkey_b64 = get("x-shoal-pubkey")?;
    let timestamp = get("x-shoal-timestamp")?;
    let signature_b64 = get("x-shoal-signature")?;

    let ts: i64 = timestamp.parse().map_err(|_| AuthError::BadEncoding)?;
    if (now - ts).abs() > MAX_CLOCK_SKEW_SECS {
        return Err(AuthError::SkewedTimestamp);
    }

    let pubkey_bytes: [u8; 32] = B64
        .decode(pubkey_b64)
        .map_err(|_| AuthError::BadEncoding)?
        .try_into()
        .map_err(|_| AuthError::BadEncoding)?;
    let key = VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| AuthError::BadEncoding)?;

    let sig_bytes: [u8; 64] = B64
        .decode(signature_b64)
        .map_err(|_| AuthError::BadEncoding)?
        .try_into()
        .map_err(|_| AuthError::BadEncoding)?;
    let sig = Signature::from_bytes(&sig_bytes);

    let msg = signing_message(method, path_and_query, timestamp, body);
    key.verify(&msg, &sig).map_err(|_| AuthError::BadSignature)?;

    Ok(pubkey_b64.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_headers(key: &SigningKey, method: &str, path: &str, body: &[u8], ts: i64) -> HeaderMap {
        let ts = ts.to_string();
        let msg = signing_message(method, path, &ts, body);
        let sig = key.sign(&msg);
        let mut h = HeaderMap::new();
        h.insert("x-shoal-pubkey", HeaderValue::from_str(&B64.encode(key.verifying_key().as_bytes())).unwrap());
        h.insert("x-shoal-timestamp", HeaderValue::from_str(&ts).unwrap());
        h.insert("x-shoal-signature", HeaderValue::from_str(&B64.encode(sig.to_bytes())).unwrap());
        h
    }

    #[test]
    fn accepts_valid_signature() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed_headers(&key, "POST", "/v1/ops", b"{}", 1000);
        let got = verify(&h, "POST", "/v1/ops", b"{}", 1000).unwrap();
        assert_eq!(got, B64.encode(key.verifying_key().as_bytes()));
    }

    #[test]
    fn rejects_wrong_body() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed_headers(&key, "POST", "/v1/ops", b"{}", 1000);
        assert_eq!(
            verify(&h, "POST", "/v1/ops", b"tampered", 1000),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn rejects_wrong_path() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed_headers(&key, "GET", "/v1/ops?since=0", b"", 1000);
        assert_eq!(
            verify(&h, "GET", "/v1/ops?since=99", b"", 1000),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn rejects_skewed_timestamp() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let h = signed_headers(&key, "POST", "/v1/ops", b"{}", 1000);
        assert_eq!(
            verify(&h, "POST", "/v1/ops", b"{}", 1000 + MAX_CLOCK_SKEW_SECS + 1),
            Err(AuthError::SkewedTimestamp)
        );
    }
}
