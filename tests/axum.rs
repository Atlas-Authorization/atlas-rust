//! Hermetic tests for the framework-native Axum integration (`axum` feature).
//!
//! No network: an RSA keypair is generated in-test, the JWKS is served
//! statically by the verifier, and the router is driven with
//! `tower::ServiceExt::oneshot` — so a request flows through the real extractor,
//! layer and `require_auth` helper against the real verifier, start to finish,
//! with nothing mocked but the key material. Mirrors the signer in
//! `tests/integration.rs`.
#![cfg(feature = "axum")]

use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware;
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use tower::ServiceExt; // oneshot

use atlasauth::axum::{require_auth, AtlasClaims, AtlasLayer};
use atlasauth::{AtlasBackend, Claims, Jwks};

// ── key material (identical approach to tests/integration.rs) ────────────────

struct KeyMaterial {
    pem: Vec<u8>,
    n: String,
    e: String,
}

fn gen_key() -> KeyMaterial {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate key");
    let pem = priv_key
        .to_pkcs1_pem(LineEnding::LF)
        .expect("encode pem")
        .as_bytes()
        .to_vec();
    let pub_key = RsaPublicKey::from(&priv_key);
    let n = URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
    KeyMaterial { pem, n, e }
}

fn primary() -> &'static KeyMaterial {
    static K: OnceLock<KeyMaterial> = OnceLock::new();
    K.get_or_init(gen_key)
}

fn jwks_for(km: &KeyMaterial, kid: &str) -> Jwks {
    serde_json::from_value(json!({
        "keys": [{ "kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": km.n, "e": km.e }]
    }))
    .unwrap()
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn sign_rs256(km: &KeyMaterial, kid: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(&km.pem).expect("encoding key");
    encode(&header, claims, &key).expect("sign")
}

const ISSUER: &str = "https://inst.fapi.atlasauth.net";

fn valid_claims() -> Value {
    let now = now_secs();
    json!({
        "iss": ISSUER,
        "sub": "user_1",
        "sid": "sess_1",
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 3600,
        "token_use": "session",
        "aud": ISSUER,
        "org_role": "admin",
        "org_permissions": ["billing:read"],
    })
}

fn backend() -> Arc<AtlasBackend> {
    Arc::new(
        AtlasBackend::builder(ISSUER)
            .static_jwks(jwks_for(primary(), "kid-1"))
            .build()
            .unwrap(),
    )
}

fn valid_token() -> String {
    sign_rs256(primary(), "kid-1", &valid_claims())
}

// ── handlers ─────────────────────────────────────────────────────────────────

// Extractor path: the handler only runs with a verified session. Also exercises
// the `has(...)` permission guard over the existing `Claims::has_permission`.
async fn me(claims: AtlasClaims) -> String {
    format!("{}:{}", claims.sub, claims.has("billing:read"))
}

// Optional extractor: serves anonymous and signed-in callers alike, never 401s.
async fn opt(claims: Option<AtlasClaims>) -> String {
    match claims {
        Some(c) => c.sub.clone(),
        None => "anon".to_string(),
    }
}

// Layer / middleware path: reads the `Claims` the layer inserted into extensions.
async fn from_extension(Extension(claims): Extension<Claims>) -> String {
    claims.sub.clone()
}

/// A fresh router per request (`oneshot` consumes the service).
fn app() -> Router {
    let be = backend();
    let guarded = Router::new()
        .route("/guarded", get(from_extension))
        .layer(AtlasLayer::new(be.clone()));
    let via_fn = Router::new()
        .route("/fn", get(from_extension))
        .layer(middleware::from_fn_with_state(be.clone(), require_auth));
    Router::new()
        .route("/me", get(me))
        .route("/opt", get(opt))
        .merge(guarded)
        .merge(via_fn)
        .with_state(be)
}

async fn body_string(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn bearer(uri: &str, token: &str) -> Request {
    Request::builder()
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn anon(uri: &str) -> Request {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn extractor_valid_bearer_yields_claims() {
    let resp = app().oneshot(bearer("/me", &valid_token())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // sub extracted, and the `has(...)` guard sees the permission.
    assert_eq!(body_string(resp).await, "user_1:true");
}

#[tokio::test]
async fn extractor_missing_credential_is_401() {
    let resp = app().oneshot(anon("/me")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn extractor_invalid_token_is_401() {
    let resp = app()
        .oneshot(bearer("/me", "not-a-real-jwt"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn extractor_reads_session_cookie() {
    let req = Request::builder()
        .uri("/me")
        .header(header::COOKIE, format!("__session={}", valid_token()))
        .body(Body::empty())
        .unwrap();
    let resp = app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "user_1:true");
}

#[tokio::test]
async fn optional_extractor_never_rejects() {
    // No credential → 200 + "anon", never a 401.
    let resp = app().oneshot(anon("/opt")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "anon");

    // An *invalid* credential is also tolerated — the optional variant yields
    // None rather than failing the request.
    let resp = app().oneshot(bearer("/opt", "garbage")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "anon");

    // A valid credential attaches.
    let resp = app().oneshot(bearer("/opt", &valid_token())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "user_1");
}

#[tokio::test]
async fn layer_protects_whole_router() {
    // Valid → the inner handler runs and reads the inserted claims.
    let resp = app()
        .oneshot(bearer("/guarded", &valid_token()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "user_1");

    // Missing → the layer short-circuits with 401; the handler never runs.
    let resp = app().oneshot(anon("/guarded")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn require_auth_helper_protects_route() {
    let resp = app().oneshot(bearer("/fn", &valid_token())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "user_1");

    let resp = app().oneshot(anon("/fn")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
