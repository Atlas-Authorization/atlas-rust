//! Hermetic tests for the actix-web integration (`actix` feature): a real extractor against the real verifier.
#![cfg(feature = "actix")]

use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::{http::StatusCode, test, web, App};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};

use atlasauth::actix::{AtlasClaims, AtlasRejection};
use atlasauth::{AtlasBackend, Jwks};

const ISSUER: &str = "https://inst.fapi.atlasauth.net";

struct Key {
    pem: Vec<u8>,
    n: String,
    e: String,
}

fn key() -> Key {
    let mut rng = rand::thread_rng();
    let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public = RsaPublicKey::from(&private);
    Key {
        pem: private.to_pkcs1_pem(LineEnding::LF).unwrap().as_bytes().to_vec(),
        n: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
        e: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn sign(k: &Key, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("kid-1".into());
    encode(&header, claims, &EncodingKey::from_rsa_pem(&k.pem).unwrap()).unwrap()
}

fn claims(exp_offset: i64, perms: Value) -> Value {
    json!({
        "iss": ISSUER, "sub": "user_1", "sid": "sess_1", "iat": now() - 10, "nbf": now() - 10,
        "exp": now() + exp_offset, "token_use": "session", "aud": ISSUER, "org_role": "admin", "org_permissions": perms,
    })
}

fn backend(k: &Key) -> web::Data<AtlasBackend> {
    let jwks: Jwks = serde_json::from_value(json!({"keys": [{"kty": "RSA", "kid": "kid-1", "alg": "RS256", "use": "sig", "n": k.n, "e": k.e}]})).unwrap();
    web::Data::new(AtlasBackend::builder(ISSUER).static_jwks(jwks).build().unwrap())
}

async fn me(c: AtlasClaims) -> String {
    c.sub.clone()
}

async fn billing(c: AtlasClaims) -> Result<String, AtlasRejection> {
    c.require("billing:read")?;
    Ok("ok".into())
}

async fn opt(c: Option<AtlasClaims>) -> String {
    c.map(|c| c.sub.clone()).unwrap_or_else(|| "anon".into())
}

macro_rules! app {
    ($data:expr) => {
        test::init_service(
            App::new()
                .app_data($data)
                .route("/me", web::get().to(me))
                .route("/billing", web::get().to(billing))
                .route("/opt", web::get().to(opt)),
        )
        .await
    };
}

#[actix_web::test]
async fn a_valid_bearer_token_reaches_the_handler() {
    let k = key();
    let app = app!(backend(&k));
    let token = sign(&k, &claims(3600, json!([])));
    let req = test::TestRequest::get().uri("/me").insert_header(("Authorization", format!("Bearer {token}"))).to_request();
    let body = test::call_and_read_body(&app, req).await;
    assert_eq!(body, "user_1");
}

#[actix_web::test]
async fn the_session_cookie_is_read_when_there_is_no_header() {
    let k = key();
    let app = app!(backend(&k));
    let token = sign(&k, &claims(3600, json!([])));
    let req = test::TestRequest::get().uri("/me").insert_header(("Cookie", format!("a=b; __session={token}"))).to_request();
    assert_eq!(test::call_service(&app, req).await.status(), StatusCode::OK);
}

#[actix_web::test]
async fn missing_expired_forged_and_garbage_credentials_are_401() {
    let k = key();
    let other = key();
    let app = app!(backend(&k));
    for auth in [
        None,
        Some("Bearer not.a.jwt".to_string()),
        Some(format!("Bearer {}", sign(&k, &claims(-3600, json!([]))))),
        Some(format!("Bearer {}", sign(&other, &claims(3600, json!([]))))),
    ] {
        let mut req = test::TestRequest::get().uri("/me");
        if let Some(a) = auth {
            req = req.insert_header(("Authorization", a));
        }
        let res = test::call_service(&app, req.to_request()).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(res.headers().contains_key("www-authenticate"));
    }
}

#[actix_web::test]
async fn a_missing_permission_is_403() {
    let k = key();
    let app = app!(backend(&k));
    let without = sign(&k, &claims(3600, json!([])));
    let with = sign(&k, &claims(3600, json!(["billing:read"])));
    let req = |t: &str| test::TestRequest::get().uri("/billing").insert_header(("Authorization", format!("Bearer {t}"))).to_request();
    assert_eq!(test::call_service(&app, req(&without)).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(test::call_service(&app, req(&with)).await.status(), StatusCode::OK);
}

#[actix_web::test]
async fn the_optional_extractor_never_rejects() {
    let k = key();
    let app = app!(backend(&k));
    let body = test::call_and_read_body(&app, test::TestRequest::get().uri("/opt").to_request()).await;
    assert_eq!(body, "anon");
}

#[actix_web::test]
async fn an_unregistered_verifier_fails_closed_with_500() {
    let app = test::init_service(App::new().route("/me", web::get().to(me))).await;
    let res = test::call_service(&app, test::TestRequest::get().uri("/me").insert_header(("Authorization", "Bearer a.b.c")).to_request()).await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
