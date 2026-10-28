//! Hermetic tests for the Rocket integration (`rocket` feature): a real request guard against the real verifier.
#![cfg(feature = "rocket")]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rocket::http::{Header as HttpHeader, Status};
use rocket::local::asynchronous::Client;
use rocket::{get, routes};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};

use atlasauth::rocket::AtlasClaims;
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

fn backend(k: &Key) -> Arc<AtlasBackend> {
    let jwks: Jwks = serde_json::from_value(json!({"keys": [{"kty": "RSA", "kid": "kid-1", "alg": "RS256", "use": "sig", "n": k.n, "e": k.e}]})).unwrap();
    Arc::new(AtlasBackend::builder(ISSUER).static_jwks(jwks).build().unwrap())
}

#[get("/me")]
fn me(c: AtlasClaims) -> String {
    c.sub.clone()
}

#[get("/billing")]
fn billing(c: AtlasClaims) -> Result<&'static str, Status> {
    c.require("billing:read")?;
    Ok("ok")
}

#[get("/opt")]
fn opt(c: Option<AtlasClaims>) -> String {
    c.map(|c| c.sub.clone()).unwrap_or_else(|| "anon".into())
}

async fn client(b: Option<Arc<AtlasBackend>>) -> Client {
    let mut r = rocket::build().mount("/", routes![me, billing, opt]);
    if let Some(b) = b {
        r = r.manage(b);
    }
    Client::tracked(r).await.unwrap()
}

#[rocket::async_test]
async fn a_valid_bearer_token_reaches_the_route_and_the_cookie_works_too() {
    let k = key();
    let c = client(Some(backend(&k))).await;
    let token = sign(&k, &claims(3600, json!([])));
    let r = c.get("/me").header(HttpHeader::new("Authorization", format!("Bearer {token}"))).dispatch().await;
    assert_eq!(r.status(), Status::Ok);
    assert_eq!(r.into_string().await.unwrap(), "user_1");
    let r = c.get("/me").header(HttpHeader::new("Cookie", format!("a=b; __session={token}"))).dispatch().await;
    assert_eq!(r.status(), Status::Ok);
}

#[rocket::async_test]
async fn missing_expired_forged_and_garbage_credentials_are_401() {
    let k = key();
    let other = key();
    let c = client(Some(backend(&k))).await;
    assert_eq!(c.get("/me").dispatch().await.status(), Status::Unauthorized);
    for token in ["not.a.jwt".to_string(), sign(&k, &claims(-3600, json!([]))), sign(&other, &claims(3600, json!([])))] {
        let r = c.get("/me").header(HttpHeader::new("Authorization", format!("Bearer {token}"))).dispatch().await;
        assert_eq!(r.status(), Status::Unauthorized);
    }
}

#[rocket::async_test]
async fn a_missing_permission_is_403_and_the_optional_guard_never_rejects() {
    let k = key();
    let c = client(Some(backend(&k))).await;
    let without = sign(&k, &claims(3600, json!([])));
    let with = sign(&k, &claims(3600, json!(["billing:read"])));
    let get = |t: &str| c.get("/billing").header(HttpHeader::new("Authorization", format!("Bearer {t}")));
    assert_eq!(get(&without).dispatch().await.status(), Status::Forbidden);
    assert_eq!(get(&with).dispatch().await.status(), Status::Ok);
    assert_eq!(c.get("/opt").dispatch().await.into_string().await.unwrap(), "anon");
}

#[rocket::async_test]
async fn an_unmanaged_verifier_fails_closed() {
    let c = client(None).await;
    let r = c.get("/me").header(HttpHeader::new("Authorization", "Bearer a.b.c")).dispatch().await;
    assert_eq!(r.status(), Status::InternalServerError);
}
