//! DPoP (RFC 9449) on the access-token verifier: the same vectors as the
//! TypeScript `@atlasauth/backend` suite, plus every other refusal path.
//! Hermetic: keys are generated in-test, the JWKS is static, and the proofs are
//! genuine ES256 / RS256 / PS256 / EdDSA JWSs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::EncodePrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Map, Value};

use atlasauth::{
    build_challenge, dpop_access_token_hash, jwk_thumbprint, normalize_htu, protected_resource_metadata_requiring_dpop,
    AccessTokenOptions, AccessTokenResult, AtlasBackend, DpopNonceSource, DpopReplayStore, HmacDpopNonceSource, Jwks,
    MemoryDpopReplayStore, ResourceRequest, DPOP_ALGS,
};

const ISSUER: &str = "https://auth.example.com";
const API: &str = "https://api.example.com/mcp";
const META: &str = "https://api.example.com/.well-known/oauth-protected-resource/mcp";

struct As {
    pem: String,
    jwks: Value,
}

fn authz() -> &'static As {
    static K: OnceLock<As> = OnceLock::new();
    K.get_or_init(|| {
        let ec = p256::SecretKey::random(&mut rand::thread_rng());
        let point = ec.public_key().to_encoded_point(false);
        As {
            pem: ec.to_pkcs8_pem(LineEnding::LF).unwrap().to_string(),
            jwks: json!({ "keys": [{ "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256",
                "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()) }] }),
        }
    })
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn backend() -> Arc<AtlasBackend> {
    let jwks: Jwks = serde_json::from_value(authz().jwks.clone()).unwrap();
    Arc::new(AtlasBackend::builder(ISSUER).static_jwks(jwks).build().unwrap())
}

fn token(jkt: Option<&str>) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let mut c = json!({ "iss": ISSUER, "sub": "user_1", "aud": API, "exp": now() + 300, "token_use": "access_token",
        "scope": "tools:read", "client_id": "cli_1", "jti": format!("t{}", N.fetch_add(1, Ordering::SeqCst)) });
    if let Some(j) = jkt {
        c["cnf"] = json!({ "jkt": j });
    }
    let mut h = Header::new(Algorithm::ES256);
    h.kid = Some("k1".into());
    encode(&h, &c, &EncodingKey::from_ec_pem(authz().pem.as_bytes()).unwrap()).unwrap()
}

struct Key {
    alg: &'static str,
    jwk: Map<String, Value>,
    jkt: String,
    enc: EncodingKey,
}

fn key(alg: &'static str) -> Key {
    let (jwk, enc) = match alg {
        "ES256" => {
            let ec = p256::SecretKey::random(&mut rand::thread_rng());
            let p = ec.public_key().to_encoded_point(false);
            let jwk = json!({ "kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(p.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(p.y().unwrap()) });
            (jwk, EncodingKey::from_ec_pem(ec.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).unwrap())
        }
        "RS256" | "PS256" => {
            let rsa = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
            let pubk = RsaPublicKey::from(&rsa);
            let jwk = json!({ "kty": "RSA", "n": URL_SAFE_NO_PAD.encode(pubk.n().to_bytes_be()), "e": URL_SAFE_NO_PAD.encode(pubk.e().to_bytes_be()) });
            (jwk, EncodingKey::from_rsa_pem(rsa.to_pkcs1_pem(LineEnding::LF).unwrap().as_bytes()).unwrap())
        }
        _ => {
            use ed25519_dalek::pkcs8::EncodePrivateKey as _;
            let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let jwk = json!({ "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes()) });
            (jwk, EncodingKey::from_ed_der(sk.to_pkcs8_der().unwrap().as_bytes()))
        }
    };
    let jwk = jwk.as_object().unwrap().clone();
    let jkt = jwk_thumbprint(&jwk).unwrap();
    Key { alg, jwk, jkt, enc }
}

#[derive(Default)]
struct P {
    claims: Vec<(&'static str, Option<Value>)>,
    header: Option<Value>,
    sign_alg: Option<&'static str>,
    tamper: bool,
}

fn proof(k: &Key, token: &str, o: P) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let mut body = json!({ "htm": "POST", "htu": API, "jti": format!("j{}", N.fetch_add(1, Ordering::SeqCst)),
        "iat": now(), "ath": dpop_access_token_hash(token) });
    for (c, v) in o.claims {
        match v {
            Some(v) => body[c] = v,
            None => {
                body.as_object_mut().unwrap().remove(c);
            }
        }
    }
    let h = o.header.unwrap_or_else(|| json!({ "typ": "dpop+jwt", "alg": k.alg, "jwk": k.jwk }));
    let enc = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
    let mut input = format!("{}.{}", enc(&h), enc(&body));
    let alg: Algorithm = o.sign_alg.unwrap_or(k.alg).parse().unwrap();
    let sig = jsonwebtoken::crypto::sign(input.as_bytes(), &k.enc, alg).unwrap();
    if o.tamper {
        input = format!("{}.{}", enc(&h), enc(&json!({ "htm": "POST", "jti": "x" })));
    }
    format!("{input}.{sig}")
}

fn simple(k: &Key, token: &str) -> String {
    proof(k, token, P::default())
}

fn with(k: &Key, token: &str, claims: Vec<(&'static str, Option<Value>)>) -> String {
    proof(k, token, P { claims, ..Default::default() })
}

fn opts() -> AccessTokenOptions {
    AccessTokenOptions {
        audiences: vec![API.into()],
        resource_metadata_url: Some(META.into()),
        dpop_replay_store: Some(Arc::new(MemoryDpopReplayStore::new(0))),
        ..Default::default()
    }
}

async fn check(b: &AtlasBackend, o: &AccessTokenOptions, scheme: &str, tok: &str, proof: Option<&str>) -> AccessTokenResult {
    check_at(b, o, scheme, tok, proof, "POST", &format!("{API}?x=1")).await
}

async fn check_at(
    b: &AtlasBackend,
    o: &AccessTokenOptions,
    scheme: &str,
    tok: &str,
    proof: Option<&str>,
    method: &str,
    url: &str,
) -> AccessTokenResult {
    let authorization = format!("{scheme} {tok}");
    b.verify_access_token_request(&ResourceRequest { method, url, authorization: Some(&authorization), dpop: proof }, o).await
}

fn refused(r: &AccessTokenResult, want: &str, name: &str) {
    match r {
        AccessTokenResult::Refused { status, error, www_authenticate, description, .. } => {
            assert_eq!(*status, 401, "{name}");
            assert_eq!(*error, Some(want), "{name}: {description}");
            assert!(www_authenticate.starts_with("DPoP "), "{name}: {www_authenticate}");
            assert!(www_authenticate.contains(&format!("error=\"{want}\"")), "{name}");
            assert!(www_authenticate.contains("algs=\"ES256"), "{name}");
        }
        AccessTokenResult::Ok { .. } => panic!("{name}: expected a refusal"),
    }
}

#[tokio::test]
async fn accepts_a_bound_token_with_a_matching_proof_for_every_alg() {
    let b = backend();
    let o = opts();
    for alg in ["ES256", "RS256", "PS256", "EdDSA"] {
        let k = key(alg);
        let tok = token(Some(&k.jkt));
        match check(&b, &o, "DPoP", &tok, Some(&simple(&k, &tok))).await {
            AccessTokenResult::Ok { dpop_bound, subject, .. } => {
                assert!(dpop_bound, "{alg}");
                assert_eq!(subject, "user_1");
            }
            AccessTokenResult::Refused { description, .. } => panic!("{alg}: {description}"),
        }
    }
    match check(&b, &o, "Bearer", &token(None), None).await {
        AccessTokenResult::Ok { dpop_bound, .. } => assert!(!dpop_bound),
        r => panic!("bearer refused: {r:?}"),
    }
}

#[tokio::test]
async fn never_accepts_a_bound_token_as_bearer() {
    let b = backend();
    let o = opts();
    let k = key("ES256");
    let tok = token(Some(&k.jkt));
    refused(&check(&b, &o, "Bearer", &tok, Some(&simple(&k, &tok))).await, "invalid_token", "bearer");
    refused(&b.verify_access_token(Some(&format!("DPoP {tok}")), &o).await, "invalid_dpop_proof", "no proof");
    let unbound = token(None);
    refused(&check(&b, &o, "DPoP", &unbound, Some(&simple(&k, &unbound))).await, "invalid_token", "unbound as DPoP");
}

#[tokio::test]
async fn rejects_every_bad_proof() {
    let b = backend();
    let o = opts();
    let k = key("ES256");
    let other = key("ES256");
    let tok = token(Some(&k.jkt));
    let t = now();
    let mut priv_jwk = k.jwk.clone();
    priv_jwk.insert("d".into(), json!("AAAA"));
    let hdr = |typ: &str, alg: &str, jwk: Option<&Map<String, Value>>| {
        let mut h = json!({ "typ": typ, "alg": alg });
        if let Some(j) = jwk {
            h["jwk"] = json!(j);
        }
        Some(h)
    };
    let rsa = key("RS256");
    let cases: Vec<(&str, Option<String>)> = vec![
        ("missing proof", None),
        ("malformed", Some("not-a-jwt".into())),
        ("garbage header", Some("e30.e30.e30".into())),
        ("another key", Some(simple(&other, &tok))),
        ("wrong htm", Some(with(&k, &tok, vec![("htm", Some(json!("GET")))]))),
        ("wrong htu", Some(with(&k, &tok, vec![("htu", Some(json!("https://api.example.com/other")))]))),
        ("wrong host", Some(with(&k, &tok, vec![("htu", Some(json!("https://evil.example.com/mcp")))]))),
        ("relative htu", Some(with(&k, &tok, vec![("htu", Some(json!("/mcp")))]))),
        ("wrong ath", Some(with(&k, &tok, vec![("ath", Some(json!("nope")))]))),
        ("no ath", Some(with(&k, &tok, vec![("ath", None)]))),
        ("proof for another token", Some(simple(&k, &token(Some(&k.jkt))))),
        ("stale", Some(with(&k, &tok, vec![("iat", Some(json!(t - 3600)))]))),
        ("future", Some(with(&k, &tok, vec![("iat", Some(json!(t + 60)))]))),
        ("no iat", Some(with(&k, &tok, vec![("iat", None)]))),
        ("expired exp", Some(with(&k, &tok, vec![("exp", Some(json!(t - 60)))]))),
        ("no jti", Some(with(&k, &tok, vec![("jti", None)]))),
        ("typ JWT", Some(proof(&k, &tok, P { header: hdr("JWT", "ES256", Some(&k.jwk)), ..Default::default() }))),
        ("alg HS256", Some(proof(&k, &tok, P { header: hdr("dpop+jwt", "HS256", Some(&k.jwk)), ..Default::default() }))),
        ("alg none", Some(proof(&k, &tok, P { header: hdr("dpop+jwt", "none", Some(&k.jwk)), ..Default::default() }))),
        ("alg ES512", Some(proof(&k, &tok, P { header: hdr("dpop+jwt", "ES512", Some(&k.jwk)), ..Default::default() }))),
        ("no jwk", Some(proof(&k, &tok, P { header: hdr("dpop+jwt", "ES256", None), ..Default::default() }))),
        ("private jwk", Some(proof(&k, &tok, P { header: hdr("dpop+jwt", "ES256", Some(&priv_jwk)), ..Default::default() }))),
        (
            "alg/key mismatch",
            Some(proof(&rsa, &tok, P { header: hdr("dpop+jwt", "RS256", Some(&k.jwk)), ..Default::default() })),
        ),
        ("bad signature", Some(proof(&k, &tok, P { tamper: true, ..Default::default() }))),
    ];
    for (name, p) in &cases {
        refused(&check(&b, &o, "DPoP", &tok, p.as_deref()).await, "invalid_dpop_proof", name);
    }
    let once = with(&k, &tok, vec![("jti", Some(json!("fixed")))]);
    assert!(check(&b, &o, "DPoP", &tok, Some(&once)).await.is_ok());
    refused(&check(&b, &o, "DPoP", &tok, Some(&once)).await, "invalid_dpop_proof", "replay");
    let tok_other = token(Some(&other.jkt));
    assert!(
        check(&b, &o, "DPoP", &tok_other, Some(&with(&other, &tok_other, vec![("jti", Some(json!("fixed")))]))).await.is_ok(),
        "same jti, other key"
    );
}

#[tokio::test]
async fn require_dpop_refuses_an_unbound_token() {
    let b = backend();
    let o = AccessTokenOptions { require_dpop: true, ..opts() };
    refused(&check(&b, &o, "Bearer", &token(None), None).await, "invalid_token", "requireDpop");
    match b.verify_access_token(None, &o).await {
        AccessTokenResult::Refused { status, error, www_authenticate, .. } => {
            assert_eq!(status, 401);
            assert_eq!(error, None);
            assert!(www_authenticate.starts_with("DPoP ") && www_authenticate.contains("algs=\""), "{www_authenticate}");
        }
        r => panic!("{r:?}"),
    }
}

#[tokio::test]
async fn htu_normalisation_and_public_origin() {
    let b = backend();
    let o = opts();
    let k = key("ES256");
    let tok = token(Some(&k.jkt));
    for htu in ["HTTPS://API.Example.COM:443/mcp", "https://api.example.com/mcp?other=2#frag"] {
        assert!(check(&b, &o, "DPoP", &tok, Some(&with(&k, &tok, vec![("htu", Some(json!(htu)))]))).await.is_ok(), "{htu}");
    }
    refused(&check_at(&b, &o, "DPoP", &tok, Some(&simple(&k, &tok)), "POST", "/mcp?x=1").await, "invalid_dpop_proof", "path");
    let vo = AccessTokenOptions { public_origin: Some("https://api.example.com".into()), ..opts() };
    assert!(check_at(&b, &vo, "DPoP", &tok, Some(&simple(&k, &tok)), "post", "/mcp?x=1").await.is_ok());
    for (given, want) in [
        ("https://A.example.com:443", "https://a.example.com/"),
        ("http://a.example.com:80/x?y#z", "http://a.example.com/x"),
        ("https://a.example.com:8443/p/", "https://a.example.com:8443/p/"),
        ("https://[::1]:443/p", "https://[::1]/p"),
    ] {
        assert_eq!(normalize_htu(given).as_deref(), Some(want), "{given}");
    }
    assert_eq!(normalize_htu("ftp://x/y"), None);
}

#[tokio::test]
async fn server_nonce() {
    let clock_ms = Arc::new(AtomicU64::new((now() as u64) * 1000));
    let c = clock_ms.clone();
    let nonces = Arc::new(HmacDpopNonceSource::with_clock(&[b's'; 32], 60, Arc::new(move || c.load(Ordering::SeqCst))).unwrap());
    let o = AccessTokenOptions { dpop_nonces: Some(nonces.clone()), ..opts() };
    let b = backend();
    let k = key("ES256");
    let tok = token(Some(&k.jkt));
    let r = check(&b, &o, "DPoP", &tok, Some(&simple(&k, &tok))).await;
    refused(&r, "use_dpop_nonce", "no nonce");
    let issued_nonce = r.dpop_nonce().unwrap().to_owned();
    assert_eq!(issued_nonce, nonces.current());
    refused(&check(&b, &o, "DPoP", &tok, Some(&with(&k, &tok, vec![("nonce", Some(json!("made-up")))]))).await, "use_dpop_nonce", "wrong");
    let ok = check(&b, &o, "DPoP", &tok, Some(&with(&k, &tok, vec![("nonce", Some(json!(issued_nonce)))]))).await;
    assert!(ok.is_ok() && ok.dpop_nonce().is_some(), "{ok:?}");
    let issued = nonces.current();
    clock_ms.fetch_add(60_000, Ordering::SeqCst);
    assert!(nonces.valid(&issued));
    clock_ms.fetch_add(60_000, Ordering::SeqCst);
    assert!(!nonces.valid(&issued));
    refused(&check(&b, &o, "DPoP", &tok, Some(&with(&k, &tok, vec![("nonce", Some(json!(issued)))]))).await, "use_dpop_nonce", "stale");
    assert!(HmacDpopNonceSource::new(b"short", 0).is_err());
}

#[test]
fn helpers() {
    let n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
    let jwk = json!({ "kty": "RSA", "e": "AQAB", "alg": "RS256", "kid": "2011-04-29", "n": n });
    assert_eq!(jwk_thumbprint(jwk.as_object().unwrap()).as_deref(), Some("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"));
    assert_eq!(jwk_thumbprint(json!({ "kty": "oct", "k": "x" }).as_object().unwrap()), None);
    let t = Arc::new(AtomicU64::new(1_000_000));
    let tc = t.clone();
    let store = MemoryDpopReplayStore::with_clock(2, Arc::new(move || tc.load(Ordering::SeqCst)));
    assert!(store.claim("a", 1_060_000));
    assert!(!store.claim("a", 1_060_000));
    t.store(1_120_000, Ordering::SeqCst);
    assert!(store.claim("a", 1_180_000));
    store.claim("b", 1_180_000);
    store.claim("c", 1_180_000);
    assert!(store.len() <= 2);
    let doc = protected_resource_metadata_requiring_dpop(API, ISSUER, &[]);
    assert_eq!(doc["dpop_bound_access_tokens_required"], json!(true));
    assert_eq!(doc["dpop_signing_alg_values_supported"], json!(DPOP_ALGS));
    assert_eq!(
        build_challenge("DPoP", None, Some("use_dpop_nonce"), Some("n"), None, None),
        format!("DPoP error=\"use_dpop_nonce\", error_description=\"n\", algs=\"{}\"", DPOP_ALGS.join(" "))
    );
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn axum_layer_dpop_with_nonce() {
    use axum::body::Body;
    use axum::extract::Request;
    use axum::routing::put;
    use axum::{Extension, Router};
    use tower::ServiceExt;

    use atlasauth::axum::AtlasAccessTokenLayer;

    let nonces = Arc::new(HmacDpopNonceSource::new(&[b'k'; 32], 0).unwrap());
    let options = AccessTokenOptions {
        public_origin: Some("https://api.example.com".into()),
        dpop_nonces: Some(nonces),
        ..opts()
    };
    let app = Router::new()
        .route(
            "/docs/1",
            put(|Extension(t): Extension<AccessTokenResult>| async move {
                match t {
                    AccessTokenResult::Ok { dpop_bound: true, .. } => "bound",
                    _ => "plain",
                }
            }),
        )
        .layer(AtlasAccessTokenLayer::new(backend(), options));
    let k = key("EdDSA");
    let tok = token(Some(&k.jkt));
    let p = |nonce: Option<&str>, jti: &str| {
        with(&k, &tok, vec![
            ("htm", Some(json!("PUT"))),
            ("htu", Some(json!("https://api.example.com/docs/1"))),
            ("nonce", nonce.map(|n| json!(n))),
            ("jti", Some(json!(jti))),
        ])
    };
    let send = |proofs: Vec<String>| {
        let mut req = Request::builder().method("PUT").uri("/docs/1?draft=1").header("authorization", format!("DPoP {tok}"));
        for pr in proofs {
            req = req.header("dpop", pr);
        }
        app.clone().oneshot(req.body(Body::empty()).unwrap())
    };
    let first = send(vec![p(None, "a")]).await.unwrap();
    assert_eq!(first.status(), 401);
    let nonce = first.headers().get("dpop-nonce").unwrap().to_str().unwrap().to_owned();
    assert!(first.headers().get("www-authenticate").unwrap().to_str().unwrap().starts_with("DPoP error=\"use_dpop_nonce\""));
    let ok = send(vec![p(Some(&nonce), "b")]).await.unwrap();
    assert_eq!(ok.status(), 200);
    assert!(ok.headers().get("dpop-nonce").is_some());
    let body = axum::body::to_bytes(ok.into_body(), 1024).await.unwrap();
    assert_eq!(&body[..], b"bound");
    let replay = send(vec![p(Some(&nonce), "b")]).await.unwrap();
    assert_eq!(replay.status(), 401);
    assert!(replay.headers().get("www-authenticate").unwrap().to_str().unwrap().contains("error=\"invalid_dpop_proof\""));
    assert_eq!(send(vec![p(Some(&nonce), "c"), p(Some(&nonce), "d")]).await.unwrap().status(), 401);
}
