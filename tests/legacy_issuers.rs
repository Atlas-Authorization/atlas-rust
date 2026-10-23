//! Legacy-issuer (Better Auth) JWTs accepted during a cutover: routed by `iss`,
//! verified against that issuer's own keys only, `sub` mapped to the Atlas user,
//! bounded by the window. Hermetic: keys are generated in-test.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};

use atlasauth::{
    AtlasBackend, BoxFuture, Clock, Jwks, JwksSource, LegacyIssuer, TransportError, VerifyError, LEGACY_ISSUER_ALGS,
};

const ATLAS: &str = "https://atlas.test";
const OLD: &str = "https://app.example.com";

struct Keys {
    ed_pem: String,
    ec_pem: String,
    rsa_pem: Vec<u8>,
    atlas_pem: Vec<u8>,
    old_jwks: Value,
    atlas_jwks: Value,
}

fn rsa_jwk(key: &RsaPrivateKey, kid: &str, alg: Option<&str>) -> Value {
    let p = RsaPublicKey::from(key);
    let mut v = json!({ "kty": "RSA", "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(p.n().to_bytes_be()), "e": URL_SAFE_NO_PAD.encode(p.e().to_bytes_be()) });
    if let Some(a) = alg {
        v["alg"] = json!(a);
    }
    v
}

fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| {
        let ed = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let ed_pem = ed.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let ec = p256::SecretKey::random(&mut rand::thread_rng());
        let point = ec.public_key().to_encoded_point(false);
        let ec_pem = ec.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let rsa = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let rsa_pem = rsa.to_pkcs1_pem(LineEnding::LF).unwrap().as_bytes().to_vec();
        let atlas = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let atlas_pem = atlas.to_pkcs1_pem(LineEnding::LF).unwrap().as_bytes().to_vec();
        let old_jwks = json!({ "keys": [
            { "kty": "OKP", "crv": "Ed25519", "kid": "ed-1", "alg": "EdDSA",
              "x": URL_SAFE_NO_PAD.encode(ed.verifying_key().to_bytes()) },
            { "kty": "EC", "crv": "P-256", "kid": "ec-1",
              "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()) },
            rsa_jwk(&rsa, "rsa-1", None),
        ]});
        let atlas_jwks = json!({ "keys": [ rsa_jwk(&atlas, "atlas-1", Some("RS256")) ] });
        Keys { ed_pem, ec_pem, rsa_pem, atlas_pem, old_jwks, atlas_jwks }
    })
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn now_ms() -> u64 {
    now() as u64 * 1000
}

fn sign(alg: Algorithm, kid: &str, claims: &Value) -> String {
    let k = keys();
    let mut h = Header::new(alg);
    h.kid = Some(kid.into());
    let key = match alg {
        Algorithm::EdDSA => EncodingKey::from_ed_pem(k.ed_pem.as_bytes()).unwrap(),
        Algorithm::ES256 => EncodingKey::from_ec_pem(k.ec_pem.as_bytes()).unwrap(),
        _ if kid == "atlas-1" => EncodingKey::from_rsa_pem(&k.atlas_pem).unwrap(),
        _ => EncodingKey::from_rsa_pem(&k.rsa_pem).unwrap(),
    };
    encode(&h, claims, &key).unwrap()
}

fn old_claims() -> Value {
    json!({ "iss": OLD, "sub": "ba_user_1", "exp": now() + 600, "iat": now(), "email": "a@example.com" })
}

fn jwks(v: &Value) -> Jwks {
    serde_json::from_value(v.clone()).unwrap()
}

fn issuer() -> LegacyIssuer {
    LegacyIssuer::new(OLD, now_ms() + 3_600_000)
        .jwks(jwks(&keys().old_jwks))
        .resolve_subject(|sub, _| (sub == "ba_user_1").then(|| "user_atlas_1".to_string()))
}

fn backend(legacy: LegacyIssuer) -> AtlasBackend {
    AtlasBackend::builder(ATLAS).static_jwks(jwks(&keys().atlas_jwks)).legacy_issuer(legacy).build().unwrap()
}

#[tokio::test]
async fn accepts_every_supported_better_auth_algorithm_and_maps_the_subject() {
    let b = backend(issuer());
    for (alg, kid) in [
        (Algorithm::EdDSA, "ed-1"),
        (Algorithm::ES256, "ec-1"),
        (Algorithm::RS256, "rsa-1"),
        (Algorithm::PS256, "rsa-1"),
    ] {
        let claims = b.verify(&sign(alg, kid, &old_claims())).await.unwrap_or_else(|e| panic!("{alg:?}: {e}"));
        assert_eq!(claims.sub, "user_atlas_1");
        assert_eq!(claims.iss, OLD);
        assert_eq!(claims.external_id.as_deref(), Some("ba_user_1"));
        assert_eq!(claims.email.as_deref(), Some("a@example.com"));
        assert_eq!(claims.extra["legacy"], json!({ "kind": "better_auth", "issuer": OLD, "sub": "ba_user_1" }));
    }
    assert_eq!(LEGACY_ISSUER_ALGS, ["EdDSA", "ES256", "RS256", "PS256"]);
}

#[tokio::test]
async fn atlas_tokens_still_verify_and_never_against_legacy_keys() {
    let b = backend(issuer());
    let atlas = sign(Algorithm::RS256, "atlas-1", &json!({ "iss": ATLAS, "sub": "user_x", "sid": "sess_1", "exp": now() + 60 }));
    assert_eq!(b.verify(&atlas).await.unwrap().sub, "user_x");
    // An Atlas-issuer token signed with the OLD key is not accepted...
    let forged = sign(Algorithm::RS256, "rsa-1", &json!({ "iss": ATLAS, "sub": "user_x", "exp": now() + 60 }));
    assert_eq!(b.verify(&forged).await, Err(VerifyError::Invalid));
    // ...and an old-issuer token signed with the Atlas key is not either.
    let mut c = old_claims();
    c["iss"] = json!(OLD);
    let crossed = sign(Algorithm::RS256, "atlas-1", &c);
    assert_eq!(b.verify(&crossed).await, Err(VerifyError::Invalid));
}

#[tokio::test]
async fn refuses_after_the_window_without_exp_on_bad_audience_or_unmapped_subject() {
    // Window over: the token is treated as foreign (and fails Atlas verification).
    let ended = LegacyIssuer::new(OLD, 1_000).jwks(jwks(&keys().old_jwks)).resolve_subject(|_, _| Some("u".into()));
    assert_eq!(backend(ended).verify(&sign(Algorithm::EdDSA, "ed-1", &old_claims())).await, Err(VerifyError::Invalid));

    let b = backend(issuer());
    let mut no_exp = old_claims();
    no_exp.as_object_mut().unwrap().remove("exp");
    assert_eq!(b.verify(&sign(Algorithm::EdDSA, "ed-1", &no_exp)).await, Err(VerifyError::Invalid));

    let mut expired = old_claims();
    expired["exp"] = json!(now() - 3600);
    assert_eq!(b.verify(&sign(Algorithm::EdDSA, "ed-1", &expired)).await, Err(VerifyError::Invalid));

    let mut other = old_claims();
    other["sub"] = json!("ba_unknown");
    assert_eq!(b.verify(&sign(Algorithm::EdDSA, "ed-1", &other)).await, Err(VerifyError::Invalid));

    let aud = backend(issuer().audience("https://api.example.com"));
    assert_eq!(aud.verify(&sign(Algorithm::EdDSA, "ed-1", &old_claims())).await, Err(VerifyError::Invalid));
    let mut with_aud = old_claims();
    with_aud["aud"] = json!("https://api.example.com");
    assert_eq!(aud.verify(&sign(Algorithm::EdDSA, "ed-1", &with_aud)).await.unwrap().sub, "user_atlas_1");

    // Better Auth puts the user id in `id` when `sub` is absent.
    let mut id_only = old_claims();
    id_only.as_object_mut().unwrap().remove("sub");
    id_only["id"] = json!("ba_user_1");
    assert_eq!(b.verify(&sign(Algorithm::EdDSA, "ed-1", &id_only)).await.unwrap().sub, "user_atlas_1");
}

#[tokio::test]
async fn algorithm_pinning_and_the_es512_limit() {
    // Restricting the algorithms refuses the others.
    let only_ed = backend(issuer().algorithms(["EdDSA"]));
    assert!(only_ed.verify(&sign(Algorithm::EdDSA, "ed-1", &old_claims())).await.is_ok());
    assert_eq!(only_ed.verify(&sign(Algorithm::RS256, "rsa-1", &old_claims())).await, Err(VerifyError::Invalid));
    // A key's type fixes its algorithm: an RSA key never verifies an EdDSA header.
    assert_eq!(
        backend(issuer()).verify(&sign(Algorithm::ES256, "rsa-1", &old_claims())).await,
        Err(VerifyError::Invalid)
    );

    // ES512 cannot be verified by this crate: naming it is a build error...
    let err = AtlasBackend::builder(ATLAS)
        .static_jwks(jwks(&keys().atlas_jwks))
        .legacy_issuer(issuer().algorithms(["EdDSA", "ES512"]))
        .build()
        .err()
        .expect("ES512 refused");
    assert!(err.to_string().contains("ES512"), "{err}");
    // ...and an ES512-headed token is refused.
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES512","kid":"p521"}"#);
    let payload = URL_SAFE_NO_PAD.encode(old_claims().to_string());
    let token = format!("{header}.{payload}.{}", URL_SAFE_NO_PAD.encode([1u8; 132]));
    assert_eq!(backend(issuer()).verify(&token).await, Err(VerifyError::Invalid));
}

#[test]
fn configuration_errors_are_raised_at_build() {
    let build = |l: LegacyIssuer| AtlasBackend::builder(ATLAS).static_jwks(jwks(&keys().atlas_jwks)).legacy_issuer(l).build();
    let msg = |l: LegacyIssuer| build(l).err().map(|e| e.to_string()).unwrap_or_default();
    assert!(msg(LegacyIssuer::new(ATLAS, now_ms() + 1).jwks(jwks(&keys().old_jwks)).resolve_subject(|_, _| None))
        .contains("cannot be the Atlas issuer"));
    assert!(msg(LegacyIssuer::new(OLD, 0).jwks(jwks(&keys().old_jwks)).resolve_subject(|_, _| None)).contains("until"));
    assert!(msg(LegacyIssuer::until_rfc3339(OLD, "soon").jwks(jwks(&keys().old_jwks)).resolve_subject(|_, _| None))
        .contains("until"));
    assert!(msg(LegacyIssuer::new(OLD, now_ms() + 1).resolve_subject(|_, _| None)).contains("exactly one"));
    assert!(msg(LegacyIssuer::new(OLD, now_ms() + 1)
        .jwks(jwks(&keys().old_jwks))
        .jwks_url("https://app.example.com/api/auth/jwks")
        .resolve_subject(|_, _| None))
    .contains("exactly one"));
    assert!(msg(LegacyIssuer::new(OLD, now_ms() + 1).jwks(jwks(&keys().old_jwks))).contains("subject resolver"));
    assert!(msg(issuer().algorithms(["HS256"])).contains("unsupported algorithm"));
    assert!(build(LegacyIssuer::until_rfc3339(OLD, "2099-01-01T00:00:00Z").jwks(jwks(&keys().old_jwks)).resolve_subject(|_, _| None)).is_ok());
}

struct CountingJwks {
    body: Value,
    calls: AtomicUsize,
}

impl JwksSource for CountingJwks {
    fn fetch<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Jwks, TransportError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let out = if url == "https://app.example.com/api/auth/jwks" {
            Ok(jwks(&self.body))
        } else {
            Err(TransportError::new("unexpected url"))
        };
        Box::pin(async move { out })
    }
}

#[tokio::test]
async fn fetches_the_old_key_set_by_url_and_caches_it() {
    let source = Arc::new(CountingJwks { body: keys().old_jwks.clone(), calls: AtomicUsize::new(0) });
    let b = AtlasBackend::builder(ATLAS)
        .static_jwks(jwks(&keys().atlas_jwks))
        .jwks_source(source.clone())
        .legacy_issuer(
            LegacyIssuer::new(OLD, now_ms() + 3_600_000)
                .jwks_url("https://app.example.com/api/auth/jwks")
                .resolve_subject(|_, _| Some("user_atlas_1".into())),
        )
        .build()
        .unwrap();
    for _ in 0..3 {
        assert_eq!(b.verify(&sign(Algorithm::EdDSA, "ed-1", &old_claims())).await.unwrap().sub, "user_atlas_1");
    }
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unreachable_old_keys_are_no_keys_and_azp_is_enforced() {
    struct Down;
    impl JwksSource for Down {
        fn fetch<'a>(&'a self, _url: &'a str) -> BoxFuture<'a, Result<Jwks, TransportError>> {
            Box::pin(async { Err(TransportError::new("down")) })
        }
    }
    let b = AtlasBackend::builder(ATLAS)
        .static_jwks(jwks(&keys().atlas_jwks))
        .jwks_source(Arc::new(Down))
        .legacy_issuer(
            LegacyIssuer::new(OLD, now_ms() + 3_600_000)
                .jwks_url("https://app.example.com/api/auth/jwks")
                .resolve_subject(|_, _| Some("u".into())),
        )
        .build()
        .unwrap();
    assert_eq!(b.verify(&sign(Algorithm::EdDSA, "ed-1", &old_claims())).await, Err(VerifyError::NoKeys));

    let azp = AtlasBackend::builder(ATLAS)
        .static_jwks(jwks(&keys().atlas_jwks))
        .authorized_parties(["https://app.example.com"])
        .legacy_issuer(issuer())
        .build()
        .unwrap();
    let mut wrong = old_claims();
    wrong["azp"] = json!("https://evil.example");
    assert_eq!(azp.verify(&sign(Algorithm::EdDSA, "ed-1", &wrong)).await, Err(VerifyError::UnauthorizedParty));
    assert!(azp.verify(&sign(Algorithm::EdDSA, "ed-1", &old_claims())).await.is_ok());
}

#[tokio::test]
async fn the_window_closes_on_the_injected_clock() {
    let t = Arc::new(AtomicU64::new(now_ms()));
    let t2 = t.clone();
    let clock: Clock = Arc::new(move || t2.load(Ordering::SeqCst));
    let b = AtlasBackend::builder(ATLAS)
        .static_jwks(jwks(&keys().atlas_jwks))
        .clock(clock)
        .legacy_issuer(issuer())
        .build()
        .unwrap();
    let token = sign(Algorithm::EdDSA, "ed-1", &old_claims());
    assert!(b.verify(&token).await.is_ok());
    t.store(now_ms() + 3_600_001, Ordering::SeqCst);
    assert_eq!(b.verify(&token).await, Err(VerifyError::Invalid));
}

#[cfg(feature = "backend")]
#[tokio::test]
async fn the_backend_resolver_looks_up_external_id_and_caches() {
    use atlasauth::backend::{BackendClient, FakeTransport};
    use atlasauth::{BackendSubjectResolver, HttpRequest, HttpResponse};

    let fake = FakeTransport::new(|req: &HttpRequest| {
        let body = if req.url.contains("external_id=ba_user_1") {
            r#"{"object":"list","data":[{"id":"user_atlas_9"}]}"#
        } else {
            r#"{"object":"list","data":[]}"#
        };
        HttpResponse { status: 200, body: body.into() }
    });
    let client = BackendClient::builder("sk_test_x").transport(Arc::new(fake.clone())).build().unwrap();
    let b = AtlasBackend::builder(ATLAS)
        .static_jwks(jwks(&keys().atlas_jwks))
        .legacy_subject_resolver(Arc::new(BackendSubjectResolver::new(client)))
        .legacy_issuer(LegacyIssuer::new(OLD, now_ms() + 3_600_000).jwks(jwks(&keys().old_jwks)))
        .build()
        .unwrap();
    let token = sign(Algorithm::EdDSA, "ed-1", &old_claims());
    assert_eq!(b.verify(&token).await.unwrap().sub, "user_atlas_9");
    assert_eq!(b.verify(&token).await.unwrap().sub, "user_atlas_9");
    let reqs = fake.requests();
    assert_eq!(reqs.len(), 1, "cached");
    assert!(reqs[0].url.contains("/v1/users?") && reqs[0].url.contains("limit=1"), "{}", reqs[0].url);
    assert!(reqs[0].headers.iter().any(|(k, v)| k == "authorization" && v == "Bearer sk_test_x"));

    let mut unknown = old_claims();
    unknown["sub"] = json!("ba_nobody");
    assert_eq!(b.verify(&sign(Algorithm::EdDSA, "ed-1", &unknown)).await, Err(VerifyError::Invalid));
}
