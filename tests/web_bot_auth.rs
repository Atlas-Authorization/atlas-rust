//! Web Bot Auth: RFC 9421 parsing, the signature base, signing and verification round trips, replay
//! protection, the directory cache and the allow / block decision.
#![cfg(feature = "web-bot-auth")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use atlasauth::web_bot_auth::*;
use atlasauth::BoxFuture;
use serde_json::{json, Value};

const SEED: [u8; 32] = [7u8; 32];
const AGENT: &str = "https://bot.example";
const URL: &str = "https://site.example/page?x=1";

struct Dir {
    keys: Option<Vec<WebBotAuthJwk>>,
    calls: AtomicUsize,
}

impl DirectoryKeys for Dir {
    fn get_keys<'a>(&'a self, _url: &'a str, _refresh: bool) -> BoxFuture<'a, Option<Vec<WebBotAuthJwk>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let k = self.keys.clone();
        Box::pin(async move { k })
    }
}

fn dir() -> Dir {
    Dir { keys: Some(vec![WebBotAuthJwk { x: public_key_x(&SEED) }]), calls: AtomicUsize::new(0) }
}

fn signed(created: i64, expires: i64, nonce: Option<&str>) -> WebBotAuthRequest {
    let mut input = SignWebBotAuthInput::new("GET", URL, AGENT, SEED, created, expires);
    input.nonce = nonce.map(str::to_string);
    WebBotAuthRequest::new("GET", URL, sign_web_bot_auth_request(&input).unwrap())
}

fn opts(now_ms: i64) -> WebBotAuthVerifyOptions {
    WebBotAuthVerifyOptions { now_ms: Some(now_ms), ..Default::default() }
}

#[tokio::test]
async fn a_signed_request_verifies_and_names_its_directory_and_key() {
    let req = signed(1_000, 1_300, Some("n1"));
    let r = verify_web_bot_auth(&req, &dir(), &opts(1_100_000)).await;
    assert!(r.verified && r.signed, "{:?}", r.reason);
    assert_eq!(r.directory.as_deref(), Some(AGENT));
    assert_eq!(r.key_id.unwrap(), ed25519_jwk_thumbprint(&public_key_x(&SEED)));
    assert_eq!(r.nonce.as_deref(), Some("n1"));
    assert_eq!(r.label.as_deref(), Some("sig1"));
}

#[tokio::test]
async fn an_unsigned_request_is_not_signed_and_a_tampered_one_fails() {
    let none = WebBotAuthRequest::new("GET", URL, []);
    let r = verify_web_bot_auth(&none, &dir(), &opts(1_100_000)).await;
    assert!(!r.signed && !r.verified);
    assert_eq!(r.reason, Some(WebBotAuthFailure::NoSignature));

    // The signature covers @authority: the same headers on another host do not verify.
    let mut req = signed(1_000, 1_300, None);
    req.url = "https://evil.example/page".into();
    assert_eq!(verify_web_bot_auth(&req, &dir(), &opts(1_100_000)).await.reason, Some(WebBotAuthFailure::BadSignature));

    // A different key in the directory: the keyid is not found.
    let other = Dir { keys: Some(vec![WebBotAuthJwk { x: public_key_x(&[9u8; 32]) }]), calls: AtomicUsize::new(0) };
    let r = verify_web_bot_auth(&signed(1_000, 1_300, None), &other, &opts(1_100_000)).await;
    assert_eq!(r.reason, Some(WebBotAuthFailure::KeyNotFound));
    assert_eq!(other.calls.load(Ordering::SeqCst), 2, "a miss asks for a refresh once");

    let gone = Dir { keys: None, calls: AtomicUsize::new(0) };
    assert_eq!(verify_web_bot_auth(&signed(1_000, 1_300, None), &gone, &opts(1_100_000)).await.reason, Some(WebBotAuthFailure::DirectoryUnavailable));

    // A flipped signature byte.
    let mut req = signed(1_000, 1_300, None);
    for (k, v) in req.headers.iter_mut() {
        if k == "signature" {
            let flipped = if v.contains("A") { v.replacen('A', "B", 1) } else { v.replacen('B', "A", 1) };
            *v = flipped;
        }
    }
    assert_eq!(verify_web_bot_auth(&req, &dir(), &opts(1_100_000)).await.reason, Some(WebBotAuthFailure::BadSignature));
}

#[tokio::test]
async fn the_time_window_and_lifetime_are_enforced() {
    let d = dir();
    // created=1000s, expires=1300s.
    assert_eq!(verify_web_bot_auth(&signed(1_000, 1_300, None), &d, &opts(700_000)).await.reason, Some(WebBotAuthFailure::NotYetValid));
    assert_eq!(verify_web_bot_auth(&signed(1_000, 1_300, None), &d, &opts(2_000_000)).await.reason, Some(WebBotAuthFailure::Expired));
    assert_eq!(verify_web_bot_auth(&signed(1_000, 9_000, None), &d, &opts(1_100_000)).await.reason, Some(WebBotAuthFailure::LifetimeTooLong));
    assert_eq!(verify_web_bot_auth(&signed(1_300, 1_000, None), &d, &opts(1_100_000)).await.reason, Some(WebBotAuthFailure::BadParams));
    // Inside the skew either side still passes.
    assert!(verify_web_bot_auth(&signed(1_000, 1_300, None), &d, &opts(1_320_000)).await.verified);
}

#[tokio::test]
async fn a_replayed_nonce_is_refused_when_a_claim_hook_is_given() {
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let s = seen.clone();
    let mut o = opts(1_100_000);
    o.claim_nonce = Some(Arc::new(move |key: &str, _| {
        let mut g = s.lock().unwrap();
        if g.iter().any(|k| k == key) {
            false
        } else {
            g.push(key.to_string());
            true
        }
    }));
    let req = signed(1_000, 1_300, Some("once"));
    let d = dir();
    assert!(verify_web_bot_auth(&req, &d, &o).await.verified);
    assert_eq!(verify_web_bot_auth(&req, &d, &o).await.reason, Some(WebBotAuthFailure::Replayed));
}

#[test]
fn signature_input_and_header_parse_with_parameters() {
    let inputs = parse_signature_input(r#"sig1=("@authority" "signature-agent";key="a" "@query-param";name="x");created=1;keyid="k";tag="web-bot-auth""#).unwrap();
    assert_eq!(inputs.len(), 1);
    let i = &inputs[0];
    assert_eq!(i.label, "sig1");
    assert_eq!(i.components.len(), 3);
    assert_eq!(i.components[1].params, vec![("key".to_string(), SfParam::Str("a".into()))]);
    assert!(i.params.contains(&("created".to_string(), SfParam::Int(1))));
    assert!(parse_signature_input("sig1=nonsense").is_none());
    assert!(parse_signature_input("=(\"a\")").is_none());

    let sigs = parse_signature_header("sig1=:AAEC:").unwrap();
    assert_eq!(sigs, vec![("sig1".to_string(), vec![0u8, 1, 2])]);
    assert!(parse_signature_header("sig1=AAEC").is_none());
}

#[test]
fn signature_agent_and_directory_are_normalised() {
    assert_eq!(parse_signature_agent("\"https://bot.example/\"", None).as_deref(), Some("https://bot.example"));
    assert_eq!(parse_signature_agent("bot.example", None).as_deref(), Some("https://bot.example"));
    assert_eq!(parse_signature_agent("sig1=\"https://a.example\", sig2=\"https://b.example\"", Some("sig2")).as_deref(), Some("https://b.example"));
    assert_eq!(parse_signature_agent("sig1=\"https://a.example\"", Some("other")).as_deref(), Some("https://a.example"));
    assert!(parse_signature_agent("http://bot.example", None).is_none());
    assert!(parse_signature_agent("https://user:pw@bot.example", None).is_none());
    assert!(parse_signature_agent("https://bot.example/?q=1", None).is_none());
    assert_eq!(normalize_directory("https://bot.example:8443/dir/").as_deref(), Some("https://bot.example:8443/dir"));
    assert_eq!(directory_url_for("https://bot.example"), "https://bot.example/.well-known/http-message-signatures-directory");
}

#[test]
fn the_signature_base_follows_rfc_9421() {
    let req = WebBotAuthRequest::new(
        "get",
        "https://Example.com:8443/a/b?x=1&y=a%20b",
        [("Signature-Agent".to_string(), "\"https://bot.example\"".to_string()), ("Dict".to_string(), "a=1,  b=(1   2)".to_string())],
    );
    let comps = vec![
        WebBotAuthComponent::new("@method"),
        WebBotAuthComponent::new("@authority"),
        WebBotAuthComponent::new("@path"),
        WebBotAuthComponent::new("@query"),
        WebBotAuthComponent::new("@query-param").with_param("name", SfParam::Str("y".into())),
        WebBotAuthComponent::new("signature-agent"),
        WebBotAuthComponent::new("dict").with_param("key", SfParam::Str("b".into())),
    ];
    let base = build_signature_base(&req, &comps, "(...)").unwrap();
    let lines: Vec<&str> = base.lines().collect();
    assert_eq!(lines[0], "\"@method\": GET");
    assert_eq!(lines[1], "\"@authority\": example.com:8443");
    assert_eq!(lines[2], "\"@path\": /a/b");
    assert_eq!(lines[3], "\"@query\": ?x=1&y=a%20b");
    assert_eq!(lines[4], "\"@query-param\";name=\"y\": a%20b");
    assert_eq!(lines[5], "\"signature-agent\": \"https://bot.example\"");
    assert_eq!(lines[6], "\"dict\";key=\"b\": (1 2)");
    assert_eq!(lines[7], "\"@signature-params\": (...)");

    assert_eq!(build_signature_base(&req, &[WebBotAuthComponent::new("x-missing")], "()"), Err(BaseError::ComponentMissing));
    assert_eq!(build_signature_base(&req, &[WebBotAuthComponent::new("@bogus")], "()"), Err(BaseError::UnsupportedComponent));
    assert_eq!(build_signature_base(&req, &[WebBotAuthComponent::new("@method"), WebBotAuthComponent::new("@method")], "()"), Err(BaseError::UnsupportedComponent));
    assert_eq!(build_signature_base(&req, &[WebBotAuthComponent::new("Signature-Agent")], "()"), Err(BaseError::UnsupportedComponent));
}

#[test]
fn the_sf_and_bs_parameters_serialise_canonically() {
    let req = WebBotAuthRequest::new("GET", URL, [("x-list".to_string(), "1,   2 , \"a\"".to_string())]);
    let sf = WebBotAuthComponent::new("x-list").with_param("sf", SfParam::Bool(true));
    assert_eq!(build_signature_base(&req, &[sf], "()").unwrap().lines().next().unwrap(), "\"x-list\";sf: 1, 2, \"a\"");
    let bs = WebBotAuthComponent::new("x-list").with_param("bs", SfParam::Bool(true));
    assert!(build_signature_base(&req, &[bs], "()").unwrap().starts_with("\"x-list\";bs: :"));
}

#[test]
fn a_directory_document_keeps_only_well_formed_ed25519_keys() {
    let x = public_key_x(&SEED);
    let doc = json!({ "keys": [
        { "kty": "OKP", "crv": "Ed25519", "x": x },
        { "kty": "RSA", "n": "AQAB", "e": "AQAB" },
        { "kty": "OKP", "crv": "Ed25519", "x": "short" } ] });
    let keys = parse_directory(&doc);
    assert_eq!(keys, vec![WebBotAuthJwk { x }]);
    assert!(parse_directory(&Value::Null).is_empty());
}

struct Fetch {
    doc: Option<Value>,
    calls: Arc<AtomicUsize>,
}

impl DirectoryFetcher for Fetch {
    fn fetch_json<'a>(&'a self, _url: &'a str) -> BoxFuture<'a, Option<Value>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let d = self.doc.clone();
        Box::pin(async move { d })
    }
}

#[tokio::test]
async fn the_directory_cache_serves_from_memory_throttles_refreshes_and_keeps_a_good_copy() {
    let calls = Arc::new(AtomicUsize::new(0));
    let doc = json!({ "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": public_key_x(&SEED) }] });
    let now = Arc::new(std::sync::atomic::AtomicU64::new(1_000_000));
    let n = now.clone();
    let cache = WebBotAuthDirectoryCache::new(Fetch { doc: Some(doc), calls: calls.clone() }).with_clock(Arc::new(move || n.load(Ordering::SeqCst)));
    assert!(cache.get_keys("u", false).await.is_some());
    assert!(cache.get_keys("u", false).await.is_some());
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the second read is cached");
    assert!(cache.get_keys("u", true).await.is_some());
    assert_eq!(calls.load(Ordering::SeqCst), 1, "a refresh inside the cooldown is refused");
    now.fetch_add(61_000, Ordering::SeqCst);
    assert!(cache.get_keys("u", true).await.is_some());
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // A directory that goes away keeps serving the last good copy.
    let broken = Arc::new(AtomicUsize::new(0));
    let cache2 = WebBotAuthDirectoryCache::new(Fetch { doc: None, calls: broken.clone() });
    assert!(cache2.get_keys("u", false).await.is_none(), "never fetched, nothing to serve");
}

#[test]
fn decisions_only_trust_a_verified_directory_and_a_block_beats_an_allow() {
    let verified = WebBotAuthResult { signed: true, verified: true, directory: Some(AGENT.into()), key_id: Some("k".into()), ..Default::default() };
    let entry = |name: Option<&str>| WebBotAuthListEntry { directory: "bot.example".into(), name: name.map(str::to_string) };
    let allow = WebBotAuthPolicy { allow: vec![entry(Some("Friendly bot"))], block: vec![] };
    let d = decide_web_bot_auth(&verified, &allow);
    assert_eq!((d.tier, d.decision), (WebBotAuthTier::Allowed, WebBotAuthDecisionKind::Allow));
    assert_eq!(d.agent.unwrap().name, "Friendly bot");
    let both = WebBotAuthPolicy { allow: vec![entry(None)], block: vec![entry(None)] };
    let d = decide_web_bot_auth(&verified, &both);
    assert_eq!((d.tier, d.decision), (WebBotAuthTier::Blocked, WebBotAuthDecisionKind::Block));
    assert_eq!(d.agent.unwrap().name, "bot.example");
    let none = decide_web_bot_auth(&verified, &WebBotAuthPolicy::default());
    assert_eq!((none.tier, none.decision), (WebBotAuthTier::Verified, WebBotAuthDecisionKind::Unknown));

    let failed = WebBotAuthResult { signed: true, verified: false, reason: Some(WebBotAuthFailure::BadSignature), directory: Some(AGENT.into()), ..Default::default() };
    let d = decide_web_bot_auth(&failed, &both);
    assert_eq!((d.tier, d.decision), (WebBotAuthTier::Unverified, WebBotAuthDecisionKind::Unknown));
    assert!(d.agent.is_none(), "a failed claim is never attributed to the directory it named");
    assert_eq!(d.reason, Some(WebBotAuthFailure::BadSignature));
}

#[tokio::test]
async fn the_local_verifier_ties_it_together_and_can_reject_replays() {
    let doc = json!({ "keys": [{ "kty": "OKP", "crv": "Ed25519", "x": public_key_x(&SEED) }] });
    let now_ms = 1_100_000u64;
    let opts = WebBotAuthVerifierOptions {
        policy: WebBotAuthPolicy { allow: vec![WebBotAuthListEntry { directory: AGENT.into(), name: None }], block: vec![] },
        reject_replays: true,
        ..Default::default()
    };
    let v = WebBotAuthVerifier::new(Fetch { doc: Some(doc), calls: Arc::new(AtomicUsize::new(0)) }, opts).with_clock(Arc::new(move || now_ms));
    let req = signed(1_000, 1_300, Some("n"));
    let first = v.verify(&req).await;
    assert!(first.verified && first.decision == WebBotAuthDecisionKind::Allow);
    let second = v.verify(&req).await;
    assert!(!second.verified);
    assert_eq!(second.reason, Some(WebBotAuthFailure::Replayed));
}
