//! `doctor`: check an Atlas integration from the machine it runs on (feature `backend`).
//!
//! It verifies the shape of your keys, the clock against the API's `Date` header (token times are checked with
//! a few seconds of leeway), that the JWKS is reachable and holds usable keys, the public service status, and
//! that your secret key is accepted. Every check reports `Pass`, `Warn`, `Fail` or `Skip` with a message; the
//! report never contains a key.
//!
//! ```no_run
//! # async fn demo(transport: std::sync::Arc<dyn atlasauth::HttpTransport>) {
//! use atlasauth::doctor::{run, DoctorOptions};
//! let report = run(&DoctorOptions::new(transport)
//!     .secret_key("sk_live_...")
//!     .issuer("https://auth.example.com")).await;
//! println!("{report}");
//! assert!(report.ok());
//! # }
//! ```

use std::fmt;
use std::sync::Arc;

use serde_json::Value;

use crate::backend::resilience_support::{http_date_to_epoch, local_now_seconds};
use crate::http::{HttpMethod, HttpRequest, HttpTransport};
use crate::jwks::Jwks;
use crate::key_format::{parse_key_prefix, KeyKind};
use crate::verify::CLOCK_SKEW_SECONDS;

/// The outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorStatus {
    Pass,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    pub name: &'static str,
    pub status: DoctorStatus,
    pub message: String,
}

/// Every check, in the order they ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    /// No check failed (warnings are allowed).
    pub fn ok(&self) -> bool {
        !self.checks.iter().any(|c| c.status == DoctorStatus::Fail)
    }
}

impl fmt::Display for DoctorReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in &self.checks {
            let tag = match c.status {
                DoctorStatus::Pass => "PASS",
                DoctorStatus::Warn => "WARN",
                DoctorStatus::Fail => "FAIL",
                DoctorStatus::Skip => "SKIP",
            };
            writeln!(f, "[{tag}] {}: {}", c.name, c.message)?;
        }
        Ok(())
    }
}

/// What to check.
#[derive(Clone)]
pub struct DoctorOptions {
    pub transport: Arc<dyn HttpTransport>,
    /// The Backend API origin. Default `https://api.atlasauth.net`.
    pub api_url: String,
    pub secret_key: Option<String>,
    pub publishable_key: Option<String>,
    pub webhook_secret: Option<String>,
    /// The instance issuer (`https://` + its frontend API host); the JWKS defaults to `{issuer}/.well-known/jwks.json`.
    pub issuer: Option<String>,
    pub jwks_url: Option<String>,
    /// Clock skew (seconds) past which the clock check fails. Default 60.
    pub max_skew_seconds: i64,
}

impl DoctorOptions {
    pub fn new(transport: Arc<dyn HttpTransport>) -> Self {
        DoctorOptions {
            transport,
            api_url: "https://api.atlasauth.net".into(),
            secret_key: None,
            publishable_key: None,
            webhook_secret: None,
            issuer: None,
            jwks_url: None,
            max_skew_seconds: 60,
        }
    }
    pub fn api_url(mut self, v: impl Into<String>) -> Self {
        self.api_url = v.into();
        self
    }
    pub fn secret_key(mut self, v: impl Into<String>) -> Self {
        self.secret_key = Some(v.into());
        self
    }
    pub fn publishable_key(mut self, v: impl Into<String>) -> Self {
        self.publishable_key = Some(v.into());
        self
    }
    pub fn webhook_secret(mut self, v: impl Into<String>) -> Self {
        self.webhook_secret = Some(v.into());
        self
    }
    pub fn issuer(mut self, v: impl Into<String>) -> Self {
        self.issuer = Some(v.into());
        self
    }
    pub fn jwks_url(mut self, v: impl Into<String>) -> Self {
        self.jwks_url = Some(v.into());
        self
    }
}

fn check(name: &'static str, status: DoctorStatus, message: impl Into<String>) -> DoctorCheck {
    DoctorCheck { name, status, message: message.into() }
}

fn env_of(key: &str) -> Option<&'static str> {
    parse_key_prefix(key).and_then(|p| p.environment)
}

fn key_checks(o: &DoctorOptions) -> DoctorCheck {
    let mut problems: Vec<String> = Vec::new();
    let mut envs: Vec<&'static str> = Vec::new();
    let mut seen = 0;
    let mut want = |value: &Option<String>, label: &str, kinds: &[KeyKind]| {
        if let Some(v) = value {
            seen += 1;
            match parse_key_prefix(v) {
                Some(p) if kinds.contains(&p.kind) => envs.extend(env_of(v)),
                _ => problems.push(format!("the {label} does not look like one")),
            }
        }
    };
    want(&o.secret_key, "secret key (sk_...)", &[KeyKind::Secret, KeyKind::Platform]);
    want(&o.publishable_key, "publishable key (pk_...)", &[KeyKind::Publishable]);
    want(&o.webhook_secret, "webhook secret (whsec_...)", &[KeyKind::WebhookSecret]);
    if seen == 0 {
        return check("keys", DoctorStatus::Skip, "no keys given");
    }
    if !problems.is_empty() {
        return check("keys", DoctorStatus::Fail, problems.join("; "));
    }
    if envs.iter().any(|e| *e != envs[0]) {
        return check("keys", DoctorStatus::Warn, "the keys mix live and test environments");
    }
    check("keys", DoctorStatus::Pass, format!("{seen} key(s) well formed{}", envs.first().map(|e| format!(" ({e})")).unwrap_or_default()))
}

/// Run every check that has what it needs. Never fails the call itself: a check that cannot run is `Skip`.
pub async fn run(o: &DoctorOptions) -> DoctorReport {
    let mut checks = vec![key_checks(o)];
    let base = o.api_url.trim_end_matches('/').to_string();

    // Service status, and the API's own clock from its Date header.
    let status_req = HttpRequest::new(HttpMethod::Get, format!("{base}/v1/status")).header("accept", "application/json");
    match o.transport.send_full(status_req, None).await {
        Err(e) => {
            checks.push(check("api", DoctorStatus::Fail, format!("the API is unreachable: {}", e.0)));
            checks.push(check("clock", DoctorStatus::Skip, "the API is unreachable"));
            checks.push(check("status", DoctorStatus::Skip, "the API is unreachable"));
        }
        Ok(resp) => {
            checks.push(check("api", DoctorStatus::Pass, format!("{base} answered {}", resp.status)));
            match resp.header("date").and_then(http_date_to_epoch) {
                None => checks.push(check("clock", DoctorStatus::Skip, "the API sent no usable Date header")),
                Some(server) => {
                    let skew = local_now_seconds() - server;
                    let status = if skew.abs() > o.max_skew_seconds {
                        DoctorStatus::Fail
                    } else if skew.abs() > CLOCK_SKEW_SECONDS as i64 {
                        DoctorStatus::Warn
                    } else {
                        DoctorStatus::Pass
                    };
                    checks.push(check("clock", status, format!("this machine is {skew}s {} the API (token checks allow {CLOCK_SKEW_SECONDS}s)", if skew >= 0 { "ahead of" } else { "behind" })));
                }
            }
            let body: Value = serde_json::from_str(&resp.body).unwrap_or(Value::Null);
            checks.push(match body.get("status").and_then(Value::as_str) {
                Some("operational") => check("status", DoctorStatus::Pass, "all systems operational"),
                Some("degraded") => check("status", DoctorStatus::Warn, "Atlas reports degraded service"),
                Some("major_outage") => check("status", DoctorStatus::Fail, "Atlas reports a major outage"),
                _ => check("status", DoctorStatus::Skip, "the status answer was not understood"),
            });
        }
    }

    // JWKS reachability.
    let jwks_url = o.jwks_url.clone().or_else(|| o.issuer.as_ref().map(|i| format!("{}/.well-known/jwks.json", i.trim_end_matches('/'))));
    checks.push(match jwks_url {
        None => check("jwks", DoctorStatus::Skip, "no issuer or jwks_url given"),
        Some(url) => match o.transport.send(HttpRequest::new(HttpMethod::Get, url.clone()).header("accept", "application/json")).await {
            Err(e) => check("jwks", DoctorStatus::Fail, format!("{url} is unreachable: {}", e.0)),
            Ok(r) if !(200..300).contains(&r.status) => check("jwks", DoctorStatus::Fail, format!("{url} answered {}", r.status)),
            Ok(r) => match serde_json::from_str::<Jwks>(&r.body) {
                Err(_) => check("jwks", DoctorStatus::Fail, format!("{url} is not a JWKS")),
                Ok(set) => {
                    let usable = set.keys.iter().filter(|k| k.signing_alg().is_some()).count();
                    if usable == 0 {
                        check("jwks", DoctorStatus::Fail, format!("{url} holds no key this SDK can verify with"))
                    } else {
                        check("jwks", DoctorStatus::Pass, format!("{usable} usable signing key(s)"))
                    }
                }
            },
        },
    });

    // Config: https, and a secret key the API accepts.
    let mut cfg_problems = Vec::new();
    for (label, url) in [("api_url", Some(&o.api_url)), ("issuer", o.issuer.as_ref()), ("jwks_url", o.jwks_url.as_ref())] {
        if let Some(u) = url.filter(|u| !u.starts_with("https://") && !u.starts_with("http://localhost") && !u.starts_with("http://127.0.0.1")) {
            cfg_problems.push(format!("{label} {u} is not https"));
        }
    }
    checks.push(if cfg_problems.is_empty() { check("config", DoctorStatus::Pass, "URLs are https") } else { check("config", DoctorStatus::Fail, cfg_problems.join("; ")) });

    checks.push(match &o.secret_key {
        None => check("secret_key", DoctorStatus::Skip, "no secret key given"),
        Some(k) => {
            let req = HttpRequest::new(HttpMethod::Get, format!("{base}/v1/instance")).header("authorization", format!("Bearer {k}")).header("accept", "application/json");
            match o.transport.send(req).await {
                Err(e) => check("secret_key", DoctorStatus::Fail, format!("could not reach the API: {}", e.0)),
                Ok(r) if r.status == 401 => check("secret_key", DoctorStatus::Fail, "the API rejected the secret key (401): wrong key, revoked, or another instance"),
                Ok(r) if r.status == 403 => check("secret_key", DoctorStatus::Warn, "the key is valid but lacks a scope to read the instance (403)"),
                Ok(r) if (200..300).contains(&r.status) => check("secret_key", DoctorStatus::Pass, "the API accepted the secret key"),
                Ok(r) => check("secret_key", DoctorStatus::Warn, format!("the API answered {}", r.status)),
            }
        }
    });
    DoctorReport { checks }
}
