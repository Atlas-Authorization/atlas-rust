//! Atlas credential formats.
//!
//! Atlas keys come in two formats. The suite format is
//! `atlas_<live|test>_<kind>_<random><checksum>` (`sk`, `psk`, `dsk`, `whsec`,
//! `pl`, `at`); the legacy format is `sk_live_…`, `sk_test_…`, `pk_…`,
//! `psk_…`, `whsec_…` and `dsk_…`. Any prefix check in your code must accept
//! both, which is what these helpers do. They look at the prefix only: no
//! checksum is validated and Atlas is not contacted.

/// What a credential is, by its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// An instance secret key (`sk`).
    Secret,
    /// A platform key (`psk`).
    Platform,
    /// A publishable key (`pk`); has no suite form.
    Publishable,
    /// A deploy key (`dsk`).
    Deploy,
    /// A webhook signing secret (`whsec`).
    WebhookSecret,
    /// A partner-link secret (`pl`); suite format only.
    PartnerLink,
    /// A one-hour access token from an operator token exchange (`at`);
    /// suite format only.
    AccessToken,
}

/// What [`parse_key_prefix`] learned from a credential's prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedKey {
    /// The kind of credential.
    pub kind: KeyKind,
    /// `"live"`, `"test"`, or `None` when the key carries no environment.
    pub environment: Option<&'static str>,
    /// `true` for the `atlas_<env>_<kind>_…` format, `false` for legacy.
    pub suite: bool,
}

fn env_of(s: &str) -> Option<&'static str> {
    match s {
        "live" => Some("live"),
        "test" => Some("test"),
        _ => None,
    }
}

/// Classify a credential by its prefix, accepting the suite format
/// (`atlas_live_sk_…`) and the legacy one (`sk_live_…`, `pk_test_…`, `psk_…`,
/// `whsec_…`). `None` for anything else.
pub fn parse_key_prefix(key: &str) -> Option<ParsedKey> {
    if let Some(rest) = key.strip_prefix("atlas_") {
        let mut parts = rest.splitn(3, '_');
        let env = env_of(parts.next()?)?;
        let kind = match parts.next()? {
            "sk" => KeyKind::Secret,
            "psk" => KeyKind::Platform,
            "dsk" => KeyKind::Deploy,
            "whsec" => KeyKind::WebhookSecret,
            "pl" => KeyKind::PartnerLink,
            "at" => KeyKind::AccessToken,
            _ => return None,
        };
        // The random part must be present.
        parts.next()?;
        return Some(ParsedKey { kind, environment: Some(env), suite: true });
    }
    let parts: Vec<&str> = key.splitn(3, '_').collect();
    if parts.len() < 2 {
        return None;
    }
    match parts[0] {
        "sk" | "pk" => {
            if parts.len() == 3 {
                if let Some(env) = env_of(parts[1]) {
                    let kind = if parts[0] == "sk" { KeyKind::Secret } else { KeyKind::Publishable };
                    return Some(ParsedKey { kind, environment: Some(env), suite: false });
                }
            }
            None
        }
        "psk" | "dsk" | "whsec" => {
            let kind = match parts[0] {
                "psk" => KeyKind::Platform,
                "dsk" => KeyKind::Deploy,
                _ => KeyKind::WebhookSecret,
            };
            let environment = if parts.len() == 3 { env_of(parts[1]) } else { None };
            Some(ParsedKey { kind, environment, suite: false })
        }
        _ => None,
    }
}

fn is_kind(key: &str, kind: KeyKind) -> bool {
    parse_key_prefix(key).map(|p| p.kind == kind).unwrap_or(false)
}

/// Whether `key` is an instance secret key in either format
/// (`atlas_live_sk_…` or `sk_live_…`).
pub fn is_secret_key(key: &str) -> bool {
    is_kind(key, KeyKind::Secret)
}

/// Whether `key` is a platform key in either format (`atlas_live_psk_…` or
/// `psk_…`).
pub fn is_platform_key(key: &str) -> bool {
    is_kind(key, KeyKind::Platform)
}

/// Whether `key` is a publishable key (`pk_live_…` / `pk_test_…`).
pub fn is_publishable_key(key: &str) -> bool {
    is_kind(key, KeyKind::Publishable)
}

/// Whether `key` is a webhook signing secret in either format
/// (`atlas_live_whsec_…` or `whsec_…`). Webhook verification is unchanged: the
/// whole string is the HMAC key.
pub fn is_webhook_secret(key: &str) -> bool {
    is_kind(key, KeyKind::WebhookSecret)
}

/// Whether `key` is a partner-link secret (`atlas_live_pl_…`).
pub fn is_partner_link_secret(key: &str) -> bool {
    is_kind(key, KeyKind::PartnerLink)
}

/// Whether `key` is a one-hour Atlas access token from an operator token
/// exchange (`atlas_live_at_…`).
pub fn is_access_token(key: &str) -> bool {
    is_kind(key, KeyKind::AccessToken)
}
