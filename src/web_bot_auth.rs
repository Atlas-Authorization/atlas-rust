//! Web Bot Auth: verify who is behind an automated request (feature `web-bot-auth`).
//!
//! A bot signs its requests with an Ed25519 key (RFC 9421 HTTP Message Signatures, tag `web-bot-auth`) and
//! names the place its public keys live in the `Signature-Agent` header. The key is found in the directory
//! served at `<Signature-Agent>/.well-known/http-message-signatures-directory`, and the signature's `keyid`
//! is the RFC 7638 JWK thumbprint of that key. The Rust peer of the TypeScript verifier: the same parsing,
//! the same signature base, the same failure reasons.
//!
//! Fetching a directory is injected ([`DirectoryFetcher`]) so each caller brings its own network policy; the
//! built-in [`TransportDirectoryFetcher`] refuses non-https and literal / single-label hosts and caps the
//! body at 64 KB, but a fetcher you pass must refuse private addresses itself (resolve once, connect to the
//! vetted address only, never follow a redirect).
//!
//! ```no_run
//! # async fn demo(transport: std::sync::Arc<dyn atlasauth::HttpTransport>) {
//! use atlasauth::web_bot_auth::{TransportDirectoryFetcher, WebBotAuthRequest, WebBotAuthVerifier, WebBotAuthVerifierOptions};
//!
//! let verifier = WebBotAuthVerifier::new(TransportDirectoryFetcher::new(transport), WebBotAuthVerifierOptions::default());
//! let req = WebBotAuthRequest::new("GET", "https://site.example/page", [("signature-input".into(), "...".into())]);
//! let decision = verifier.verify(&req).await;
//! if decision.verified { /* decision.agent names the bot */ }
//! # }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD, URL_SAFE_NO_PAD};
use base64::engine::DecodePaddingMode;
use base64::{alphabet, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::clock::{system_clock, Clock};
use crate::http::{encode_segment, HttpMethod, HttpRequest, HttpTransport};
use crate::jwks::BoxFuture;

pub const WEB_BOT_AUTH_TAG: &str = "web-bot-auth";
pub const WEB_BOT_AUTH_DIRECTORY_PATH: &str = "/.well-known/http-message-signatures-directory";
pub const WEB_BOT_AUTH_DIRECTORY_MEDIA_TYPE: &str = "application/http-message-signatures-directory+json";
/// Clock skew tolerated on `created` and `expires`, in seconds.
pub const WEB_BOT_AUTH_DEFAULT_SKEW_SECONDS: i64 = 30;
/// The longest `expires - created` accepted, in seconds.
pub const WEB_BOT_AUTH_DEFAULT_MAX_LIFETIME_SECONDS: i64 = 3600;
const DIRECTORY_MAX_BYTES: usize = 64 * 1024;

// ── encoding helpers ────────────────────────────────────────────────────────

const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent).with_decode_allow_trailing_bits(true),
);

fn base64_to_bytes(input: &str) -> Option<Vec<u8>> {
    let body = input.trim_end_matches('=');
    let padding = input.len() - body.len();
    if padding > 2 || !body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/') {
        return None;
    }
    LENIENT.decode(body).ok()
}

/// Decode base64url (no padding), or `None` when the text is not base64url.
pub fn base64url_to_bytes(input: &str) -> Option<Vec<u8>> {
    if !input.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return None;
    }
    base64_to_bytes(&input.replace('-', "+").replace('_', "/"))
}

fn sl(text: &str, a: usize, b: usize) -> &str {
    text.get(a..b).unwrap_or("")
}

// ── JWKs and thumbprints ────────────────────────────────────────────────────

/// An Ed25519 public key as a JWK (`kty` `OKP`, `crv` `Ed25519`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBotAuthJwk {
    /// The base64url public key.
    pub x: String,
}

/// RFC 7638 thumbprint (base64url SHA-256) of an Ed25519 public JWK: the web-bot-auth `keyid`.
pub fn ed25519_jwk_thumbprint(x: &str) -> String {
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

/// The raw 32-byte public key of a JWK, or `None` when it is not a well-formed Ed25519 key.
pub fn ed25519_jwk_bytes(jwk: &Value) -> Option<[u8; 32]> {
    if jwk.get("kty").and_then(Value::as_str) != Some("OKP") || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519") {
        return None;
    }
    let bytes = base64url_to_bytes(jwk.get("x")?.as_str()?)?;
    bytes.try_into().ok()
}

/// Pick the usable Ed25519 keys out of a directory document (a JWK Set). At most 20 are kept.
pub fn parse_directory(doc: &Value) -> Vec<WebBotAuthJwk> {
    doc.get("keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|k| ed25519_jwk_bytes(k).is_some())
        .filter_map(|k| k.get("x").and_then(Value::as_str).map(|x| WebBotAuthJwk { x: x.to_string() }))
        .take(20)
        .collect()
}

// ── structured fields (the subset RFC 9421 headers use) ─────────────────────

/// A structured-field parameter value.
#[derive(Debug, Clone, PartialEq)]
pub enum SfParam {
    /// A string or a token (the two compare alike here, as in the reference verifier).
    Str(String),
    Int(i64),
    Dec(f64),
    Bool(bool),
    Bytes(Vec<u8>),
}

type SfParams = Vec<(String, SfParam)>;

fn key_ok(k: &str) -> bool {
    let mut c = k.chars();
    matches!(c.next(), Some(f) if f.is_ascii_lowercase() || f == '*') && c.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.*-".contains(c))
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b":/!#$%&'*+-.^_`|~".contains(&b)
}

/// Split on `sep` outside of strings and parentheses.
fn split_top(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let (mut depth, mut quoted, mut start) = (0i32, false, 0usize);
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        if quoted {
            if c == '\\' {
                chars.next();
            } else if c == '"' {
                quoted = false;
            }
        } else if c == '"' {
            quoted = true;
        } else if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
        } else if c == sep && depth == 0 {
            out.push(sl(s, start, i).to_string());
            start = i + c.len_utf8();
        }
    }
    out.push(sl(s, start, s.len()).to_string());
    out.into_iter().map(|m| m.trim().to_string()).filter(|m| !m.is_empty()).collect()
}

/// Read a quoted sf-string starting at `i` (which must be the opening quote): `(value, end)`.
fn read_string(s: &str, i: usize) -> Option<(String, usize)> {
    let b = s.as_bytes();
    if b.get(i) != Some(&b'"') {
        return None;
    }
    let mut out = String::new();
    let mut j = i + 1;
    while j < b.len() {
        let c = b[j];
        if c == b'\\' {
            let n = *b.get(j + 1)?;
            if n != b'"' && n != b'\\' {
                return None;
            }
            out.push(n as char);
            j += 2;
            continue;
        } else if c == b'"' {
            return Some((out, j + 1));
        } else if !(0x20..=0x7e).contains(&c) {
            return None;
        }
        out.push(c as char);
        j += 1;
    }
    None
}

/// Parse `;k=v;k2` (possibly empty). `None` when malformed.
fn parse_params(text: &str) -> Option<SfParams> {
    let b = text.as_bytes();
    let mut out: SfParams = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b';' {
            return None;
        }
        i += 1;
        let mut key = String::new();
        while i < b.len() && (b[i].is_ascii_lowercase() || b[i].is_ascii_digit() || b"_.*-".contains(&b[i])) {
            key.push(b[i] as char);
            i += 1;
        }
        if !key_ok(&key) {
            return None;
        }
        if b.get(i) != Some(&b'=') {
            out.push((key, SfParam::Bool(true)));
            continue;
        }
        i += 1;
        let value = match b.get(i) {
            Some(b'"') => {
                let (v, end) = read_string(text, i)?;
                i = end;
                SfParam::Str(v)
            }
            Some(b':') => {
                let close = i + 1 + text.get(i + 1..)?.find(':')?;
                let bytes = base64_to_bytes(sl(text, i + 1, close))?;
                i = close + 1;
                SfParam::Bytes(bytes)
            }
            Some(b'?') => {
                let v = match sl(text, i, i + 2) {
                    "?0" => false,
                    "?1" => true,
                    _ => return None,
                };
                i += 2;
                SfParam::Bool(v)
            }
            Some(c) if c.is_ascii_digit() || *c == b'-' => {
                let mut n = String::new();
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.' || b[i] == b'-') {
                    n.push(b[i] as char);
                    i += 1;
                }
                let (int_part, frac) = match n.split_once('.') {
                    Some((a, f)) => (a, Some(f)),
                    None => (n.as_str(), None),
                };
                let digits = int_part.trim_start_matches('-');
                if digits.is_empty() || digits.len() > 15 || !digits.bytes().all(|d| d.is_ascii_digit()) || int_part.matches('-').count() > 1 || (int_part.contains('-') && !int_part.starts_with('-')) {
                    return None;
                }
                match frac {
                    None => SfParam::Int(n.parse().ok()?),
                    Some(f) if (1..=3).contains(&f.len()) && f.bytes().all(|d| d.is_ascii_digit()) => SfParam::Dec(n.parse().ok()?),
                    Some(_) => return None,
                }
            }
            Some(c) if c.is_ascii_alphabetic() || *c == b'*' => {
                let mut t = String::new();
                while i < b.len() && is_token_char(b[i]) {
                    t.push(b[i] as char);
                    i += 1;
                }
                SfParam::Str(t)
            }
            _ => return None,
        };
        out.push((key, value));
    }
    Some(out)
}

fn param<'a>(p: &'a SfParams, k: &str) -> Option<&'a SfParam> {
    p.iter().find(|(name, _)| name == k).map(|(_, v)| v)
}

fn param_str<'a>(p: &'a SfParams, k: &str) -> Option<&'a str> {
    match param(p, k) {
        Some(SfParam::Str(s)) => Some(s.as_str()),
        _ => None,
    }
}

/// A covered component: a header name or derived component, with its RFC 9421 parameters (`sf`, `key`, `bs`, `name`).
#[derive(Debug, Clone, PartialEq)]
pub struct WebBotAuthComponent {
    pub name: String,
    pub params: Vec<(String, SfParam)>,
}

impl WebBotAuthComponent {
    pub fn new(name: impl Into<String>) -> Self {
        WebBotAuthComponent { name: name.into(), params: Vec::new() }
    }
    pub fn with_param(mut self, key: impl Into<String>, value: SfParam) -> Self {
        self.params.push((key.into(), value));
        self
    }
}

/// A parsed `Signature-Input` member.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedSignatureInput {
    pub label: String,
    pub components: Vec<WebBotAuthComponent>,
    pub params: Vec<(String, SfParam)>,
    /// The inner list and its parameters exactly as sent: the `@signature-params` value.
    pub raw: String,
}

/// Parse a `Signature-Input` field. `None` when any member is malformed.
pub fn parse_signature_input(header: &str) -> Option<Vec<ParsedSignatureInput>> {
    let mut out = Vec::new();
    for member in split_top(header, ',') {
        let eq = member.find('=')?;
        if eq == 0 {
            return None;
        }
        let label = member[..eq].trim().to_string();
        let raw = member[eq + 1..].trim().to_string();
        if !key_ok(&label) || !raw.starts_with('(') {
            return None;
        }
        let rb = raw.as_bytes();
        let (mut close, mut quoted, mut i) = (None, false, 1);
        while i < rb.len() {
            let c = rb[i];
            if quoted {
                if c == b'\\' {
                    i += 1;
                } else if c == b'"' {
                    quoted = false;
                }
            } else if c == b'"' {
                quoted = true;
            } else if c == b')' {
                close = Some(i);
                break;
            }
            i += 1;
        }
        let close = close?;
        let inner = sl(&raw, 1, close);
        let ib = inner.as_bytes();
        let mut components = Vec::new();
        let mut i = 0;
        while i < ib.len() {
            if ib[i] == b' ' {
                i += 1;
                continue;
            }
            let (name, end) = read_string(inner, i)?;
            i = end;
            let mut ptext = String::new();
            while i < ib.len() && ib[i] != b' ' {
                if ib[i] == b'"' {
                    let (_, q) = read_string(inner, i)?;
                    ptext.push_str(sl(inner, i, q));
                    i = q;
                } else {
                    ptext.push(ib[i] as char);
                    i += 1;
                }
            }
            components.push(WebBotAuthComponent { name, params: parse_params(&ptext)? });
        }
        let params = parse_params(sl(&raw, close + 1, raw.len()))?;
        out.push(ParsedSignatureInput { label, components, params, raw });
    }
    (!out.is_empty()).then_some(out)
}

/// Parse a `Signature` field into `(label, signature bytes)` members. `None` when malformed.
pub fn parse_signature_header(header: &str) -> Option<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for member in split_top(header, ',') {
        let (label, rest) = member.split_once('=')?;
        let inner = rest.strip_prefix(':')?.strip_suffix(':')?;
        if !key_ok(label) || !inner.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=') {
            return None;
        }
        out.push((label.to_string(), base64_to_bytes(inner)?));
    }
    (!out.is_empty()).then_some(out)
}

/// The directory a `Signature-Agent` value names, normalised: https, no credentials, query or fragment, no
/// trailing slash. Accepts a quoted string (`"https://bot.example"`), a bare URL, or the dictionary form
/// (`sig1="https://bot.example"`; the member for `label` wins, else the first). `None` when it names nothing usable.
pub fn parse_signature_agent(value: &str, label: Option<&str>) -> Option<String> {
    let mut v = value.trim().to_string();
    if v.is_empty() {
        return None;
    }
    let is_dict = {
        let head: String = v.chars().take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.*-".contains(*c)).collect();
        !head.is_empty() && key_ok(&head) && v[head.len()..].starts_with('=')
    };
    if is_dict {
        let members = split_top(&v, ',');
        let pick = members.iter().find(|m| label.is_some_and(|l| m.starts_with(&format!("{l}=")))).or_else(|| members.first())?.clone();
        v = pick[pick.find('=')? + 1..].trim().to_string();
    }
    if v.starts_with('"') {
        let (s, end) = read_string(&v, 0)?;
        if end != v.len() {
            return None;
        }
        v = s;
    }
    normalize_directory(&v)
}

/// Canonical form of a directory reference: `https://host[:port][/path]`. A bare host gets `https://`. `None`
/// for anything that is not an https URL without credentials, query or fragment.
pub fn normalize_directory(input: &str) -> Option<String> {
    let mut s = input.trim().to_string();
    if s.is_empty() {
        return None;
    }
    let has_scheme = s.find("://").is_some_and(|i| i > 0 && s[..i].chars().all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c)) && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic()));
    if !has_scheme {
        s = format!("https://{s}");
    }
    let u = Url::parse(&s).ok()?;
    if u.scheme() != "https" || !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() || u.host_str().map_or(true, str::is_empty) {
        return None;
    }
    let origin = u.origin().ascii_serialization();
    Some(format!("{origin}{}", u.path().trim_end_matches('/')))
}

/// The URL the directory is fetched from.
pub fn directory_url_for(directory: &str) -> String {
    format!("{directory}{WEB_BOT_AUTH_DIRECTORY_PATH}")
}

// ── signature base (RFC 9421 section 2.5) ───────────────────────────────────

/// The request as the origin server saw it.
#[derive(Debug, Clone)]
pub struct WebBotAuthRequest {
    /// The HTTP method.
    pub method: String,
    /// The absolute request URL (scheme, host, path, query).
    pub url: String,
    pub headers: Vec<(String, String)>,
}

impl WebBotAuthRequest {
    pub fn new(method: impl Into<String>, url: impl Into<String>, headers: impl IntoIterator<Item = (String, String)>) -> Self {
        WebBotAuthRequest { method: method.into(), url: url.into(), headers: headers.into_iter().collect() }
    }
}

/// A header's value as RFC 9421 reads it: fields of one name joined with ", ", whitespace trimmed.
pub fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    let parts: Vec<&str> = headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()).collect();
    (!parts.is_empty()).then(|| parts.join(", "))
}

const DERIVED: [&str; 7] = ["@method", "@authority", "@path", "@target-uri", "@scheme", "@query", "@request-target"];

fn escape_sf_string(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The component identifier as it is written in `Signature-Input` and in the signature base: `"name";param=value`.
pub fn serialize_component_id(c: &WebBotAuthComponent) -> String {
    let mut out = escape_sf_string(&c.name);
    for (k, v) in &c.params {
        match v {
            SfParam::Bool(true) => out.push_str(&format!(";{k}")),
            SfParam::Bool(false) => out.push_str(&format!(";{k}=?0")),
            SfParam::Str(s) => out.push_str(&format!(";{k}={}", escape_sf_string(s))),
            SfParam::Int(n) => out.push_str(&format!(";{k}={n}")),
            SfParam::Dec(n) => out.push_str(&format!(";{k}={n}")),
            SfParam::Bytes(b) => out.push_str(&format!(";{k}=:{}:", STANDARD.encode(b))),
        }
    }
    out
}

// Canonical structured-field serialization (RFC 8941 section 4), for the `sf` and `key` parameters. Strings,
// tokens, byte sequences and booleans are already canonical when valid; whitespace, list separators and
// decimals are normalised. Anything malformed is `None`.

fn sf_key_len(text: &str) -> usize {
    let b = text.as_bytes();
    if !b.first().is_some_and(|c| c.is_ascii_lowercase() || *c == b'*') {
        return 0;
    }
    b.iter().take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_.*-".contains(c)).count()
}

fn sf_bare_item(text: &str, i: usize) -> Option<(String, usize)> {
    let b = text.as_bytes();
    match b.get(i)? {
        b'"' => read_string(text, i).map(|(_, end)| (sl(text, i, end).to_string(), end)),
        b':' => {
            let close = i + 1 + text.get(i + 1..)?.find(':')?;
            base64_to_bytes(sl(text, i + 1, close))?;
            Some((sl(text, i, close + 1).to_string(), close + 1))
        }
        b'?' => match sl(text, i, i + 2) {
            m @ ("?0" | "?1") => Some((m.to_string(), i + 2)),
            _ => None,
        },
        c if c.is_ascii_digit() || *c == b'-' => {
            let rest = &text[i..];
            let int_len = 1 + rest[1..].bytes().take_while(u8::is_ascii_digit).count();
            if rest.get(..int_len)?.trim_start_matches('-').is_empty() || int_len > 16 {
                return None;
            }
            let frac_len = if rest[int_len..].starts_with('.') { 1 + rest[int_len + 1..].bytes().take_while(u8::is_ascii_digit).count() } else { 0 };
            if frac_len == 0 {
                return Some((rest[..int_len].to_string(), i + int_len));
            }
            if !(2..=4).contains(&frac_len) {
                return None;
            }
            let num: f64 = rest[..int_len + frac_len].parse().ok()?;
            let mut fixed = format!("{num:.3}").trim_end_matches('0').to_string();
            if fixed.ends_with('.') {
                fixed.push('0');
            }
            Some((fixed, i + int_len + frac_len))
        }
        c if c.is_ascii_alphabetic() || *c == b'*' => {
            let n = b[i..].iter().take_while(|c| is_token_char(**c)).count();
            Some((sl(text, i, i + n).to_string(), i + n))
        }
        _ => None,
    }
}

fn sf_params(text: &str, mut i: usize) -> Option<(String, usize)> {
    let b = text.as_bytes();
    let mut out = String::new();
    loop {
        let mut j = i;
        while matches!(b.get(j), Some(b' ') | Some(b'\t')) {
            j += 1;
        }
        if b.get(j) != Some(&b';') {
            return Some((out, i));
        }
        j += 1;
        while b.get(j) == Some(&b' ') {
            j += 1;
        }
        let kl = sf_key_len(&text[j..]);
        if kl == 0 {
            return None;
        }
        out.push(';');
        out.push_str(sl(text, j, j + kl));
        j += kl;
        if b.get(j) == Some(&b'=') {
            let (v, end) = sf_bare_item(text, j + 1)?;
            out.push('=');
            out.push_str(&v);
            j = end;
        }
        i = j;
    }
}

fn sf_item(text: &str) -> Option<String> {
    let t = text.trim();
    let (body, end) = if t.starts_with('(') {
        let (mut depth, mut quoted, mut close) = (0i32, false, None);
        let tb = t.as_bytes();
        let mut k = 0;
        while k < tb.len() {
            let ch = tb[k];
            if quoted {
                if ch == b'\\' {
                    k += 1;
                } else if ch == b'"' {
                    quoted = false;
                }
            } else if ch == b'"' {
                quoted = true;
            } else if ch == b'(' {
                depth += 1;
            } else if ch == b')' {
                depth -= 1;
                if depth == 0 {
                    close = Some(k);
                    break;
                }
            }
            k += 1;
        }
        let close = close?;
        let inner: String = sl(t, 1, close).split_whitespace().collect::<Vec<_>>().join(" ");
        let mut members = Vec::new();
        for m in split_top(&inner, ' ') {
            members.push(sf_item(&m)?);
        }
        (format!("({})", members.join(" ")), close + 1)
    } else {
        sf_bare_item(t, 0)?
    };
    let (params, pend) = sf_params(t, end)?;
    if !sl(t, pend, t.len()).trim().is_empty() {
        return None;
    }
    Some(body + &params)
}

/// `key=value` members of a Dictionary, canonicalised, in order. `None` when malformed.
fn sf_dictionary(text: &str) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    for member in split_top(text, ',') {
        let kl = sf_key_len(&member);
        if kl == 0 {
            return None;
        }
        let key = member[..kl].to_string();
        let rest = &member[kl..];
        let value = match rest.strip_prefix('=') {
            Some(v) => sf_item(v)?,
            None => sf_item(&format!("?1{rest}"))?,
        };
        out.push((key, value));
    }
    (!out.is_empty()).then_some(out)
}

/// The canonical Structured Field form of a header value (Dictionary when it reads as one, else List or Item).
fn sf_serialize(text: &str) -> Option<String> {
    let members = split_top(text, ',');
    let starts_key = |m: &str, with_eq: bool| {
        let kl = sf_key_len(m);
        kl > 0 && match m.as_bytes().get(kl) { None => !with_eq, Some(b'=') => true, Some(b';') => !with_eq, _ => false }
    };
    let dict = !members.is_empty() && members.iter().all(|m| starts_key(m, false) || starts_key(m, true)) && members.iter().any(|m| starts_key(m, true));
    if dict {
        let d = sf_dictionary(text)?;
        return Some(
            d.into_iter()
                .map(|(k, v)| {
                    if v == "?1" {
                        k
                    } else if let Some(rest) = v.strip_prefix("?1;") {
                        format!("{k};{rest}")
                    } else {
                        format!("{k}={v}")
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
        );
    }
    let mut items = Vec::new();
    for m in &members {
        items.push(sf_item(m)?);
    }
    (!items.is_empty()).then(|| items.join(", "))
}

fn component_value(c: &WebBotAuthComponent, req: &WebBotAuthRequest, url: &Url) -> Option<String> {
    let name = c.name.as_str();
    let params = &c.params;
    if name == "@query-param" {
        let [(k, SfParam::Str(want))] = params.as_slice() else { return None };
        if k != "name" {
            return None;
        }
        let found: Vec<String> = url.query_pairs().filter(|(k, _)| k == want.as_str()).map(|(_, v)| v.into_owned()).collect();
        return (found.len() == 1).then(|| encode_segment(&found[0]));
    }
    if name.starts_with('@') {
        if !params.is_empty() {
            return None;
        }
        let path = if url.path().is_empty() { "/" } else { url.path() };
        let search = url.query().map(|q| format!("?{q}")).unwrap_or_default();
        return match name {
            "@method" => Some(req.method.to_uppercase()),
            "@authority" => Some(match url.port() {
                Some(p) => format!("{}:{p}", url.host_str()?.to_lowercase()),
                None => url.host_str()?.to_lowercase(),
            }),
            "@path" => Some(path.to_string()),
            "@target-uri" => Some(url.as_str().to_string()),
            "@scheme" => Some(url.scheme().to_lowercase()),
            "@query" => Some(if search.is_empty() { "?".to_string() } else { search }),
            "@request-target" => Some(format!("{path}{search}")),
            _ => None,
        };
    }
    let raw = header_value(&req.headers, name)?;
    if params.is_empty() {
        return Some(raw);
    }
    // Header-field parameters: at most one of sf, key (with a string value) or bs.
    let [(k, v)] = params.as_slice() else { return None };
    match (k.as_str(), v) {
        ("sf", SfParam::Bool(true)) => sf_serialize(&raw),
        ("key", SfParam::Str(member)) => sf_dictionary(&raw)?.into_iter().find(|(key, _)| key == member).map(|(_, value)| value),
        ("bs", SfParam::Bool(true)) => Some(format!(":{}:", STANDARD.encode(raw.as_bytes()))),
        _ => None,
    }
}

/// Why a signature base could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseError {
    UnsupportedComponent,
    ComponentMissing,
    BadRequest,
}

/// Build the RFC 9421 signature base: one `"id": value` line per covered component, then the
/// `@signature-params` line. `signature_params` is the inner list with its parameters, serialised exactly as it
/// appears in `Signature-Input`.
pub fn build_signature_base(req: &WebBotAuthRequest, components: &[WebBotAuthComponent], signature_params: &str) -> Result<String, BaseError> {
    let url = Url::parse(&req.url).map_err(|_| BaseError::BadRequest)?;
    let mut seen = std::collections::HashSet::new();
    let mut lines = Vec::new();
    for c in components {
        if c.name != c.name.to_lowercase() {
            return Err(BaseError::UnsupportedComponent);
        }
        if c.name.starts_with('@') && !DERIVED.contains(&c.name.as_str()) && c.name != "@query-param" {
            return Err(BaseError::UnsupportedComponent);
        }
        let id = serialize_component_id(c);
        if !seen.insert(id.clone()) {
            return Err(BaseError::UnsupportedComponent);
        }
        if !c.params.iter().all(|(k, _)| ["sf", "key", "bs", "name"].contains(&k.as_str())) {
            return Err(BaseError::UnsupportedComponent);
        }
        // A derived component takes no header parameters (only @query-param takes `name`).
        if c.name.starts_with('@') && c.name != "@query-param" && !c.params.is_empty() {
            return Err(BaseError::UnsupportedComponent);
        }
        let v = component_value(c, req, &url).ok_or(BaseError::ComponentMissing)?;
        if v.contains('\r') || v.contains('\n') {
            return Err(BaseError::ComponentMissing);
        }
        lines.push(format!("{id}: {v}"));
    }
    lines.push(format!("\"@signature-params\": {signature_params}"));
    Ok(lines.join("\n"))
}

// ── verification ────────────────────────────────────────────────────────────

/// Why a web-bot-auth verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebBotAuthFailure {
    NoSignature,
    NoWebBotAuthSignature,
    Malformed,
    MissingSignatureAgent,
    BadSignatureAgent,
    BadParams,
    UnsupportedAlgorithm,
    UnsupportedComponent,
    ComponentMissing,
    ComponentsNotCovered,
    BadRequest,
    NotYetValid,
    Expired,
    LifetimeTooLong,
    DirectoryUnavailable,
    KeyNotFound,
    BadSignature,
    Replayed,
}

impl WebBotAuthFailure {
    /// The reason as the other Atlas SDKs spell it.
    pub fn as_str(&self) -> &'static str {
        use WebBotAuthFailure::*;
        match self {
            NoSignature => "no_signature",
            NoWebBotAuthSignature => "no_web_bot_auth_signature",
            Malformed => "malformed",
            MissingSignatureAgent => "missing_signature_agent",
            BadSignatureAgent => "bad_signature_agent",
            BadParams => "bad_params",
            UnsupportedAlgorithm => "unsupported_algorithm",
            UnsupportedComponent => "unsupported_component",
            ComponentMissing => "component_missing",
            ComponentsNotCovered => "components_not_covered",
            BadRequest => "bad_request",
            NotYetValid => "not_yet_valid",
            Expired => "expired",
            LifetimeTooLong => "lifetime_too_long",
            DirectoryUnavailable => "directory_unavailable",
            KeyNotFound => "key_not_found",
            BadSignature => "bad_signature",
            Replayed => "replayed",
        }
    }
}

impl From<BaseError> for WebBotAuthFailure {
    fn from(e: BaseError) -> Self {
        match e {
            BaseError::UnsupportedComponent => WebBotAuthFailure::UnsupportedComponent,
            BaseError::ComponentMissing => WebBotAuthFailure::ComponentMissing,
            BaseError::BadRequest => WebBotAuthFailure::BadRequest,
        }
    }
}

/// The result of [`verify_web_bot_auth`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct WebBotAuthResult {
    /// True when the request carried a signature header at all.
    pub signed: bool,
    pub verified: bool,
    pub reason: Option<WebBotAuthFailure>,
    /// The normalised directory the signer claims (trust it only when `verified`).
    pub directory: Option<String>,
    pub key_id: Option<String>,
    pub label: Option<String>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub nonce: Option<String>,
}

/// Where directory keys come from. `refresh` asks for a fresh copy (the key was not in the cached one).
/// `None`: unavailable.
pub trait DirectoryKeys: Send + Sync {
    fn get_keys<'a>(&'a self, directory_url: &'a str, refresh: bool) -> BoxFuture<'a, Option<Vec<WebBotAuthJwk>>>;
}

type ClaimNonce = Arc<dyn Fn(&str, i64) -> bool + Send + Sync>;

/// Options of [`verify_web_bot_auth`].
#[derive(Clone)]
pub struct WebBotAuthVerifyOptions {
    /// Epoch ms; `None` reads the system clock.
    pub now_ms: Option<i64>,
    pub skew_seconds: i64,
    pub max_lifetime_seconds: i64,
    /// Replay guard: called after the signature verified, with a key unique to the signature's nonce and the
    /// time it may be forgotten (epoch ms); returns `true` the first time it is seen. Without it nonces are
    /// not tracked.
    pub claim_nonce: Option<ClaimNonce>,
}

impl Default for WebBotAuthVerifyOptions {
    fn default() -> Self {
        WebBotAuthVerifyOptions { now_ms: None, skew_seconds: WEB_BOT_AUTH_DEFAULT_SKEW_SECONDS, max_lifetime_seconds: WEB_BOT_AUTH_DEFAULT_MAX_LIFETIME_SECONDS, claim_nonce: None }
    }
}

fn fail(reason: WebBotAuthFailure, base: WebBotAuthResult) -> WebBotAuthResult {
    WebBotAuthResult { signed: true, verified: false, reason: Some(reason), ..base }
}

/// Verify the web-bot-auth signature on a request. Never panics on bad input.
pub async fn verify_web_bot_auth(req: &WebBotAuthRequest, keys: &dyn DirectoryKeys, opts: &WebBotAuthVerifyOptions) -> WebBotAuthResult {
    let (Some(input_header), Some(sig_header)) = (header_value(&req.headers, "signature-input"), header_value(&req.headers, "signature")) else {
        return WebBotAuthResult { reason: Some(WebBotAuthFailure::NoSignature), ..Default::default() };
    };
    let (Some(inputs), Some(sigs)) = (parse_signature_input(&input_header), parse_signature_header(&sig_header)) else {
        return fail(WebBotAuthFailure::Malformed, WebBotAuthResult::default());
    };
    let Some((input, signature)) = inputs.iter().find_map(|i| {
        (param_str(&i.params, "tag") == Some(WEB_BOT_AUTH_TAG)).then(|| sigs.iter().find(|(l, _)| *l == i.label).map(|(_, s)| (i, s))).flatten()
    }) else {
        return fail(WebBotAuthFailure::NoWebBotAuthSignature, WebBotAuthResult::default());
    };
    let p = &input.params;
    let base = WebBotAuthResult { label: Some(input.label.clone()), ..Default::default() };

    let created = match param(p, "created") {
        Some(SfParam::Int(n)) => Some(*n),
        _ => None,
    };
    let expires = match param(p, "expires") {
        Some(SfParam::Int(n)) => Some(*n),
        _ => None,
    };
    let key_id = param_str(p, "keyid").filter(|k| !k.is_empty() && k.len() <= 128);
    let nonce = match param(p, "nonce") {
        None => Ok(None),
        Some(SfParam::Str(n)) if n.len() <= 512 => Ok(Some(n.clone())),
        Some(_) => Err(()),
    };
    let (Some(created), Some(expires), Some(key_id), Ok(nonce)) = (created, expires, key_id, nonce) else {
        return fail(WebBotAuthFailure::BadParams, base);
    };
    let base = WebBotAuthResult { key_id: Some(key_id.to_string()), created: Some(created), expires: Some(expires), ..base };
    if let Some(alg) = param(p, "alg") {
        if !matches!(alg, SfParam::Str(a) if a == "ed25519") {
            return fail(WebBotAuthFailure::UnsupportedAlgorithm, base);
        }
    }

    // Time window: created not in the future, expires not in the past, both within a small skew.
    let now_sec = opts.now_ms.unwrap_or_else(|| system_clock()() as i64).div_euclid(1000);
    let skew = opts.skew_seconds;
    if expires <= created {
        return fail(WebBotAuthFailure::BadParams, base);
    }
    if expires - created > opts.max_lifetime_seconds {
        return fail(WebBotAuthFailure::LifetimeTooLong, base);
    }
    if created > now_sec + skew {
        return fail(WebBotAuthFailure::NotYetValid, base);
    }
    if expires < now_sec - skew {
        return fail(WebBotAuthFailure::Expired, base);
    }

    // Coverage: the signature must bind the host, and the directory claim it relies on.
    let Some(agent_header) = header_value(&req.headers, "signature-agent") else {
        return fail(WebBotAuthFailure::MissingSignatureAgent, base);
    };
    let agent_component = input.components.iter().find(|c| c.name == "signature-agent");
    let (true, Some(agent_component)) = (input.components.iter().any(|c| c.name == "@authority"), agent_component) else {
        return fail(WebBotAuthFailure::ComponentsNotCovered, base);
    };
    // Covered as a dictionary member (`;key="m"`): the directory must come from that member, or an uncovered one could be swapped in.
    let agent_key = param_str(&agent_component.params, "key");
    if let Some(k) = agent_key {
        if !split_top(&agent_header, ',').iter().any(|m| m.starts_with(&format!("{k}="))) {
            return fail(WebBotAuthFailure::BadSignatureAgent, base);
        }
    }
    let Some(directory) = parse_signature_agent(&agent_header, Some(agent_key.unwrap_or(&input.label))) else {
        return fail(WebBotAuthFailure::BadSignatureAgent, base);
    };
    let base = WebBotAuthResult { directory: Some(directory.clone()), ..base };

    let signed_base = match build_signature_base(req, &input.components, &input.raw) {
        Ok(b) => b,
        Err(e) => return fail(e.into(), base),
    };

    let dir_url = directory_url_for(&directory);
    let find = |ks: &Option<Vec<WebBotAuthJwk>>| ks.as_ref().and_then(|ks| ks.iter().find(|k| ed25519_jwk_thumbprint(&k.x) == key_id).cloned());
    let mut ks = keys.get_keys(&dir_url, false).await;
    let mut jwk = find(&ks);
    if jwk.is_none() {
        ks = keys.get_keys(&dir_url, true).await;
        jwk = find(&ks);
    }
    let Some(jwk) = jwk else {
        return fail(if ks.is_none() { WebBotAuthFailure::DirectoryUnavailable } else { WebBotAuthFailure::KeyNotFound }, base);
    };

    let ok = base64url_to_bytes(&jwk.x)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .zip(Signature::from_slice(signature).ok())
        .is_some_and(|(vk, sig)| vk.verify_strict(signed_base.as_bytes(), &sig).is_ok());
    if !ok {
        return fail(WebBotAuthFailure::BadSignature, base);
    }

    if let (Some(claim), Some(n)) = (&opts.claim_nonce, &nonce) {
        if !claim(&format!("{directory}|{key_id}|{n}"), expires * 1000 + skew * 1000) {
            return fail(WebBotAuthFailure::Replayed, base);
        }
    }
    WebBotAuthResult { signed: true, verified: true, nonce, ..base }
}

// ── signing (for bots and tests) ────────────────────────────────────────────

/// What to sign.
pub struct SignWebBotAuthInput {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    /// The directory URL the bot publishes its keys under.
    pub signature_agent: String,
    /// The Ed25519 private key: the 32-byte seed.
    pub private_key: [u8; 32],
    pub created: i64,
    pub expires: i64,
    pub nonce: Option<String>,
    pub label: String,
    /// Covered components; must include `@authority` and `signature-agent`.
    pub components: Vec<WebBotAuthComponent>,
}

impl SignWebBotAuthInput {
    /// Sign `method url` covering `@authority` and `signature-agent`, label `sig1`.
    pub fn new(method: impl Into<String>, url: impl Into<String>, signature_agent: impl Into<String>, private_key: [u8; 32], created: i64, expires: i64) -> Self {
        SignWebBotAuthInput {
            method: method.into(),
            url: url.into(),
            headers: Vec::new(),
            signature_agent: signature_agent.into(),
            private_key,
            created,
            expires,
            nonce: None,
            label: "sig1".into(),
            components: vec![WebBotAuthComponent::new("@authority"), WebBotAuthComponent::new("signature-agent")],
        }
    }
}

/// The base64url public key (`x`) of an Ed25519 seed: what the bot publishes in its directory.
pub fn public_key_x(private_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(private_key).verifying_key().to_bytes())
}

/// Produce the three headers (`signature-agent`, `signature-input`, `signature`) for a request.
pub fn sign_web_bot_auth_request(input: &SignWebBotAuthInput) -> Result<Vec<(String, String)>, BaseError> {
    let sk = SigningKey::from_bytes(&input.private_key);
    let key_id = ed25519_jwk_thumbprint(&URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes()));
    let agent_header = format!("\"{}\"", input.signature_agent);
    let ids: Vec<String> = input.components.iter().map(serialize_component_id).collect();
    let params = format!(
        "({});created={};keyid=\"{key_id}\";alg=\"ed25519\";expires={}{};tag=\"{WEB_BOT_AUTH_TAG}\"",
        ids.join(" "),
        input.created,
        input.expires,
        input.nonce.as_ref().map(|n| format!(";nonce=\"{n}\"")).unwrap_or_default()
    );
    let mut headers = input.headers.clone();
    headers.push(("signature-agent".into(), agent_header.clone()));
    let req = WebBotAuthRequest { method: input.method.clone(), url: input.url.clone(), headers };
    let base = build_signature_base(&req, &input.components, &params)?;
    let sig = sk.sign(base.as_bytes());
    Ok(vec![
        ("signature-agent".into(), agent_header),
        ("signature-input".into(), format!("{}={params}", input.label)),
        ("signature".into(), format!("{}=:{}:", input.label, STANDARD.encode(sig.to_bytes()))),
    ])
}

// ── directory cache and fetcher ─────────────────────────────────────────────

/// Fetch and JSON-parse a directory document; `None` on any failure.
pub trait DirectoryFetcher: Send + Sync {
    fn fetch_json<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Option<Value>>;
}

fn is_private_host_literal(host: &str) -> bool {
    let h = host.to_lowercase();
    let h = h.trim_start_matches('[').trim_end_matches(']');
    h == "localhost" || h.ends_with(".localhost") || h.contains(':') || h.parse::<std::net::Ipv4Addr>().is_ok() || !h.contains('.')
}

/// A [`DirectoryFetcher`] over an [`HttpTransport`]: https only, no literal or single-label hosts, a 64 KB cap.
/// The transport must not follow redirects and must refuse private addresses itself.
pub struct TransportDirectoryFetcher(Arc<dyn HttpTransport>);

impl TransportDirectoryFetcher {
    pub fn new(transport: Arc<dyn HttpTransport>) -> Self {
        TransportDirectoryFetcher(transport)
    }
}

impl DirectoryFetcher for TransportDirectoryFetcher {
    fn fetch_json<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Option<Value>> {
        Box::pin(async move {
            let u = Url::parse(url).ok()?;
            if u.scheme() != "https" || u.host_str().map_or(true, is_private_host_literal) {
                return None;
            }
            let resp = self.0.send(HttpRequest::new(HttpMethod::Get, url).header("accept", WEB_BOT_AUTH_DIRECTORY_MEDIA_TYPE)).await.ok()?;
            if !(200..300).contains(&resp.status) || resp.body.len() > DIRECTORY_MAX_BYTES {
                return None;
            }
            serde_json::from_str(&resp.body).ok()
        })
    }
}

struct CacheEntry {
    keys: Option<Vec<WebBotAuthJwk>>,
    at: i64,
    fetched_at: i64,
}

/// A small in-memory directory cache.
pub struct WebBotAuthDirectoryCache<F: DirectoryFetcher> {
    fetcher: F,
    entries: Mutex<HashMap<String, CacheEntry>>,
    pub ttl_ms: i64,
    pub failure_ttl_ms: i64,
    /// The least time between refreshes of one directory, so a bot cannot force a fetch per request.
    pub refresh_cooldown_ms: i64,
    pub max_entries: usize,
    now: Clock,
}

impl<F: DirectoryFetcher> WebBotAuthDirectoryCache<F> {
    /// Defaults: trust a fetched directory 10 minutes, remember a failure 1 minute, refresh at most once a
    /// minute, hold 1000 directories.
    pub fn new(fetcher: F) -> Self {
        WebBotAuthDirectoryCache { fetcher, entries: Mutex::new(HashMap::new()), ttl_ms: 600_000, failure_ttl_ms: 60_000, refresh_cooldown_ms: 60_000, max_entries: 1000, now: system_clock() }
    }

    /// Inject a clock (epoch ms), for tests.
    pub fn with_clock(mut self, now: Clock) -> Self {
        self.now = now;
        self
    }

    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

impl<F: DirectoryFetcher> DirectoryKeys for WebBotAuthDirectoryCache<F> {
    fn get_keys<'a>(&'a self, url: &'a str, refresh: bool) -> BoxFuture<'a, Option<Vec<WebBotAuthJwk>>> {
        Box::pin(async move {
            let t = (self.now)() as i64;
            let hit = {
                let g = self.entries.lock().unwrap();
                g.get(url).map(|h| (h.keys.clone(), h.at, h.fetched_at))
            };
            if let Some((keys, at, fetched_at)) = &hit {
                let ttl = if keys.is_some() { self.ttl_ms } else { self.failure_ttl_ms };
                if t - at < ttl && !(refresh && t - fetched_at >= self.refresh_cooldown_ms) {
                    return keys.clone();
                }
            }
            let parsed = self.fetcher.fetch_json(url).await.map(|d| parse_directory(&d)).unwrap_or_default();
            let fetched = (!parsed.is_empty()).then_some(parsed);
            // A failed refresh keeps serving the last good copy rather than dropping a working directory.
            let kept = fetched.or_else(|| hit.and_then(|h| h.0));
            let mut g = self.entries.lock().unwrap();
            if g.len() >= self.max_entries && !g.contains_key(url) {
                if let Some(oldest) = g.iter().min_by_key(|(_, e)| e.fetched_at).map(|(k, _)| k.clone()) {
                    g.remove(&oldest);
                }
            }
            g.insert(url.to_string(), CacheEntry { keys: kept.clone(), at: t, fetched_at: t });
            kept
        })
    }
}

// ── decision (allow and block lists) ────────────────────────────────────────

/// One allow- or block-list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBotAuthListEntry {
    /// A directory URL or bare host. Normalised before comparing.
    pub directory: String,
    /// A label for the agent. Defaults to the directory host.
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct WebBotAuthPolicy {
    pub allow: Vec<WebBotAuthListEntry>,
    pub block: Vec<WebBotAuthListEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebBotAuthDecisionKind {
    Allow,
    Block,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebBotAuthTier {
    Allowed,
    Blocked,
    Verified,
    Unverified,
}

/// Who signed: set only when verified, because an unverified claim proves nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBotAuthAgent {
    pub directory: String,
    pub key_id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebBotAuthDecision {
    pub verified: bool,
    pub agent: Option<WebBotAuthAgent>,
    pub tier: WebBotAuthTier,
    pub decision: WebBotAuthDecisionKind,
    /// Why verification failed (absent when verified).
    pub reason: Option<WebBotAuthFailure>,
}

/// Turn a verification result into a decision. Only a VERIFIED directory can be allowed or blocked: an unsigned
/// or failed request is `Unknown`, never trusted and never attributed to the directory it claimed. A block entry
/// beats an allow entry.
pub fn decide_web_bot_auth(result: &WebBotAuthResult, policy: &WebBotAuthPolicy) -> WebBotAuthDecision {
    let (true, Some(directory), Some(key_id)) = (result.verified, &result.directory, &result.key_id) else {
        return WebBotAuthDecision { verified: false, agent: None, tier: WebBotAuthTier::Unverified, decision: WebBotAuthDecisionKind::Unknown, reason: result.reason };
    };
    let find = |list: &[WebBotAuthListEntry]| list.iter().find(|e| normalize_directory(&e.directory).as_deref() == Some(directory.as_str())).cloned();
    let blocked = find(&policy.block);
    let allowed = if blocked.is_some() { None } else { find(&policy.allow) };
    let entry = blocked.as_ref().or(allowed.as_ref());
    let name = entry
        .and_then(|e| e.name.as_ref())
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .or_else(|| Url::parse(directory).ok().and_then(|u| u.host_str().map(str::to_string)))
        .unwrap_or_default();
    let (tier, decision) = match (&blocked, &allowed) {
        (Some(_), _) => (WebBotAuthTier::Blocked, WebBotAuthDecisionKind::Block),
        (_, Some(_)) => (WebBotAuthTier::Allowed, WebBotAuthDecisionKind::Allow),
        _ => (WebBotAuthTier::Verified, WebBotAuthDecisionKind::Unknown),
    };
    WebBotAuthDecision { verified: true, agent: Some(WebBotAuthAgent { directory: directory.clone(), key_id: key_id.clone(), name }), tier, decision, reason: None }
}

// ── local verifier ──────────────────────────────────────────────────────────

/// Options of a [`WebBotAuthVerifier`].
#[derive(Clone, Default)]
pub struct WebBotAuthVerifierOptions {
    pub policy: WebBotAuthPolicy,
    pub skew_seconds: Option<i64>,
    pub max_lifetime_seconds: Option<i64>,
    /// Refuse a signature whose nonce was seen before (in memory, per process). Off by default: some bots reuse
    /// one signed request until it expires.
    pub reject_replays: bool,
}

/// A verifier that runs inside your own server: no call to Atlas, directories cached in memory.
pub struct WebBotAuthVerifier<F: DirectoryFetcher> {
    cache: WebBotAuthDirectoryCache<F>,
    opts: WebBotAuthVerifierOptions,
    seen: Arc<Mutex<HashMap<String, i64>>>,
    now: Clock,
}

impl<F: DirectoryFetcher> WebBotAuthVerifier<F> {
    pub fn new(fetcher: F, opts: WebBotAuthVerifierOptions) -> Self {
        WebBotAuthVerifier { cache: WebBotAuthDirectoryCache::new(fetcher), opts, seen: Arc::new(Mutex::new(HashMap::new())), now: system_clock() }
    }

    /// Inject a clock (epoch ms), for tests.
    pub fn with_clock(mut self, now: Clock) -> Self {
        self.cache = self.cache.with_clock(now.clone());
        self.now = now;
        self
    }

    /// Verify and decide. Never panics.
    pub async fn verify(&self, req: &WebBotAuthRequest) -> WebBotAuthDecision {
        let now = (self.now)() as i64;
        let claim_nonce: Option<ClaimNonce> = self.opts.reject_replays.then(|| {
            let seen = self.seen.clone();
            let f: ClaimNonce = Arc::new(move |key: &str, expires_at_ms: i64| {
                let mut g = seen.lock().unwrap();
                if g.len() > 5000 {
                    g.retain(|_, exp| *exp > now);
                }
                if g.len() > 20_000 {
                    return false; // fail closed rather than grow without bound
                }
                if g.get(key).is_some_and(|prior| *prior > now) {
                    return false;
                }
                g.insert(key.to_string(), expires_at_ms);
                true
            });
            f
        });
        let o = WebBotAuthVerifyOptions {
            now_ms: Some(now),
            skew_seconds: self.opts.skew_seconds.unwrap_or(WEB_BOT_AUTH_DEFAULT_SKEW_SECONDS),
            max_lifetime_seconds: self.opts.max_lifetime_seconds.unwrap_or(WEB_BOT_AUTH_DEFAULT_MAX_LIFETIME_SECONDS),
            claim_nonce,
        };
        decide_web_bot_auth(&verify_web_bot_auth(req, &self.cache, &o).await, &self.opts.policy)
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}
