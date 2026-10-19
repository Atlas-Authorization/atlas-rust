# atlasauth

The official **Rust backend verification crate** for [Atlas](https://atlasauth.net).
It is the Rust peer of the TypeScript `@atlasauth/backend`, Go (`atlas-go`), and
Ruby SDKs — the same verification semantics, the same claim names, the same
`@no-email.invalid` handling.

> This is a **server-side** crate. API-key verification uses your instance
> **secret key** (`sk_...`), which must never ship to a browser or mobile app.
> For client-side sign-in flows use the JS, Swift, Kotlin, or Flutter SDKs.

It does the two things a Rust service needs:

- **Verify a session token locally** against the instance JWKS — fast, offline,
  and correct within the short token lifetime, with no outbound call per request.
- **Verify an end-user API key** (`ak_...`) against Atlas, with separate positive
  and negative caches so a busy API — or a caller hammering a bad key — never
  hammers Atlas.

## Install

On [crates.io](https://crates.io/crates/atlasauth):

```toml
# Cargo.toml
[dependencies]
atlasauth = "0.10"
```

Requires Rust 1.70+. The default `reqwest-transport` feature pulls in `reqwest`
(rustls) for the built-in HTTP transport; disable it to supply your own.

## Token verification

Backend services verify a session JWT **locally** against the instance JWKS. The
JWKS is cached in-process and refetched on an unknown `kid` at most once a minute
— the rate limit is a security property, not politeness: it stops a caller
sending random `kid`s from turning your process into a traffic amplifier aimed at
the JWKS endpoint.

```rust
use atlasauth::{AtlasBackend, VerifyError};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let backend = AtlasBackend::new(
    // issuer — required; an unchecked issuer accepts any Atlas instance's tokens.
    "https://your-instance-fapi.atlasauth.net",
    // JWKS URL — fetched and cached.
    "https://your-instance-fapi.atlasauth.net/.well-known/jwks.json",
)?;

match backend.verify(session_jwt).await {
    Ok(claims) => {
        // claims.sub, claims.sid, claims.org_id, claims.org_role, claims.org_permissions …
        if claims.has_permission("billing:read") {
            // authorized
        }
    }
    Err(VerifyError::Malformed) => { /* 400 */ }
    Err(_) => { /* 401 — one coarse reason for every failure, by design */ }
}
# Ok(()) }
# let session_jwt = "";
```

Verification is **RS256 only**: a token whose header says `alg: none`, `HS256`,
or anything else is rejected before any key is touched. It also checks `exp` /
`nbf` (5 s clock-skew tolerance), the issuer, and — as an OP token-confusion
guard — rejects any token carrying a `token_use` other than `session` or an
unexpected `aud`.

### From a request

An `Authorization: Bearer …` header wins over a `__session` cookie (a
deliberately-set header should not be overridden by a stale cookie):

```rust
# use atlasauth::AtlasBackend;
# async fn demo(backend: &AtlasBackend, authz: Option<&str>, cookie: Option<&str>) {
let result = backend.authenticate_request(authz, cookie).await;
# let _ = result;
# }
```

### Authorized parties and audience

```rust
# use atlasauth::AtlasBackend;
# fn demo() -> Result<(), atlasauth::ConfigError> {
let backend = AtlasBackend::builder("https://your-instance-fapi.atlasauth.net")
    .jwks_url("https://your-instance-fapi.atlasauth.net/.well-known/jwks.json")
    .authorized_parties(["https://app.example.com"]) // optional azp allowlist
    .audiences(["ins_your_instance_id"])              // optional — accept any of these aud
    .build()?;
# let _ = backend;
# Ok(()) }
```

Audience checking is optional and backwards-compatible. An Atlas session token
carries its instance id as `aud` by default, so **leave it unset and the token
still verifies** (the OP token-confusion guard is the `token_use:"session"`
marker, not the presence of `aud`). Set one or more expected audiences — via
`.audience(x)` one at a time or `.audiences([...])` — and the token's `aud` must
contain **at least one** of them (OR), which is how a single verifier can serve
tokens for several instances or resource servers.

### Offline / CI

Pass a static key set instead of a URL — no network call is ever made:

```rust
# use atlasauth::{AtlasBackend, Jwks};
# fn demo(jwks: Jwks) -> Result<(), atlasauth::ConfigError> {
let backend = AtlasBackend::builder("https://your-instance-fapi.atlasauth.net")
    .static_jwks(jwks)
    .build()?;
# let _ = backend;
# Ok(()) }
```

## Identity & email helpers

Resolving "what is this user's real email?" has one subtlety: when an OAuth
provider shares no email, Atlas seeds a `…@no-email.invalid` placeholder. The
helpers treat it as *no real email*:

```rust
# use atlasauth::User;
# fn demo(user: User) {
// None when the user has only the @no-email.invalid placeholder.
let email: Option<&str> = user.primary_email();

for addr in user.real_emails() { /* placeholder filtered out */ }
let has_email = user.has_real_email();
# let _ = (email, has_email); }
```

`atlasauth::real_email(s)` is the standalone twin: `Some(s)` for a real address,
`None` for the placeholder or an empty string. The verified session's `email`
claim has the same filter: `claims.real_email()`.

## API-key verification

End-user API keys (`ak_...`) are verified **online** against Atlas, because a
key's validity (revoked? expired? subject deleted?) lives server-side. To keep a
busy API from calling out per request, results are cached — with a **longer
positive** TTL and a **short negative** TTL, so a bad key is answered locally
without hammering Atlas, yet a freshly-minted key starts working within seconds.

```rust
use atlasauth::ApiKeyVerifier;

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
// Defaults to https://api.atlasauth.net; override with .builder(...).base_url(...).
let verifier = ApiKeyVerifier::new("sk_live_...")?;

let verdict = verifier.verify(presented_secret).await?;
if verdict.valid {
    // verdict.subject_type, verdict.subject_id, verdict.claims …
}
# Ok(()) }
# let presented_secret = "";
```

Every negative — unknown, malformed, revoked, expired, or a since-deleted
subject — resolves to the same `valid == false`, so a caller learns nothing about
which keys exist. A `valid == false` verdict is **not** an error; an
`ApiKeyError` means the endpoint could not be reached or the response did not
parse (e.g. a bad `sk_` key → HTTP 401).

The secret key is sent as `Authorization: Bearer sk_...` and is never placed in a
URL.

## Back-channel logout

When a user signs out, Atlas can POST a `logout_token` (OpenID Connect
Back-Channel Logout) to your app's back-channel logout URI. Verify it with the
same `AtlasBackend` you use for tokens — built with the issuer of the provider
that registered your client (`https://atlasauth.net` for Sign in with Atlas
apps, your instance issuer for your instance's own OAuth clients):

```rust
use atlasauth::{AtlasBackend, LogoutTokenReplayCache};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let verifier = AtlasBackend::new(
    "https://atlasauth.net",
    "https://atlasauth.net/.well-known/jwks.json",
)?;
let claims = verifier.verify_logout_token(logout_token, "your_client_id").await?;
// claims.sid / claims.sub / claims.jti / claims.iat
# Ok(()) }
# let logout_token = "";
```

The check follows the spec: RS256 only, the expected issuer, your client id in
`aud`, `iat` present (and not in the future), `exp` honoured when present, a
`jti`, the back-channel logout event, a `sid` and/or `sub`, no `nonce`, and a
`typ` of `logout+jwt` when present. Any failure is a `VerifyError` — answer 400.

A framework-agnostic handler:

```rust
use atlasauth::{AtlasBackend, LogoutTokenReplayCache};

/// POST /backchannel-logout  (Content-Type: application/x-www-form-urlencoded)
/// Returns (status, headers) — map it onto your framework's response type.
async fn backchannel_logout(
    verifier: &AtlasBackend,
    seen: &LogoutTokenReplayCache,
    form: &std::collections::HashMap<String, String>,
    now_seconds: i64,
) -> (u16, Vec<(&'static str, &'static str)>) {
    let no_store = vec![("Cache-Control", "no-store")];
    let Some(token) = form.get("logout_token") else { return (400, no_store) };
    let Ok(claims) = verifier.verify_logout_token(token, "your_client_id").await else {
        return (400, no_store);
    };
    if !seen.check_and_remember(&claims.jti, now_seconds) {
        return (400, no_store); // replayed
    }
    match (&claims.sid, &claims.sub) {
        (Some(sid), _) => end_sessions_with_sid(sid).await,   // your session store
        (None, Some(sub)) => end_sessions_for_user(sub).await,
        (None, None) => unreachable!("the verifier requires sid or sub"),
    }
    (200, no_store)
}
# async fn end_sessions_with_sid(_: &str) {}
# async fn end_sessions_for_user(_: &str) {}
```

`LogoutTokenReplayCache` remembers each accepted `jti` in memory so a replayed
token is refused. It covers one process; with several instances, record the
`jti` in your shared store instead (for example a Redis `SET <jti> 1 NX EX 300`).

## Management API (`backend` feature)

```toml
atlasauth = { version = "0.10", features = ["backend"] }
```

`BackendClient` covers the whole Backend API with your secret key, and the
Platform API with a platform key:

```rust
use atlasauth::backend::{types, BackendClient, CursorParams, Query};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let atlas = BackendClient::new("sk_live_...")?;

// Typed resources
let user = atlas.users().get("user_123").await?;
let page = atlas.users().list(CursorParams { limit: Some(50), ..Default::default() }).await?;

// Setup check: every misconfiguration the server can see, with how to fix it
let preflight = atlas.instance().preflight().await?;
for f in preflight.findings.iter().filter(|f| f.is_error()) {
    eprintln!("{}: {} — {}", f.code, f.message, f.fix);
}

// Every other endpoint: one typed method per route
let role = atlas
    .roles()
    .create(&types::RolesCreateBody::new().with_key("editor").with_name("Editor"))
    .await?;
let waitlist = atlas.waitlist().list(&Query::new().set("limit", 20)).await?;
for entry in &waitlist.data {
    println!("{} {}", entry.id, entry.status);
}
# let _ = (user, page, role, waitlist); Ok(()) }
```

Typed surfaces include users, organizations (memberships, invitations, domains,
policy, settings, branding, design), sessions, API keys, machines, billing,
entitlement overrides, notifications, audit events, tickets, user erasure, the
instance preflight, cookie consent, email/SMS delivery providers, social sign-in
providers, webhook endpoints, and the sign-in page design. Everything else —
roles and permissions, OAuth clients, SSO/LDAP/SCIM, FGA and the
OpenFGA-compatible API, connectors, data subject requests, templates,
localizations, log streams, network ACLs, RADIUS, rate limits, risk-based MFA,
bot signals, jobs, and the test-mode helpers — has a typed method per route,
whose request and response structs live in `atlasauth::backend::types`:

- Build a request with `Type::new()` and the `with_*` setters (or
  `Type::default()` and assign fields). Unset optional fields are left out of
  the request; `clear_*` sends `null` where the API lets you clear a value.
- Every struct has an `extra` map. On a response it keeps any field the server
  added after this crate was released; on a request, `with_extra(key, value)`
  sends a field this crate does not know yet.
- Enumerations are plain `String`s (each field's docs list the known values), so
  a new value from the server never fails to decode.
- A few operations whose request or response is open-ended JSON keep
  `serde_json::Value` on that side. `BackendClient::request_value` calls any
  route with raw JSON.

### Strict request bodies

By default the API ignores a body field it does not accept and names it in an
`Atlas-Unknown-Fields` response header. Turn on strict mode to get a
`422 UNKNOWN_FIELD` instead, and/or log what was ignored:

```rust
use atlasauth::backend::{BackendClient, codes, BackendError};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let atlas = BackendClient::builder("sk_live_...")
    .strict(true)                                   // Atlas-Strict: true on every write
    .on_unknown_fields(|u| eprintln!("{:?} {} ignored {:?}", u.method, u.path, u.fields))
    .build()?;

// Per-call override:
let lenient = atlas.with_strict(Some(false));
# let _ = lenient; Ok(()) }
```

Error codes worth branching on are in `atlasauth::backend::codes`
(`UNKNOWN_FIELD`, `WRONG_KEY_SURFACE`, `INVALID_KEY`, `PLAN_IN_USE`,
`EMAIL_DELIVERY_NOT_CONFIGURED`, `EMAIL_PROVIDER_REQUIRED`, `EMAIL_PROVIDER_IN_USE`, …):
`err.has_code(codes::UNKNOWN_FIELD)`.

### API key spend caps

Give an end-user API key caps per unit and period (`"request"`, `"day"`,
`"month"` or `"total"`), then meter what each call costs. A debit that would
exceed a cap records nothing and comes back with `allowed: false`; it is not an
error:

```rust
use atlasauth::backend::{codes, types, BackendClient, CreateApiKeyBody, UpdateApiKeyBody};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let atlas = BackendClient::new("sk_live_...")?;
let key = atlas
    .api_keys()
    .create(
        &CreateApiKeyBody {
            subject_type: "user".into(),
            subject_id: "user_123".into(),
            limits: Some(vec![
                types::ApiKeyLimit::new("requests", 1000, "day"),
                types::ApiKeyLimit::new("usd_cents", 5000, "month"),
            ]),
            ..Default::default()
        },
        None,
    )
    .await?;

let debit = atlas
    .api_keys()
    .record_usage(
        &key.id,
        // a retry with the same idempotency key returns the first outcome
        &types::ApiKeysRecordUsageBody::new(12, "usd_cents").with_idempotency_key("req_8f2c"),
    )
    .await?;
if !debit.allowed {
    assert_eq!(debit.code.as_deref(), Some(codes::LIMIT_EXCEEDED)); // debit.exceeded lists the caps
}

let usage = atlas.api_keys().get_usage(&key.id).await?; // used / remaining / resets_at per cap
atlas
    .api_keys()
    .update(&key.id, &UpdateApiKeyBody { limits: Some(None), ..Default::default() }) // remove the caps
    .await?;
# let _ = usage; Ok(()) }
```

`ApiKeyVerifier::verify` also returns the key's `name`, `scopes`,
`constraints`, `limits` and current `usage`.

### Session keep-alive

If your app loads the Atlas frontend SDK only on some pages, time spent on the
other pages can count as inactivity. Touch the session from your backend to
slide its inactivity window:

```rust
# async fn demo(atlas: atlasauth::backend::BackendClient) -> Result<(), Box<dyn std::error::Error>> {
let s = atlas.sessions().touch("sess_123").await?;
// s.idle_expires_at is the new deadline; s.extended is false when a touch in the last minute already did it
# let _ = s; Ok(()) }
```

A touch never extends past the session's absolute expiry and never revives an
ended session (409 `SESSION_REVOKED`, `SESSION_IDLE_EXPIRED` or
`SESSION_EXPIRED`). It writes at most once a minute, so calling it on every
request is safe.

### Cookie settings link

With cookie consent on, the hosted pages can show a "Cookie settings" link in
their footer that reopens your consent tool. Pick a preset (`cookiemunch`,
`cookiebot`, `onetrust`, or `custom` with your own attributes):

```rust
use atlasauth::backend::{cookie_settings_link_presets, BackendClient, CookieSettingsLinkInput, SetCookieConsentBody};

# async fn demo(atlas: &BackendClient) -> Result<(), Box<dyn std::error::Error>> {
let cc = atlas
    .instance()
    .set_cookie_consent(&SetCookieConsentBody {
        script_url: "https://consent.cookiebot.com/uc.js".into(),
        settings_link: Some(CookieSettingsLinkInput {
            label: "Cookie settings".into(),
            preset: Some(cookie_settings_link_presets::COOKIEBOT.into()),
            ..Default::default()
        }),
        ..Default::default()
    })
    .await?;
// cc.settings_link.rendered_attributes: your attributes plus the preset's trigger
# let _ = cc; Ok(()) }
```

### Removing the email provider

Removing the email provider is refused with `409 EMAIL_PROVIDER_IN_USE` while
features that need email (email code or link sign-in, sign-up email
verification, password reset) are on and nothing else would send email. The
error's `meta.features` names them. To remove it anyway:

```rust
use atlasauth::backend::{BackendClient, DeleteMessagingProviderParams, MessagingChannel};

# async fn demo(atlas: &BackendClient) -> Result<(), Box<dyn std::error::Error>> {
atlas
    .messaging_providers()
    .delete_with(MessagingChannel::Email, &DeleteMessagingProviderParams { force: true })
    .await?;
# Ok(()) }
```

### Logout without a confirmation page

For a first-party OAuth client, `skip_logout_confirmation` makes RP-initiated
logout with the client's `client_id` and an exactly registered
`post_logout_redirect_uri` end the session and redirect straight back, without
the "Sign out?" page:
`types::OAuthClientsUpdateBody::new().with_skip_logout_confirmation(true)`.
On a third-party client the API answers `422 VALIDATION_FAILED`.

### Sign-in page design and image uploads

The design is fully typed (`AtlasDesign`: preset, palettes, typography, shape,
card, layout, buttons, inputs, backgrounds, logo). Images are uploaded as raw
bytes; the content type is detected from the bytes when you pass `None`:

```rust
use atlasauth::backend::{AtlasDesign, BackendClient, DesignAssetKind, DesignLogo};

# async fn demo(atlas: &BackendClient, png: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
let logo = atlas.design().upload_asset(DesignAssetKind::Logo, png, None).await?;
let design = AtlasDesign {
    preset: Some("glass".into()),
    logo: Some(DesignLogo { asset_id: Some(logo.asset_id), ..Default::default() }),
    ..Default::default()
};
let preview = atlas.design().preview(&design).await?;  // nothing saved
atlas.design().put(&design).await?;
atlas.design().patch_organization("org_123", serde_json::json!({ "palette": { "primary": "#0F766E" } })).await?;
# let _ = preview; Ok(()) }
```

### Domain moves, logout fan-out and managed email

```rust,no_run
# async fn demo(atlas: &atlasauth::backend::BackendClient) -> Result<(), atlasauth::backend::BackendError> {
use atlasauth::backend::types;
// Move every URL from the old origin to the new one; `dry_run` first shows the diff.
let body = types::OriginMoveRequest::new("https://old.example.com", "https://example.com").with_dry_run(true);
let preview = atlas.instance().move_origin(&body).await?;
println!("{} fields move", preview.changes.len());
# Ok(()) }
```

`logout_notify_endpoints()` registers services that get the same `logout_token` as your OIDC apps,
`messaging_providers().create_managed_email(..)` sends email from your own domain through Atlas, and with a platform
key `platform().atlas_id_apps().find_users(..)` answers a privacy request for one app and
`platform().atlas_id_publisher()` claims the publisher name shown on consent screens.

### Platform API: Sign in with Atlas apps

Build the client with a platform key (`psk_…`) and use `platform()`:

```rust
use atlasauth::backend::{BackendClient, CreateAtlasIdAppBody};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let platform = BackendClient::new("psk_live_...")?;
let app = platform.platform().atlas_id_apps().create(&CreateAtlasIdAppBody {
    name: "Acme".into(),
    redirect_uris: vec!["https://acme.example/callback".into()],
    post_logout_redirect_uris: Some(vec!["https://acme.example/signed-out".into()]),
    backchannel_logout_uri: Some("https://acme.example/backchannel-logout".into()),
    ..Default::default()
}, None).await?;
// app.client_id, app.client_secret (shown once)
# let _ = app; Ok(()) }
```

`platform().apps()` provisions and manages the apps your platform owns, and
`platform().upload_design_asset(...)` uploads images for app designs.

## Custom transport (no reqwest)

Disable the default feature to compile with no HTTP dependency and supply your
own transport by implementing `JwksSource` (for session verification) and/or
`HttpPost` (for API-key verification):

```toml
atlasauth = { version = "0.10", default-features = false }
```

```rust
use atlasauth::{AtlasBackend, JwksSource};
use std::sync::Arc;

# fn demo(my_source: Arc<dyn JwksSource>) -> Result<(), atlasauth::ConfigError> {
let backend = AtlasBackend::builder("https://your-instance-fapi.atlasauth.net")
    .jwks_url("https://your-instance-fapi.atlasauth.net/.well-known/jwks.json")
    .jwks_source(my_source)
    .build()?;
# let _ = backend;
# Ok(()) }
```

For the management client, implement `HttpTransport`. Its `send_full` method
(which has a default) carries binary upload bodies and returns response
headers; override it if you need image uploads or `Atlas-Unknown-Fields`
reporting through your own transport.

## Development

```sh
cargo build
cargo test   # hermetic — generates keys in-test and mocks all HTTP; no network
cargo clippy
cargo fmt
```

## License

MIT.
