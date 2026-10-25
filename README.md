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
`messaging_providers().create_managed_email(..)` sets your domain up on your own Resend or Brevo account
(`with_transport` + `with_config(..with_api_key(..))`, or `with_provider_id`), and with a platform
key `platform().atlas_id_apps().find_users(..)` answers a privacy request for one app and
`platform().atlas_id_publisher()` claims the publisher name shown on consent screens.

### OAuth client secret rotation and development email

```rust,no_run
# async fn demo(atlas: &atlasauth::backend::BackendClient) -> Result<(), atlasauth::backend::BackendError> {
use atlasauth::backend::types;
// The previous secret keeps working for the overlap (default 24 hours, at most 7 days); 0 revokes it now.
let body = types::OAuthClientsRotateSecretBody::new().with_overlap_seconds(3600);
let rotated = atlas.oauth_clients().rotate_secret_with("oc_123", &body, None).await?;
println!("new secret shown once; old one stops at {:?}", rotated.previous_secret_expires_at);

// A development instance can send sign-in emails through your provider without a verified domain.
let dev = types::MessagingProvidersEnableDevelopmentEmailBody::new().with_provider_id("mp_123");
atlas.messaging_providers().enable_development_email(&dev).await?;
# Ok(()) }
```

`Webhook::verify` accepts an `atlas-signature` header that carries several signatures separated by spaces
(`v1,<sig> v1,<sig>`). While an endpoint secret rotates, Atlas may sign each delivery with the old and the new
secret; the delivery verifies when any one signature matches.

### Webhook rotation overlaps and the trusted reverse proxy

A webhook rotation stops the old secret at once by default. Pass an overlap (at most 7 days) to keep it signing
each delivery next to the new one while you deploy; choose one only once every receiver accepts several
signatures. If a reverse proxy serves the Frontend API from your own origin, give it a proxy secret: it sends the
secret in `X-Atlas-Proxy-Secret` and the browser's IP in `X-Atlas-Client-IP`, and Atlas uses that IP for rate
limits, lockout, risk signals and audit logs.

```rust,no_run
# async fn demo(atlas: &atlasauth::backend::BackendClient) -> Result<(), atlasauth::backend::BackendError> {
use atlasauth::backend::{types, RotateWebhookSecretBody};
let rotated = atlas
    .webhook_endpoints()
    .rotate_secret_with("whep_123", &RotateWebhookSecretBody::new().with_overlap_seconds(3600))
    .await?;
println!("old secret signs until {:?}", rotated.previous_secret_expires_at);

let created = atlas.instance().create_proxy_secret(&types::InstanceCreateProxySecretBody::new()).await?;
println!("store this in your proxy, shown once: {}", created.secret);
let state = atlas.instance().get_proxy_secret().await?; // set, created_at, previous_expires_at
let _ = state.set;
// Rotate: the old secret keeps working for an hour.
atlas.instance().create_proxy_secret(&types::InstanceCreateProxySecretBody::new().with_overlap_seconds(3600)).await?;
atlas.instance().delete_proxy_secret().await?;
# Ok(()) }
```

Platform rotations take an overlap too: `platform().apps().rotate_instance_secret_with(..,
&RotatePlatformSecretBody::new().with_overlap_seconds(0), ..)` (default 72 hours),
`platform().atlas_id_apps().rotate_secret_with(..)` (default 24 hours) and `rotate_webhook_secret_with(..)`
(default 0).

### Policy acceptance

Terms of service, a privacy policy or any policy your users accept at sign-up (and again at sign-in when a new
version takes effect):

```rust,ignore
let tos = atlas.policies().create(&types::PoliciesCreateBody::default()
    .with_key("tos").with_title("Terms of service")).await?;
atlas.policies().create_version("tos", &version_body).await?;      // a draft, or publish at once
atlas.policies().publish_version("tos", "2026-10-24", &publish_body).await?; // effective_at in epoch ms
let standing = atlas.users().get_policies("user_123", &Query::new()).await?;
let csv = atlas.policies().export_acceptances_csv("tos", &Query::new()).await?;
```

`instance().set_policy_source(..)` connects an external system that serves your policy text (the signing secret is
write-only); `instance().update_policy_settings(..)` turns on the `pol` session claim, which `Claims::pol()` and
`Claims::has_accepted_policy(key, version)` read.

To serve the feed yourself (feature `backend`), `verify_policy_feed_request(&PolicyFeedRequest { .. })` checks Atlas's
signed `GET {endpoint_url}/policies` request, and `sign_policy_source_event(&PolicySourceEvent::Published { key, version }, secret)`
produces the signed body and headers to POST to the source's `webhook_url`.

### Referral attribution

With referral attribution on, Atlas reports every interactive sign-up to your referral platform before
`user.created` is sent. `User` gains `referral` (who referred them, or `None`), `referral_code` and `referral_link`.

```rust,ignore
use atlasauth::backend::{types, Query, UpdateUserBody};

let body = types::InstanceUpdateReferralsBody::new()
    .with_enabled(true)
    .with_provider("webhook") // the Atlas referral protocol; or a built-in vendor adapter
    .with_endpoint_url("https://referrals.example.com/atlas")
    .with_signing_secret(std::env::var("REFERRAL_SIGNING_SECRET")?)
    .with_security(types::InstanceUpdateReferralsBodySecurity::new().with_on_high_risk("hold"))
    .clear_link_template(); // sent as null
atlas.instance().update_referrals(&body, None).await?;
let test = atlas.instance().test_referrals().await?; // ok, http_status, latency_ms, error
let failed = atlas.instance().list_referral_calls(&Query::new().set("status", "failed")).await?;
atlas.instance().retry_referral_call(&failed.data[0].id, None).await?;

atlas.users().update("user_123", &UpdateUserBody { referral_code: Some(Some("ada-1".into())), ..Default::default() }).await?;
atlas.users().flag_referral("user_123", Some("self-referral"), None).await?;
```

Enabling without what the provider needs is `422 REFERRALS_NOT_CONFIGURED`; a code another user holds is
`409 REFERRAL_CODE_TAKEN`. A late answer from the platform arrives as the `user.referral_attributed` webhook
(`EventType::UserReferralAttributed`, data `UserReferralAttributedEvent`).

Two-way sync: a provider with the `inbound` capability sends referral changes made after sign-up back to Atlas.
The settings report `inbound` (`url` to give the platform, `secret_set`, `endpoint_id`, and `last_event` with
`at`, `type`, `outcome`). Store the platform's event secret with `with_inbound_secret` (write-only, 16-512
characters) and its subscription id with `with_inbound_endpoint_id`; `clear_inbound_secret` /
`clear_inbound_endpoint_id` send null.

Browser capture: `browser_sources` lists the referral programs whose script or cookie the browser reads
(`clear_browser_sources` goes back to the provider's default, reported by `browser_sources_default`), and
`consent_provider` picks the consent manager that decides (`auto`, one manager, or `app`).

### Migrate from Better Auth

Import the sealed bundle the Better Auth exporter wrote (`npx atlas-better-auth-export --public-key <kid:key>`;
the key is `better_auth_imports().get_public_key()` → `compact`):

```rust
use atlasauth::backend::{types, BackendClient, UploadOptions, WaitOptions};

# async fn demo(bundle: String) -> Result<(), Box<dyn std::error::Error>> {
let atlas = BackendClient::new("sk_live_...")?;
let imports = atlas.better_auth_imports();
let imp = imports.upload(&bundle, UploadOptions::default()).await?;   // parts of ≤ 8 MiB, then finalize
let imp = imports.wait_for(&imp.id, WaitOptions::default()).await?;    // a large bundle is analyzed in the background
// Read imp.report (models, conflicts, skipped, action items), then:
let done = imports.apply(&imp.id, &types::BetterAuthImportsApplyBody::new().with_confirm_conflicts(true)).await?;
let done = imports.wait_for(&done.id, WaitOptions::default()).await?;  // `completed`, or `failed` (apply again resumes)
# let _ = done; Ok(()) }
```

**No forced logout.** Turn the session bridge on (`better_auth_bridge().update(...)` with `enabled`, `ends_at`,
`cookie_prefix` and an optional `live_fallback`), then put the bridge in front of your routes. A returning user's
Better Auth cookie is exchanged once, server to server with your secret key (forwarding the user's IP and user
agent), for Atlas session cookies:

```rust
use std::sync::Arc;
use atlasauth::backend::{BackendClient, BetterAuthBridge};
use atlasauth::axum::{AtlasLayer, BetterAuthBridgeLayer};

# fn demo(backend: Arc<atlasauth::AtlasBackend>) -> Result<(), Box<dyn std::error::Error>> {
let bridge = Arc::new(BetterAuthBridge::new(BackendClient::new("sk_live_...")?).sign_in_url("/sign-in"));
let session = AtlasLayer::new(backend).with_better_auth_bridge(bridge.clone()); // or BetterAuthBridgeLayer::new(bridge)
# let _ = session; Ok(()) }
```

Without Axum, call `bridge.decide(cookie_header, client_ip, user_agent).await` and render the `BridgeDecision`
(`should_redirect()`, `cookies[i].to_set_cookie()`, `continuation_url(..)`), or use
`exchange_better_auth_session` directly. Better Auth cookies are cleared only when the refusal is final, so a
closed bridge, a 429 or an outage retries on a later request.

**Better Auth JWTs** your API clients still hold can be accepted until a cutover date:

```rust
use std::sync::Arc;
use atlasauth::{AtlasBackend, BackendSubjectResolver, LegacyIssuer};

# fn demo(client: atlasauth::backend::BackendClient) -> Result<(), Box<dyn std::error::Error>> {
let backend = AtlasBackend::builder("https://your-instance-fapi.atlasauth.net")
    .jwks_url("https://your-instance-fapi.atlasauth.net/.well-known/jwks.json")
    .legacy_issuer(
        LegacyIssuer::until_rfc3339("https://app.example.com", "2026-12-31T00:00:00Z")
            .jwks_url("https://app.example.com/api/auth/jwks"),
    )
    .legacy_subject_resolver(Arc::new(BackendSubjectResolver::new(client))) // sub → Atlas user via external_id
    .build()?;
# let _ = backend; Ok(()) }
```

Verified claims carry `sub` (the Atlas id), `external_id` (the Better Auth id) and `extra["legacy"]`. EdDSA,
ES256, RS256 and PS256 are accepted; **ES512 is not supported by this crate** (its signature backend has no
P-521), so ES512 tokens are refused — let them expire, or verify them elsewhere during the window.

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

Test and review accounts (0.26): `platform().atlas_id_apps().provisioned_accounts()` creates accounts
confined to one app (`list`, `create`, `get`, `remove`, `rotate_password`). It needs the scope
`platform:atlas_id_apps:provision`, or `atlas_id_apps:<app id>:provision` for a single app. The password is
returned once as `password`, or as `sealed_password` when the client has a `secret_recipient`; `Debug` never
prints it. `platform().domains()` (`list`, `claim`, `check`, `remove`) manages the verified domains that
`test_mode` and `provisioned_verified_domains_only` (on `UpdateAtlasIdAppBody`) rely on. New error codes:
`TEST_ACCOUNT_RESTRICTED`, `PROVISIONED_ACCOUNT_LIMIT_REACHED`, `DOMAIN_NOT_VERIFIED`.

`platform().apps()` provisions and manages the apps your platform owns, and
`platform().upload_design_asset(...)` uploads images for app designs.

## Integrator platform (0.23)

Secret keys, `whoami`, partner links, the privacy executor client, identity
integrations, webhook health / replay / signature v2, status, notices, audit
exports and the operator device login live next to the rest of the Management
API (`backend` feature; `client` for the CLI login helpers).

```rust
use atlasauth::backend::{
    metadata_query, new_traceparent, BackendClient, CreateSecretKeyBody, ProvisioningInput, Query,
};
use atlasauth::HttpMethod;

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let atlas = BackendClient::new("atlas_live_sk_...")?; // atlas_<env>_sk_… and sk_live_… both work

// What am I calling with?
let me = atlas.whoami().await?;
println!("{} {:?}", me.key["type"], me.key["effective_scopes"]);

// Mint a scoped, expiring key (the secret is in `secret` once, or sealed — see below)
let key = atlas
    .secret_keys()
    .create(
        &CreateSecretKeyBody { name: Some("ci".into()), scopes: vec!["read_only".into()], ..Default::default() },
        Some("idem-ci-1"),
    )
    .await?;

// Preview any write: the changes it would make, nothing changes
let plan = atlas
    .dry_run(HttpMethod::Patch, "/v1/platform/apps/ins_1", Some(serde_json::json!({"name": "New"})))
    .await?;
assert!(plan.dry_run);

// Trace a call end to end: the trace id lands on webhook deliveries it triggers
let traced = atlas.with_traceparent(Some(new_traceparent()));
traced.webhook_endpoints().test_now("we_1", "10s").await?;

// Idempotent provisioning: external_ref + metadata tags, filter by tag
let body = ProvisioningInput { external_ref: Some("tenant-42".into()), ..Default::default() }
    .apply(serde_json::json!({"name": "Tenant 42"}));
# let _ = (key, body);
# Ok(()) }
```

- **Credentials**: `secret_keys()` (create / list / get / update / rotate with
  overlap / revoke), `keys()`, `partner_links()` (+ `.outbound()`),
  `atlas_id_grants()`, `platform().whoami()` / `list_keys` / `create_key` /
  `audit_logs` / audit streams. `is_secret_key`, `is_platform_key`,
  `is_webhook_secret`, `parse_key_prefix` … accept the `atlas_<env>_<kind>_…`
  and legacy (`sk_` / `pk_` / `psk_` / `whsec_`) formats.
- **Webhooks**: `webhook_endpoints().get` / `upsert_by_url` / `test_now` /
  `redeliver_window` / `replay` / `deliveries_with`, the health fields on
  `WebhookEndpoint`, destinations (EventBridge, Pub/Sub, Cloudflare Queues),
  `delivery()` (health, egress IPs, alert contacts). `Webhook::verify_url`
  verifies the URL-bound `v2` signature; `canonical_webhook_event` /
  `webhook_event_spellings` map the deprecated event names.
- **Privacy executor**: `privacy()` (lookup, requests, orchestrator),
  `verify_privacy_call` for the signed calls and `privacy_request.*` events
  (with the `traceparent` Atlas sent).
- **Identity integrations**: `instance().set_integration` /
  `integration_deliveries`, `sessions().get_integration_token`,
  `integrations().card` / `revoke_sessions`, public instance metadata.
- **Instance**: `unknown_fields_report`, `openapi_diff`, `integration_health`,
  `embed`, `preflight_with`, `status()`, `notices()`, `security_advisories()`,
  `sub_processors()`, `audit_exports()`, `entitlements()`.
- **Lists**: `users().list_query(&Query)` (`updated_after`, `order_by`), cursor
  `starting_after` on org memberships, revoked keys and the delivery logs.
- **Errors**: `AtlasApiError::is_insufficient_scope()` (accepts the old
  `SCOPE_MISSING`), `required_scope()`, `is_step_up_required()`,
  `is_route_not_found()` + `did_you_mean()`, and the new codes in `codes::`.
- **Back-channel logout**: `AtlasBackend::handle_backchannel_logout` verifies
  the token, runs your callback and returns the `200` / `400` / `503 +
  Retry-After` answer (`BackchannelLogoutResponse`).

### CLI login (`client` feature)

```rust
use std::sync::Arc;
use atlasauth::client::*;
use atlasauth::{HttpTransport, ReqwestTransport};

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let http: Arc<dyn HttpTransport> = Arc::new(ReqwestTransport::new());
let opts = OperatorOptions::default();

let start = start_operator_login(&http, None, &opts).await?;
println!("Open {} and enter {}", start.verification_uri, start.user_code);
let operator = poll_operator_login(&http, &start, &opts).await?;

// A one-hour token bound to one instance, with only the scopes you ask for
let t = exchange_operator_token(&http, &operator.access_token, "ins_123", &["users:read"], &opts).await?;
# let _ = t; Ok(()) }
```

Root actions need a multi-factor sign-in within five minutes (otherwise
`STEP_UP_REQUIRED`, see `OperatorError::is_step_up_required`).
`partner_link_token` runs `client_credentials` for a partner service and
`revoke_leaked_keys` reports leaked credentials. With the `backend` feature,
`backend_client_from_access_token` builds a `BackendClient` from the token.

### Sealed secrets (`sealed-box` feature)

```rust
use atlasauth::{generate_seal_key_pair, open_sealed_secret};
use atlasauth::backend::BackendClient;

# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
let pair = generate_seal_key_pair();
let atlas = BackendClient::builder("atlas_live_sk_...").secret_recipient(pair.recipient()).build()?;
let key = atlas.secret_keys().rotate("key_1", Some(0), None, None).await?;
let secret = open_sealed_secret(key.sealed_secret.as_deref().unwrap(), &pair)?; // never in plaintext on the wire
# let _ = secret; Ok(()) }
```

Built on the `crypto_box` crate (libsodium `crypto_box_seal`).

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
