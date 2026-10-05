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

```toml
# Cargo.toml
[dependencies]
atlasauth = "0.1"
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

## Custom transport (no reqwest)

Disable the default feature to compile with no HTTP dependency and supply your
own transport by implementing `JwksSource` (for session verification) and/or
`HttpPost` (for API-key verification):

```toml
atlasauth = { version = "0.1", default-features = false }
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

## Development

```sh
cargo build
cargo test   # hermetic — generates keys in-test and mocks all HTTP; no network
cargo clippy
cargo fmt
```

## License

MIT.
