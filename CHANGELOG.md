# Changelog

All notable changes to the `atlasauth` crate are documented here.

## 0.9.0

- **API key spend caps.** `CreateApiKeyBody::limits` and
  `UpdateApiKeyBody::limits` (`Some(None)` removes the caps) take
  `types::ApiKeyLimit` (`unit`, `amount`, `period`: `request`, `day`, `month`
  or `total`; build one with `ApiKeyLimit::new(unit, amount, period)`). `ApiKey`
  gains `limits` and `usage` (`types::ApiKeyLimitState`: `unit`, `period`,
  `amount`, `used`, `remaining`, `window_start`, `resets_at`).
- **Usage metering.** `api_keys().record_usage(id, &types::ApiKeysRecordUsageBody)`
  (`amount`, `unit`, optional `idempotency_key`) returns
  `types::ApiKeyUsageDebit` (`key_id`, `unit`, `amount`, `allowed`, `code`,
  `exceeded`, `usage`, `counters`, `idempotent_replay`); a refusal is
  `allowed: false` with `code` `"LIMIT_EXCEEDED"`, not an error.
  `api_keys().get_usage(id)` returns `types::ApiKeyUsage` (`key_id`, `limits`,
  `usage`, `counters` of `types::ApiKeyUsageCounter`).
- **Verify.** `ApiKeyVerification` gains `name`, `scopes`, `constraints`,
  `limits` (`ApiKeyCap`), `usage` (`ApiKeyCapUsage`) and `expires_at`.
- **Session keep-alive.** `sessions().touch(id)` returns `types::SessionTouch`
  (the session plus `idle_expires_at` and `extended`). `Session` gains
  `idle_expires_at`.
- **Users.** `CreateUserBody::notify` and
  `types::ImportExportImportUsersBody::notify` (unset or `false` sends nothing to
  the user).
- **Webhooks.** `EventType` gains `ApiKeyCreated`, `ApiKeyUpdated`,
  `ApiKeyRevoked`, `ApiKeyLimitReached`, `EntitlementOverrideCreated`,
  `EntitlementOverrideDeleted` and `EntitlementOverrideExpired`. These types
  used to arrive as `EventType::Other(..)`.
- **Error codes.** `codes::LIMIT_EXCEEDED`, `SESSION_REVOKED`,
  `SESSION_IDLE_EXPIRED` and `SESSION_EXPIRED`.
- **Breaking (struct literals only).** `CreateApiKeyBody`, `UpdateApiKeyBody`,
  `CreateUserBody`, `ApiKeyVerification` and `EventType` have new fields or
  variants; code that builds these with `..Default::default()` or matches
  `EventType` with a wildcard arm is unaffected.
- Coverage: 450 Backend API and Platform API operations.

## 0.8.0

- **Typed long-tail API.** The 285 Backend API / Platform API operations that
  0.7 exposed as JSON in, JSON out (roles and permissions, OAuth clients,
  SSO/LDAP/SCIM, FGA and the OpenFGA-compatible API, connectors, data subject
  requests, templates, localizations, log streams, network ACLs, RADIUS, rate
  limits, risk-based MFA, bot signals, jobs, test-mode helpers, and the remaining
  user, organization and instance routes) now take and return structs from the
  new `backend::types` module, generated from the API's published schemas. The
  method names are unchanged; their `serde_json::Value` parameters and results
  are replaced (e.g. `roles().create(&types::RolesCreateBody::new().with_key("editor"))`
  returns a `types::Role`).
  - Request structs: `Type::new()` plus `with_*` setters (or `default()` and
    field assignment); unset optional fields are omitted, `clear_*` sends `null`
    where a value can be cleared, and `with_extra` sends a field this crate
    does not know yet.
  - Response structs keep any field added by the server after this release in
    an `extra` map; an absent list reads as empty.
  - Enumerations are `String`s (known values listed in each field's docs), so a
    new server value never breaks decoding. Structs are `#[non_exhaustive]`, so
    new fields can be added without a breaking release.
  - Where the API documents a request or response as open-ended JSON (the
    instance branding update and preview bodies, the API-key verification
    result, the OpenFGA write result), that side stays `serde_json::Value`.
  - `BackendClient::request_value` still calls any route with raw JSON.

## 0.7.0

- **Full Backend API and Platform API coverage.** `BackendClient` now has a
  method for every public Backend API and Platform API route (447 operations).
  New typed surfaces are listed below; every other route — roles and
  permissions, OAuth clients, SSO/LDAP/SCIM connections, FGA and the
  OpenFGA-compatible API, connectors, data subject requests, email/SMS
  templates, localizations, log streams, network ACLs, RADIUS clients, rate
  limits, risk-based MFA, bot signals, jobs, imports/exports, redirect URLs,
  JWT templates, and the test-mode helpers, plus the remaining user and
  organization sub-resources — gets one method per route that takes and
  returns `serde_json::Value`. List methods take a new `Query` builder for
  `limit`, `starting_after`, and filters.
- **Back-channel logout.** `AtlasBackend::verify_logout_token(token, client_id)`
  verifies an OpenID Connect back-channel `logout_token` (RS256, issuer,
  audience, `iat`/`exp`, `jti`, the logout event, `sid`/`sub`, no `nonce`,
  `typ: logout+jwt`) and returns `LogoutTokenClaims { sub, sid, jti, iat }`.
  `LogoutTokenReplayCache` refuses a replayed `jti`. Available without any
  feature flag.
- **Sign in with Atlas apps (Platform API).** `platform().atlas_id_apps()`
  creates, lists, updates, deletes and rotates the secret of Sign in with Atlas
  apps, with post-logout redirect URIs, back-/front-channel logout URIs, and
  branding (theme, colours, legal links, page copy, design);
  `preview_design()` renders a design without saving it.
  `platform().apps()` provisions and manages owned apps, and
  `platform().upload_design_asset()` / `list_design_assets()` /
  `delete_design_asset()` manage platform design images. Build the client with
  a `psk_…` platform key.
- **Sign-in page design.** `design()` reads, replaces, merge-patches and
  previews the instance design and per-organization designs, uploads/lists/
  deletes design images, and reads the design catalog. The design document is
  fully typed (`AtlasDesign` and its sections).
- **Raw uploads.** Image uploads send the raw bytes with their content type
  (detected from the bytes when not given). `HttpTransport` gains a
  `send_full` method (with a default implementation, so existing transports
  keep compiling) that carries a binary body and returns response headers.
- **Strict request bodies.** `BackendClientBuilder::strict(true)` sends
  `Atlas-Strict: true` on every write so an unknown body field is refused with
  `422 UNKNOWN_FIELD`; `strict(false)` opts out of an instance-wide default.
  `BackendClient::with_strict(..)` overrides it per call.
  `BackendClientBuilder::on_unknown_fields(..)` reports the fields the server
  ignored (`Atlas-Unknown-Fields`).
- **Instance preflight.** `instance().preflight()` returns typed findings
  (severity, code, message, fix, subject).
- **Cookie consent.** `instance().get_cookie_consent()` /
  `set_cookie_consent()` / `delete_cookie_consent()`.
- **Typed email and SMS delivery providers.** `messaging_providers()` with
  `EmailProviderConfig` (resend, ses, smtp, brevo, mailgun) and
  `SmsProviderConfig` (twilio, vonage, messagebird, plivo, telnyx, sinch,
  infobip, clicksend, bandwidth, aws_sns), plus `get`, `delete`, and `test`.
- **Social sign-in providers.** `oauth_providers()`: list with `provider` /
  `configured` filters, get, upsert (credentials, `display_name`, `icon_url`,
  `mode`, and wallet `settings` — `WalletSettings` builds them, `None` clears a
  value), delete, enable/disable, sign-in/sign-up scope, and a credentials test.
  Responses include `icon_url`, `mode`, and `setting_values`.
- **Webhook endpoints.** `webhook_endpoints()`: list (with the subscribable
  events and retry schedule), create, update, delete, reveal/rotate secret,
  send a test event, list deliveries, and redeliver.
- **Typed organization policy.** `OrgPolicy` (read it with
  `OrganizationPolicy::typed()`) and `organizations().patch_policy(id,
  &OrgPolicyPatch { .. })`, where `Some(None)` clears a key.
- **Error codes.** `backend::codes` names the stable codes worth branching on
  (`UNKNOWN_FIELD`, `WRONG_KEY_SURFACE`, `INVALID_KEY`, `PLAN_IN_USE`,
  `EMAIL_DELIVERY_NOT_CONFIGURED`, `EMAIL_PROVIDER_REQUIRED`, …).
- **Fix: entitlement override lookup.** `entitlement_overrides().get(id)` called
  a route that does not exist. It now lists the overrides and returns the
  matching one (or a `404 NOT_FOUND` error), and is deprecated in favour of
  `list()` with a subject filter. `EntitlementOverride` also exposes
  `created_by` and `created_at`.
- **Fix: notification categories.** Categories are keyed by `key` with a
  `label`; the client sent `name`/`description`, which the server ignores.
  `NotificationCategoryBody` and `NotificationCategory` gain `key` and `label`
  (the old fields still work and are sent under the new names), and
  `notification_categories().get(key)` — which also called a route that does
  not exist — now lists and filters.

## 0.6.3

- **Filter + paging for enrolment-token listing.** `machines().list_enrolment_tokens()`
  is unchanged (first page, every scope), and a new
  `machines().list_enrolment_tokens_with(&ListEnrolmentTokensParams { .. })` adds
  organization scoping and cursor paging. `organization_id` takes an `OrgFilter`:
  `OrgFilter::Org(id)` for one organization, or `OrgFilter::OrgLess` to select the
  org-less (platform) pool (sent on the wire as `organization_id=null`); leaving it
  unset returns tokens across every scope. `limit` (1–100) and `starting_after`
  page the results.
- **`next_cursor` on the list envelope.** The `ListPage<T>` returned by the
  backend list methods now exposes `next_cursor: Option<String>` alongside
  `has_more` — the opaque cursor to pass back as the next page's `starting_after`.
  It is `None` on routes that return a single unpaged page. Additive only.
- **Self-service client from a stored session.** `SelfServiceClient::from_stored(&stored)`
  builds a self-service client directly from a `StoredSessionManager`, driven by
  the persisted session — calls auto-refresh and the client follows the same
  session the stored manager signs out and revokes, with no hand-built
  `StaticBearer`. `StoredSessionManager::manager_arc()` exposes the shared manager
  handle this uses.

## 0.6.2

- **Enrolment `device_key`.** `EnrolMachineBody` gains an optional `device_key`
  field — an opaque, client-chosen per-device handle sent at enrolment. On the
  native (`machine` feature) client, `MachineClient::enroll_with` takes the same
  optional value; the existing `MachineClient::enroll` signature is unchanged.
  The field is omitted from the request when unset.
- **`machines().redeem()`.** New backend method for `POST /v1/machines/redeem`:
  redeem an enrolment token and resolve it to its payload (`data`), the owner
  user / organization it binds to, and the token's own `id`, returned as the new
  `RedeemedEnrolment` type.
- **`device_key` on machine records.** The `Machine`, `EnrolledMachine`, and
  native `Enrollment` response types now echo back the `device_key` recorded at
  enrolment.
- **Stored-session options.** `StoredSessionManager` adds two options, both
  backwards compatible:
  - `StoredSessionManager::new_without_jwt(...)` persists the rotating refresh
    token but keeps the short-lived session JWT out of the secure store, so a
    reload always refreshes before first use.
  - `set_app_value` / `app_value` store a small opaque app-held value alongside
    the session in the same blob; it is cleared automatically on sign-out.
