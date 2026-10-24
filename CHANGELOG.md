# Changelog

All notable changes to the `atlasauth` crate are documented here.

## 0.24.0 — 2026-10-24

### Added

- **Enterprise SSO claims.** `Claims` gains `sso_connection_id`, `sso_organization_id` (the Atlas organization that owns the connection, absent for an instance-wide one, independent of `org_id`) and `sso_connection_type` (`saml` | `oidc`). New OIDC relying-party readers: `oidc_organization_of`, `oidc_organizations_of`, `oidc_sso_of` (`OidcSsoContext`: `connection_id`, `organization_id`, `connection_type`, `tenant_id`, `issuer`, `domain`) and `oidc_authorize_url_with_organization`. Scope a per-organization "require SSO" rule on `sso_organization_id`, never on "signed in via SSO".
- **Adopting a Sign in with Atlas app.** `platform().atlas_id_apps().set_managed_by(id, &AtlasIdAppsSetManagedByBody)` (`PUT /v1/platform/atlas_id_apps/{id}/managed_by`; `::new(instance)` hands it over, `::release()` takes it back). `AtlasIdApp` gains `managed_via` (`instance_toggle` | `adopted`) and `button_rendered_origins`.
- **Instance-surface app setup check.** `atlas_id_grants().preflight(app_id)` (`GET /v1/atlas_id_apps/{id}/preflight`). `AtlasIdAppPreflight` gains `button_rendered_origins`, `authorize_requests_7d`, `fallback_origins` and `homepage_includes_script`.
- **Dry run.** `DryRunResult` gains `warnings`, `would_return_status`, `suppressed` and `validation_skipped` (`DryRunValidationSkipped`); `mode` is `native`, `rollback` or `plan`.
- **Sealed secrets.** `sealed_secret`, `sealed_client_secret`, `sealed_webhook_secret`, `sealed_token` and `secrets_sealed` (`SecretsSealed`) on every generated response that carries a shown-once secret, and on `AtlasIdApp`. `secret_recipient` already sends `X-Secret-Recipient` on every call, so every newly covered route answers sealed. The generator adds the fields (`scripts/sealed_fields.py`).
- `ListPage::object`; `WebhookEndpoint::last_failing_since`; `AtlasApiError::is_origin_not_allowed` and `codes::ORIGIN_NOT_ALLOWED`.

## 0.23.0 — 2026-10-24

### Added

- **Integrator platform surface.** `whoami()`; `secret_keys()` (create with `owner` / `expires_at` / `allowed_ips` / `key_format`, list, get, update, rotate with overlap, revoke) and `keys()`; `partner_links()` with `.outbound()`; `atlas_id_grants()`; `platform().whoami()`, `list_keys` / `create_key` / `update_key` / `revoke_key`, `audit_logs` and the audit streams (`list` / `create` / `update` / `delete` / `test`); `platform().apps()`: `create_secret_key`, `secret_keys_with`, `clone_config`, `sandbox_teardown`. Typed `SecretKey`, `PartnerLink`, `Whoami`; the other bodies are generic over `Serialize` and the other responses are `serde_json::Value`.
- **Privacy executor.** `privacy()`: `discover`, `preset`, `lookup`, `create_request` / `get_request` / `cancel_request`, and the orchestrator settings. `verify_privacy_call` verifies the signed case calls and `privacy_request.*` events (HMAC, five-minute window, the `traceparent` Atlas sent); `privacy_request_from_event`.
- **Identity integrations.** `instance().list_integrations` / `get_integration` / `set_integration` / `delete_integration` / `integration_deliveries` / `reveal_integration_events_secret` / `integration_atlas_id_token`; `sessions().get_integration_token` (the `getToken({for})` mint); `integrations()`: `report_verify_error`, `card`, `revoke_sessions`, `instance_metadata`.
- **Webhooks.** New endpoint fields (`signature_versions`, `event_naming`, `alert_contacts`, `destination`, `external_ref`, `metadata`, health: `consecutive_failures`, `success_rate_24h`, `last_failure`, `attempts_24h`, `replay`); `UpdateWebhookEndpointBody` carries them and event destinations. `webhook_endpoints()`: `get`, `list_with`, `upsert_by_url`, `test_now` (`?wait=`), `redeliver_window`, `replay`, `deliveries_with` (status / event_type / since / until / `starting_after`, `latency_ms`). `delivery()`: `health`, `egress_ips`, `set_alert_contacts`. `Webhook::verify_url` for the URL-bound `v2` signature (`v1` accepted unless `require_v2`; unknown versions ignored). The deprecated event spellings (`WEBHOOK_EVENT_ALIASES`, `canonical_webhook_event`, `webhook_event_spellings`, `Event::canonical_type`) and the new event types (`webhook_endpoint.*`, `delivery_target.*`, `webhook.test`, `secret_key.expiring` / `revoked`, `privacy_request.*`, `user.deletion_scheduled` / `canceled`).
- **Instance and status.** `unknown_fields_report`, `openapi_diff`, `integration_health` / `integration_health_providers`, `embed`, `preflight_with`, `install_referral` (provider id `referalli`), `messaging_providers().channel`, `design().import_brand_url` / `remove_brand`; `status()` (subscription, incidents, dependencies), `notices()`, `security_advisories()`, `sub_processors()`, `audit_exports()`, `entitlements()`.
- **Provisioning and tracing.** `BackendClient::dry_run` / `with_dry_run` (`?dry_run=true`, no `Idempotency-Key`), `ProvisioningInput` (`external_ref`, `metadata`) and `metadata_query` for tag filters, `with_traceparent` / builder `traceparent`, `new_traceparent` / `parse_traceparent` / `traceparent_from_headers`.
- **Lists.** `users().list_query` (`updated_after` / `updated_before` / `order_by=-updated_at`), `organizations().memberships(id).list_query`, `api_keys().list_revoked_query`.
- **Errors.** `codes::INSUFFICIENT_SCOPE` (the former `SCOPE_MISSING` is still accepted by `AtlasApiError::is_insufficient_scope`), `STEP_UP_REQUIRED`, `ROUTE_NOT_FOUND`, `NOT_A_LIVE_INSTANCE`, `TEST_MODE_ONLY`, `TESTING_UNAVAILABLE`, `PARTNER_LINK_UNAVAILABLE`; `AtlasErrorItem` gains `docs_url`, `did_you_mean`, `allowed_methods`; `AtlasApiError::required_scope`, `is_step_up_required`, `is_route_not_found`, `did_you_mean`, `is_not_found`.
- **Key formats.** `is_secret_key`, `is_platform_key`, `is_publishable_key`, `is_webhook_secret`, `is_partner_link_secret`, `is_access_token`, `parse_key_prefix` accept `atlas_<live|test>_<kind>_…` and `sk_` / `pk_` / `psk_` / `whsec_`.
- **Back-channel logout.** `AtlasBackend::handle_backchannel_logout` and `BackchannelLogoutResponse` (`200` / `400` / `503` + `Retry-After`); the token verifier is unchanged.
- **CLI device login** (feature `client`). `start_operator_login`, `poll_operator_login`, `exchange_operator_token`, `partner_link_token`, `revoke_leaked_keys`, `get_operator_configuration`; `backend_client_from_access_token` with `backend`.
- **Sealed secrets** (new feature `sealed-box`, the vetted `crypto_box` crate). `BackendClient` `secret_recipient` (sends `X-Secret-Recipient`), `generate_seal_key_pair`, `open_sealed_secret`, `seal_box`, `open_sealed_box`.

### Not included

- The generated catalog (`src/backend/catalog.rs`, `types.rs`) was not regenerated: the API spec is produced by a running server and the catalog generator was not run for this release. The routes above are hand-written; the catalog's list methods already take a free-form `Query`, so `since` / `starting_after` work there.

## 0.22.0 — 2026-10-24

### Added

- **Policy acceptance.** `policies()` (catalog regenerated from the current API, nothing removed): `list`, `create`, `get`, `update`, `delete` (a never-published policy is deleted, one with history is retired), `list_versions`, `create_version` (a draft, or `publish` with `effective_at`), `get_version`, `update_version` / `delete_version` (drafts only), `publish_version` (`effective_at`), `retire_version`, `list_acceptances`, and the hand-written `export_acceptances_csv(id, &Query)`. `users().get_policies(id, &Query)` returns a user's standing on every policy. `instance()`: `get_policy_settings` / `update_policy_settings` (the `pol` session claim) and `get_policy_source` / `set_policy_source` (the signing secret is write-only) / `delete_policy_source` / `test_policy_source` / `sync_policy_source` / `list_policy_source_deliveries`.
- **Policy source protocol helpers** (feature `backend`). `verify_policy_feed_request(&PolicyFeedRequest { .. })` checks Atlas's signed `GET {endpoint_url}/policies` (`atlas-signature` `v1,<base64 HMAC-SHA256>` over `{id}.{timestamp}.GET\n{path+query}`, millisecond timestamps, several `v1` values accepted, 5-minute window; the result carries the `key` query parameter), and `sign_policy_source_event(&PolicySourceEvent::Published { key, version } | Retired { key }, secret)` signs `policy.published` / `policy.retired` events for Atlas. Cross-checked against the TypeScript reference vectors.
- `Claims::pol()` and `Claims::has_accepted_policy(key, version)` read the `pol` claim. Webhook `EventType::UserPolicyAccepted` (`user.policy_accepted`) and `EventType::PolicyVersionPublished` (`policy.version_published`).
- `scripts/gen_catalog.py` knows the `/v1/policies` namespace and the method names of the policy routes.

## 0.21.0 — 2026-10-24

### Added

- **Migrate from Better Auth — bundle import.** `better_auth_imports()` (catalog regenerated from the current API): `get_public_key`, `rotate_public_key`, `create`, `list`, `get`, `upload_part`, `finalize`, `dry_run`, `apply`, `delete`, `list_jwks`, `delete_jwk`, typed as one shared `types::BetterAuthImport` (status, progress, the dry-run `report`, the `result`), `types::BetterAuthImportKey` and `types::BetterAuthImportOptionsInput`. Helpers: `upload(bundle, UploadOptions)` creates the import, uploads the sealed bundle in line-aligned parts of at most 8 MiB (`split_bundle_parts`, `BETTER_AUTH_IMPORT_PART_BYTES`) and finalizes it; `wait_for(id, WaitOptions)` polls until the import leaves `analyzing` / `queued` / `applying`.
- **Better Auth session bridge.** `better_auth_bridge()`: `get` / `update` / `delete` the bridge settings (migration window, cookie prefix, live fallback with a write-only secret) and `exchange(token, &ExchangeParams)` — the secret-key exchange, forwarding the end user's IP and user agent (`X-Atlas-Client-IP`, `X-Atlas-Client-User-Agent`) and never retried (the token is single use). `exchange_better_auth_session` classifies the answer (`BetterAuthExchangeResult::Session` / `NeedsMfa` / `Refused` with a `BridgeRefusal`). `BetterAuthBridge` is the framework-neutral bridge: it reads the Better Auth cookie, exchanges it once and returns a `BridgeDecision` with the Atlas cookies to set and the Better Auth cookies to clear (cleared only on final refusals), plus `continuation_url` for a second factor. Cookie helpers `better_auth_cookie_names`, `read_better_auth_session_cookie`, `client_ip_from_headers`.
- **Axum.** `axum::BetterAuthBridgeLayer` and `AtlasLayer::with_better_auth_bridge(bridge)` (features `axum` + `backend`): a `GET` / `HEAD` carrying a Better Auth session cookie is answered with a `307` to the same URL carrying the Atlas session cookies (or to the bridge's sign-in URL when a second factor is owed).
- **Better Auth JWTs during the cutover.** `AtlasBackendBuilder::legacy_issuer(LegacyIssuer)`: a token whose `iss` is the old issuer, inside its window, is verified against that issuer's own keys only (`jwks` or `jwks_url`), must carry `exp`, and has its `sub` mapped to the Atlas user — by `LegacyIssuer::resolve_subject`, or by `legacy_subject_resolver(Arc::new(BackendSubjectResolver::new(client)))` (feature `backend`), which looks the user up by `external_id` and caches it for five minutes. Verified claims carry `sub` (Atlas id), `external_id` (the old id) and `extra["legacy"]`. Accepted algorithms: EdDSA, ES256, RS256, PS256 (`LEGACY_ISSUER_ALGS`). **ES512 is not supported** by this crate's signature backend: an ES512 token is refused and naming `ES512` is a build error.
- `action_gallery().installs(..)` (`GET /v1/action_gallery_installs`), which the catalog generator had skipped.

## 0.20.0 — 2026-10-24

### Added

- **DPoP (RFC 9449) on the access-token verifier.** `AtlasBackend::verify_access_token_request(&ResourceRequest { method, url, authorization, dpop }, &options)` accepts a DPoP-bound token (`cnf.jkt`) only with the DPoP scheme and a valid proof (never as Bearer): `typ` `dpop+jwt`, `DPOP_ALGS` (ES256, ES384, RS256/384/512, PS256/384/512, EdDSA; no ES512, which the signature backend lacks), public embedded JWK, signature, `htm`, normalised `htu` (`normalize_htu`; `public_origin` for path-only URLs), `iat` window, `ath` (`dpop_access_token_hash`), `jti` replay via a `DpopReplayStore` (a process-wide `MemoryDpopReplayStore` by default), RFC 7638 `jwk_thumbprint` match. `require_dpop` refuses unbound tokens; `dpop_nonces` (`HmacDpopNonceSource`) demands a server nonce (`use_dpop_nonce`; `AccessTokenResult::dpop_nonce()` for the `DPoP-Nonce` header). `AccessTokenResult::Ok` gains `dpop_bound` / `dpop_nonce`, `Refused` gains `dpop_nonce`. `build_challenge(scheme, …)` renders `DPoP` challenges with `algs`; `protected_resource_metadata` advertises `dpop_signing_alg_values_supported`; `protected_resource_metadata_requiring_dpop`. `verify_access_token(authorization, …)` stays (no proof, so bound tokens are refused). Axum: `axum::AtlasAccessTokenLayer` guards routes with an access token, checks the DPoP proof against the request, inserts the `AccessTokenResult` into extensions and sets `DPoP-Nonce`. `sha2`, `base64` and `hmac` are now regular dependencies.
- **Catalog regenerated** for the new Backend API surface (no public type, method or field removed or retyped): billing `get_subscription`, `get_settings` / `update_settings`, `check_feature`, `sync_plan_entitlements`, plan `kind` / `limits` / `seat_feature_id`, usage `feature` / `subscription_id`; `custom_oauth_providers()` (CRUD, `discover`, `preview_profile_mapping`, `preview_provider_profile_mapping`, signing keys); SSO connection relying-party settings, SAML Single Logout fields, `preview_profile_mapping`, signing keys and the SAML encryption-key methods; `action_gallery()` and `action_templates()`, `actions().gallery_update`; sessions `set_custom_data` / `update_custom_data`; `instance().set_wallet_rpc_secret`, `get_signing_key_provider` / `set_signing_key_provider` / `remove_signing_key_provider`; rate-limit `rules`; attack protection `dormant_accounts`; OAuth client and resource-server token format, lifetimes and `introspection_client_ids`.
- **Opaque access tokens.** `AccessTokenOptions::introspection` (an `Arc<Introspector>`, with the `backend` or `client` feature) validates non-JWT access tokens at Atlas's RFC 7662 endpoint with your API's client credentials, cached by token hash (TTL, negative TTL, never past `exp`, bounded); `IntrospectionOptions::introspect_jwts` checks JWTs live too.
- **Vercel BotID attestations.** `create_botid_attestation(secret, is_bot, is_verified_bot, ttl_seconds, now_seconds)` (feature `backend`) signs a verdict in Atlas's `atlas_botid.v1` format.
- **Device sign-in approval** on `client::SelfServiceClient`: `lookup_device_authorization`, `approve_device_authorization`, `deny_device_authorization` (`PendingDeviceAuthorization`); `ClientApiError::code` / `needs_reverification` / `is_invalid_code`; `client::format_user_code`, `client::user_code_from_url`.
- **Upstream logout on sign-out.** `SelfServiceClient::revoke_session_for_logout(session_id, return_url)` returns `SessionLogout` with the upstream OIDC `upstream_logout_url` and the SAML `saml_logout_url` (https only) to open in the system browser.
- Webhook `EventType::SessionUpdated` (`session.updated`) and `EventType::UserReactivated` (`user.reactivated`).
- `instance().set_account_linking_trust(...)` and `instance().set_captcha_config(...)`; `backend::CAPTCHA_PROVIDERS` (incl. `captchafox`, `vercel_botid`), `LINKING_TRUST_LEVELS`, `BILLING_PROVIDERS`, `SIGNING_KEY_PROVIDERS`, `EMAIL_TEMPLATE_ACCOUNT_REACTIVATED`; `Session::custom_data()`.

### Changed

- The `backend` feature now also enables `rand` (for the BotID `jti`).
- With introspection compiled in but not configured, a token that is not a JWT is refused with "configure `introspection` to accept opaque tokens" instead of "malformed".

## 0.19.0 — 2026-10-23

### Added

- **Backend client, regenerated from the current API.** App roles (`app_roles()`: list, create, get, update, delete, `list_users`; per user `users().get_app_roles` / `set_app_roles` / `remove_app_role`), organization teams (`list_teams`, `create_team`, `get_team`, `update_team`, `delete_team`, `list_team_members`, `add_team_member`, `remove_team_member`) and org-scoped roles (`list_roles`, `create_role`, `update_role`, `delete_role`), `get_by_slug`, `check_slug`, `resend_invitation`; billing providers (`list_providers`, `get_provider`, `set_provider`, `test_provider`, `delete_provider`) and `change_subscription` / `cancel_subscription` / `restore_subscription`; `list_signing_keys` / `rotate_signing_key` (RS256 or ES256); `oauth_initial_access_tokens()`; `scim_tokens().update`; `list_before_user_create_calls`, `get_referral_call`. Request and response types carry the new fields: user search filters and `ban_expires_at`, timed-ban bodies, API key controls (`enabled`, `rate_limit`, `remaining`, `prefix`, `expires_in_seconds`, `required_scopes`, coded verify refusals), OAuth client `disabled` / `require_pkce` / `subject_type` / `sector_identifier_uri` / `client_secret_expires_at`, resource server `publish_resource_metadata` / `signing_alg`, plan `provider` / `annual_price_id`, import `external_id` / `created_at` / phones / `organization_memberships` / `create_organizations` / `password_hash_config`.
- `Claims::app_roles` / `app_permissions` / `has_app_role` / `has_app_permission` (no active organization needed).
- **Access-token verification for your API.** `AtlasBackend::verify_access_token(authorization, &AccessTokenOptions)` checks an Atlas-issued OAuth access token locally (issuer, expiry, `token_use`, audience, scopes) and returns `AccessTokenResult::Refused` with the RFC 6750 / RFC 9728 `WWW-Authenticate` challenge; `build_www_authenticate`, `protected_resource_metadata`, `protected_resource_metadata_path`. DPoP-bound tokens are refused.

### Changed

- Session and logout-token verification accept **ES256** as well as RS256 (`SIGNING_ALGS`), and nothing else; `Jwk` reads `crv` / `x` / `y`, and the token's `kid` selects one key whose type fixes the algorithm.

## 0.18.0

### Added

- Referral settings carry browser capture: `browser_sources` (the referral programs whose script or cookie the browser reads; null on update resets to the provider's default), `browser_sources_default`, and `consent_provider` (`auto`, one consent manager, or `app`). Builders `with_browser_sources` / `clear_browser_sources` and `with_consent_provider` (catalog regenerated from the spec).

## 0.17.0

### Added

- **Two-way referral sync.** Referral settings carry two-way sync: `inbound` (`url`, `secret_set`, `endpoint_id`, `last_event`) on reads, write-only `inbound_secret` and `inbound_endpoint_id` on updates (null clears), and provider capability `inbound`. Builders `with_inbound_secret` / `clear_inbound_secret` and `with_inbound_endpoint_id` / `clear_inbound_endpoint_id` (catalog regenerated from the spec).

## 0.16.0

### Added
- **Referral delivery v2.** `instance().simulate_referral_signup(&body)` (a sign-up call for a throwaway `atlas_test_…` customer; no user is created), `instance().start_referral_backfill(&body)` and `instance().get_referral_backfill(id)`, `instance().retry_failed_referral_calls(&body)`. `instance().list_referral_calls` gains `starting_after` and `error_code` (`limit` up to 1000); calls carry `latency_ms`, `error_code`, `request_id`, `batch_id`, `response` and `highlights`.
- **Settings.** `get_referrals` / `update_referrals` gain `tracking_token`, `code_lookup_url`, `signup_code_field`, `forward_lifecycle`, `mirror_to_public_metadata`, `include_referral_claims`, and `connection.last_ping` / `connection.alert`. Provider id `referalli` (formerly `referally`, still accepted).
- **Sign-up hook.** `instance().get_before_user_create_hook()`, `update_before_user_create_hook(&body)` and `test_before_user_create_hook()`.
- **Users.** `users().get_referral(id)` returns the stored attribution. `types::UserReferral` gains `partner_external_ref`, `referral_status` and `notes`.
- **Webhooks.** `EventType::UserReferralResolved` (`user.referral_resolved`): attribution finished after `user.created`; the data is the full user.
- Preflight can report `referrals_secret_invalid`, `referrals_program_inactive`, `referrals_unreachable`, `referrals_clock_skew` and `referrals_external_id_unset`.

### Changed
- `UserReferral.status` is now where attribution stands (`pending`, `attributed`, `none`, `failed`, `held`, `flagged`) and is always present; the platform's own status moved to `referral_status`. `EventType` has a new variant, so exhaustive matches need updating.

## 0.15.0

### Added
- **Referral attribution settings.** `instance().get_referrals()` (`types::InstanceGetReferralsResponse`, with `security`: `types::ReferralSecuritySettings`, `connection` and `providers`), `instance().update_referrals(&types::InstanceUpdateReferralsBody, idempotency_key)` (nested `types::InstanceUpdateReferralsBodySecurity`; `clear_*` sends a nullable field as null), `instance().test_referrals()` (`types::InstanceTestReferralsResponse`), `instance().list_referral_calls(&Query)` (`limit`, `status`, `kind`, `user_id`; calls carry `risk`: `types::ReferralRisk`) and `instance().retry_referral_call(id, idempotency_key)`.
- **Users.** `User` gains `referral` (`types::UserReferral`: `partner_id`, `referrer_external_id`, `referrer_user_id`, `matched_via`, `status`, `risk_level`, `flagged`), `referral_code` and `referral_link`. `CreateUserBody` gains `referral` (`CreateUserReferral`: `code`, `click_id`, `anon_id`) and `referral_code`; `UpdateUserBody` gains `referral_code` (`Some(None)` sends null). New `users().flag_referral(id, reason, idempotency_key)` (`UserReferralFlag`).
- **Webhooks.** `EventType::UserReferralAttributed` (`user.referral_attributed`) and `UserReferralAttributedEvent` for its data.
- **Error codes.** `codes::REFERRALS_NOT_CONFIGURED` (422) and `codes::REFERRAL_CODE_TAKEN` (409). Preflight can report `referrals_enabled_unverified` and `referrals_without_bot_protection`.
- Catalog regenerated from the current spec (the referral operations; the generated `types::User` gains the referral fields).

### Changed
- `User`, `CreateUserBody` and `UpdateUserBody` have new public fields, and `EventType` a new variant: code that builds these structs without `..Default::default()`, or matches `EventType` exhaustively, needs updating.

## 0.14.0

### Added
- **Trusted reverse proxy secret.** `instance().get_proxy_secret()` (`types::ProxySecret`: `set`, `created_at`, `previous_expires_at`, `secret_header`, `client_ip_header`), `instance().create_proxy_secret(&types::InstanceCreateProxySecretBody)` (`overlap_seconds` on a rotation: default 86400, `0` stops the old secret now, at most 604800; returns `types::ProxySecretCreated` with `secret`, shown once, and `rotated`) and `instance().delete_proxy_secret()`.
- **Webhook secret rotation with an overlap.** `webhook_endpoints().rotate_secret_with(id, &RotateWebhookSecretBody)` (`overlap_seconds`, default 0, at most 604800). `WebhookSecret` gains `overlap_seconds` and `previous_secret_expires_at`; `WebhookEndpoint` gains `previous_secret_expires_at`.
- **Per-instance platform rotation with an overlap.** `platform().apps().rotate_instance_secret_with(id, instance_id, &RotatePlatformSecretBody, idempotency_key)` (`overlap_seconds`, default 259200, `0` revokes the prior keys now). The response carries `app_id`, `instance_id`, `overlap_seconds` and `previous_keys_expire_at`.
- **Sign in with Atlas apps.** `platform().atlas_id_apps().rotate_secret_with(id, &RotateAtlasIdAppSecretBody)` (default 24 hours) and `rotate_webhook_secret_with(id, &types::AtlasIdAppsRotateWebhookSecretBody)` (default 0). `AtlasIdApp` and the webhook rotate response gain `previous_secret_expires_at`, `secret_issued_at`, `webhook_previous_secret_expires_at` and `overlap_seconds`.
- Catalog regenerated from the current spec (doc text for managed email feedback on Resend).

### Changed
- `rotate_webhook_secret(id)` keeps its signature and now sends the default (empty) body; the server default is unchanged (no overlap).
- `platform().apps().rotate_instance_secret(..)` without a body now keeps the prior keys valid for 72 hours (the server's new default). Use `rotate_instance_secret_with` with `overlap_seconds` 0 for the old behaviour.

## 0.13.0

### Added
- **OAuth client secret rotation with overlap.** `oauth_clients().rotate_secret_with(id, &types::OAuthClientsRotateSecretBody, idempotency_key)` takes `overlap_seconds` (default 86400, `0` revokes the old secret now, at most 604800). `rotate_secret(id, idempotency_key)` keeps its signature (default overlap). The OAuth client responses gain `previous_secret_expires_at`; the rotate response gains `overlap_seconds`.
- **Development email sender.** `messaging_providers().get_development_email()`, `enable_development_email(&types::MessagingProvidersEnableDevelopmentEmailBody)` and `disable_development_email()` (`types::DevelopmentEmail`). `MessagingProviders` gains `development_email`.
- **Managed email on your own provider account.** `types::MessagingProvidersCreateManagedEmailBody` gains `transport`, `config` (`api_key`) and `provider_id`. `types::ManagedEmail` gains `provider_id` and `feedback_webhook`; `reputation` is `your_provider_account`. The delete response gains `provider_removed`.
- **Provider mode.** `MessagingProvider` gains `id` and `mode`; `messaging_providers().set_email_with_mode(&provider, Some("development"))`.
- **Allowed origins with an integration.** `AllowedOriginEntry` (`new`, `with_integration`, `REDIRECT` / `EMBEDDED` / `AUTO`); `types::InstanceUpdateBody::with_allowed_origin_entries(..)`; `CreatePlatformAppBody` and `UpdatePlatformAppBody` gain `allowed_origin_entries`.
- **Issuer and verification endpoints.** The instance responses gain `issuer`, `discovery_url`, `jwks_uri` and `allowed_origin_integrations`; `PlatformApp` gains `frontend_api_host`, `issuer`, `discovery_url`, `jwks_uri` and `allowed_origin_integrations`.
- **Login readiness.** `types::LoginReadiness` gains `integration` (`types::LoginReadinessIntegration`); each check gains `applies`.
- **Email verification.** `types::EmailAddressVerification` gains `strategy`.
- **Branding audiences.** `types::BrandingSettings` and the resolved branding gain `audiences`; `auth_config` gains `branding.audiences`, `strictRequestBodies` and `dangerouslyReportSkippedEmailsAsVerified`.
- **Error codes.** `codes::READ_ONLY_FIELD`, `DEVELOPMENT_EMAIL_NOT_ALLOWED`, `DEVELOPMENT_EMAIL_UNAVAILABLE`, `DEVELOPMENT_EMAIL_LIMIT_REACHED`, `DEVELOPMENT_EMAIL_TEMPLATE_NOT_ALLOWED`.
- **Webhooks, several signatures.** `Webhook::verify` / `verify_delivery` accept an `atlas-signature` header with several space-separated `v1,<signature>` entries and verify when any one matches (each compared in constant time). A single signature works as before.

### Changed (breaking)
- `types::InstanceUpdateBody::allowed_origins` is `Vec<Value>` (a string or `{ origin, integration }` per entry). Use `with_allowed_origin_entries(["https://a.example"])` for plain origins.
- `types::ManagedEmail::limits` is a `Value` (always `null` now); `types::ManagedEmailLimits` is removed.
- `types::OAuthClientsRotateSecretResponse` types the fields the API always returns as plain values (`object`, `id`, `client_id`, `client_secret`, `overlap_seconds`) instead of `Option`.
- **Struct literals only.** `MessagingProvider` and `PlatformApp` gain fields; `CreatePlatformAppBody` and `UpdatePlatformAppBody` gain `allowed_origin_entries` (use `..Default::default()`).

## 0.12.0

### Added
- **Back-channel logout, retryable failures.** `VerifyError::is_retryable()` is true for `NoKeys`: the issuer's keys could not be fetched (a network error, a JWKS outage, or a just-rotated key whose refetch failed). Answer `503` with `Retry-After` then, so Atlas retries the delivery, and `400` otherwise. A logout token whose `kid` is unknown after a failed JWKS refetch is now `NoKeys` (was `Invalid`).
- `Webhook::verify_delivery(raw, headers)` returns `VerifiedDelivery { event, delivery_id, timestamp }`:
  the envelope plus the signed `atlas-id` (stable across retries of one event; deduplicate on it) and
  `atlas-timestamp` (epoch ms). `Webhook::verify` is unchanged.
- **Full API coverage again.** Every Backend API and Platform API operation in the current public API has a
  method. New: `instance().move_origin` (domain moves), `instance().connections`,
  `instance().get_ / set_ / delete_chatly_integration` and `..._forumulate_integration`;
  `logout_notify_endpoints()` (`list`, `create`, `get`, `update`, `delete`, `list_deliveries`);
  `messaging_providers().get_ / create_ / verify_ / delete_managed_email`;
  `oauth_clients().list_backchannel_deliveries` / `test_backchannel_logout`; on `platform().atlas_id_apps()`:
  `list_backchannel_deliveries`, `test_backchannel_logout`, `preflight`, `find_users`, `revoke_grant`,
  `move_origin`, `rotate_webhook_secret`; `platform().atlas_id_publisher()` (`get`, `set`, `update`,
  `delete`, `verify`) and `platform().config_changelog`. Request and response types are in `types`.
- **More fields.** `User::version`; `CookieConsent::culture` and `declared_cookies` (`DeclaredCookie`);
  `SetCookieConsentBody::culture`; `Preflight::sdk_versions_seen` (`SdkVersionSeen`, `SdkAdvisory`);
  `WebhookDelivery::error` and `location`; `WebhookEndpointList::event_catalog` and `event_audiences`;
  `CustomDomain::dns`; `MessagingProviders::managed_email`; `AtlasIdApp::webhook_url`, `webhook_events`,
  `webhook_active`, `webhook_secret`; `UpdateAtlasIdAppBody::webhook_url`. In `types`: `BrandingResolved`
  gains every writable branding field plus the derived values, `ConfigChangelogEntry::target`,
  `types::User::version` and `UsersRevokeSessionsResponse::grants_revoked`.

## 0.11.0

### Added
- **Captcha is bring-your-own-keys.** `codes::CAPTCHA_KEYS_REQUIRED` (422) and `codes::CAPTCHA_IN_USE` (409, `meta.flows`).
- `InstanceSetCaptchaSecretBody::with_provider` stores the secret for a named provider before captcha is turned on.
- Bulk OAuth client import rows gain `logo_url`, `first_party` and `skip_logout_confirmation`.

### Changed (breaking)
- `instance().delete_captcha_secret(&Query)` and `instance().update(&body, &Query)` take a query (`provider` / `force`;
  `force`). Pass `&Query::new()` for the previous behaviour.
- The bulk import row's `allowed_scopes` is now `scopes`, the field the API actually reads (the old name was ignored).

## 0.10.0

- **OAuth clients.** `types::OAuthClientsCreateBody` and
  `types::OAuthClientsUpdateBody` gain `skip_logout_confirmation`
  (`with_skip_logout_confirmation`); the OAuth client responses
  (`types::OAuthClientsGetResponse`, `OAuthClientsCreateResponse`,
  `OAuthClientsUpdateResponse`, `OAuthClientsRotateSecretResponse`, the list
  and import items) gain `skip_logout_confirmation: Option<bool>`. First-party
  clients only (`422 VALIDATION_FAILED` on a third-party client); when true,
  RP-initiated logout with an exactly registered `post_logout_redirect_uri`
  redirects straight back without the confirmation page.
- **Cookie consent.** `SetCookieConsentBody::settings_link`
  (`Option<CookieSettingsLinkInput>`: `label`, `preset`, `attributes`) adds a
  footer "Cookie settings" link to the hosted pages. `CookieConsent` gains
  `settings_link: Option<CookieSettingsLink>` (`label`, `preset`,
  `attributes`, `rendered_attributes`). Preset names are in
  `cookie_settings_link_presets` (`COOKIEMUNCH`, `COOKIEBOT`, `ONETRUST`,
  `CUSTOM`); `preset` stays a `String`, so new values still decode.
- **Email provider removal.** `messaging_providers().delete_with(channel,
  &DeleteMessagingProviderParams { force })` sends `?force=true` to remove the
  email provider while email-dependent features are on. `delete(channel)` is
  unchanged.
- **Error codes.** `codes::EMAIL_PROVIDER_IN_USE` (409; `meta.features` lists
  the features that need email).
- **Sessions.** `Session` (from `sessions().get` / `list`) gains
  `last_active_organization_id` and `impersonated_by`. `types::Session` (from
  `users().list_sessions`) already carried them and `idle_expires_at`, which
  stays an `Option<i64>`.
- **Regenerated** from the current API reference (no new operations).
- **Breaking (struct literals only).** `CookieConsent`, `SetCookieConsentBody`
  and `Session` have new fields; code that builds `SetCookieConsentBody` with
  `..Default::default()` is unaffected.

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
