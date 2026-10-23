#!/usr/bin/env python3
"""Generate the long-tail Backend API / Platform API surface of the `atlasauth`
crate from the public OpenAPI document.

Usage (from sdks/rust):

    python3 scripts/gen_catalog.py                      # fetches the live spec
    python3 scripts/gen_catalog.py --spec openapi.json  # or a local copy
    python3 scripts/gen_catalog.py --report             # also list typed / JSON ops

Writes:

  src/backend/catalog.rs   resource namespaces with one method per operation:
                           a typed method (request struct in, response struct
                           out; serde_json::Value only where the schema is open)
  src/backend/types.rs     request/response structs generated from the schemas
  tests/catalog.rs         every operation (JSON and typed) hits its method+path
  tests/catalog_types.rs   every typed response decodes a sample and round-trips

Which operations: every BAPI + PLATFORM operation of the spec that the
hand-written modules (src/backend/*.rs other than the generated files) do not
already implement. Re-run after the API grows; the output is deterministic.

Type mapping:
  object with properties  -> struct (#[non_exhaustive], Default, serde
                             rename where the JSON name is not snake_case, and
                             a `#[serde(flatten)] extra` map keeping unknown keys)
  optional / nullable     -> Option<T> (request-only nullable optionals are
                             Option<Option<T>>: Some(None) sends null to clear;
                             an optional collection on a response-only type is a
                             plain Vec/map that reads as empty when absent)
  enum / const            -> String (known values listed in the doc) so a new
                             server value never breaks parsing
  array                   -> Vec<T>;  map (additionalProperties) -> HashMap<String, T>
  anyOf/oneOf of >1 shape, empty schema -> serde_json::Value
"""
import json, re, os, sys, glob, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SPEC_URL = 'https://api.atlasauth.net/v1/openapi.json'
GENERATED = {'catalog.rs', 'types.rs'}

def load_spec():
    src = SPEC_URL
    if '--spec' in sys.argv:
        src = sys.argv[sys.argv.index('--spec') + 1]
    if src.startswith('http'):
        req = urllib.request.Request(src, headers={'user-agent': 'atlasauth-rust-gen'})
        with urllib.request.urlopen(req) as r:
            return json.load(r)
    with open(src) as f:
        return json.load(f)

d = load_spec()
# Schemas the spec renamed while keeping the same shape: generate against the
# earlier name so existing method signatures stay source-compatible
# (e.g. branding().update(&types::BrandingSettings)).
REF_ALIAS = {'BrandingPatch': 'BrandingSettings'}
_raw = json.dumps(d)
for _new, _old in REF_ALIAS.items():
    _raw = _raw.replace(f'"#/components/schemas/{_new}"', f'"#/components/schemas/{_old}"')
d = json.loads(_raw)
comps = d['components']

# ── which operations ─────────────────────────────────────────────────────────
spec_ops = set()
for p, pops in d['paths'].items():
    for m, o in pops.items():
        if m in ('get', 'post', 'put', 'patch', 'delete') and o.get('tags', [''])[0] in ('BAPI', 'PLATFORM'):
            spec_ops.add((m.upper(), re.sub(r'\{[^}]+\}', '{}', p)))
handwritten = set()
for f in sorted(glob.glob(os.path.join(ROOT, 'src/backend/*.rs'))):
    if os.path.basename(f) in GENERATED:
        continue
    src = open(f).read()
    for body in re.split(r'\n\s*(?:pub(?:\([a-z]+\))? )?(?:async )?fn ', src)[1:]:
        methods = re.findall(r'HttpMethod::(Get|Post|Put|Patch|Delete)', body)
        paths = re.findall(r'"(/v1/[^"]*)"', body)
        for m in methods:
            for p in paths:
                handwritten.add((m.upper(), re.sub(r'\{[^}]*\}', '{}', p).split('?')[0]))
missing = spec_ops - handwritten

# Existing namespaces we EXTEND (struct, has-extra-field) -> how to reach parent id.
EXISTING = {
    'Users': None, 'Organizations': None, 'Instance': None, 'Billing': None, 'ApiKeys': None,
    'Sessions': None, 'Invitations': None, 'OrgSettingsSchemaApi': None,
    'MessagingProvidersApi': None, 'AtlasIdApps': None, 'AtlasIdPublisherApi': None, 'PlatformApi': None,
}

# prefix -> (Struct, accessor, doc). Longest prefix wins.
NS = [
    ('/v1/users', 'Users', None, None),
    ('/v1/organizations', 'Organizations', None, None),
    ('/v1/instance', 'Instance', None, None),
    ('/v1/billing', 'Billing', None, None),
    ('/v1/api_keys', 'ApiKeys', None, None),
    ('/v1/sessions', 'Sessions', None, None),
    ('/v1/invitations', 'Invitations', None, None),
    ('/v1/organization_settings_schema', 'OrgSettingsSchemaApi', None, None),
    ('/v1/messaging_providers', 'MessagingProvidersApi', None, None),
    ('/v1/platform/atlas_id_apps', 'AtlasIdApps', None, None),
    ('/v1/platform/atlas_id_publisher', 'AtlasIdPublisherApi', None, None),
    ('/v1/platform/config_changelog', 'PlatformApi', None, None),
    ('/v1/logout_notify_endpoints', 'LogoutNotifyEndpoints', 'logout_notify_endpoints', 'Logout fan-out endpoints: services that get the same logout_token as your OIDC apps'),
    ('/v1/actions', 'Actions', 'actions', 'Actions: custom code run on auth triggers'),
    ('/v1/app_roles', 'AppRoles', 'app_roles', 'App roles: instance-wide user roles (the app_roles / app_permissions claims)'),
    ('/v1/oauth_initial_access_tokens', 'OAuthInitialAccessTokens', 'oauth_initial_access_tokens', 'Initial access tokens for OAuth dynamic client registration (RFC 7591)'),
    ('/v1/actor_tokens', 'ActorTokens', 'actor_tokens', 'Actor (impersonation) tokens'),
    ('/v1/allowlist_identifiers', 'AllowlistIdentifiers', 'allowlist_identifiers', 'Sign-up allowlist'),
    ('/v1/blocklist_identifiers', 'BlocklistIdentifiers', 'blocklist_identifiers', 'Sign-up blocklist'),
    ('/v1/attack_protection', 'AttackProtection', 'attack_protection', 'Attack protection settings'),
    ('/v1/audit_logs', 'AuditLogs', 'audit_logs', 'The instance audit log'),
    ('/v1/bot_labels', 'BotSignals', 'bot_signals', 'Bot signals and labels'),
    ('/v1/bot_signals', 'BotSignals', 'bot_signals', 'Bot signals and labels'),
    ('/v1/branding', 'Branding', 'branding', 'Instance branding'),
    ('/v1/captcha', 'Captcha', 'captcha', 'CAPTCHA verification'),
    ('/v1/config_changelog', 'ConfigChangelog', 'config_changelog', 'The configuration change log'),
    ('/v1/connectors', 'Connectors', 'connectors', 'Connectors (custom OAuth providers) and the community directory'),
    ('/v1/data_subject_requests', 'DataSubjectRequests', 'data_subject_requests', 'Data subject (privacy) requests'),
    ('/v1/diagnostics', 'Diagnostics', 'diagnostics', 'Diagnostics'),
    ('/v1/directory', 'Directory', 'directory', 'The user directory'),
    ('/v1/email_addresses', 'EmailAddresses', 'email_addresses', 'Email addresses'),
    ('/v1/email_templates', 'EmailTemplates', 'email_templates', 'Email templates'),
    ('/v1/events', 'Events', 'events', 'The event log'),
    ('/v1/fga', 'Fga', 'fga', 'Fine-grained authorization (FGA) stores'),
    ('/v1/openfga', 'OpenFga', 'openfga', 'The OpenFGA-compatible API'),
    ('/v1/jobs', 'Jobs', 'jobs', 'Background jobs (imports and exports)'),
    ('/v1/jwt_templates', 'JwtTemplates', 'jwt_templates', 'JWT templates'),
    ('/v1/legacy_auth_connection', 'LegacyAuthConnection', 'legacy_auth_connection', 'The legacy-auth (lazy migration) connection'),
    ('/v1/localizations', 'Localizations', 'localizations', 'Localizations'),
    ('/v1/log_streams', 'LogStreams', 'log_streams', 'Log streams'),
    ('/v1/lti_platforms', 'LtiPlatforms', 'lti_platforms', 'LTI platforms'),
    ('/v1/managed_waf', 'ManagedWaf', 'managed_waf', 'The managed WAF'),
    ('/v1/mcp_connector', 'McpConnector', 'mcp_connector', 'The remote MCP connector'),
    ('/v1/mcp', 'Mcp', 'mcp', 'The Atlas MCP server'),
    ('/v1/network_acls', 'NetworkAcls', 'network_acls', 'Network ACLs'),
    ('/v1/oauth_clients', 'OAuthClients', 'oauth_clients', 'OAuth clients (Atlas as an OAuth provider)'),
    ('/v1/org_ldap_connections', 'OrgLdapConnections', 'org_ldap_connections', 'Organization LDAP connections'),
    ('/v1/pca', 'Pca', 'pca', 'Proof-carrying authority controls'),
    ('/v1/permissions', 'Permissions', 'permissions', 'Permissions'),
    ('/v1/radius_clients', 'RadiusClients', 'radius_clients', 'RADIUS clients'),
    ('/v1/rate_limit_policy', 'RateLimitPolicy', 'rate_limit_policy', 'The rate-limit policy'),
    ('/v1/redirect_urls', 'RedirectUrls', 'redirect_urls', 'Redirect URLs'),
    ('/v1/resource_servers', 'ResourceServers', 'resource_servers', 'Resource servers (APIs)'),
    ('/v1/risk_based_mfa', 'RiskBasedMfa', 'risk_based_mfa', 'Risk-based MFA'),
    ('/v1/roles', 'Roles', 'roles', 'Roles'),
    ('/v1/scim_provisioning_targets', 'ScimProvisioningTargets', 'scim_provisioning_targets', 'Outbound SCIM provisioning targets'),
    ('/v1/scim_tokens', 'ScimTokens', 'scim_tokens', 'Inbound SCIM tokens'),
    ('/v1/session_exchange_apps', 'SessionExchangeApps', 'session_exchange_apps', 'Session exchange apps'),
    ('/v1/sign_in_tokens', 'SignInTokens', 'sign_in_tokens', 'Sign-in tokens'),
    ('/v1/sms_templates', 'SmsTemplates', 'sms_templates', 'SMS templates'),
    ('/v1/sso_connections', 'SsoConnections', 'sso_connections', 'SSO connections'),
    ('/v1/sso_onboarding_profiles', 'SsoOnboarding', 'sso_onboarding', 'SSO self-serve onboarding'),
    ('/v1/sso_onboarding_tickets', 'SsoOnboarding', 'sso_onboarding', 'SSO self-serve onboarding'),
    ('/v1/test_instance', 'Testing', 'testing', 'Test-mode helpers'),
    ('/v1/test_users', 'Testing', 'testing', 'Test-mode helpers'),
    ('/v1/testing_tokens', 'Testing', 'testing', 'Test-mode helpers'),
    ('/v1/tokens', 'Tokens', 'tokens', 'Token verification'),
    ('/v1/usage', 'Usage', 'usage', 'Usage'),
    ('/v1/user_exports', 'ImportExport', 'import_export', 'User import and export'),
    ('/v1/user_imports', 'ImportExport', 'import_export', 'User import and export'),
    ('/v1/waitlist_entries', 'Waitlist', 'waitlist', 'The waitlist'),
]

# (struct, json field) pairs that stay Option<T> although the spec now marks
# them required: they shipped optional, and making them plain would break
# callers that match on the Option.
KEEP_OPTIONAL = {
    ('Session', 'idle_expires_at'),
}

# Exact (METHOD, template-path) -> method name overrides.
OVR = {
    ('GET', '/v1/app_roles/{id}/users'): 'list_users',
    ('GET', '/v1/users/{id}/app_roles'): 'get_app_roles',
    ('POST', '/v1/users/{id}/app_roles'): 'set_app_roles',
    ('DELETE', '/v1/users/{id}/app_roles/{roleId}'): 'remove_app_role',
    ('DELETE', '/v1/oauth_initial_access_tokens/{id}'): 'revoke',
    ('GET', '/v1/organizations/by_slug/{slug}'): 'get_by_slug',
    ('GET', '/v1/organizations/check_slug'): 'check_slug',
    ('GET', '/v1/organizations/{id}/roles'): 'list_roles',
    ('POST', '/v1/organizations/{id}/roles'): 'create_role',
    ('PATCH', '/v1/organizations/{id}/roles/{roleId}'): 'update_role',
    ('DELETE', '/v1/organizations/{id}/roles/{roleId}'): 'delete_role',
    ('GET', '/v1/organizations/{id}/teams'): 'list_teams',
    ('POST', '/v1/organizations/{id}/teams'): 'create_team',
    ('GET', '/v1/organizations/{id}/teams/{teamId}'): 'get_team',
    ('PATCH', '/v1/organizations/{id}/teams/{teamId}'): 'update_team',
    ('DELETE', '/v1/organizations/{id}/teams/{teamId}'): 'delete_team',
    ('GET', '/v1/organizations/{id}/teams/{teamId}/members'): 'list_team_members',
    ('POST', '/v1/organizations/{id}/teams/{teamId}/members'): 'add_team_member',
    ('DELETE', '/v1/organizations/{id}/teams/{teamId}/members/{userId}'): 'remove_team_member',
    ('POST', '/v1/organizations/{id}/invitations/{invitationId}/resend'): 'resend_invitation',
    ('GET', '/v1/billing/providers'): 'list_providers',
    ('GET', '/v1/billing/providers/{provider}'): 'get_provider',
    ('PUT', '/v1/billing/providers/{provider}'): 'set_provider',
    ('DELETE', '/v1/billing/providers/{provider}'): 'delete_provider',
    ('POST', '/v1/billing/providers/{provider}/test'): 'test_provider',
    ('POST', '/v1/billing/subscriptions/{id}/change'): 'change_subscription',
    ('POST', '/v1/billing/subscriptions/{id}/cancel'): 'cancel_subscription',
    ('POST', '/v1/billing/subscriptions/{id}/restore'): 'restore_subscription',
    ('GET', '/v1/instance/signing_keys'): 'list_signing_keys',
    ('POST', '/v1/instance/signing_keys/rotate'): 'rotate_signing_key',
    ('GET', '/v1/instance/hooks/before_user_create/calls'): 'list_before_user_create_calls',
    ('GET', '/v1/instance/referrals/calls/{id}'): 'get_referral_call',
    ('GET', '/v1/api_keys/{id}/usage'): 'get_usage',
    ('POST', '/v1/api_keys/{id}/usage'): 'record_usage',
    ('GET', '/v1/actions/bindings/{trigger}'): 'get_bindings',
    ('PUT', '/v1/actions/bindings/{trigger}'): 'set_bindings',
    ('GET', '/v1/attack_protection'): 'get',
    ('PATCH', '/v1/attack_protection'): 'update',
    ('GET', '/v1/bot_labels'): 'list_labels',
    ('POST', '/v1/bot_labels'): 'create_label',
    ('GET', '/v1/bot_signals'): 'list',
    ('GET', '/v1/branding'): 'get',
    ('PATCH', '/v1/branding'): 'update',
    ('POST', '/v1/branding/preview'): 'preview',
    ('POST', '/v1/captcha/verify'): 'verify',
    ('POST', '/v1/connectors/{slug}/install'): 'install',
    ('POST', '/v1/connectors/{slug}/reviews'): 'review',
    ('POST', '/v1/connectors/{id}/shared_credentials'): 'set_shared_credentials',
    ('GET', '/v1/diagnostics/login_readiness'): 'login_readiness',
    ('GET', '/v1/diagnostics/request_inspector'): 'request_inspector',
    ('GET', '/v1/directory'): 'list',
    ('POST', '/v1/email_addresses/{eid}/primary'): 'set_primary',
    ('POST', '/v1/email_addresses/{eid}/verify'): 'verify',
    ('PUT', '/v1/email_templates/{name}'): 'upsert',
    ('GET', '/v1/fga/stores'): 'list_stores',
    ('POST', '/v1/fga/stores'): 'create_store',
    ('GET', '/v1/fga/stores/{id}'): 'get_store',
    ('DELETE', '/v1/fga/stores/{id}'): 'delete_store',
    ('GET', '/v1/fga/stores/{id}/authorization-models'): 'list_authorization_models',
    ('POST', '/v1/fga/stores/{id}/authorization-models'): 'write_authorization_model',
    ('GET', '/v1/fga/stores/{id}/authorization-models/{mid}'): 'get_authorization_model',
    ('POST', '/v1/fga/stores/{id}/batch-check'): 'batch_check',
    ('POST', '/v1/fga/stores/{id}/list-objects'): 'list_objects',
    ('GET', '/v1/openfga/stores'): 'list_stores',
    ('POST', '/v1/openfga/stores'): 'create_store',
    ('GET', '/v1/openfga/stores/{store}'): 'get_store',
    ('GET', '/v1/openfga/stores/{store}/authorization-models'): 'read_authorization_models',
    ('POST', '/v1/openfga/stores/{store}/authorization-models'): 'write_authorization_model',
    ('GET', '/v1/openfga/stores/{store}/authorization-models/{mid}'): 'read_authorization_model',
    ('POST', '/v1/openfga/stores/{store}/batch-check'): 'batch_check',
    ('POST', '/v1/openfga/stores/{store}/list-objects'): 'list_objects',
    ('GET', '/v1/jobs/{id}/errors'): 'list_errors',
    ('GET', '/v1/legacy_auth_connection'): 'get',
    ('PUT', '/v1/legacy_auth_connection'): 'set',
    ('DELETE', '/v1/legacy_auth_connection'): 'delete',
    ('GET', '/v1/managed_waf'): 'get',
    ('PUT', '/v1/managed_waf'): 'set',
    ('GET', '/v1/managed_waf/status'): 'status',
    ('GET', '/v1/mcp_connector'): 'get',
    ('PUT', '/v1/mcp_connector'): 'set',
    ('DELETE', '/v1/mcp_connector'): 'delete',
    ('GET', '/v1/mcp'): 'get',
    ('POST', '/v1/mcp'): 'call',
    ('GET', '/v1/oauth_clients/{clientId}/grants'): 'list_grants',
    ('POST', '/v1/oauth_clients/{clientId}/grants'): 'create_grant',
    ('DELETE', '/v1/oauth_clients/{clientId}/grants/{grantId}'): 'delete_grant',
    ('POST', '/v1/oauth_clients/import'): 'import',
    ('GET', '/v1/pca/attestors'): 'get_attestors',
    ('PUT', '/v1/pca/attestors'): 'set_attestors',
    ('POST', '/v1/pca/freeze'): 'freeze',
    ('DELETE', '/v1/pca/freeze'): 'unfreeze',
    ('POST', '/v1/pca/revocations'): 'revoke',
    ('POST', '/v1/pca/stepups/{id}/deny'): 'deny_stepup',
    ('GET', '/v1/rate_limit_policy'): 'get',
    ('PATCH', '/v1/rate_limit_policy'): 'update',
    ('GET', '/v1/risk_based_mfa'): 'get',
    ('PATCH', '/v1/risk_based_mfa'): 'update',
    ('PUT', '/v1/roles/{id}/permissions'): 'set_permissions',
    ('GET', '/v1/sso_connections/{id}/saml_metadata'): 'saml_metadata',
    ('GET', '/v1/sso_onboarding_profiles'): 'list_profiles',
    ('POST', '/v1/sso_onboarding_profiles'): 'create_profile',
    ('GET', '/v1/sso_onboarding_profiles/{id}'): 'get_profile',
    ('DELETE', '/v1/sso_onboarding_profiles/{id}'): 'delete_profile',
    ('POST', '/v1/sso_onboarding_profiles/{id}/tickets'): 'create_ticket',
    ('POST', '/v1/sso_onboarding_tickets/{id}/revoke'): 'revoke_ticket',
    ('POST', '/v1/test_instance'): 'create_test_instance',
    ('POST', '/v1/test_users/purge'): 'purge_test_users',
    ('POST', '/v1/testing_tokens'): 'create_testing_token',
    ('POST', '/v1/tokens/verify'): 'verify',
    ('GET', '/v1/usage'): 'get',
    ('POST', '/v1/user_exports'): 'export_users',
    ('POST', '/v1/user_imports'): 'import_users',
    ('POST', '/v1/waitlist_entries/bulk'): 'bulk_create',
    ('POST', '/v1/invitations/bulk'): 'bulk_create',
    ('POST', '/v1/api_keys/verify'): 'verify',
    ('POST', '/v1/sessions/{id}/tokens/{template}'): 'create_token',
    ('POST', '/v1/organization_settings_schema'): 'create',
    ('GET', '/v1/instance'): 'get',
    ('PATCH', '/v1/instance'): 'update',
    ('PUT', '/v1/instance/captcha_secret'): 'set_captcha_secret',
    ('DELETE', '/v1/instance/captcha_secret'): 'delete_captcha_secret',
    ('PUT', '/v1/instance/kerberos_secret'): 'set_kerberos_secret',
    ('DELETE', '/v1/instance/kerberos_secret'): 'delete_kerberos_secret',
    ('PUT', '/v1/instance/ldap_connections/{connectionId}/bind_password'): 'set_ldap_bind_password',
    ('DELETE', '/v1/instance/ldap_connections/{connectionId}/bind_password'): 'delete_ldap_bind_password',
    ('GET', '/v1/instance/security'): 'get_security',
    ('PATCH', '/v1/instance/security'): 'update_security',
    ('PATCH', '/v1/billing/plans/{id}'): 'update_plan',
    ('POST', '/v1/billing/subjects/{type}/{id}/sync_seats'): 'sync_seats',
    ('POST', '/v1/billing/subscriptions/import'): 'import_subscriptions',
    ('POST', '/v1/billing/usage'): 'report_usage',
    ('POST', '/v1/users/by_emails'): 'by_emails',
    ('POST', '/v1/users/{id}/approval_requests'): 'create_approval_request',
    ('GET', '/v1/users/{id}/approval_requests/{approvalId}'): 'get_approval_request',
    ('POST', '/v1/users/{id}/consents'): 'create_consent',
    ('GET', '/v1/users/{id}/consents'): 'list_consents',
    ('POST', '/v1/users/{id}/directives'): 'push_directive',
    ('DELETE', '/v1/users/{id}/directives'): 'clear_directives',
    ('POST', '/v1/users/{id}/email_addresses'): 'create_email_address',
    ('POST', '/v1/users/{id}/email_addresses/{eid}/primary'): 'set_primary_email_address',
    ('POST', '/v1/users/{id}/email_addresses/{eid}/verify'): 'verify_email_address',
    ('POST', '/v1/users/{id}/external_accounts/connect'): 'connect_external_account',
    ('GET', '/v1/users/{id}/identities'): 'list_identities',
    ('POST', '/v1/users/{id}/identities'): 'link_identity',
    ('DELETE', '/v1/users/{id}/identities/by-provider/{provider}'): 'unlink_identity_by_provider',
    ('POST', '/v1/users/{id}/identities/import'): 'import_identities',
    ('DELETE', '/v1/users/{id}/identities/{identityId}'): 'unlink_identity',
    ('PUT', '/v1/users/{id}/metadata'): 'set_metadata',
    ('DELETE', '/v1/users/{id}/mfa/{factorId}'): 'delete_mfa_factor',
    ('GET', '/v1/users/{id}/notification_preferences'): 'get_notification_preferences',
    ('PATCH', '/v1/users/{id}/notification_preferences'): 'update_notification_preferences',
    ('GET', '/v1/users/{id}/oauth_access_tokens/{provider}'): 'oauth_access_tokens',
    ('DELETE', '/v1/users/{id}/passkeys/{passkeyId}'): 'delete_passkey',
    ('POST', '/v1/users/{id}/password'): 'set_password',
    ('POST', '/v1/users/{id}/phone_numbers'): 'create_phone_number',
    ('DELETE', '/v1/users/{id}/phone_numbers/{pid}'): 'delete_phone_number',
    ('POST', '/v1/users/{id}/phone_numbers/{pid}/verify'): 'verify_phone_number',
    ('DELETE', '/v1/users/{id}/profile_image'): 'delete_profile_image',
    ('POST', '/v1/users/{id}/progression/events'): 'record_progression_event',
    ('POST', '/v1/users/{id}/reset_mfa'): 'reset_mfa',
    ('GET', '/v1/users/{id}/resolved'): 'resolved',
    ('GET', '/v1/users/{id}/sessions'): 'list_sessions',
    ('POST', '/v1/users/{id}/sessions/revoke'): 'revoke_sessions',
    ('GET', '/v1/users/{id}/sign_in_history'): 'sign_in_history',
    ('GET', '/v1/users/{id}/state'): 'state',
    ('GET', '/v1/organizations/{id}/audit_streams'): 'list_audit_streams',
    ('POST', '/v1/organizations/{id}/audit_streams'): 'create_audit_stream',
    ('DELETE', '/v1/organizations/{id}/audit_streams/{streamId}'): 'delete_audit_stream',
    ('GET', '/v1/organizations/{orgId}/end_users'): 'list_end_users',
    ('POST', '/v1/organizations/{orgId}/end_users'): 'add_end_user',
    ('PATCH', '/v1/organizations/{orgId}/end_users/{userId}'): 'update_end_user',
    ('DELETE', '/v1/organizations/{orgId}/end_users/{userId}'): 'remove_end_user',
    ('PUT', '/v1/organizations/{orgId}/groups/{groupId}/roles/{roleId}'): 'assign_group_role',
    ('DELETE', '/v1/organizations/{orgId}/groups/{groupId}/roles/{roleId}'): 'unassign_group_role',
    ('GET', '/v1/organizations/{id}/hierarchy'): 'hierarchy',
    ('PUT', '/v1/organizations/{id}/metadata'): 'set_metadata',
    ('PUT', '/v1/organizations/{id}/parent'): 'set_parent',
    ('GET', '/v1/organizations/{orgId}/reader_domain'): 'get_reader_domain',
    ('POST', '/v1/organizations/{orgId}/reader_domain'): 'set_reader_domain',
    ('DELETE', '/v1/organizations/{orgId}/reader_domain'): 'delete_reader_domain',
    ('PATCH', '/v1/organizations/{id}/settings'): 'patch_settings',
    ('POST', '/v1/scim_tokens/{id}/revoke'): 'revoke',
    ('POST', '/v1/sign_in_tokens/{id}/revoke'): 'revoke',
    ('POST', '/v1/actor_tokens/{id}/revoke'): 'revoke',
    ('POST', '/v1/data_subject_requests/{id}/cancel'): 'cancel',
    ('POST', '/v1/data_subject_requests/{id}/fulfill'): 'fulfill',
    ('POST', '/v1/data_subject_requests/{id}/reject'): 'reject',
    ('POST', '/v1/waitlist_entries/{id}/decide'): 'decide',
    ('POST', '/v1/sms_templates/{name}/preview'): 'preview',
    ('POST', '/v1/email_templates/{name}/preview'): 'preview',
    ('POST', '/v1/managed_waf/provision'): 'provision',
    ('POST', '/v1/managed_waf/deprovision'): 'deprovision',
    ('POST', '/v1/oauth_clients/{id}/rotate_secret'): 'rotate_secret',
    ('GET', '/v1/instance/integrations/chatly'): 'get_chatly_integration',
    ('PUT', '/v1/instance/integrations/chatly'): 'set_chatly_integration',
    ('DELETE', '/v1/instance/integrations/chatly'): 'delete_chatly_integration',
    ('GET', '/v1/instance/integrations/forumulate'): 'get_forumulate_integration',
    ('PUT', '/v1/instance/integrations/forumulate'): 'set_forumulate_integration',
    ('DELETE', '/v1/instance/integrations/forumulate'): 'delete_forumulate_integration',
    ('GET', '/v1/logout_notify_endpoints/{id}/deliveries'): 'list_deliveries',
    ('GET', '/v1/messaging_providers/email/managed'): 'get_managed_email',
    ('POST', '/v1/messaging_providers/email/managed'): 'create_managed_email',
    ('DELETE', '/v1/messaging_providers/email/managed'): 'delete_managed_email',
    ('POST', '/v1/messaging_providers/email/managed/verify'): 'verify_managed_email',
    ('GET', '/v1/messaging_providers/email/development'): 'get_development_email',
    ('POST', '/v1/messaging_providers/email/development'): 'enable_development_email',
    ('DELETE', '/v1/messaging_providers/email/development'): 'disable_development_email',
    ('GET', '/v1/instance/proxy_secret'): 'get_proxy_secret',
    ('POST', '/v1/instance/proxy_secret'): 'create_proxy_secret',
    ('DELETE', '/v1/instance/proxy_secret'): 'delete_proxy_secret',
    ('GET', '/v1/instance/referrals'): 'get_referrals',
    ('PATCH', '/v1/instance/referrals'): 'update_referrals',
    ('GET', '/v1/instance/referrals/calls'): 'list_referral_calls',
    ('POST', '/v1/instance/referrals/calls/{id}/retry'): 'retry_referral_call',
    ('POST', '/v1/instance/referrals/test'): 'test_referrals',
    ('POST', '/v1/instance/referrals/simulate'): 'simulate_referral_signup',
    ('POST', '/v1/instance/referrals/backfill'): 'start_referral_backfill',
    ('GET', '/v1/instance/referrals/backfill/{id}'): 'get_referral_backfill',
    ('POST', '/v1/instance/referrals/calls/retry_failed'): 'retry_failed_referral_calls',
    ('GET', '/v1/instance/hooks/before_user_create'): 'get_before_user_create_hook',
    ('PATCH', '/v1/instance/hooks/before_user_create'): 'update_before_user_create_hook',
    ('POST', '/v1/instance/hooks/before_user_create/test'): 'test_before_user_create_hook',
    ('GET', '/v1/users/{id}/referral'): 'get_referral',
    ('GET', '/v1/oauth_clients/{id}/backchannel_deliveries'): 'list_backchannel_deliveries',
    ('POST', '/v1/oauth_clients/{id}/backchannel_logout/test'): 'test_backchannel_logout',
    ('GET', '/v1/platform/atlas_id_apps/{id}/backchannel_deliveries'): 'list_backchannel_deliveries',
    ('POST', '/v1/platform/atlas_id_apps/{id}/backchannel_logout/test'): 'test_backchannel_logout',
    ('GET', '/v1/platform/atlas_id_apps/{id}/users'): 'find_users',
    ('DELETE', '/v1/platform/atlas_id_apps/{id}/grants/{grantId}'): 'revoke_grant',
    ('POST', '/v1/platform/atlas_id_apps/{id}/webhook/rotate_secret'): 'rotate_webhook_secret',
    ('GET', '/v1/platform/atlas_id_publisher'): 'get',
    ('PUT', '/v1/platform/atlas_id_publisher'): 'set',
    ('PATCH', '/v1/platform/atlas_id_publisher'): 'update',
    ('DELETE', '/v1/platform/atlas_id_publisher'): 'delete',
    ('GET', '/v1/platform/config_changelog'): 'config_changelog',
}

# ── naming helpers ──────────────────────────────────────────────────────────
def snake(s):
    s = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s).replace('-', '_')
    return s.lower()

def pascal(s):
    parts = re.split(r'[^A-Za-z0-9]+', re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s))
    out = ''.join(p[:1].upper() + p[1:].lower() for p in parts if p)
    if not out or out[0].isdigit():
        out = 'T' + out
    return out

RUST_KW = {'type', 'ref', 'self', 'match', 'move', 'use', 'mod', 'impl', 'fn', 'struct', 'enum', 'trait',
           'loop', 'where', 'in', 'as', 'box', 'crate', 'dyn', 'override', 'final', 'async', 'await',
           'const', 'static', 'let', 'if', 'else', 'for', 'while', 'return', 'pub', 'mut', 'true', 'false',
           'super', 'extern', 'unsafe', 'continue', 'break', 'abstract', 'become', 'do', 'macro', 'priv',
           'typeof', 'unsized', 'virtual', 'yield', 'try', 'gen'}
NO_RAW = {'self', 'super', 'crate', 'Self'}

def pname(name, struct, index):
    n = snake(name)
    if n == 'id' and index == 0:
        if struct == 'Users': return 'user_id'
        if struct == 'Organizations': return 'org_id'
    if n in RUST_KW: n = n + '_'
    if n == 'type_': n = 'subject_type'
    return n

def field_ident(name):
    n = snake(name)
    n = re.sub(r'[^a-z0-9_]', '_', n)
    n = re.sub(r'_+', '_', n).strip('_') or 'field'
    if n[0].isdigit():
        n = 'n' + n
    if n in NO_RAW:
        return n + '_'
    if n in RUST_KW:
        return 'r#' + n
    return n

def default_name(method, rel):
    segs = [s for s in rel.split('/') if s]
    lits = [s for s in segs if not s.startswith('{')]
    ends_param = bool(segs) and segs[-1].startswith('{')
    if not segs:
        return {'GET': 'list', 'POST': 'create', 'PUT': 'set', 'PATCH': 'update', 'DELETE': 'delete'}[method]
    if ends_param and not lits:
        return {'GET': 'get', 'POST': 'create', 'PUT': 'upsert', 'PATCH': 'update', 'DELETE': 'delete'}[method]
    word = snake(lits[-1]) if lits else 'item'
    if method in ('POST', 'GET'): return word
    return {'PUT': 'set_', 'PATCH': 'update_', 'DELETE': 'delete_'}[method] + word

def deref(s):
    while isinstance(s, dict) and '$ref' in s:
        s = comps['schemas'][s['$ref'].split('/')[-1]]
    return s

def props_of(x):
    x = deref(x)
    out = set(x.get('properties', {}).keys())
    for k in ('allOf', 'anyOf', 'oneOf'):
        for y in x.get(k, []):
            out |= props_of(y)
    return out

def is_list_response(o):
    for c, r in o.get('responses', {}).items():
        if not c.startswith('2'):
            continue
        sch = ((r.get('content') or {}).get('application/json') or {}).get('schema', {})
        pr = props_of(sch)
        if 'data' in pr or 'has_more' in pr:
            return True
    return False

def json_request_schema(o):
    rb = o.get('requestBody')
    if not rb:
        return None
    c = rb.get('content', {}).get('application/json')
    if c is None:
        return None
    return c.get('schema', {})

def json_response(o):
    """(kind, schema): kind is 'json' (schema), 'empty' (2xx with no body), or None."""
    for c, r in sorted(o.get('responses', {}).items()):
        if not c.startswith('2'):
            continue
        content = r.get('content') or {}
        if not content:
            return 'empty', None
        j = content.get('application/json')
        if j and j.get('schema') is not None:
            return 'json', j['schema']
        return None, None
    return None, None

# ── type generation ─────────────────────────────────────────────────────────
def doc_lines(text, width=92):
    text = (text or '').replace('\r', ' ').replace('\n', ' ').strip()
    if not text:
        return []
    text = text.replace('[', '\\[').replace(']', '\\]').replace('<', '&lt;').replace('>', '&gt;')
    words, lines, cur = text.split(), [], ''
    for w in words:
        if cur and len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + ' ' + w).strip()
    if cur:
        lines.append(cur)
    return lines

def merged_object(s):
    """Merge an object schema with its allOf parts -> (properties, required, additionalProperties)."""
    s = deref(s)
    props, req, addl = {}, set(), s.get('additionalProperties')
    for part in s.get('allOf', []):
        p2, r2, a2 = merged_object(part)
        props.update(p2)
        req |= r2
        if a2 is not None:
            addl = a2
    props.update(s.get('properties', {}) or {})
    req |= set(s.get('required', []) or [])
    return props, req, addl

def is_struct_schema(s):
    s = deref(s)
    if not isinstance(s, dict):
        return False
    if s.get('properties'):
        return True
    if s.get('allOf'):
        return any(is_struct_schema(p) for p in s['allOf'])
    return False

class TypeGen:
    def __init__(self):
        self.structs = {}        # rust name -> dict
        self.order = []
        self.taken = set()
        self.comp_names = {}     # component -> rust type name
        self.in_progress = set()

    def unique(self, name):
        base, n = name, 2
        while name in self.taken:
            name = f'{base}{n}'
            n += 1
        self.taken.add(name)
        return name

    def rtype(self, s, ctx, req, direct=True):
        """-> (rust type, nullable)"""
        if s is None or s is True or s == {}:
            return 'Value', False
        if not isinstance(s, dict):
            return 'Value', False
        if '$ref' in s:
            cname = s['$ref'].split('/')[-1]
            t = self.component(cname, req)
            if direct and t in self.in_progress:
                return f'Box<{t}>', False
            return t, False
        for key in ('anyOf', 'oneOf'):
            if key in s:
                variants = [v for v in s[key] if not (isinstance(v, dict) and v.get('type') == 'null')]
                nullable = len(variants) != len(s[key])
                if len(variants) == 1:
                    t, n2 = self.rtype(variants[0], ctx, req, direct)
                    return t, nullable or n2
                return 'Value', False
        if s.get('allOf') and not s.get('properties') and len(s['allOf']) == 1:
            return self.rtype(s['allOf'][0], ctx, req, direct)
        t = s.get('type')
        nullable = False
        if isinstance(t, list):
            nn = [x for x in t if x != 'null']
            nullable = len(nn) != len(t)
            if len(nn) != 1:
                return 'Value', False
            t = nn[0]
        if 'const' in s and t is None:
            return ('String', nullable) if isinstance(s['const'], str) else ('Value', False)
        if 'enum' in s and t is None:
            return ('String', nullable) if all(isinstance(v, str) for v in s['enum']) else ('Value', False)
        if t == 'string':
            return 'String', nullable
        if t == 'integer':
            return 'i64', nullable
        if t == 'number':
            return 'f64', nullable
        if t == 'boolean':
            return 'bool', nullable
        if t == 'array':
            it, _ = self.rtype(s.get('items'), ctx + 'Item', req, direct=False)
            return f'Vec<{it}>', nullable
        if t == 'object' or s.get('properties') or s.get('allOf'):
            if is_struct_schema(s):
                return self.make_struct(ctx, s, req), nullable
            ap = s.get('additionalProperties')
            if isinstance(ap, dict) and ap:
                vt, _ = self.rtype(ap, ctx + 'Value', req, direct=False)
                return f'HashMap<String, {vt}>', nullable
            return 'Map<String, Value>', nullable
        return 'Value', False

    def component(self, cname, req):
        if cname in self.comp_names:
            t = self.comp_names[cname]
            if req and t in self.structs:
                self.mark_req(t)
            return t
        s = comps['schemas'][cname]
        if is_struct_schema(s):
            name = self.unique(pascal(cname))
            self.comp_names[cname] = name
            self.make_struct(name, s, False, fixed=True, comp=cname)
            if req:
                self.mark_req(name)
            return name
        t, _ = self.rtype(s, pascal(cname), req)
        self.comp_names[cname] = t
        return t

    def mark_req(self, name, seen=None):
        seen = seen or set()
        if name in seen or name not in self.structs:
            return
        seen.add(name)
        self.structs[name]['setters'] = True
        for f in self.structs[name]['fields']:
            for inner in re.findall(r'[A-Z][A-Za-z0-9]*', f['ty']):
                if inner in self.structs:
                    self.mark_req(inner, seen)

    def make_struct(self, name, s, req, fixed=False, comp=None):
        if not fixed:
            name = self.unique(name)
        props, required, _ = merged_object(s)
        st = dict(name=name, doc=deref(s).get('description') or (f'The `{comp}` object.' if comp else ''),
                  fields=[], req_only=req and not comp, setters=req, schema=s)
        self.structs[name] = st
        self.order.append(name)
        self.in_progress.add(name)
        used = {'extra'}
        for pn, ps in props.items():
            ident = field_ident(pn)
            if ident == 'extra':
                ident = 'extra_field'
            base, k = ident, 2
            while ident in used:
                ident = f'{base}_{k}'
                k += 1
            used.add(ident)
            ty, nullable = self.rtype(ps, name + pascal(pn), req)
            psd = deref(ps) if isinstance(ps, dict) else {}
            doc = psd.get('description', '') if isinstance(psd, dict) else ''
            enum = None
            if isinstance(psd, dict):
                if 'enum' in psd:
                    enum = [v for v in psd['enum'] if isinstance(v, str)]
                elif 'const' in psd and isinstance(psd['const'], str):
                    enum = [psd['const']]
                else:
                    for key in ('anyOf', 'oneOf'):
                        for v in psd.get(key, []):
                            if isinstance(v, dict) and 'enum' in v:
                                enum = [x for x in v['enum'] if isinstance(x, str)]
            st['fields'].append(dict(json=pn, ident=ident, ty=ty, nullable=nullable,
                                     required=pn in required and (name, pn) not in KEEP_OPTIONAL, doc=doc, enum=enum, schema=ps))
        self.in_progress.discard(name)
        return name

    def field_kind(self, st, f):
        """-> (declared type, serde attrs, setter inner type, kind)"""
        rawname = f['ident'][2:] if f['ident'].startswith('r#') else f['ident']
        attrs = []
        if rawname != f['json']:
            attrs.append(f'rename = "{f["json"]}"')
        if f['required'] and not f['nullable']:
            attrs.append('default')
            return f['ty'], attrs, 'plain'
        if f['required'] and f['nullable']:
            attrs.append('default')
            return f'Option<{f["ty"]}>', attrs, 'opt'
        if not st['setters'] and not f['nullable']:
            # Response-only: an absent collection reads as empty.
            for prefix in ('Vec', 'HashMap', 'Map'):
                if f['ty'].startswith(prefix + '<'):
                    attrs += ['default', f'skip_serializing_if = "{prefix}::is_empty"']
                    return f['ty'], attrs, 'plain'
        if f['nullable'] and st['req_only']:
            attrs += ['default', 'skip_serializing_if = "Option::is_none"', 'deserialize_with = "double_option"']
            return f'Option<Option<{f["ty"]}>>', attrs, 'opt2'
        attrs += ['default', 'skip_serializing_if = "Option::is_none"']
        return f'Option<{f["ty"]}>', attrs, 'opt'

    def emit(self):
        out = []
        for name in self.order:
            st = self.structs[name]
            for l in doc_lines(st['doc']):
                out.append(f'/// {l}')
            out.append('#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]')
            out.append('#[non_exhaustive]')
            out.append(f'pub struct {name} {{')
            for f in st['fields']:
                decl, attrs, _ = self.field_kind(st, f)
                dl = doc_lines(f['doc'])
                if f['enum']:
                    vals = ', '.join(f'`{v}`' for v in f['enum'][:24])
                    if len(f['enum']) > 24:
                        vals += ', …'
                    if dl:
                        dl.append('')
                    dl.append(('Known values: ' if len(f['enum']) > 1 else 'Always ') + vals + '.')
                for l in dl:
                    out.append(f'    ///{" " + l if l else ""}')
                out.append(f'    #[serde({", ".join(attrs)})]')
                out.append(f'    pub {f["ident"]}: {decl},')
            out.append('    /// Fields this version of the crate does not know about, kept verbatim.')
            out.append('    /// In a request, keys set here are sent as-is (a forward-compatible escape hatch).')
            out.append('    #[serde(flatten)]')
            out.append('    pub extra: Map<String, Value>,')
            out.append('}\n')
            if st['setters']:
                out.extend(self.emit_setters(st))
        return out

    def emit_setters(self, st):
        out = [f'impl {st["name"]} {{']
        req = [f for f in st['fields'] if f['required'] and not f['nullable']]
        args = ', '.join(f'{f["ident"]}: impl Into<{f["ty"]}>' for f in req)
        out.append('    /// A value with the required fields set and every other field unset.')
        out.append(f'    pub fn new({args}) -> Self {{')
        if req:
            inits = ', '.join(f'{f["ident"]}: {f["ident"]}.into()' for f in req)
            out.append(f'        Self {{ {inits}, ..Default::default() }}')
        else:
            out.append('        Self::default()')
        out.append('    }')
        for f in st['fields']:
            decl, _, kind = self.field_kind(st, f)
            raw = f['ident'][2:] if f['ident'].startswith('r#') else f['ident']
            wrap = {'plain': 'v.into()', 'opt': 'Some(v.into())', 'opt2': 'Some(Some(v.into()))'}[kind]
            out.append(f'    /// Set `{f["json"]}`.')
            out.append(f'    pub fn with_{raw}(mut self, v: impl Into<{f["ty"]}>) -> Self {{')
            out.append(f'        self.{f["ident"]} = {wrap};')
            out.append('        self')
            out.append('    }')
            if kind == 'opt2':
                out.append(f'    /// Send `{f["json"]}: null` to clear it.')
                out.append(f'    pub fn clear_{raw}(mut self) -> Self {{')
                out.append(f'        self.{f["ident"]} = Some(None);')
                out.append('        self')
                out.append('    }')
        out.append('    /// Set a field this version of the crate does not know about.')
        out.append('    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {')
        out.append('        self.extra.insert(key.into(), value.into());')
        out.append('        self')
        out.append('    }')
        out.append('}\n')
        return out

    # A sample JSON value for a schema: every property present, so a decode ->
    # encode round-trip must reproduce it exactly.
    def sample(self, s, depth=0, stack=()):
        if s is None or s is True or s == {} or not isinstance(s, dict):
            return 'sample'
        if '$ref' in s:
            cname = s['$ref'].split('/')[-1]
            if cname in stack:
                return None
            return self.sample(comps['schemas'][cname], depth + 1, stack + (cname,))
        for key in ('anyOf', 'oneOf'):
            if key in s:
                variants = [v for v in s[key] if not (isinstance(v, dict) and v.get('type') == 'null')]
                if len(variants) == 1:
                    return self.sample(variants[0], depth, stack)
                return {'any': 1}
        if s.get('allOf') and not s.get('properties') and len(s['allOf']) == 1:
            return self.sample(s['allOf'][0], depth, stack)
        t = s.get('type')
        if isinstance(t, list):
            nn = [x for x in t if x != 'null']
            if len(nn) != 1:
                return 'sample'
            t = nn[0]
        if 'const' in s and t is None:
            return s['const']
        if 'enum' in s and t is None:
            return s['enum'][0]
        if t == 'string':
            if 'enum' in s and s['enum']:
                return s['enum'][0] if isinstance(s['enum'][0], str) else 'x'
            if 'const' in s:
                return s['const']
            return 'x'
        if t == 'integer':
            return 7
        if t == 'number':
            return 1.5
        if t == 'boolean':
            return True
        if t == 'array':
            v = self.sample(s.get('items'), depth + 1, stack)
            return [] if v is None else [v]
        if t == 'object' or s.get('properties') or s.get('allOf'):
            if is_struct_schema(s):
                props, req, _ = merged_object(s)
                out = {}
                for pn, ps in props.items():
                    v = self.sample(ps, depth + 1, stack)
                    if v is not None:
                        out[pn] = v
                    elif pn in req:
                        # A required field that only recurses: no finite valid
                        # sample of this object exists, so the (optional) parent
                        # leaves it out rather than emitting an invalid `{}`.
                        return None
                return out
            ap = s.get('additionalProperties')
            if isinstance(ap, dict) and ap:
                v = self.sample(ap, depth + 1, stack)
                return {} if v is None else {'k': v}
            return {'k': 'v'}
        return 'sample'


tg = TypeGen()

# ── operations ──────────────────────────────────────────────────────────────
def ns_prefix(st):
    return st[:-3] if st.endswith('Api') else st

ops = []
for p, pops in sorted(d['paths'].items()):
    np = re.sub(r'\{[^}]+\}', '{}', p)
    for m, o in pops.items():
        if m not in ('get', 'post', 'put', 'patch', 'delete'):
            continue
        M = m.upper()
        if (M, np) not in missing:
            continue
        ns = None
        for pre, st, acc, doc in sorted(NS, key=lambda x: -len(x[0])):
            if p == pre or p.startswith(pre + '/'):
                ns = (pre, st, acc, doc)
                break
        if ns is None:
            print('NO NAMESPACE', M, p, file=sys.stderr)
            continue
        pre, st, acc, doc = ns
        name = OVR.get((M, p)) or default_name(M, p[len(pre):])
        params = re.findall(r'\{([^}]+)\}', p)
        q = [x.get('name') for x in o.get('parameters', []) if x.get('in') == 'query']
        if M == 'GET' and not q and (is_list_response(o) or name.startswith('list') or name in ('read_authorization_models', 'sign_in_history')):
            q = ['limit', 'starting_after', 'and any filter the route documents']
        hdr = [x.get('name') for x in o.get('parameters', []) if x.get('in') == 'header']
        rs = json_request_schema(o)
        ops.append(dict(M=M, p=p, st=st, acc=acc, doc=doc, name=name, params=params, q=q,
                        idem='Idempotency-Key' in hdr, body='req' if rs is not None else None,
                        req_schema=rs, resp=json_response(o),
                        summary=(o.get('summary') or '').strip()))

# Operations that gained a request body after release: the method keeps its
# bodyless signature (sending the default body) and `<name>_with` takes the body,
# so existing callers compile unchanged.
BODY_ADDED = {
    ('POST', '/v1/oauth_clients/{id}/rotate_secret'),
    ('POST', '/v1/platform/atlas_id_apps/{id}/webhook/rotate_secret'),
}
for op in ops:
    op['fn'] = op['name'] + '_with' if (op['M'], op['p']) in BODY_ADDED else op['name']

seen = {}
for op in ops:
    k = (op['st'], op['name'])
    if k in seen:
        print('COLLISION', k, seen[k], op['M'], op['p'], file=sys.stderr)
    seen[k] = (op['M'], op['p'])

# Resolve request/response types. Requests first so request-only inline
# structs get their builder setters.
for op in ops:
    prefix = ns_prefix(op['st']) + pascal(op['name'])
    op['req_ty'] = None
    rs = op['req_schema']
    if rs is not None:
        if '$ref' in rs or is_struct_schema(rs):
            t = tg.rtype(rs, prefix + 'Body', True)[0]
            op['req_ty'] = t if t in tg.structs else None
            if op['req_ty'] and t.startswith(prefix) and not tg.structs[t]['doc']:
                tg.structs[t]['doc'] = f"The request body of `{op['M']} {op['p']}`."
for op in ops:
    prefix = ns_prefix(op['st']) + pascal(op['name'])
    kind, sch = op['resp']
    op['resp_ty'] = None
    if kind == 'empty':
        op['resp_ty'] = '()'
    elif kind == 'json' and ('$ref' in sch or is_struct_schema(sch)):
        t = tg.rtype(sch, prefix + 'Response', False)[0]
        op['resp_ty'] = t if t in tg.structs else None
        if op['resp_ty'] and t.startswith(prefix) and not tg.structs[t]['doc']:
            tg.structs[t]['doc'] = f"The response of `{op['M']} {op['p']}`."
    op['typed'] = op['req_ty'] is not None or op['resp_ty'] is not None

def q_ty(t):
    """A type as written in catalog.rs (generated structs live in `types`)."""
    if t is None or t in ('()', 'Value'):
        return t
    return re.sub(r'\b([A-Z][A-Za-z0-9]*)\b',
                  lambda mm: f'types::{mm.group(1)}' if mm.group(1) in tg.structs else mm.group(1), t)

# ── emit types.rs ───────────────────────────────────────────────────────────
types_rs = ['''// @generated by scripts/gen_catalog.py from the public OpenAPI document — do not edit.
//! Request and response types for the generated Backend API / Platform API
//! methods of [`super::BackendClient`]'s resource namespaces.
//!
//! Every struct is `#[non_exhaustive]`: build a request with `Type::new(..)`
//! (required fields) and the `with_*` setters, or `Type::default()` and field
//! assignment. Every struct carries an `extra` map: on a response it keeps any
//! field the server added after this crate was released; on a request its keys
//! are sent as-is. Enumerations are `String`s (known values are listed on the
//! field) so a new server value never breaks decoding.

#![allow(clippy::too_many_arguments, clippy::large_enum_variant, clippy::derive_partial_eq_without_eq)]

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

/// `Some(None)` for an explicit JSON `null`, so a decoded request keeps the
/// difference between "absent" and "clear".
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Option::<T>::deserialize(de).map(Some)
}
''']
types_rs += tg.emit()
types_src = '\n'.join(types_rs) + '\n'
if 'HashMap<' not in types_src.split('use serde::')[1]:
    types_src = types_src.replace('use std::collections::HashMap;\n\n', '')
if 'double_option"' not in types_src:
    types_src = re.sub(r'/// `Some\(None\)` for an explicit.*?\n}\n', '', types_src, flags=re.S)
    types_src = types_src.replace('use serde::{Deserialize, Deserializer, Serialize};', 'use serde::{Deserialize, Serialize};')
open(os.path.join(ROOT, 'src/backend/types.rs'), 'w').write(types_src)

# ── emit catalog.rs ─────────────────────────────────────────────────────────
def rust_doc(text):
    return doc_lines(text)

def path_expr(p, params, st):
    fmt = re.sub(r'\{[^}]+\}', '{}', p)
    if not params:
        return f'"{p}"', False
    args = ', '.join(f'seg({pname(x, st, i)})' for i, x in enumerate(params))
    return f'format!("{fmt}", {args})', True

METH = {'GET': 'Get', 'POST': 'Post', 'PUT': 'Put', 'PATCH': 'Patch', 'DELETE': 'Delete'}

lines = ['''// @generated by scripts/gen_catalog.py from the public OpenAPI document — do not edit.
//! The rest of the Backend API and Platform API surface: every remaining
//! operation of the public API, as thin, consistently-named methods.
//!
//! Each method takes a request struct from [`types`](super::types) and returns a
//! response struct (unknown response fields are kept in its `extra` map; set
//! `extra` on a request to send a field this crate does not know yet). Where the
//! API documents a body as open-ended JSON, that side is a
//! [`serde_json::Value`]. Filters go in a [`Query`]. Each method's doc names its
//! route. [`BackendClient::request_value`] calls any route with raw JSON.
//!
//! ```no_run
//! # async fn demo(atlas: &atlasauth::backend::BackendClient) -> Result<(), atlasauth::backend::BackendError> {
//! use atlasauth::backend::{types, Query};
//! let role = atlas
//!     .roles()
//!     .create(&types::RolesCreateBody::new().with_key("editor").with_name("Editor"))
//!     .await?;
//! let page = atlas.waitlist().list(&Query::new().set("limit", 20)).await?;
//! # let _ = (role, page); Ok(()) }
//! ```

#![allow(clippy::too_many_arguments)]

use serde_json::Value;

use crate::http::HttpMethod;

use super::client::BackendClient;
use super::error::BackendError;
use super::pagination::Query;
use super::resources::{body_of, seg};
use super::types;
#[allow(unused_imports)]
use super::{
    ApiKeys, AtlasIdApps, AtlasIdPublisherApi, Billing, Instance, Invitations, MessagingProvidersApi,
    OrgSettingsSchemaApi, Organizations, PlatformApi, Sessions, Users,
};
''']

structs = []
for op in ops:
    if op['st'] not in EXISTING and op['st'] not in [s[0] for s in structs]:
        structs.append((op['st'], op['acc'], op['doc']))

for st, acc, doc in structs:
    lines.append(f'/// {doc}. Reached via [`BackendClient::{acc}`].')
    lines.append(f"pub struct {st}<'a> {{\n    pub(super) client: &'a BackendClient,\n}}\n")

by_struct = {}
for op in ops:
    by_struct.setdefault(op['st'], []).append(op)

for st, sops in by_struct.items():
    lines.append(f"impl {st}<'_> {{")
    for op in sops:
        pexpr, owned = path_expr(op['p'], op['params'], st)
        meth = METH[op['M']]
        doc = rust_doc(f"`{op['M']} {op['p']}`" + (f" — {op['summary']}" if op['summary'] else ''))
        qdoc = [f"Query parameters: {', '.join('`' + x + '`' for x in op['q'])}."] if op['q'] else []
        qexpr = '&query.as_pairs()' if op['q'] else '&[]'
        iexpr = 'idempotency_key' if op['idem'] else 'None'

        def sig(body_ty):
            a = ['&self'] + [f'{pname(x, st, i)}: &str' for i, x in enumerate(op['params'])]
            if op['body']:
                a.append(f'body: {body_ty}')
            if op['q']:
                a.append('query: &Query')
            if op['idem']:
                a.append('idempotency_key: Option<&str>')
            return ', '.join(a)

        def body_lines(bexpr, ret):
            out = []
            if owned:
                out.append(f'        let path = {pexpr};')
                pref = '&path'
            else:
                pref = pexpr
            out.append(f'        self.client.request(HttpMethod::{meth}, {pref}, {qexpr}, {bexpr}, {iexpr}).await')
            return out

        req_t = q_ty(op['req_ty']) if op['req_ty'] else 'Value'
        resp_t = q_ty(op['resp_ty']) if op['resp_ty'] else 'Value'
        body_arg = f'&{req_t}' if op['req_ty'] else 'Value'
        for l in doc:
            lines.append(f'    /// {l}')
        for l in ([''] + qdoc if qdoc else []):
            lines.append(f'    ///{" " + l if l else ""}')
        notes = []
        if op['req_ty']:
            notes.append(f'Takes [`{req_t}`].')
        elif op['body']:
            notes.append('Takes a JSON body (the API documents it as open-ended).')
        if op['resp_ty'] == '()':
            notes.append('Returns nothing (`204 No Content`).')
        elif op['resp_ty']:
            notes.append(f'Returns [`{resp_t}`].')
        else:
            notes.append('Returns the response JSON (the API documents it as open-ended).')
        lines.append('    ///')
        lines.append(f'    /// {" ".join(notes)}')
        lines.append(f"    pub async fn {op['fn']}({sig(body_arg)}) -> Result<{resp_t}, BackendError> {{")
        bexpr = 'body_of(body)?' if op['req_ty'] else ('Some(body)' if op['body'] else 'None')
        lines += body_lines(bexpr, resp_t)
        lines.append('    }')
        if op['fn'] != op['name'] and op['req_ty']:
            legacy = [a for a in sig(body_arg).split(', ') if not a.startswith('body: ')]
            call = [a.split(':')[0] for a in legacy[1:]]
            call.insert(len(op['params']), f'&{req_t}::default()')
            lines.append(f"    /// `{op['M']} {op['p']}` with the default body; see [`{op['fn']}`](Self::{op['fn']}).")
            lines.append(f"    pub async fn {op['name']}({', '.join(legacy)}) -> Result<{resp_t}, BackendError> {{")
            lines.append(f"        self.{op['fn']}({', '.join(call)}).await")
            lines.append('    }')
    lines.append('}\n')

lines.append('impl BackendClient {')
for st, acc, doc in structs:
    lines.append(f'    /// {doc}.')
    lines.append(f"    pub fn {acc}(&self) -> {st}<'_> {{\n        {st} {{ client: self }}\n    }}")
lines.append('}')
open(os.path.join(ROOT, 'src/backend/catalog.rs'), 'w').write('\n'.join(lines) + '\n')

# ── emit tests/catalog.rs ───────────────────────────────────────────────────
ACCESSOR = {'Users': 'users', 'Organizations': 'organizations', 'Instance': 'instance', 'Billing': 'billing',
            'ApiKeys': 'api_keys', 'Sessions': 'sessions', 'Invitations': 'invitations',
            'OrgSettingsSchemaApi': 'org_settings_schema', 'MessagingProvidersApi': 'messaging_providers',
            'AtlasIdApps': 'platform().atlas_id_apps', 'AtlasIdPublisherApi': 'platform().atlas_id_publisher',
            'PlatformApi': 'platform'}
t = ['''// @generated by scripts/gen_catalog.py — do not edit.
//! Every catalog operation sends the documented method and path (and its query, body, and idempotency
//! key) through the request core.
#![cfg(feature = "backend")]

use std::sync::Arc;

use atlasauth::backend::{types, BackendClient, FakeTransport, Query};
use atlasauth::{HttpMethod, HttpResponse};
use serde_json::json;

fn client(fake: &FakeTransport) -> BackendClient {
    BackendClient::builder("sk_test_x")
        .transport(Arc::new(fake.clone()))
        .max_retries(0)
        .build()
        .unwrap()
}

/// Body expectation: none, exactly `{"k":1}`, or any JSON object.
#[derive(Clone, Copy, PartialEq)]
enum B {
    None,
    K,
    Obj,
}

#[tokio::test]
async fn every_catalog_operation_hits_its_route() {
    // An empty 2xx body decodes as JSON `null`: into `()` for a 204 route and
    // into `Value::Null` otherwise; a typed struct needs an object.
    let fake = FakeTransport::new(|req| HttpResponse {
        status: 200,
        body: if req.url.contains("no_content") { String::new() } else { r#"{"ok":true}"#.into() },
    });
    let c = client(&fake);
    let q = Query::new().set("limit", 2);
    let mut expected: Vec<(HttpMethod, String, B, bool)> = Vec::new();
''']
n_calls = 0
for op in ops:
    concrete = op['p']
    pargs = []
    no_content = op.get('resp_ty') == '()'
    for i, x in enumerate(op['params']):
        val = f'p{i}_{snake(x)}' + ('_no_content' if no_content and i == 0 else '')
        pargs.append(f'"{val}"')
        concrete = concrete.replace('{' + x + '}', val, 1)
    tail = (['&q'] if op['q'] else []) + (['Some("idem_1")'] if op['idem'] else [])
    acc = ACCESSOR.get(op['st'], op['acc'])
    url = concrete + ('?limit=2' if op['q'] else '')
    meth = METH[op['M']]
    idem = 'true' if op['idem'] else 'false'
    if op['req_ty']:
        barg = [f'&{q_ty(op["req_ty"])}::default()']
        bexp = 'B::Obj'
    elif op['body']:
        barg = ['json!({"k": 1})']
        bexp = 'B::K'
    else:
        barg, bexp = [], 'B::None'
    t.append(f'    c.{acc}().{op["fn"]}({", ".join(pargs + barg + tail)}).await.unwrap();')
    t.append(f'    expected.push((HttpMethod::{meth}, "{url}".into(), {bexp}, {idem}));')
    n_calls += 1
t.append('''
    let reqs = fake.requests();
    assert_eq!(reqs.len(), expected.len());
    for (req, (m, path, body, idem)) in reqs.iter().zip(expected.iter()) {
        assert_eq!(req.method, *m, "{path}");
        assert_eq!(req.url, format!("https://api.atlasauth.net{path}"));
        match body {
            B::None => assert!(req.body.is_none(), "{path}"),
            B::K => assert_eq!(req.body.as_deref(), Some(r#"{"k":1}"#), "{path}"),
            B::Obj => {
                let v: serde_json::Value = serde_json::from_str(req.body.as_deref().expect(path)).unwrap();
                assert!(v.is_object(), "{path}");
            }
        }
        let has_idem = req.headers.iter().any(|(k, v)| k == "idempotency-key" && v == "idem_1");
        assert_eq!(has_idem, *idem, "{path}");
    }
}
''')
t.append(f'// {len(ops)} operations, {sum(1 for o in ops if o["typed"])} typed; {n_calls} calls.')
open(os.path.join(ROOT, 'tests/catalog.rs'), 'w').write('\n'.join(t) + '\n')

# ── emit tests/catalog_types.rs ─────────────────────────────────────────────
dt = ['''// @generated by scripts/gen_catalog.py — do not edit.
//! Every typed catalog response decodes a sample built from its schema (every
//! field present, plus one the crate does not know), keeps the unknown field in
//! `extra`, and re-encodes to exactly the same JSON.
#![cfg(feature = "backend")]

use atlasauth::backend::types;
use serde_json::{json, Value};

fn round_trip<T>(sample: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let mut v: Value = serde_json::from_str(sample).unwrap();
    v.as_object_mut().unwrap().insert("zz_added_later".into(), json!({"kept": true}));
    let typed: T = serde_json::from_value(v.clone()).unwrap();
    assert_eq!(serde_json::to_value(&typed).unwrap(), v, "{}", std::any::type_name::<T>());
}
''']
done = set()
by_ns = {}
for op in ops:
    rt = op.get('resp_ty')
    if not rt or rt == '()' or rt not in tg.structs or rt in done:
        continue
    done.add(rt)
    by_ns.setdefault(op['st'], []).append((op, rt))
for st, items in by_ns.items():
    dt.append('#[test]')
    dt.append(f'fn decode_{snake(st)}() {{')
    for op, rt in items:
        kind, sch = op['resp']
        sample = json.dumps(tg.sample(sch), separators=(',', ':'), sort_keys=True)
        dt.append(f'    // {op["M"]} {op["p"]}')
        dt.append(f'    round_trip::<types::{rt}>(r#"{sample}"#);')
    dt.append('}\n')
dt.append('''#[test]
fn unknown_fields_survive_and_typed_fields_decode() {
    let v = json!({"object": "action", "id": "act_1", "name": "Tag", "trigger": "post_login",
        "code": "x", "enabled": true, "created_at": 1, "updated_at": 2, "brand_new": [1, 2]});
    let a: types::Action = serde_json::from_value(v).unwrap();
    assert_eq!(a.id, "act_1");
    assert!(a.enabled);
    assert_eq!(a.extra.get("brand_new"), Some(&json!([1, 2])));
}
''')
open(os.path.join(ROOT, 'tests/catalog_types.rs'), 'w').write('\n'.join(dt) + '\n')

# Format the generated files when rustfmt is available (the output is valid
# Rust either way).
import shutil, subprocess
if shutil.which('rustfmt'):
    subprocess.run(['rustfmt', '--edition', '2021'] + [os.path.join(ROOT, f) for f in (
        'src/backend/catalog.rs', 'src/backend/types.rs', 'tests/catalog.rs', 'tests/catalog_types.rs')], check=True)

typed = [o for o in ops if o['typed']]
print(f'generated {len(ops)} ops ({len(typed)} typed) in {len(structs)} new namespaces; '
      f'{len(tg.structs)} types; {n_calls} catalog test calls', file=sys.stderr)
if '--report' in sys.argv:
    for o in ops:
        req = o['req_ty'] or ('Value' if o['body'] else '-')
        resp = o['resp_ty'] or 'Value'
        print(f"{'TYPED' if o['typed'] else 'JSON '} {o['M']:6} {o['p']:70} req={req} resp={resp}")
