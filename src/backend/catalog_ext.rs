//! More of the Backend API: the identity-governance, access-policy, vault,
//! connection, analytics, migration and other management resources, as thin,
//! consistently-named methods in the same style as the rest of the catalog.
//!
//! Each method takes a request struct from [`types`](super::types) or
//! [`types_ext`](super::types_ext) and returns a response struct (unknown
//! response fields are kept in its `extra` map; set `extra` on a request to send
//! a field this crate does not know yet). Where the API documents a body as
//! open-ended JSON, that side is a [`serde_json::Value`]. Filters go in a
//! [`Query`]. Each method's doc names its route.

#![allow(clippy::too_many_arguments)]

use serde_json::Value;

use crate::http::HttpMethod;

use super::client::BackendClient;
use super::error::BackendError;
use super::pagination::Query;
use super::resources::{body_of, seg};
use super::{types, types_ext};
#[allow(unused_imports)]
use super::{
    Actions, AttackProtection, Fga, Instance, Integrations, OAuthClients, OpenFga,
    OrgLdapConnections, Organizations, RiskBasedMfa, Users,
};

/// The `app_catalog` operations of the Backend API. Reached via [`BackendClient::app_catalog`].
pub struct AppCatalog<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `ldap_server_clients` operations of the Backend API. Reached via [`BackendClient::ldap_server_clients`].
pub struct LdapServerClients<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `users / required_actions` operations of the Backend API. Reached via [`Users::required_actions`].
pub struct UsersRequiredActions<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `users / notes` operations of the Backend API. Reached via [`Users::notes`].
pub struct UsersNotes<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `users / guardians` operations of the Backend API. Reached via [`Users::guardians`].
pub struct UsersGuardians<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `journeys` operations of the Backend API. Reached via [`BackendClient::journeys`].
pub struct Journeys<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `users / search` operations of the Backend API. Reached via [`Users::search`].
pub struct UsersSearch<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `users / search / views` operations of the Backend API. Reached via [`UsersSearch::views`].
pub struct UsersSearchViews<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `groups` operations of the Backend API. Reached via [`BackendClient::groups`].
pub struct Groups<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `groups / rules` operations of the Backend API. Reached via [`Groups::rules`].
pub struct GroupsRules<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `migrations` operations of the Backend API. Reached via [`BackendClient::migrations`].
pub struct Migrations<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `migrations / imports` operations of the Backend API. Reached via [`Migrations::imports`].
pub struct MigrationsImports<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `managed_grants` operations of the Backend API. Reached via [`BackendClient::managed_grants`].
pub struct ManagedGrants<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `least_privilege` operations of the Backend API. Reached via [`BackendClient::least_privilege`].
pub struct LeastPrivilege<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `delivery_health` operations of the Backend API. Reached via [`BackendClient::delivery_health`].
pub struct DeliveryHealth<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `flags` operations of the Backend API. Reached via [`BackendClient::flags`].
pub struct Flags<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `mfa_factors` operations of the Backend API. Reached via [`BackendClient::mfa_factors`].
pub struct MfaFactors<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `mfa_factors / yubikeys` operations of the Backend API. Reached via [`MfaFactors::yubikeys`].
pub struct MfaFactorsYubikeys<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `mfa_factors / smart_card_mappings` operations of the Backend API. Reached via [`MfaFactors::smart_card_mappings`].
pub struct MfaFactorsSmartCardMappings<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `analytics` operations of the Backend API. Reached via [`BackendClient::analytics`].
pub struct Analytics<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `analytics / reports` operations of the Backend API. Reached via [`Analytics::reports`].
pub struct AnalyticsReports<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `analytics / alert_rules` operations of the Backend API. Reached via [`Analytics::alert_rules`].
pub struct AnalyticsAlertRules<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `marketing` operations of the Backend API. Reached via [`BackendClient::marketing`].
pub struct Marketing<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `audit_event_schemas` operations of the Backend API. Reached via [`BackendClient::audit_event_schemas`].
pub struct AuditEventSchemas<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `directory_pull_sources` operations of the Backend API. Reached via [`BackendClient::directory_pull_sources`].
pub struct DirectoryPullSources<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `directory_pull_sources / sync_runs` operations of the Backend API. Reached via [`DirectoryPullSources::sync_runs`].
pub struct DirectoryPullSourcesSyncRuns<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `org_ldap_connections / sync_runs` operations of the Backend API. Reached via [`OrgLdapConnections::sync_runs`].
pub struct OrgLdapConnectionsSyncRuns<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `relay_agents` operations of the Backend API. Reached via [`BackendClient::relay_agents`].
pub struct RelayAgents<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `oauth_clients / app_settings` operations of the Backend API. Reached via [`OAuthClients::app_settings`].
pub struct OAuthClientsAppSettings<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `oauth_clients / workload_identity` operations of the Backend API. Reached via [`OAuthClients::workload_identity`].
pub struct OAuthClientsWorkloadIdentity<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `oauth_clients / trusted_issuers` operations of the Backend API. Reached via [`OAuthClients::trusted_issuers`].
pub struct OAuthClientsTrustedIssuers<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `oauth_client_profiles` operations of the Backend API. Reached via [`BackendClient::oauth_client_profiles`].
pub struct OauthClientProfiles<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `oauth_clients / login_requests` operations of the Backend API. Reached via [`OAuthClients::login_requests`].
pub struct OAuthClientsLoginRequests<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `oauth_clients / consent_requests` operations of the Backend API. Reached via [`OAuthClients::consent_requests`].
pub struct OAuthClientsConsentRequests<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `passkey_api` operations of the Backend API. Reached via [`BackendClient::passkey_api`].
pub struct PasskeyApi<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `vc` operations of the Backend API. Reached via [`BackendClient::vc`].
pub struct Vc<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `vc / credential_types` operations of the Backend API. Reached via [`Vc::credential_types`].
pub struct VcCredentialTypes<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `vc / credentials` operations of the Backend API. Reached via [`Vc::credentials`].
pub struct VcCredentials<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `vc / presentation_requests` operations of the Backend API. Reached via [`Vc::presentation_requests`].
pub struct VcPresentationRequests<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `listen` operations of the Backend API. Reached via [`BackendClient::listen`].
pub struct Listen<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `agent_registration` operations of the Backend API. Reached via [`BackendClient::agent_registration`].
pub struct AgentRegistration<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `agents` operations of the Backend API. Reached via [`BackendClient::agents`].
pub struct Agents<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `agent_access_requests` operations of the Backend API. Reached via [`BackendClient::agent_access_requests`].
pub struct AgentAccessRequests<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `workflows` operations of the Backend API. Reached via [`BackendClient::workflows`].
pub struct Workflows<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `page_templates` operations of the Backend API. Reached via [`BackendClient::page_templates`].
pub struct PageTemplates<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `service_connectors` operations of the Backend API. Reached via [`BackendClient::service_connectors`].
pub struct ServiceConnectors<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `desktop_mfa` operations of the Backend API. Reached via [`BackendClient::desktop_mfa`].
pub struct DesktopMfa<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `identity_verification` operations of the Backend API. Reached via [`BackendClient::identity_verification`].
pub struct IdentityVerification<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `iga` operations of the Backend API. Reached via [`BackendClient::iga`].
pub struct Iga<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `iga / entitlements` operations of the Backend API. Reached via [`Iga::entitlements`].
pub struct IgaEntitlements<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `iga / requests` operations of the Backend API. Reached via [`Iga::requests`].
pub struct IgaRequests<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `iga / grants` operations of the Backend API. Reached via [`Iga::grants`].
pub struct IgaGrants<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `iga / delegations` operations of the Backend API. Reached via [`Iga::delegations`].
pub struct IgaDelegations<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `iga / sod` operations of the Backend API. Reached via [`Iga::sod`].
pub struct IgaSod<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `iga / lifecycle` operations of the Backend API. Reached via [`Iga::lifecycle`].
pub struct IgaLifecycle<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `iga / campaigns` operations of the Backend API. Reached via [`Iga::campaigns`].
pub struct IgaCampaigns<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `scim_provisioning_presets` operations of the Backend API. Reached via [`BackendClient::scim_provisioning_presets`].
pub struct ScimProvisioningPresets<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `organizations / webhook_endpoints` operations of the Backend API. Reached via [`Organizations::webhook_endpoints`].
pub struct OrganizationsWebhookEndpoints<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `vault` operations of the Backend API. Reached via [`BackendClient::vault`].
pub struct Vault<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `vault / key_provider` operations of the Backend API. Reached via [`Vault::key_provider`].
pub struct VaultKeyProvider<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `connections` operations of the Backend API. Reached via [`BackendClient::connections`].
pub struct Connections<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `connections / oauth_clients` operations of the Backend API. Reached via [`Connections::oauth_clients`].
pub struct ConnectionsOauthClients<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `connections / webhooks` operations of the Backend API. Reached via [`Connections::webhooks`].
pub struct ConnectionsWebhooks<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `ssf` operations of the Backend API. Reached via [`BackendClient::ssf`].
pub struct Ssf<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `ssf / streams` operations of the Backend API. Reached via [`Ssf::streams`].
pub struct SsfStreams<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `ssf / receivers` operations of the Backend API. Reached via [`Ssf::receivers`].
pub struct SsfReceivers<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `network_zones` operations of the Backend API. Reached via [`BackendClient::network_zones`].
pub struct NetworkZones<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `access_policies` operations of the Backend API. Reached via [`BackendClient::access_policies`].
pub struct AccessPolicies<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `abac` operations of the Backend API. Reached via [`BackendClient::abac`].
pub struct Abac<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `abac / templates` operations of the Backend API. Reached via [`Abac::templates`].
pub struct AbacTemplates<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `abac / links` operations of the Backend API. Reached via [`Abac::links`].
pub struct AbacLinks<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `abac / schema` operations of the Backend API. Reached via [`Abac::schema`].
pub struct AbacSchema<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `resources` operations of the Backend API. Reached via [`BackendClient::resources`].
pub struct Resources<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `resources / types` operations of the Backend API. Reached via [`Resources::types`].
pub struct ResourcesTypes<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `resources / assignments` operations of the Backend API. Reached via [`Resources::assignments`].
pub struct ResourcesAssignments<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `org_role_grants` operations of the Backend API. Reached via [`BackendClient::org_role_grants`].
pub struct OrgRoleGrants<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `devices` operations of the Backend API. Reached via [`BackendClient::devices`].
pub struct Devices<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `authz_decisions` operations of the Backend API. Reached via [`BackendClient::authz_decisions`].
pub struct AuthzDecisions<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `authz_decisions / settings` operations of the Backend API. Reached via [`AuthzDecisions::settings`].
pub struct AuthzDecisionsSettings<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `policy_bundles` operations of the Backend API. Reached via [`BackendClient::policy_bundles`].
pub struct PolicyBundles<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `proxy_apps` operations of the Backend API. Reached via [`BackendClient::proxy_apps`].
pub struct ProxyApps<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `mcp_gateways` operations of the Backend API. Reached via [`BackendClient::mcp_gateways`].
pub struct McpGateways<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `mcp_gateways / budgets` operations of the Backend API. Reached via [`McpGateways::budgets`].
pub struct McpGatewaysBudgets<'a> {
    pub(super) client: &'a BackendClient,
}

/// The `instance / integrations` operations of the Backend API. Reached via [`Instance::integrations`].
pub struct InstanceIntegrations<'a> {
    pub(super) client: &'a BackendClient,
}

impl AppCatalog<'_> {
    /// `GET /v1/app_catalog` — List the app presets: about 100 SAML apps (Slack, GitHub, Snowflake,
    /// Notion, HubSpot and more) and about 45 OpenID Connect apps (Grafana, GitLab, Argo CD, Vault,
    /// Cloudflare Zero Trust and more), each with its protocol, category, the parameters it needs,
    /// whether its values were confirmed in the vendor's docs (verified) and that page
    /// (source_url).
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AppCatalogPresetsResponse`].
    pub async fn presets(
        &self,
        query: &Query,
    ) -> Result<types_ext::AppCatalogPresetsResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/app_catalog",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/app_catalog/installed` — List the installed apps (SAML and OpenID Connect) with
    /// their email-domain allow-list and assignment.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AppCatalogInstalledResponse`].
    pub async fn installed(
        &self,
        query: &Query,
    ) -> Result<types_ext::AppCatalogInstalledResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/app_catalog/installed",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/app_catalog/{id}/install` — Install a catalog app from its preset and params, with
    /// an optional name, installed_id, allowed_email_domains and assignment. A SAML preset becomes
    /// a SAML service provider; an OIDC preset registers a confidential OAuth client with the
    /// preset's redirect URIs and returns client_id, client_secret (shown once), redirect_uri and
    /// issuer to paste into the app. 409 if the installed_id exists. → 201.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AppCatalogInstallBody`]. Returns [`types_ext::AppCatalogInstallResponse`].
    pub async fn install(
        &self,
        id: &str,
        body: &types_ext::AppCatalogInstallBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AppCatalogInstallResponse, BackendError> {
        let path = format!("/v1/app_catalog/{}/install", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `PATCH /v1/app_catalog/installed/{id}` — Change an installed app's name,
    /// allowed_email_domains or assignment. Assignment applies to the launcher and to single
    /// sign-on: someone not assigned is refused with 403.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AppCatalogUpdateBody`]. Returns [`types_ext::AppCatalogUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::AppCatalogUpdateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AppCatalogUpdateResponse, BackendError> {
        let path = format!("/v1/app_catalog/installed/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `DELETE /v1/app_catalog/installed/{id}` — Uninstall an app: it disappears from the launcher
    /// and Atlas stops signing people in to it (an OIDC app's OAuth client and its grants are
    /// deleted).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn uninstall(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/app_catalog/installed/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl LdapServerClients<'_> {
    /// `GET /v1/ldap_server_clients` — List the LDAP interface service accounts with their base DN,
    /// bind DN and allowed source networks. Secrets are never returned.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::LdapServerClientsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::LdapServerClientsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/ldap_server_clients",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/ldap_server_clients` — Create a service account for the LDAPS interface: base_dn
    /// (dc=/o=/ou= parts, unique across Atlas), bind_cn, allowed_cidrs (empty = nobody may
    /// connect), allow_user_bind and size_limit. The secret is returned once as secret.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::LdapServerClientsCreateBody`]. Returns [`types_ext::LdapServerClientsCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::LdapServerClientsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::LdapServerClientsCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/ldap_server_clients",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/ldap_server_clients/{id}` — Read one LDAP interface service account.
    ///
    /// Returns [`types_ext::LdapServerClientsGetResponse`].
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<types_ext::LdapServerClientsGetResponse, BackendError> {
        let path = format!("/v1/ldap_server_clients/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/ldap_server_clients/{id}` — Change the name, allowed networks, user-bind switch,
    /// size limit or status (active or disabled).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::LdapServerClientsUpdateBody`]. Returns [`types_ext::LdapServerClientsUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::LdapServerClientsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::LdapServerClientsUpdateResponse, BackendError> {
        let path = format!("/v1/ldap_server_clients/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/ldap_server_clients/{id}` — Delete a service account; its connections can no
    /// longer bind.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/ldap_server_clients/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/ldap_server_clients/{id}/rotate_secret` — Issue a new service-account secret
    /// (returned once); the old one stops working immediately.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::LdapServerClientsRotateSecretResponse`].
    pub async fn rotate_secret(
        &self,
        id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::LdapServerClientsRotateSecretResponse, BackendError> {
        let path = format!("/v1/ldap_server_clients/{}/rotate_secret", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
}

impl UsersRequiredActions<'_> {
    /// `POST /v1/users/{id}/required_actions` — Make a user owe an action at their next sign-in,
    /// whatever the method: update_password, verify_email, accept_policy, configure_mfa,
    /// update_profile, or custom (sent to an https url; the app closes it with DELETE). The sign-in
    /// attempt holds at needs_required_action until it is done (configure_mfa alone routes through
    /// MFA enrollment; accept_policy is closed once the policy gate passes; verify_email and
    /// configure_mfa clear themselves when already true). Re-requesting an open action is a 200
    /// with the same row. Emits user.required_action_requested. → 201.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::UsersRequiredActionsRequestBody`]. Returns [`types_ext::RequiredAction`].
    pub async fn request(
        &self,
        id: &str,
        body: &types_ext::UsersRequiredActionsRequestBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::RequiredAction, BackendError> {
        let path = format!("/v1/users/{}/required_actions", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/users/{id}/required_actions` — The actions a user currently owes, oldest first.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::UsersRequiredActionsListResponse`].
    pub async fn list(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::UsersRequiredActionsListResponse, BackendError> {
        let path = format!("/v1/users/{}/required_actions", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `DELETE /v1/users/{id}/required_actions/{rid}` — Withdraw an owed action. This is also how
    /// an application closes a custom action once the user has finished its step. Emits
    /// user.required_action_cleared. 404 when it is not open.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::UsersRequiredActionsClearResponse`].
    pub async fn clear(
        &self,
        id: &str,
        rid: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::UsersRequiredActionsClearResponse, BackendError> {
        let path = format!("/v1/users/{}/required_actions/{}", seg(id), seg(rid));
        self.client
            .request(
                HttpMethod::Delete,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/required_actions/bulk` — Owe the same action for many users at once: every member
    /// of one organization (organization_id) or an explicit user_ids list, at most 5000. Users
    /// outside the instance are skipped, and an already-open action counts as already_open. Emits
    /// user.required_action_requested per newly opened action.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::UsersRequiredActionsBulkBody`]. Returns nothing (`204 No Content`).
    pub async fn bulk(
        &self,
        body: &types_ext::UsersRequiredActionsBulkBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<(), BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/required_actions/bulk",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl UsersNotes<'_> {
    /// `GET /v1/users/{id}/notes` — The notes on a user: pinned notes first, then newest first.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::UsersNotesListResponse`].
    pub async fn list(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::UsersNotesListResponse, BackendError> {
        let path = format!("/v1/users/{}/notes", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/users/{id}/notes` — Add a note to a user (up to 5000 characters; at most 500 notes
    /// per user). The audit log records that a note was added, never its text. → 201.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::UsersNotesCreateBody`]. Returns [`types_ext::UserNote`].
    pub async fn create(
        &self,
        id: &str,
        body: &types_ext::UsersNotesCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::UserNote, BackendError> {
        let path = format!("/v1/users/{}/notes", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `PATCH /v1/users/{id}/notes/{noteId}` — Edit a note: its text, its pin, or both.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::UsersNotesUpdateBody`]. Returns [`types_ext::UserNote`].
    pub async fn update(
        &self,
        id: &str,
        note_id: &str,
        body: &types_ext::UsersNotesUpdateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::UserNote, BackendError> {
        let path = format!("/v1/users/{}/notes/{}", seg(id), seg(note_id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `DELETE /v1/users/{id}/notes/{noteId}` — Delete a note from a user. The audit log keeps that
    /// it was deleted.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::UsersNotesDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        note_id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::UsersNotesDeleteResponse, BackendError> {
        let path = format!("/v1/users/{}/notes/{}", seg(id), seg(note_id));
        self.client
            .request(
                HttpMethod::Delete,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
}

impl Users<'_> {
    /// The `users / required_actions` operations of the Backend API.
    pub fn required_actions(&self) -> UsersRequiredActions<'_> {
        UsersRequiredActions {
            client: self.client,
        }
    }
    /// The `users / notes` operations of the Backend API.
    pub fn notes(&self) -> UsersNotes<'_> {
        UsersNotes {
            client: self.client,
        }
    }
    /// The `users / guardians` operations of the Backend API.
    pub fn guardians(&self) -> UsersGuardians<'_> {
        UsersGuardians {
            client: self.client,
        }
    }
    /// The `users / search` operations of the Backend API.
    pub fn search(&self) -> UsersSearch<'_> {
        UsersSearch {
            client: self.client,
        }
    }
    /// `GET /v1/users/{id}/history` — The user change history, newest first: every profile,
    /// metadata and status change (ban, lock, directives and their reversal) with who made it, the
    /// reason and expiry, and each changed field with its value before and after. A password change
    /// and private_metadata values are recorded as redacted (the field name only). Pages with
    /// starting_after.
    ///
    /// Query parameters: `limit`, `starting_after`, `action`.
    ///
    /// Returns [`types_ext::UsersHistoryResponse`].
    pub async fn history(
        &self,
        user_id: &str,
        query: &Query,
    ) -> Result<types_ext::UsersHistoryResponse, BackendError> {
        let path = format!("/v1/users/{}/history", seg(user_id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/users/{id}/minor_status` — A user's parental-consent state (not_required for anyone
    /// at or above the age of digital consent) and their guardian links, newest first.
    ///
    /// Returns [`types_ext::UsersMinorStatusResponse`].
    pub async fn minor_status(
        &self,
        user_id: &str,
    ) -> Result<types_ext::UsersMinorStatusResponse, BackendError> {
        let path = format!("/v1/users/{}/minor_status", seg(user_id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `POST /v1/users/{id}/minor_status/assess` — Re-assess a user from their date-of-birth trait
    /// now (for users created before age gating was turned on). 400 when compliance.minors is off.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::UsersAssessMinorResponse`].
    pub async fn assess_minor(
        &self,
        user_id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::UsersAssessMinorResponse, BackendError> {
        let path = format!("/v1/users/{}/minor_status/assess", seg(user_id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/users/{id}/links` — Mint an email-verification or password-reset link (and code)
    /// for a user WITHOUT sending it, for support tools and invite flows that deliver it
    /// themselves. type "email_verification" needs an unverified address (default: the primary);
    /// the url opens GET /v1/client/email_addresses/verify and the code works wherever the address
    /// is verified by code. type "password_reset" needs a verified address and returns the url
    /// and/or code the instance's password-reset setting would have mailed, plus the reset
    /// attempt_id; redeeming it is the ordinary reset (it still asks for the second factor and sets
    /// a new password). Single-use, expires_in_seconds 60 to 86400 (default 3600). Audited as
    /// user.link_generated, never with the secret. Treat the response as a credential. → 201.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::UsersCreateLinkBody`]. Returns [`types_ext::UserLink`].
    pub async fn create_link(
        &self,
        user_id: &str,
        body: &types_ext::UsersCreateLinkBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::UserLink, BackendError> {
        let path = format!("/v1/users/{}/links", seg(user_id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/users/{id}/device_keys` — List a user’s device keys (native biometric sign-in).
    /// Never returns key material.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::UsersListDeviceKeysResponse`].
    pub async fn list_device_keys(
        &self,
        user_id: &str,
        query: &Query,
    ) -> Result<types_ext::UsersListDeviceKeysResponse, BackendError> {
        let path = format!("/v1/users/{}/device_keys", seg(user_id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `DELETE /v1/users/{id}/device_keys/{keyId}` — Revoke one of a user’s device keys so that
    /// device can no longer sign in. Scoped to the user; the account holder is notified when
    /// account-change notices are on.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::UsersDeleteDeviceKeyResponse`].
    pub async fn delete_device_key(
        &self,
        user_id: &str,
        key_id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::UsersDeleteDeviceKeyResponse, BackendError> {
        let path = format!("/v1/users/{}/device_keys/{}", seg(user_id), seg(key_id));
        self.client
            .request(
                HttpMethod::Delete,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
}

impl UsersGuardians<'_> {
    /// `POST /v1/users/{id}/guardians` — Ask a parent or guardian to approve a minor's account.
    /// Name them by email or by guardian_user_id (their address is used). Returns the pending link
    /// with a one-time consent_url that expires after compliance.minors.consentTtlHours. With
    /// send_email: true Atlas mails it through the application's own email provider (422 when none
    /// is set up); otherwise deliver consent_url yourself. → 201.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::UsersGuardiansRequestBody`]. Returns [`types_ext::UsersGuardiansRequestResponse`].
    pub async fn request(
        &self,
        id: &str,
        body: &types_ext::UsersGuardiansRequestBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::UsersGuardiansRequestResponse, BackendError> {
        let path = format!("/v1/users/{}/guardians", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/users/{id}/guardians/{linkId}/approve` — Record consent obtained another way (a
    /// signed form, a verified call): the link becomes active with consent_method admin and the
    /// account is consented. 409 for a revoked link.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::UsersGuardiansApproveBody`]. Returns [`types_ext::UsersGuardiansApproveResponse`].
    pub async fn approve(
        &self,
        id: &str,
        link_id: &str,
        body: &types_ext::UsersGuardiansApproveBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::UsersGuardiansApproveResponse, BackendError> {
        let path = format!("/v1/users/{}/guardians/{}/approve", seg(id), seg(link_id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `DELETE /v1/users/{id}/guardians/{linkId}` — Withdraw a guardian link. When no active
    /// guardian is left, the account needs consent again.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::UsersGuardiansRevokeResponse`].
    pub async fn revoke(
        &self,
        id: &str,
        link_id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::UsersGuardiansRevokeResponse, BackendError> {
        let path = format!("/v1/users/{}/guardians/{}", seg(id), seg(link_id));
        self.client
            .request(
                HttpMethod::Delete,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
}

impl Journeys<'_> {
    /// `GET /v1/flows` — The sign-in journeys.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::JourneysListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::JourneysListResponse, BackendError> {
        self.client
            .request(HttpMethod::Get, "/v1/flows", &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/flows` — Create a sign-in journey (version 1, active unless activate is false).
    /// Steps run top to bottom once a sign-in has passed its factors: refusals (deny,
    /// require_method, require_mfa), required actions the user must finish first, Action calls that
    /// may refuse, session claims and the redirect after sign-in. Action steps must name
    /// workflow_step Actions. → 201.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::JourneysCreateBody`]. Returns [`types_ext::JourneysCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::JourneysCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::JourneysCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/flows",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/flows/{id}` — One journey with its active definition (else the latest).
    ///
    /// Returns [`types_ext::JourneysGetResponse`].
    pub async fn get(&self, id: &str) -> Result<types_ext::JourneysGetResponse, BackendError> {
        let path = format!("/v1/flows/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/flows/{id}` — Change a journey. A definition becomes the next version
    /// (immutable), active unless activate is false.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::JourneysUpdateBody`]. Returns [`types_ext::JourneysUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::JourneysUpdateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::JourneysUpdateResponse, BackendError> {
        let path = format!("/v1/flows/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `DELETE /v1/flows/{id}` — Delete a journey and its versions.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/flows/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/flows/{id}/versions` — Every version of a journey, newest first.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::JourneysVersionsResponse`].
    pub async fn versions(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::JourneysVersionsResponse, BackendError> {
        let path = format!("/v1/flows/{}/versions", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/flows/{id}/activate` — Make a version the active one (roll forward or back).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::JourneysActivateBody`]. Returns [`types_ext::JourneysActivateResponse`].
    pub async fn activate(
        &self,
        id: &str,
        body: &types_ext::JourneysActivateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::JourneysActivateResponse, BackendError> {
        let path = format!("/v1/flows/{}/activate", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/flows/{id}/simulate` — What-if: run a version (default the active one) for a user
    /// and a described sign-in (method, mfa_verified, ip, application_id) without changing
    /// anything. Returns the outcome (allowed, held or refused), the effects and a per-step trace.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::JourneysSimulateBody`]. Returns [`types_ext::JourneysSimulateResponse`].
    pub async fn simulate(
        &self,
        id: &str,
        body: &types_ext::JourneysSimulateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::JourneysSimulateResponse, BackendError> {
        let path = format!("/v1/flows/{}/simulate", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl UsersSearch<'_> {
    /// The `users / search / views` operations of the Backend API.
    pub fn views(&self) -> UsersSearchViews<'_> {
        UsersSearchViews {
            client: self.client,
        }
    }
    /// `POST /v1/users/search` — Search users with a boolean filter tree (and/or/not) over profile
    /// columns, traits and metadata keys, organization and org role, MFA enrolled/strategy, sign-in
    /// strategy, last sign-in country or IP, and date ranges. Sort with order_by; page with
    /// starting_after (creation/update order) or offset (last_sign_in_at order).
    /// include_total_count adds total_count. Containment tests on public metadata and traits are
    /// answered by an index. Same user objects as GET /v1/users.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::UsersSearchQueryBody`]. Returns [`types_ext::UsersSearchQueryResponse`].
    pub async fn query(
        &self,
        body: &types_ext::UsersSearchQueryBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::UsersSearchQueryResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/users/search",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/users/search/export` — Export every user a search matches (up to 10,000;
    /// x-export-truncated says when more matched) as CSV (default) or NDJSON. fields picks columns:
    /// id, primary_email, username, first_name, last_name, external_id, created_at,
    /// last_sign_in_at, banned, mfa_enrolled, plus traits.&lt;key&gt; /
    /// public_metadata.&lt;path&gt;. CSV cells that start with = + - @ are prefixed with an
    /// apostrophe so a spreadsheet never runs them as formulas.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::UsersSearchExportBody`]. Returns nothing (`204 No Content`).
    pub async fn export(
        &self,
        body: &types_ext::UsersSearchExportBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<(), BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/users/search/export",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl UsersSearchViews<'_> {
    /// `GET /v1/users/search/views` — The saved user-search views of the instance, by name.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::UsersSearchViewsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::UsersSearchViewsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/users/search/views",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/users/search/views` — Save a named filter (and sort) to re-run. A filter that
    /// could never run is refused; a duplicate name is a 400. → 201.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::UsersSearchViewsCreateBody`]. Returns [`types_ext::UserSearchView`].
    pub async fn create(
        &self,
        body: &types_ext::UsersSearchViewsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::UserSearchView, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/users/search/views",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `PATCH /v1/users/search/views/{id}` — Rename a saved view or change its filter or sort.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::UsersSearchViewsUpdateBody`]. Returns [`types_ext::UserSearchView`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::UsersSearchViewsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::UserSearchView, BackendError> {
        let path = format!("/v1/users/search/views/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/users/search/views/{id}` — Delete a saved user-search view.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::UsersSearchViewsDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::UsersSearchViewsDeleteResponse, BackendError> {
        let path = format!("/v1/users/search/views/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl Groups<'_> {
    /// The `groups / rules` operations of the Backend API.
    pub fn rules(&self) -> GroupsRules<'_> {
        GroupsRules {
            client: self.client,
        }
    }
    /// `GET /v1/groups` — Every instance group with its member count, by slug.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::GroupsListResponse`].
    pub async fn list(&self, query: &Query) -> Result<types_ext::GroupsListResponse, BackendError> {
        self.client
            .request(HttpMethod::Get, "/v1/groups", &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/groups` — Create an instance group. Emits group.created. → 201.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::GroupsCreateBody`]. Returns [`types_ext::Group`].
    pub async fn create(
        &self,
        body: &types_ext::GroupsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::Group, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/groups",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/groups/{id}` — One group, by id or slug.
    ///
    /// Returns [`types_ext::Group`].
    pub async fn get(&self, id: &str) -> Result<types_ext::Group, BackendError> {
        let path = format!("/v1/groups/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/groups/{id}` — Change a group. Emits group.updated.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::GroupsUpdateBody`]. Returns [`types_ext::Group`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::GroupsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::Group, BackendError> {
        let path = format!("/v1/groups/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/groups/{id}` — Delete a group: its memberships go, its children move to the top
    /// level. Emits group.deleted.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::GroupsDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::GroupsDeleteResponse, BackendError> {
        let path = format!("/v1/groups/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/groups/{id}/members` — The members of one group (direct members only), with how
    /// each joined (manual, dynamic, sso, rule). Cursor paged by user id.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::GroupsListMembersResponse`].
    pub async fn list_members(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::GroupsListMembersResponse, BackendError> {
        let path = format!("/v1/groups/{}/members", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/groups/{id}/members` — Add up to 500 users by hand. A member who joined by filter,
    /// SSO or rule becomes manual, so a re-apply leaves them. Emits group.member_added per new
    /// member.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::GroupsAddMembersBody`]. Returns nothing (`204 No Content`).
    pub async fn add_members(
        &self,
        id: &str,
        body: &types_ext::GroupsAddMembersBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/groups/{}/members", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/groups/{id}/members/remove` — Remove up to 500 users from a group. Emits
    /// group.member_removed.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::GroupsRemoveMembersBody`]. Returns nothing (`204 No Content`).
    pub async fn remove_members(
        &self,
        id: &str,
        body: &types_ext::GroupsRemoveMembersBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/groups/{}/members/remove", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/groups/{id}/reapply` — Re-evaluate a dynamic group now: users matching
    /// dynamic_filter are added, those who no longer match are removed; manual members are never
    /// touched (400 when the group has no dynamic_filter, or the filter matches over 50,000 users).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::GroupsReapplyResponse`].
    pub async fn reapply(
        &self,
        id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::GroupsReapplyResponse, BackendError> {
        let path = format!("/v1/groups/{}/reapply", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/users/{id}/groups` — A user's direct groups and how they joined each.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::GroupsForUserResponse`].
    pub async fn for_user(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::GroupsForUserResponse, BackendError> {
        let path = format!("/v1/users/{}/groups", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl GroupsRules<'_> {
    /// `GET /v1/group_rules` — Group rules, lowest priority number first.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::GroupsRulesListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::GroupsRulesListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/group_rules",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/group_rules` — Create a rule: when a user matches condition, run the actions (add
    /// to a group, grant an app role, set a trait). → 201.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::GroupsRulesCreateBody`]. Returns [`types_ext::GroupRule`].
    pub async fn create(
        &self,
        body: &types_ext::GroupsRulesCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::GroupRule, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/group_rules",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/group_rules/apply` — Run every enabled rule in priority order. One result per
    /// rule.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::GroupsRulesApplyAllResponse`].
    pub async fn apply_all(
        &self,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::GroupsRulesApplyAllResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/group_rules/apply",
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/group_rules/{id}` — One group rule, with its condition and actions.
    ///
    /// Returns [`types_ext::GroupRule`].
    pub async fn get(&self, id: &str) -> Result<types_ext::GroupRule, BackendError> {
        let path = format!("/v1/group_rules/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/group_rules/{id}` — Change a group rule, its condition or actions.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::GroupsRulesUpdateBody`]. Returns [`types_ext::GroupRule`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::GroupsRulesUpdateBody,
        query: &Query,
    ) -> Result<types_ext::GroupRule, BackendError> {
        let path = format!("/v1/group_rules/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/group_rules/{id}` — Delete a rule. Memberships it created stay until removed.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::GroupsRulesDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::GroupsRulesDeleteResponse, BackendError> {
        let path = format!("/v1/group_rules/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/group_rules/{id}/apply` — Run one rule against every matching user now. Returns
    /// the match count and what changed.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::GroupsRulesApplyResponse`].
    pub async fn apply(
        &self,
        id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::GroupsRulesApplyResponse, BackendError> {
        let path = format!("/v1/group_rules/{}/apply", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
}

impl Migrations<'_> {
    /// The `migrations / imports` operations of the Backend API.
    pub fn imports(&self) -> MigrationsImports<'_> {
        MigrationsImports {
            client: self.client,
        }
    }
    /// `POST /v1/migrations/{source}/exchange` — Server-to-server exchange of an old `source`
    /// session for an Atlas session, once (what migrationBridge({ source }) calls with the secret
    /// key). The token is verified (vendor JWT against the bridge's issuer and keys, or sha256
    /// matched against imported sessions), mapped to the imported user, spent in the single-use
    /// ledger and then takes the normal sign-in path (guards, MFA policy, post_login Actions,
    /// audit). Returns tokens in the body, or a sign_in_attempt when a second factor is owed.
    /// Limited per instance (6000/min), per end-user IP (60/min) and per user (10/min). Send the
    /// end user's IP / user agent in X-Atlas-Client-IP / X-Atlas-Client-User-Agent.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::MigrationsExchangeBody`]. Returns [`types_ext::MigrationsExchangeResponse`].
    pub async fn exchange(
        &self,
        source: &str,
        body: &types_ext::MigrationsExchangeBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::MigrationsExchangeResponse, BackendError> {
        let path = format!("/v1/migrations/{}/exchange", seg(source));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/migrations/sources` — Every migration source: what it exports, whether passwords
    /// move (or need lazy migration), its bridge preset and variables, and its lazy-migration
    /// preset.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::MigrationsSourcesResponse`].
    pub async fn sources(
        &self,
        query: &Query,
    ) -> Result<types_ext::MigrationsSourcesResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/migrations/sources",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/migrations/{source}/bridge` — Read the zero-logout bridge settings for `source`
    /// (window, JWT preset / issuer / keys, claims, cookie names) and exchange counts. Never
    /// returns a shared secret.
    ///
    /// Returns [`types_ext::MigrationsGetBridgeResponse`].
    pub async fn get_bridge(
        &self,
        source: &str,
    ) -> Result<types_ext::MigrationsGetBridgeResponse, BackendError> {
        let path = format!("/v1/migrations/{}/bridge", seg(source));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PUT /v1/migrations/{source}/bridge` — Create or update the bridge settings for `source`.
    /// Every field is optional and merged onto the stored ones; a preset fills the JWT settings
    /// from its variables, explicit fields override it. The keys URL must be public https on a
    /// production instance. `better_auth` takes the Better Auth bridge body (see
    /// /v1/migrations/better_auth/bridge).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::MigrationsSetBridgeBody`]. Returns [`types_ext::MigrationsSetBridgeResponse`].
    pub async fn set_bridge(
        &self,
        source: &str,
        body: &types_ext::MigrationsSetBridgeBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::MigrationsSetBridgeResponse, BackendError> {
        let path = format!("/v1/migrations/{}/bridge", seg(source));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `DELETE /v1/migrations/{source}/bridge` — Remove the bridge settings for `source` (the
    /// bridge is off and any stored secret deleted).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::MigrationsDeleteBridgeResponse`].
    pub async fn delete_bridge(
        &self,
        source: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::MigrationsDeleteBridgeResponse, BackendError> {
        let path = format!("/v1/migrations/{}/bridge", seg(source));
        self.client
            .request(
                HttpMethod::Delete,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
}

impl MigrationsImports<'_> {
    /// `GET /v1/migrations/{source}/imports/public_key` — The instance's import public key (created
    /// on first read). Seal the export to it; only this instance can open the bundle. One key
    /// serves every source. A key with jobs:write may read it too.
    ///
    /// Returns [`types_ext::MigrationsImportsGetPublicKeyResponse`].
    pub async fn get_public_key(
        &self,
        source: &str,
    ) -> Result<types_ext::MigrationsImportsGetPublicKeyResponse, BackendError> {
        let path = format!("/v1/migrations/{}/imports/public_key", seg(source));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `POST /v1/migrations/{source}/imports/public_key/rotate` — Replace the import key. A bundle
    /// sealed to the old key no longer finalizes; export again with the new key.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::MigrationsImportsRotatePublicKeyResponse`].
    pub async fn rotate_public_key(
        &self,
        source: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::MigrationsImportsRotatePublicKeyResponse, BackendError> {
        let path = format!("/v1/migrations/{}/imports/public_key/rotate", seg(source));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/migrations/{source}/imports` — Start an import from `source` (status `uploading`).
    /// Then upload the sealed bundle with PUT …/parts/{part} and call …/finalize. Nothing is
    /// written to users until apply.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::MigrationsImportsCreateBody`]. Returns [`types_ext::MigrationsImportsCreateResponse`].
    pub async fn create(
        &self,
        source: &str,
        body: &types_ext::MigrationsImportsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::MigrationsImportsCreateResponse, BackendError> {
        let path = format!("/v1/migrations/{}/imports", seg(source));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/migrations/{source}/imports` — List the imports from `source`, newest first (cursor
    /// pagination).
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::MigrationsImportsListResponse`].
    pub async fn list(
        &self,
        source: &str,
        query: &Query,
    ) -> Result<types_ext::MigrationsImportsListResponse, BackendError> {
        let path = format!("/v1/migrations/{}/imports", seg(source));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/migrations/{source}/imports/{id}` — Fetch one import: status, the dry-run report,
    /// live progress and the apply result.
    ///
    /// Returns [`types_ext::MigrationsImportsGetResponse`].
    pub async fn get(
        &self,
        source: &str,
        id: &str,
    ) -> Result<types_ext::MigrationsImportsGetResponse, BackendError> {
        let path = format!("/v1/migrations/{}/imports/{}", seg(source), seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `DELETE /v1/migrations/{source}/imports/{id}` — Delete an import and its stored bundle. Data
    /// it already imported stays. Refused (409) while analyzing or applying.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::MigrationsImportsDeleteResponse`].
    pub async fn delete(
        &self,
        source: &str,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::MigrationsImportsDeleteResponse, BackendError> {
        let path = format!("/v1/migrations/{}/imports/{}", seg(source), seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `PUT /v1/migrations/{source}/imports/{id}/parts/{part}` — Upload part `part` (1, 2, …) of
    /// the sealed bundle: whole lines, at most 10 MiB, as `{ "data": "…" }` or a text/plain body.
    /// Re-sending a part replaces it. Only while `uploading`.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::MigrationsImportsPutPartBody`]. Returns [`types_ext::MigrationsImportsPutPartResponse`].
    pub async fn put_part(
        &self,
        source: &str,
        id: &str,
        part: &str,
        body: &types_ext::MigrationsImportsPutPartBody,
        query: &Query,
    ) -> Result<types_ext::MigrationsImportsPutPartResponse, BackendError> {
        let path = format!(
            "/v1/migrations/{}/imports/{}/parts/{}",
            seg(source),
            seg(id),
            seg(part)
        );
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `POST /v1/migrations/{source}/imports/{id}/finalize` — Close the upload: every part 1..n
    /// present, the bundle sealed to the active import key and in a format `source` reads (else 400
    /// or status `invalid`). The dry run follows: inline up to 4 MiB (200, `ready`), else in the
    /// background (202, `analyzing`; poll GET).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::MigrationsImportsFinalizeResponse`].
    pub async fn finalize(
        &self,
        source: &str,
        id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::MigrationsImportsFinalizeResponse, BackendError> {
        let path = format!(
            "/v1/migrations/{}/imports/{}/finalize",
            seg(source),
            seg(id)
        );
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/migrations/{source}/imports/{id}/dry_run` — Run the dry run again, optionally with
    /// new options (they replace the stored ones). Reads only.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::MigrationsImportsDryRunBody`]. Returns [`types_ext::MigrationsImportsDryRunResponse`].
    pub async fn dry_run(
        &self,
        source: &str,
        id: &str,
        body: &types_ext::MigrationsImportsDryRunBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::MigrationsImportsDryRunResponse, BackendError> {
        let path = format!("/v1/migrations/{}/imports/{}/dry_run", seg(source), seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/migrations/{source}/imports/{id}/apply` — Import the bundle. Every record is an
    /// idempotent upsert keyed by its source id, so applying a failed import again resumes where it
    /// stopped. Up to 1,000 remaining records run inline (200), more are queued (202). With
    /// conflicts in the dry run, send confirm_conflicts: true.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::MigrationsImportsApplyBody`]. Returns [`types_ext::MigrationsImportsApplyResponse`].
    pub async fn apply(
        &self,
        source: &str,
        id: &str,
        body: &types_ext::MigrationsImportsApplyBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::MigrationsImportsApplyResponse, BackendError> {
        let path = format!("/v1/migrations/{}/imports/{}/apply", seg(source), seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl ManagedGrants<'_> {
    /// `GET /v1/grant_management/grants` — List OpenID Grant Management grants: what each OAuth
    /// client holds for each user under a `grant_id`, newest first. Filter by `user_id`,
    /// `client_id` (the public client id) and `status`.
    ///
    /// Query parameters: `user_id`, `client_id`, `status`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::ManagedGrantsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::ManagedGrantsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/grant_management/grants",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/grant_management/grants/{id}` — Read one grant: its scopes, resource,
    /// authorization_details, status and revision.
    ///
    /// Returns [`types_ext::ManagedGrantsGetResponse`].
    pub async fn get(&self, id: &str) -> Result<types_ext::ManagedGrantsGetResponse, BackendError> {
        let path = format!("/v1/grant_management/grants/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/grant_management/grants/{id}` — Narrow a grant: send the `scopes` and/or
    /// `authorization_details` it should keep. Anything it does not already hold is a 400 (only the
    /// user widens a grant, by authorizing again with `grant_management_action=merge`). Refresh
    /// tokens under the grant are clamped to the narrower scope; a revoked grant is a 404.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ManagedGrantsNarrowBody`]. Returns [`types_ext::ManagedGrantsNarrowResponse`].
    pub async fn narrow(
        &self,
        id: &str,
        body: &types_ext::ManagedGrantsNarrowBody,
        query: &Query,
    ) -> Result<types_ext::ManagedGrantsNarrowResponse, BackendError> {
        let path = format!("/v1/grant_management/grants/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/grant_management/grants/{id}` — Revoke a grant and everything issued under it:
    /// refresh tokens stop refreshing and access tokens that carry the `grant_id` stop validating
    /// at once. `tokens_ended` counts the refresh grants that ended with it. Revoking an
    /// already-revoked grant answers 200 with `tokens_ended: 0`.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::ManagedGrantsRevokeResponse`].
    pub async fn revoke(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::ManagedGrantsRevokeResponse, BackendError> {
        let path = format!("/v1/grant_management/grants/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl LeastPrivilege<'_> {
    /// `GET /v1/least_privilege/report` — The least-privilege report: for every active secret key,
    /// OAuth client, MCP gateway and agent, what it is allowed to do against what it used over the
    /// window, the permissions never used, and the narrower grant that would still cover its use.
    /// Credentials with something unused come first. `format=csv` exports one row per permission.
    ///
    /// Query parameters: `days`, `subject_type`, `subject_id`, `only_unused`, `limit`, `format`, `starting_after`.
    ///
    /// Returns [`types_ext::LeastPrivilegeReportResponse`].
    pub async fn report(
        &self,
        query: &Query,
    ) -> Result<types_ext::LeastPrivilegeReportResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/least_privilege/report",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/least_privilege/report/{type}/{id}` — The least-privilege report of one credential
    /// (`type` is api_key, oauth_client, mcp_gateway or agent). 404 for a credential the report
    /// does not cover, such as a revoked key.
    ///
    /// Query parameters: `days`.
    ///
    /// Returns [`types_ext::LeastPrivilegeGetResponse`].
    pub async fn get(
        &self,
        subject_type: &str,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::LeastPrivilegeGetResponse, BackendError> {
        let path = format!(
            "/v1/least_privilege/report/{}/{}",
            seg(subject_type),
            seg(id)
        );
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/least_privilege/apply` — Apply a credential's suggestion: narrow a secret key's
    /// scopes, an OAuth client's allowed scopes, an MCP gateway's tool policy, or revoke an agent's
    /// unused tool grants. Preview it first with `?dry_run=true`, then send the same body for real.
    /// `digest` (from the report) must match the current suggestion, else 409, so what you
    /// previewed is what is applied; the write is conditional on the credential being unchanged. A
    /// suggestion only ever removes permissions. Over a window the data does not fully cover
    /// (`confidence: low`) it needs `acknowledge_short_window: true`. Audited as
    /// `least_privilege.applied`.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::LeastPrivilegeApplyBody`]. Returns [`types_ext::LeastPrivilegeApplyResponse`].
    pub async fn apply(
        &self,
        body: &types_ext::LeastPrivilegeApplyBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::LeastPrivilegeApplyResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/least_privilege/apply",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl DeliveryHealth<'_> {
    /// `GET /v1/delivery_health/{kind}/{id}` — Delivery health of one target. 404 until a delivery
    /// to it has been recorded.
    ///
    /// Returns [`types_ext::DeliveryHealth`].
    pub async fn get(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<types_ext::DeliveryHealth, BackendError> {
        let path = format!("/v1/delivery_health/{}/{}", seg(kind), seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
}

impl Flags<'_> {
    /// `PUT /v1/organizations/{id}/entitlements` — Assign an organization's entitlements (a plan, a
    /// feature list and/or limits, optionally expiring) without a billing subscription. Replaces
    /// whatever was assigned or overridden before; an empty body clears it and the organization
    /// falls back to its billing plan. Reaches the `pla`, `fea` and `ent` session claims on the
    /// next token.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::FlagsAssignOrganizationEntitlementsBody`]. Returns [`types_ext::FlagsAssignOrganizationEntitlementsResponse`].
    pub async fn assign_organization_entitlements(
        &self,
        id: &str,
        body: &types_ext::FlagsAssignOrganizationEntitlementsBody,
        query: &Query,
    ) -> Result<types_ext::FlagsAssignOrganizationEntitlementsResponse, BackendError> {
        let path = format!("/v1/organizations/{}/entitlements", seg(id));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `POST /v1/feature_flags` — Create a feature flag: a typed value (`boolean`, `string`, `int`
    /// or `json`) with a `default_value`, an `off_value` (served while `enabled` is false; defaults
    /// to false for a boolean, else the default) and ordered targeting `rules` by org, user, plan
    /// and percentage. 409 when the key exists.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::FlagsCreateBody`]. Returns [`types_ext::FlagsCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::FlagsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::FlagsCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/feature_flags",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/feature_flags` — List feature flags ordered by key. `starting_after` is the key of
    /// the last flag of the previous page.
    ///
    /// Query parameters: `starting_after`, `limit`.
    ///
    /// Returns [`types_ext::FlagsListResponse`].
    pub async fn list(&self, query: &Query) -> Result<types_ext::FlagsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/feature_flags",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/feature_flags/{key}` — Read one feature flag.
    ///
    /// Returns [`types_ext::FlagsRetrieveResponse`].
    pub async fn retrieve(
        &self,
        key: &str,
    ) -> Result<types_ext::FlagsRetrieveResponse, BackendError> {
        let path = format!("/v1/feature_flags/{}", seg(key));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/feature_flags/{key}` — Change a flag's description, kill switch, default or off
    /// value, or replace its rules. The type and key are fixed.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::FlagsUpdateBody`]. Returns [`types_ext::FlagsUpdateResponse`].
    pub async fn update(
        &self,
        key: &str,
        body: &types_ext::FlagsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::FlagsUpdateResponse, BackendError> {
        let path = format!("/v1/feature_flags/{}", seg(key));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/feature_flags/{key}` — Delete a feature flag.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::FlagsDeleteResponse`].
    pub async fn delete(
        &self,
        key: &str,
        query: &Query,
    ) -> Result<types_ext::FlagsDeleteResponse, BackendError> {
        let path = format!("/v1/feature_flags/{}", seg(key));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/feature_flags/evaluate` — Evaluate every flag (or the listed `keys`) for a subject
    /// (`user_id`, `org_id`, `plan`). When `plan` is omitted it is the organization's (else the
    /// user's) resolved plan. Each result carries the `value` and a `reason` (`off`, `default` or
    /// `rule:&lt;index&gt;`).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::FlagsEvaluateBody`]. Returns [`types_ext::FlagsEvaluateResponse`].
    pub async fn evaluate(
        &self,
        body: &types_ext::FlagsEvaluateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::FlagsEvaluateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/feature_flags/evaluate",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `PUT /v1/users/{id}/entitlements` — Assign a user's entitlements the same way as for an
    /// organization.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::FlagsAssignUserEntitlementsBody`]. Returns [`types_ext::FlagsAssignUserEntitlementsResponse`].
    pub async fn assign_user_entitlements(
        &self,
        id: &str,
        body: &types_ext::FlagsAssignUserEntitlementsBody,
        query: &Query,
    ) -> Result<types_ext::FlagsAssignUserEntitlementsResponse, BackendError> {
        let path = format!("/v1/users/{}/entitlements", seg(id));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
}

impl MfaFactors<'_> {
    /// The `mfa_factors / yubikeys` operations of the Backend API.
    pub fn yubikeys(&self) -> MfaFactorsYubikeys<'_> {
        MfaFactorsYubikeys {
            client: self.client,
        }
    }
    /// The `mfa_factors / smart_card_mappings` operations of the Backend API.
    pub fn smart_card_mappings(&self) -> MfaFactorsSmartCardMappings<'_> {
        MfaFactorsSmartCardMappings {
            client: self.client,
        }
    }
    /// `PUT /v1/instance/yubico_secret` — Store (write-only, encrypted) the Yubico cloud API secret
    /// key (base64, from upgrade.yubico.com/getapikey). The client id is mfa.yubikey.clientId. Used
    /// when mfa.yubikey.mode is "cloud".
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::MfaFactorsSetYubicoSecretBody`]. Returns [`types_ext::MfaFactorsSetYubicoSecretResponse`].
    pub async fn set_yubico_secret(
        &self,
        body: &types_ext::MfaFactorsSetYubicoSecretBody,
        query: &Query,
    ) -> Result<types_ext::MfaFactorsSetYubicoSecretResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/instance/yubico_secret",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/instance/yubico_secret` — Remove the stored Yubico cloud secret. Cloud-mode
    /// YubiKey sign-ins then fail until a new one is stored.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::MfaFactorsRemoveYubicoSecretResponse`].
    pub async fn remove_yubico_secret(
        &self,
        query: &Query,
    ) -> Result<types_ext::MfaFactorsRemoveYubicoSecretResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Delete,
                "/v1/instance/yubico_secret",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `PUT /v1/instance/duo_secret` — Store (write-only, encrypted) the Duo Web SDK / Universal
    /// Prompt client secret. The client id (integration key) and API host are mfa.duo.clientId and
    /// mfa.duo.apiHost.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::MfaFactorsSetDuoSecretBody`]. Returns [`types_ext::MfaFactorsSetDuoSecretResponse`].
    pub async fn set_duo_secret(
        &self,
        body: &types_ext::MfaFactorsSetDuoSecretBody,
        query: &Query,
    ) -> Result<types_ext::MfaFactorsSetDuoSecretResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/instance/duo_secret",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/instance/duo_secret` — Remove the stored Duo client secret.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::MfaFactorsRemoveDuoSecretResponse`].
    pub async fn remove_duo_secret(
        &self,
        query: &Query,
    ) -> Result<types_ext::MfaFactorsRemoveDuoSecretResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Delete,
                "/v1/instance/duo_secret",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `PUT /v1/instance/smart_card_secret` — Store (write-only, encrypted) the shared secret your
    /// TLS proxy sends in the mfa.smartCard.secretHeader header, so Atlas believes the certificate
    /// headers only from your proxy. Use a random value of at least 24 characters.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::MfaFactorsSetSmartCardSecretBody`]. Returns [`types_ext::MfaFactorsSetSmartCardSecretResponse`].
    pub async fn set_smart_card_secret(
        &self,
        body: &types_ext::MfaFactorsSetSmartCardSecretBody,
        query: &Query,
    ) -> Result<types_ext::MfaFactorsSetSmartCardSecretResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/instance/smart_card_secret",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/instance/smart_card_secret` — Remove the stored proxy secret. Smart card sign-in
    /// then refuses every request.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::MfaFactorsRemoveSmartCardSecretResponse`].
    pub async fn remove_smart_card_secret(
        &self,
        query: &Query,
    ) -> Result<types_ext::MfaFactorsRemoveSmartCardSecretResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Delete,
                "/v1/instance/smart_card_secret",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/instance/duo_health_check` — Ask Duo whether the configured integration key,
    /// stored secret and API host are accepted (Duo's health check). Reports ok and a message;
    /// nothing is changed.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::MfaFactorsDuoHealthCheckResponse`].
    pub async fn duo_health_check(
        &self,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::MfaFactorsDuoHealthCheckResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/instance/duo_health_check",
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `DELETE /v1/users/{id}/security_questions` — Clear a user's security-question answers (and
    /// any lockout). They set new ones from their account.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::MfaFactorsResetSecurityQuestionsResponse`].
    pub async fn reset_security_questions(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::MfaFactorsResetSecurityQuestionsResponse, BackendError> {
        let path = format!("/v1/users/{}/security_questions", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl MfaFactorsYubikeys<'_> {
    /// `GET /v1/yubikeys` — List the registered self-held YubiKeys (public id, owner, replay
    /// counter). The AES keys are never returned.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::MfaFactorsYubikeysListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::MfaFactorsYubikeysListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/yubikeys",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/yubikeys` — Register a YubiKey's AES key for self-held Yubico OTP
    /// (mfa.yubikey.mode "self_held"). The key is stored encrypted and never returned. Give user_id
    /// to assign it; otherwise the first user to enrol it with a valid OTP claims it. 409 when the
    /// public id is already registered.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::MfaFactorsYubikeysRegisterBody`]. Returns [`types_ext::MfaFactorsYubikeysRegisterResponse`].
    pub async fn register(
        &self,
        body: &types_ext::MfaFactorsYubikeysRegisterBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::MfaFactorsYubikeysRegisterResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/yubikeys",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `DELETE /v1/yubikeys/{id}` — Remove a registered YubiKey. A factor already enrolled with it
    /// stops verifying.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::MfaFactorsYubikeysRemoveResponse`].
    pub async fn remove(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::MfaFactorsYubikeysRemoveResponse, BackendError> {
        let path = format!("/v1/yubikeys/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl MfaFactorsSmartCardMappings<'_> {
    /// `GET /v1/users/{id}/smartcard_mappings` — List the certificate attributes registered for a
    /// user.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::MfaFactorsSmartCardMappingsListResponse`].
    pub async fn list(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::MfaFactorsSmartCardMappingsListResponse, BackendError> {
        let path = format!("/v1/users/{}/smartcard_mappings", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/users/{id}/smartcard_mappings` — Pre-register the certificate attribute that signs
    /// this user in with a smart card: kind fingerprint (SHA-256, 64 hex), serial (hex, plus the
    /// issuer DN), san_email, san_upn or subject_cn. A registered mapping only applies while its
    /// kind is listed in mfa.smartCard.mappingRules. 409 when the value is already mapped.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::MfaFactorsSmartCardMappingsAddBody`]. Returns [`types_ext::MfaFactorsSmartCardMappingsAddResponse`].
    pub async fn add(
        &self,
        id: &str,
        body: &types_ext::MfaFactorsSmartCardMappingsAddBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::MfaFactorsSmartCardMappingsAddResponse, BackendError> {
        let path = format!("/v1/users/{}/smartcard_mappings", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `DELETE /v1/users/{id}/smartcard_mappings/{mappingId}` — Remove a registered certificate
    /// mapping.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::MfaFactorsSmartCardMappingsRemoveResponse`].
    pub async fn remove(
        &self,
        id: &str,
        mapping_id: &str,
        query: &Query,
    ) -> Result<types_ext::MfaFactorsSmartCardMappingsRemoveResponse, BackendError> {
        let path = format!(
            "/v1/users/{}/smartcard_mappings/{}",
            seg(id),
            seg(mapping_id)
        );
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl Analytics<'_> {
    /// The `analytics / reports` operations of the Backend API.
    pub fn reports(&self) -> AnalyticsReports<'_> {
        AnalyticsReports {
            client: self.client,
        }
    }
    /// The `analytics / alert_rules` operations of the Backend API.
    pub fn alert_rules(&self) -> AnalyticsAlertRules<'_> {
        AnalyticsAlertRules {
            client: self.client,
        }
    }
    /// `GET /v1/analytics/funnel` — Where sign-in or sign-up attempts end, per method: started,
    /// completed, abandoned, and the step each unfinished attempt stopped at, with the completion
    /// rate. Each attempt is counted once, at its final state.
    ///
    /// Query parameters: `kind`, `from`, `to`, `days`, `granularity`, `organization_id`, `format`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AnalyticsFunnelResponse`].
    pub async fn funnel(
        &self,
        query: &Query,
    ) -> Result<types_ext::AnalyticsFunnelResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/analytics/funnel",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/analytics/journey_funnel` — What happened at each step of a sign-in journey: how
    /// often it held a sign-in (a required action or form), was completed, ran at the sign-in (an
    /// Action, claim or redirect) or refused it, with the completion rate of its holds. Steps
    /// follow the active version; a sub-flow's steps are prefixed with the sub-flow step id. No
    /// organization slice.
    ///
    /// Query parameters: `journey_id`, `from`, `to`, `days`, `granularity`, `organization_id`, `format`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AnalyticsJourneyFunnelResponse`].
    pub async fn journey_funnel(
        &self,
        query: &Query,
    ) -> Result<types_ext::AnalyticsJourneyFunnelResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/analytics/journey_funnel",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/analytics/failures` — Failed first- and second-factor attempts by reason and
    /// method, most frequent first. No organization slice (a failed attempt belongs to no
    /// organization).
    ///
    /// Query parameters: `from`, `to`, `days`, `granularity`, `organization_id`, `format`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AnalyticsFailuresResponse`].
    pub async fn failures(
        &self,
        query: &Query,
    ) -> Result<types_ext::AnalyticsFailuresResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/analytics/failures",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/analytics/breakdown` — Sign-ins split by one dimension: method, device type,
    /// browser, operating system or country (country needs a GeoIP database on the deployment;
    /// otherwise it reports `unknown`).
    ///
    /// Query parameters: `dimension`, `from`, `to`, `days`, `granularity`, `organization_id`, `format`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AnalyticsBreakdownResponse`].
    pub async fn breakdown(
        &self,
        query: &Query,
    ) -> Result<types_ext::AnalyticsBreakdownResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/analytics/breakdown",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/analytics/active_users` — Distinct active users and sign-ins per bucket, each
    /// bucket split into new users (signed up in that bucket) and returning users, plus trailing
    /// 1/7/30-day active-user counts (dau, wau, mau) ending at `to`.
    ///
    /// Query parameters: `from`, `to`, `days`, `granularity`, `organization_id`, `format`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AnalyticsActiveUsersResponse`].
    pub async fn active_users(
        &self,
        query: &Query,
    ) -> Result<types_ext::AnalyticsActiveUsersResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/analytics/active_users",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/analytics/passkey_adoption` — How many users hold a passkey (adoption rate), and
    /// the passkey share of sign-ins per bucket.
    ///
    /// Query parameters: `from`, `to`, `days`, `granularity`, `organization_id`, `format`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AnalyticsPasskeyAdoptionResponse`].
    pub async fn passkey_adoption(
        &self,
        query: &Query,
    ) -> Result<types_ext::AnalyticsPasskeyAdoptionResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/analytics/passkey_adoption",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/analytics/api_usage` — API usage per subject against its own baseline: secret keys
    /// calling the Backend API, end-user API keys verified through /v1/api_keys/verify, and
    /// organizations (Backend API calls on the organization plus verifications of its keys). For
    /// each: requests and the failure rate in the window, the average hourly rate over the 7 days
    /// before, and the ratio between them, highest ratio first (at most 100). Counts are written in
    /// batches and can lag by up to a minute.
    ///
    /// Query parameters: `subject_type`, `subject_id`, `window_minutes`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AnalyticsApiUsageResponse`].
    pub async fn api_usage(
        &self,
        query: &Query,
    ) -> Result<types_ext::AnalyticsApiUsageResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/analytics/api_usage",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
}

impl AnalyticsReports<'_> {
    /// `GET /v1/analytics/reports/inactive_users` — Compliance report: users who have not signed in
    /// for `inactive_days` (default 90), oldest id first, cursor-paginated (an export returns up to
    /// 50,000 rows).
    ///
    /// Query parameters: `inactive_days`, `limit`, `starting_after`, `from`, `to`, `days`, `granularity`, `organization_id`, `format`.
    ///
    /// Returns [`types_ext::AnalyticsReportsInactiveUsersResponse`].
    pub async fn inactive_users(
        &self,
        query: &Query,
    ) -> Result<types_ext::AnalyticsReportsInactiveUsersResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/analytics/reports/inactive_users",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/analytics/reports/mfa_coverage` — Compliance report: how many users are protected
    /// by a second factor, a passkey, either, or neither.
    ///
    /// Query parameters: `from`, `to`, `days`, `granularity`, `organization_id`, `format`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AnalyticsReportsMfaCoverageResponse`].
    pub async fn mfa_coverage(
        &self,
        query: &Query,
    ) -> Result<types_ext::AnalyticsReportsMfaCoverageResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/analytics/reports/mfa_coverage",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/analytics/reports/access_by_app` — Compliance report: for each application (OAuth
    /// client), how many users have access, how many grants are active and how many users signed in
    /// during the window.
    ///
    /// Query parameters: `from`, `to`, `days`, `granularity`, `organization_id`, `format`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AnalyticsReportsAccessByAppResponse`].
    pub async fn access_by_app(
        &self,
        query: &Query,
    ) -> Result<types_ext::AnalyticsReportsAccessByAppResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/analytics/reports/access_by_app",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
}

impl AnalyticsAlertRules<'_> {
    /// `GET /v1/analytics/alert_rules` — List analytics alert rules with their state and last
    /// measured value. The metric catalog is included.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AnalyticsAlertRulesListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::AnalyticsAlertRulesListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/analytics/alert_rules",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/analytics/alert_rules` — Create an alert rule: tell me when a sign-in health
    /// metric, or a key or organization's API usage against its baseline, crosses a threshold over
    /// a trailing window. It must have email_contacts, a webhook_url or ssf. A webhook signing
    /// secret is returned once.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AnalyticsAlertRulesCreateBody`]. Returns [`types_ext::AnalyticsAlertRulesCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::AnalyticsAlertRulesCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AnalyticsAlertRulesCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/analytics/alert_rules",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/analytics/alert_rules/{id}` — One analytics alert rule.
    ///
    /// Returns [`types_ext::AnalyticsAlertRulesGetResponse`].
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<types_ext::AnalyticsAlertRulesGetResponse, BackendError> {
        let path = format!("/v1/analytics/alert_rules/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/analytics/alert_rules/{id}` — Edit an alert rule. Editing re-arms it.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AnalyticsAlertRulesUpdateBody`]. Returns [`types_ext::AnalyticsAlertRulesUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::AnalyticsAlertRulesUpdateBody,
        query: &Query,
    ) -> Result<types_ext::AnalyticsAlertRulesUpdateResponse, BackendError> {
        let path = format!("/v1/analytics/alert_rules/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/analytics/alert_rules/{id}` — Delete an alert rule.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::AnalyticsAlertRulesDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::AnalyticsAlertRulesDeleteResponse, BackendError> {
        let path = format!("/v1/analytics/alert_rules/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/analytics/alert_rules/{id}/test` — Measure the rule now. With `notify: true` it
    /// also sends the rule's email and webhook, whether or not the rule is breaching, to prove the
    /// delivery path.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AnalyticsAlertRulesTestBody`]. Returns [`types_ext::AnalyticsAlertRulesTestResponse`].
    pub async fn test(
        &self,
        id: &str,
        body: &types_ext::AnalyticsAlertRulesTestBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AnalyticsAlertRulesTestResponse, BackendError> {
        let path = format!("/v1/analytics/alert_rules/{}/test", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl Marketing<'_> {
    /// `GET /v1/marketing_settings` — The marketing settings: which UTM / ad-click-id parameters
    /// the SDK captures onto new users, and the GA4, GTM and Hotjar ids hosted pages load after
    /// consent.
    ///
    /// Returns [`types_ext::MarketingGetSettingsResponse`].
    pub async fn get_settings(
        &self,
    ) -> Result<types_ext::MarketingGetSettingsResponse, BackendError> {
        self.client
            .request(HttpMethod::Get, "/v1/marketing_settings", &[], None, None)
            .await
    }
    /// `PUT /v1/marketing_settings` — Change the marketing settings. `capture.params` empty means
    /// the standard set (utm_source, utm_medium, utm_campaign, utm_term, utm_content, utm_id and
    /// the common ad click ids). Hosted pages load a configured script only when the visitor's
    /// consent manager grants `scripts.consent_category` (default analytics); with no consent
    /// signal nothing loads.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::MarketingUpdateSettingsBody`]. Returns [`types_ext::MarketingUpdateSettingsResponse`].
    pub async fn update_settings(
        &self,
        body: &types_ext::MarketingUpdateSettingsBody,
        query: &Query,
    ) -> Result<types_ext::MarketingUpdateSettingsResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/marketing_settings",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `GET /v1/leads` — The lead / subscribe form's submissions, newest first, with the
    /// first-touch attribution captured with each. `format=csv` exports up to 50,000.
    ///
    /// Query parameters: `limit`, `starting_after`, `form`, `format`.
    ///
    /// Returns [`types_ext::MarketingListLeadsResponse`].
    pub async fn list_leads(
        &self,
        query: &Query,
    ) -> Result<types_ext::MarketingListLeadsResponse, BackendError> {
        self.client
            .request(HttpMethod::Get, "/v1/leads", &query.as_pairs(), None, None)
            .await
    }
    /// `DELETE /v1/leads/{id}` — Delete one captured lead.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::MarketingDeleteLeadResponse`].
    pub async fn delete_lead(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::MarketingDeleteLeadResponse, BackendError> {
        let path = format!("/v1/leads/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl AuditEventSchemas<'_> {
    /// `GET /v1/audit_event_schemas` — List the registered audit event schemas, by action then
    /// version (newest first).
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AuditEventSchemasListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::AuditEventSchemasListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/audit_event_schemas",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/audit_event_schemas` — Register a schema for an action: the target types and actor
    /// types it allows and a JSON Schema its metadata must satisfy. `version` defaults to the next
    /// number for that action; a version is immutable (registering it again is a 409) - change a
    /// schema by registering a new version. From then on events with this action are validated on
    /// write.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AuditEventSchemasRegisterBody`]. Returns [`types_ext::AuditEventSchemasRegisterResponse`].
    pub async fn register(
        &self,
        body: &types_ext::AuditEventSchemasRegisterBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AuditEventSchemasRegisterResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/audit_event_schemas",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/audit_event_schemas/{id}` — One audit event schema.
    ///
    /// Returns [`types_ext::AuditEventSchemasGetResponse`].
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<types_ext::AuditEventSchemasGetResponse, BackendError> {
        let path = format!("/v1/audit_event_schemas/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/audit_event_schemas/{id}` — Change a schema version's description or status. A
    /// deprecated version is no longer applied by default but still validates events that name it
    /// with `schema_version`.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AuditEventSchemasUpdateBody`]. Returns [`types_ext::AuditEventSchemasUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::AuditEventSchemasUpdateBody,
        query: &Query,
    ) -> Result<types_ext::AuditEventSchemasUpdateResponse, BackendError> {
        let path = format!("/v1/audit_event_schemas/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/audit_event_schemas/{id}` — Remove a schema version. Events already recorded
    /// keep their `schema_version` number.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::AuditEventSchemasDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::AuditEventSchemasDeleteResponse, BackendError> {
        let path = format!("/v1/audit_event_schemas/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/audit_events/{id}/redact` — Blank named fields of one audit event (replaced by
    /// \[redacted\]) without deleting it: `actor_id`, `target_id`, `target_name` or
    /// `metadata.&lt;dotted.path&gt;`. A `reason` is required. The redaction is recorded in its own
    /// log (GET /v1/audit_events/:id/redactions) and in Atlas's audit log as `audit_event.redacted`
    /// - the fields and the reason, never the removed values.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AuditEventSchemasRedactBody`]. Returns [`types_ext::AuditEventSchemasRedactResponse`].
    pub async fn redact(
        &self,
        id: &str,
        body: &types_ext::AuditEventSchemasRedactBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AuditEventSchemasRedactResponse, BackendError> {
        let path = format!("/v1/audit_events/{}/redact", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/audit_events/{id}/redactions` — An audit event's redaction history: which fields
    /// were blanked, why, and by which key.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AuditEventSchemasRedactionsResponse`].
    pub async fn redactions(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::AuditEventSchemasRedactionsResponse, BackendError> {
        let path = format!("/v1/audit_events/{}/redactions", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl DirectoryPullSources<'_> {
    /// The `directory_pull_sources / sync_runs` operations of the Backend API.
    pub fn sync_runs(&self) -> DirectoryPullSourcesSyncRuns<'_> {
        DirectoryPullSourcesSyncRuns {
            client: self.client,
        }
    }
    /// `GET /v1/directory_pull_sources` — List HR / directory pull sources, optionally for one
    /// organization (organization_id). Credentials are never returned.
    ///
    /// Query parameters: `organization_id`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::DirectoryPullSourcesListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::DirectoryPullSourcesListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/directory_pull_sources",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/directory_pull_sources` — Create a pull source for an organization: provider
    /// (entra, google_workspace, bamboohr, hibob, personio, csv, rest_json), config, write-only
    /// credentials and settings (schedule, role mappings, disable on removal).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::DirectoryPullSourcesCreateBody`]. Returns [`types_ext::DirectoryPullSourcesCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::DirectoryPullSourcesCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::DirectoryPullSourcesCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/directory_pull_sources",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/directory_pull_sources/{id}` — Read one pull source.
    ///
    /// Returns [`types_ext::DirectoryPullSourcesGetResponse`].
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<types_ext::DirectoryPullSourcesGetResponse, BackendError> {
        let path = format!("/v1/directory_pull_sources/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/directory_pull_sources/{id}` — Change the source name, status (active or paused),
    /// config, credentials, default role or settings. Settings are merged.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::DirectoryPullSourcesUpdateBody`]. Returns [`types_ext::DirectoryPullSourcesUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::DirectoryPullSourcesUpdateBody,
        query: &Query,
    ) -> Result<types_ext::DirectoryPullSourcesUpdateResponse, BackendError> {
        let path = format!("/v1/directory_pull_sources/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/directory_pull_sources/{id}` — Delete a pull source and its run log. Users it
    /// created are kept.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/directory_pull_sources/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `PUT /v1/directory_pull_sources/{id}/csv` — Upload the CSV a csv source without a URL reads
    /// on its next run (up to 5 MiB).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::DirectoryPullSourcesSetCsvBody`]. Returns nothing (`204 No Content`).
    pub async fn set_csv(
        &self,
        id: &str,
        body: &types_ext::DirectoryPullSourcesSetCsvBody,
        query: &Query,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/directory_pull_sources/{}/csv", seg(id));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
}

impl DirectoryPullSourcesSyncRuns<'_> {
    /// `POST /v1/directory_pull_sources/{id}/sync_runs` — Queue a pull now. One run at a time per
    /// source (409 otherwise); the worker executes it.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::DirectoryPullSourcesSyncRunsCreateResponse`].
    pub async fn create(
        &self,
        id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::DirectoryPullSourcesSyncRunsCreateResponse, BackendError> {
        let path = format!("/v1/directory_pull_sources/{}/sync_runs", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/directory_pull_sources/{id}/sync_runs` — List the runs of a source with counts of
    /// people seen, created, re-roled, disabled and re-enabled.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::DirectoryPullSourcesSyncRunsListResponse`].
    pub async fn list(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::DirectoryPullSourcesSyncRunsListResponse, BackendError> {
        let path = format!("/v1/directory_pull_sources/{}/sync_runs", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/directory_pull_sources/{id}/sync_runs/{runId}` — Read one directory pull run with
    /// its counts and error.
    ///
    /// Returns [`types_ext::DirectoryPullSourcesSyncRunsGetResponse`].
    pub async fn get(
        &self,
        id: &str,
        run_id: &str,
    ) -> Result<types_ext::DirectoryPullSourcesSyncRunsGetResponse, BackendError> {
        let path = format!(
            "/v1/directory_pull_sources/{}/sync_runs/{}",
            seg(id),
            seg(run_id)
        );
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
}

impl OrgLdapConnections<'_> {
    /// The `org_ldap_connections / sync_runs` operations of the Backend API.
    pub fn sync_runs(&self) -> OrgLdapConnectionsSyncRuns<'_> {
        OrgLdapConnectionsSyncRuns {
            client: self.client,
        }
    }
    /// `GET /v1/org_ldap_connections/{id}/sync` — Read the directory-sync settings of an
    /// organization LDAP / Active Directory connection (schedule, filters, group-to-role mapping,
    /// disable-on-removal).
    ///
    /// Returns [`types_ext::OrgLdapConnectionsGetSyncResponse`].
    pub async fn get_sync(
        &self,
        id: &str,
    ) -> Result<types_ext::OrgLdapConnectionsGetSyncResponse, BackendError> {
        let path = format!("/v1/org_ldap_connections/{}/sync", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PUT /v1/org_ldap_connections/{id}/sync` — Set the directory-sync settings. Fields you omit
    /// keep their value. Enabling requires an active connection and schedules the first run
    /// immediately; disabling clears the schedule. Role mappings are matched in order, by group DN.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OrgLdapConnectionsSetSyncBody`]. Returns nothing (`204 No Content`).
    pub async fn set_sync(
        &self,
        id: &str,
        body: &types_ext::OrgLdapConnectionsSetSyncBody,
        query: &Query,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/org_ldap_connections/{}/sync", seg(id));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `GET /v1/org_ldap_connections/{id}/relay` — Which relay agent an organization LDAP
    /// connection reaches its directory through, if any.
    ///
    /// Returns [`types_ext::OrgLdapConnectionsGetRelayResponse`].
    pub async fn get_relay(
        &self,
        id: &str,
    ) -> Result<types_ext::OrgLdapConnectionsGetRelayResponse, BackendError> {
        let path = format!("/v1/org_ldap_connections/{}/relay", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PUT /v1/org_ldap_connections/{id}/relay` — Route an LDAP connection through a relay agent
    /// (agent_id), or back to a direct connection (null). The agent must be active and allow the
    /// LDAP server.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OrgLdapConnectionsSetRelayBody`]. Returns nothing (`204 No Content`).
    pub async fn set_relay(
        &self,
        id: &str,
        body: &types_ext::OrgLdapConnectionsSetRelayBody,
        query: &Query,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/org_ldap_connections/{}/relay", seg(id));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
}

impl OrgLdapConnectionsSyncRuns<'_> {
    /// `POST /v1/org_ldap_connections/{id}/sync_runs` — Queue a sync run now (202). `full`
    /// (default) lists the whole directory and, when disable-on-removal is on, bans users that left
    /// it; `delta` only reads entries changed since the last successful run. Refused with 409 while
    /// another run is queued or running.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OrgLdapConnectionsSyncRunsCreateBody`]. Returns nothing (`204 No Content`).
    pub async fn create(
        &self,
        id: &str,
        body: &types_ext::OrgLdapConnectionsSyncRunsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/org_ldap_connections/{}/sync_runs", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/org_ldap_connections/{id}/sync_runs` — The sync run log, newest first, with per-run
    /// counts (seen, created, updated, skipped, disabled, role changes, groups, errors) and any
    /// failure message.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::OrgLdapConnectionsSyncRunsListResponse`].
    pub async fn list(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::OrgLdapConnectionsSyncRunsListResponse, BackendError> {
        let path = format!("/v1/org_ldap_connections/{}/sync_runs", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/org_ldap_connections/{id}/sync_runs/{runId}` — Read one LDAP directory sync run
    /// with its counts and error.
    ///
    /// Returns [`types_ext::OrgLdapConnectionsSyncRunsGetResponse`].
    pub async fn get(
        &self,
        id: &str,
        run_id: &str,
    ) -> Result<types_ext::OrgLdapConnectionsSyncRunsGetResponse, BackendError> {
        let path = format!(
            "/v1/org_ldap_connections/{}/sync_runs/{}",
            seg(id),
            seg(run_id)
        );
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
}

impl RelayAgents<'_> {
    /// `GET /v1/relay_agents` — List the on-prem relay agents with their allowed destinations and
    /// whether each is online. Secrets are never returned.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::RelayAgentsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::RelayAgentsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/relay_agents",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/relay_agents` — Register an outbound-only relay agent. The response carries the
    /// agent token once; it cannot be read back. An agent can reach only the destinations in
    /// allowed_destinations (host, host:port, *.domain).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::RelayAgentsCreateBody`]. Returns [`types_ext::RelayAgentsCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::RelayAgentsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::RelayAgentsCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/relay_agents",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/relay_agents/{id}` — Read one relay agent, including when it last polled.
    ///
    /// Returns [`types_ext::RelayAgentsGetResponse`].
    pub async fn get(&self, id: &str) -> Result<types_ext::RelayAgentsGetResponse, BackendError> {
        let path = format!("/v1/relay_agents/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/relay_agents/{id}` — Rename an agent, change its allowed destinations or pinned
    /// client-certificate thumbprints, or revoke it (status: revoked).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::RelayAgentsUpdateBody`]. Returns [`types_ext::RelayAgentsUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::RelayAgentsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::RelayAgentsUpdateResponse, BackendError> {
        let path = format!("/v1/relay_agents/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/relay_agents/{id}` — Delete a relay agent and its queued jobs.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/relay_agents/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/relay_agents/{id}/rotate_secret` — Issue a new agent token (returned once). The
    /// old token stops working immediately.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::RelayAgentsRotateSecretResponse`].
    pub async fn rotate_secret(
        &self,
        id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::RelayAgentsRotateSecretResponse, BackendError> {
        let path = format!("/v1/relay_agents/{}/rotate_secret", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
}

impl OAuthClientsAppSettings<'_> {
    /// `GET /v1/oauth_clients/{id}/app_settings` — The per-application settings of an OAuth client:
    /// allowed sign-in methods, hosted-page branding, the user-claim allow-list for ID tokens and
    /// userinfo, and the traits a session from this app may write. Null = no restriction.
    ///
    /// Returns [`types_ext::OAuthClientsAppSettingsGetResponse`].
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<types_ext::OAuthClientsAppSettingsGetResponse, BackendError> {
        let path = format!("/v1/oauth_clients/{}/app_settings", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/oauth_clients/{id}/app_settings` — Change the per-application settings. Each
    /// field sent replaces the stored one and null clears it; fields left out keep their value.
    /// Unknown fields and malformed values are refused.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OAuthClientsAppSettingsUpdateBody`]. Returns [`types_ext::OAuthClientsAppSettingsUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::OAuthClientsAppSettingsUpdateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::OAuthClientsAppSettingsUpdateResponse, BackendError> {
        let path = format!("/v1/oauth_clients/{}/app_settings", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl OAuthClientsWorkloadIdentity<'_> {
    /// `GET /v1/workload_identity/presets` — List the workload platforms Atlas knows defaults for
    /// (SPIFFE, Kubernetes, GitHub Actions, GCP, Azure): issuer, JWKS URL and the shape of the
    /// token subject.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::OAuthClientsWorkloadIdentityPresetsResponse`].
    pub async fn presets(
        &self,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsWorkloadIdentityPresetsResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/workload_identity/presets",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/workload_identity/cloud_trust` — Trust-policy snippets that make AWS
    /// (AssumeRoleWithWebIdentity), GCP (workload identity federation) or Azure (federated
    /// credentials) accept an access token issued by this instance. Nothing is changed in the
    /// cloud.
    ///
    /// Query parameters: `provider`, `audience`, `subject`, `tenant_id`.
    ///
    /// Returns [`types_ext::OAuthClientsWorkloadIdentityCloudTrustResponse`].
    pub async fn cloud_trust(
        &self,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsWorkloadIdentityCloudTrustResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/workload_identity/cloud_trust",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
}

impl OAuthClientsTrustedIssuers<'_> {
    /// `GET /v1/oauth_clients/{id}/trusted_issuers` — List the external issuers this OAuth client
    /// trusts to assert users through the RFC 7523 jwt-bearer grant.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::OAuthClientsTrustedIssuersListResponse`].
    pub async fn list(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsTrustedIssuersListResponse, BackendError> {
        let path = format!("/v1/oauth_clients/{}/trusted_issuers", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/oauth_clients/{id}/trusted_issuers` — Trust an external issuer for this client.
    /// With purpose user_assertion (default) its signed JWTs (verified against the inline jwks or
    /// the https jwks_uri) can then be presented to POST /oauth2/token with
    /// grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer. subject_mapping says how the JWT sub
    /// names an Atlas user. With purpose client_auth or both (PRO-06 workload identity) a client
    /// registered with token_endpoint_auth_method workload_jwt authenticates by presenting a token
    /// from this issuer as its client_assertion; subject_pattern is then required and must name the
    /// workload. workload_kind github_actions, gcp and azure fill in the issuer and JWKS URL.
    /// Audited as oauth_trusted_issuer.created.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OAuthClientsTrustedIssuersCreateBody`]. Returns [`types_ext::OAuthClientsTrustedIssuersCreateResponse`].
    pub async fn create(
        &self,
        id: &str,
        body: &types_ext::OAuthClientsTrustedIssuersCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::OAuthClientsTrustedIssuersCreateResponse, BackendError> {
        let path = format!("/v1/oauth_clients/{}/trusted_issuers", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `DELETE /v1/oauth_clients/{id}/trusted_issuers/{issuerId}` — Stop trusting an issuer: its
    /// assertions are refused at once. Audited as oauth_trusted_issuer.deleted.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::OAuthClientsTrustedIssuersDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        issuer_id: &str,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsTrustedIssuersDeleteResponse, BackendError> {
        let path = format!(
            "/v1/oauth_clients/{}/trusted_issuers/{}",
            seg(id),
            seg(issuer_id)
        );
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl OAuthClients<'_> {
    /// The `oauth_clients / app_settings` operations of the Backend API.
    pub fn app_settings(&self) -> OAuthClientsAppSettings<'_> {
        OAuthClientsAppSettings {
            client: self.client,
        }
    }
    /// The `oauth_clients / workload_identity` operations of the Backend API.
    pub fn workload_identity(&self) -> OAuthClientsWorkloadIdentity<'_> {
        OAuthClientsWorkloadIdentity {
            client: self.client,
        }
    }
    /// The `oauth_clients / trusted_issuers` operations of the Backend API.
    pub fn trusted_issuers(&self) -> OAuthClientsTrustedIssuers<'_> {
        OAuthClientsTrustedIssuers {
            client: self.client,
        }
    }
    /// The `oauth_clients / login_requests` operations of the Backend API.
    pub fn login_requests(&self) -> OAuthClientsLoginRequests<'_> {
        OAuthClientsLoginRequests {
            client: self.client,
        }
    }
    /// The `oauth_clients / consent_requests` operations of the Backend API.
    pub fn consent_requests(&self) -> OAuthClientsConsentRequests<'_> {
        OAuthClientsConsentRequests {
            client: self.client,
        }
    }
    /// `GET /v1/oauth_clients/{id}/exchange_policy` — Read the token-exchange policy of an OAuth
    /// client (the defaults, with configured=false, when none is set).
    ///
    /// Returns [`types_ext::OAuthClientsGetExchangePolicyResponse`].
    pub async fn get_exchange_policy(
        &self,
        id: &str,
    ) -> Result<types_ext::OAuthClientsGetExchangePolicyResponse, BackendError> {
        let path = format!("/v1/oauth_clients/{}/exchange_policy", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PUT /v1/oauth_clients/{id}/exchange_policy` — Set the token-exchange policy of an OAuth
    /// client: allowed audiences and scopes, whether it may impersonate (no actor_token), whether
    /// delegation needs may_act, and the maximum act-chain depth. Audited as
    /// oauth_exchange_policy.updated.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OAuthClientsSetExchangePolicyBody`]. Returns [`types_ext::OAuthClientsSetExchangePolicyResponse`].
    pub async fn set_exchange_policy(
        &self,
        id: &str,
        body: &types_ext::OAuthClientsSetExchangePolicyBody,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsSetExchangePolicyResponse, BackendError> {
        let path = format!("/v1/oauth_clients/{}/exchange_policy", seg(id));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/oauth_clients/{id}/exchange_policy` — Remove the token-exchange policy of an
    /// OAuth client, restoring the defaults.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::OAuthClientsDeleteExchangePolicyResponse`].
    pub async fn delete_exchange_policy(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsDeleteExchangePolicyResponse, BackendError> {
        let path = format!("/v1/oauth_clients/{}/exchange_policy", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `PUT /v1/oauth_clients/{id}/profile` — Assign a policy profile to an OAuth client (profile
    /// null clears it). The client must already conform (auth method, redirect URIs); the profile
    /// is then enforced at /oauth2/authorize, /oauth2/par and /oauth2/token.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OAuthClientsSetProfileBody`]. Returns [`types_ext::OAuthClientsSetProfileResponse`].
    pub async fn set_profile(
        &self,
        id: &str,
        body: &types_ext::OAuthClientsSetProfileBody,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsSetProfileResponse, BackendError> {
        let path = format!("/v1/oauth_clients/{}/profile", seg(id));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `PUT /v1/oauth_clients/{id}/delegated_ui` — Set (or clear, with null) the URLs of your own
    /// sign-in and consent pages for an OAuth client. /oauth2/authorize then sends the browser
    /// there with a login_challenge / consent_challenge instead of Atlas’s pages. A client URL
    /// overrides the instance-wide oauthProvider.loginUrl / consentUrl.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OAuthClientsSetDelegatedUiBody`]. Returns [`types_ext::OAuthClientsSetDelegatedUiResponse`].
    pub async fn set_delegated_ui(
        &self,
        id: &str,
        body: &types_ext::OAuthClientsSetDelegatedUiBody,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsSetDelegatedUiResponse, BackendError> {
        let path = format!("/v1/oauth_clients/{}/delegated_ui", seg(id));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
}

impl Organizations<'_> {
    /// The `organizations / webhook_endpoints` operations of the Backend API.
    pub fn webhook_endpoints(&self) -> OrganizationsWebhookEndpoints<'_> {
        OrganizationsWebhookEndpoints {
            client: self.client,
        }
    }
    /// `GET /v1/organizations/{id}/connected_apps` — List the apps (OAuth clients) that hold an
    /// active grant in this organization's context, one entry per grant.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::OrganizationsListConnectedAppsResponse`].
    pub async fn list_connected_apps(
        &self,
        org_id: &str,
        query: &Query,
    ) -> Result<types_ext::OrganizationsListConnectedAppsResponse, BackendError> {
        let path = format!("/v1/organizations/{}/connected_apps", seg(org_id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `DELETE /v1/organizations/{id}/connected_apps/{grantId}` — Revoke one connected app grant of
    /// the organization: its tokens and any session minted from it stop working. Emits
    /// grant.revoked; audited as organization.connected_app_revoked.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::OrganizationsRevokeConnectedAppResponse`].
    pub async fn revoke_connected_app(
        &self,
        org_id: &str,
        grant_id: &str,
        query: &Query,
    ) -> Result<types_ext::OrganizationsRevokeConnectedAppResponse, BackendError> {
        let path = format!(
            "/v1/organizations/{}/connected_apps/{}",
            seg(org_id),
            seg(grant_id)
        );
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/organizations/{id}/connections/{connectionId}/secret` — The same read, scoped to an
    /// organization: 404 unless the connection is owned by that organization. Needs
    /// connections:secret_read; audited.
    ///
    /// Query parameters: `version`.
    ///
    /// Returns [`types_ext::OrganizationsGetConnectionSecretResponse`].
    pub async fn get_connection_secret(
        &self,
        org_id: &str,
        connection_id: &str,
        query: &Query,
    ) -> Result<types_ext::OrganizationsGetConnectionSecretResponse, BackendError> {
        let path = format!(
            "/v1/organizations/{}/connections/{}/secret",
            seg(org_id),
            seg(connection_id)
        );
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl OauthClientProfiles<'_> {
    /// `GET /v1/oauth_client_profiles` — List the OAuth client policy profiles: the built-ins
    /// (fapi2_security, fapi2_message_signing, pkce_required, par_required, dpop_required) and your
    /// custom ones.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::OauthClientProfilesListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::OauthClientProfilesListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/oauth_client_profiles",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `PUT /v1/oauth_client_profiles/{name}` — Create or replace a custom client policy profile
    /// (rules: PKCE, PAR, sender constraint, signed request object, allowed auth methods and
    /// signing algorithms, https-only redirects, allowed claims). Built-in names are reserved.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OauthClientProfilesSetBody`]. Returns [`types_ext::OauthClientProfilesSetResponse`].
    pub async fn set(
        &self,
        name: &str,
        body: &types_ext::OauthClientProfilesSetBody,
        query: &Query,
    ) -> Result<types_ext::OauthClientProfilesSetResponse, BackendError> {
        let path = format!("/v1/oauth_client_profiles/{}", seg(name));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/oauth_client_profiles/{name}` — Delete a custom client policy profile. 409 while
    /// any client is assigned it.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::OauthClientProfilesDeleteResponse`].
    pub async fn delete(
        &self,
        name: &str,
        query: &Query,
    ) -> Result<types_ext::OauthClientProfilesDeleteResponse, BackendError> {
        let path = format!("/v1/oauth_client_profiles/{}", seg(name));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl OAuthClientsLoginRequests<'_> {
    /// `GET /v1/oauth_login_requests` — Read a login challenge: which application is signing a user
    /// in, with what scopes, and who (if anyone) is already signed in on this browser.
    ///
    /// Query parameters: `login_challenge`.
    ///
    /// Returns [`types_ext::OAuthClientsLoginRequestsGetResponse`].
    pub async fn get(
        &self,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsLoginRequestsGetResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/oauth_login_requests",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `PUT /v1/oauth_login_requests/accept` — Accept a login challenge: the visitor authenticated
    /// as `subject` (an Atlas user id). Returns redirect_to; when the browser follows it Atlas
    /// signs the user in and continues the authorization. The returned link is single-use and valid
    /// for five minutes.
    ///
    /// Query parameters: `dry_run`, `login_challenge`.
    ///
    /// Takes [`types_ext::OAuthClientsLoginRequestsAcceptBody`]. Returns [`types_ext::OAuthClientsLoginRequestsAcceptResponse`].
    pub async fn accept(
        &self,
        body: &types_ext::OAuthClientsLoginRequestsAcceptBody,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsLoginRequestsAcceptResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/oauth_login_requests/accept",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `PUT /v1/oauth_login_requests/reject` — Reject a login challenge. Following redirect_to
    /// returns the application to its redirect_uri with the OAuth error.
    ///
    /// Query parameters: `dry_run`, `login_challenge`.
    ///
    /// Takes [`types_ext::OAuthClientsLoginRequestsRejectBody`]. Returns [`types_ext::OAuthClientsLoginRequestsRejectResponse`].
    pub async fn reject(
        &self,
        body: &types_ext::OAuthClientsLoginRequestsRejectBody,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsLoginRequestsRejectResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/oauth_login_requests/reject",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
}

impl OAuthClientsConsentRequests<'_> {
    /// `GET /v1/oauth_consent_requests` — Read a consent challenge: the signed-in user, the
    /// application and the scopes, audience, authorization details and organization it asks for.
    ///
    /// Query parameters: `consent_challenge`.
    ///
    /// Returns [`types_ext::OAuthClientsConsentRequestsGetResponse`].
    pub async fn get(
        &self,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsConsentRequestsGetResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/oauth_consent_requests",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `PUT /v1/oauth_consent_requests/accept` — Accept a consent challenge, optionally narrowing
    /// the granted scopes. Following redirect_to (in the same browser that started the flow)
    /// records the consent unless remember is false, and returns the application to its
    /// redirect_uri with a code.
    ///
    /// Query parameters: `dry_run`, `consent_challenge`.
    ///
    /// Takes [`types_ext::OAuthClientsConsentRequestsAcceptBody`]. Returns [`types_ext::OAuthClientsConsentRequestsAcceptResponse`].
    pub async fn accept(
        &self,
        body: &types_ext::OAuthClientsConsentRequestsAcceptBody,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsConsentRequestsAcceptResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/oauth_consent_requests/accept",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `PUT /v1/oauth_consent_requests/reject` — Reject a consent challenge. Following redirect_to
    /// returns the application to its redirect_uri with the OAuth error.
    ///
    /// Query parameters: `dry_run`, `consent_challenge`.
    ///
    /// Takes [`types_ext::OAuthClientsConsentRequestsRejectBody`]. Returns [`types_ext::OAuthClientsConsentRequestsRejectResponse`].
    pub async fn reject(
        &self,
        body: &types_ext::OAuthClientsConsentRequestsRejectBody,
        query: &Query,
    ) -> Result<types_ext::OAuthClientsConsentRequestsRejectResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/oauth_consent_requests/reject",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
}

impl PasskeyApi<'_> {
    /// `POST /v1/passkey_api/registration/init` — Start registering a passkey for one of your
    /// users. Returns WebAuthn creation options for the browser.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::PasskeyRegistrationInitBody`]. Returns [`types_ext::PasskeyRegistrationInitResponse`].
    pub async fn registration_init(
        &self,
        body: &types_ext::PasskeyRegistrationInitBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::PasskeyRegistrationInitResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/passkey_api/registration/init",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/passkey_api/registration/finalize` — Verify the browser’s attestation and store
    /// the passkey for the user. 409 if the credential is already registered; 403 if the
    /// authenticator is blocked by the passkey policy.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::PasskeyRegistrationFinalizeBody`]. Returns [`types_ext::PasskeyRegistrationFinalizeResponse`].
    pub async fn registration_finalize(
        &self,
        body: &types_ext::PasskeyRegistrationFinalizeBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::PasskeyRegistrationFinalizeResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/passkey_api/registration/finalize",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/passkey_api/login/init` — Start a passkey login. With user_id the user’s
    /// credentials are listed; without it the login is discoverable and the credential names the
    /// user.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::PasskeyLoginInitBody`]. Returns [`types_ext::PasskeyLoginInitResponse`].
    pub async fn login_init(
        &self,
        body: &types_ext::PasskeyLoginInitBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::PasskeyLoginInitResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/passkey_api/login/init",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/passkey_api/login/finalize` — Verify the browser’s assertion. Returns the user_id
    /// the passkey belongs to; your backend then starts its own session. Pass user_id to require
    /// that exact user. Challenges are single use.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::PasskeyLoginFinalizeBody`]. Returns [`types_ext::PasskeyLoginFinalizeResponse`].
    pub async fn login_finalize(
        &self,
        body: &types_ext::PasskeyLoginFinalizeBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::PasskeyLoginFinalizeResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/passkey_api/login/finalize",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/passkey_api/users/{userId}/passkeys` — List the passkeys registered for one of your
    /// users.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::PasskeyListResponse`].
    pub async fn list(
        &self,
        user_id: &str,
        query: &Query,
    ) -> Result<types_ext::PasskeyListResponse, BackendError> {
        let path = format!("/v1/passkey_api/users/{}/passkeys", seg(user_id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `DELETE /v1/passkey_api/users/{userId}/passkeys/{id}` — Delete one of your user’s passkeys.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::PasskeyDeleteResponse`].
    pub async fn delete(
        &self,
        user_id: &str,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::PasskeyDeleteResponse, BackendError> {
        let path = format!(
            "/v1/passkey_api/users/{}/passkeys/{}",
            seg(user_id),
            seg(id)
        );
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/passkey_api/usage` — Passkeys stored through the Passkey API on this instance (the
    /// metered quantity).
    ///
    /// Returns [`types_ext::PasskeyUsageResponse`].
    pub async fn usage(&self) -> Result<types_ext::PasskeyUsageResponse, BackendError> {
        self.client
            .request(HttpMethod::Get, "/v1/passkey_api/usage", &[], None, None)
            .await
    }
}

impl VcCredentialTypes<'_> {
    /// `GET /v1/vc/credential_types` — List the credential types you issue.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::VcCredentialTypesListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::VcCredentialTypesListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/vc/credential_types",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/vc/credential_types` — Define a credential type: its vct, and how each claim is
    /// filled from a user’s attributes. Issued as SD-JWT VC.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::VcCredentialTypesCreateBody`]. Returns [`types_ext::VcCredentialTypesCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::VcCredentialTypesCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::VcCredentialTypesCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/vc/credential_types",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/vc/credential_types/{id}` — Read one credential type.
    ///
    /// Returns [`types_ext::VcCredentialTypesGetResponse`].
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<types_ext::VcCredentialTypesGetResponse, BackendError> {
        let path = format!("/v1/vc/credential_types/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `DELETE /v1/vc/credential_types/{id}` — Delete a credential type and the records of what was
    /// issued under it.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::VcCredentialTypesDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::VcCredentialTypesDeleteResponse, BackendError> {
        let path = format!("/v1/vc/credential_types/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl Vc<'_> {
    /// The `vc / credential_types` operations of the Backend API.
    pub fn credential_types(&self) -> VcCredentialTypes<'_> {
        VcCredentialTypes {
            client: self.client,
        }
    }
    /// The `vc / credentials` operations of the Backend API.
    pub fn credentials(&self) -> VcCredentials<'_> {
        VcCredentials {
            client: self.client,
        }
    }
    /// The `vc / presentation_requests` operations of the Backend API.
    pub fn presentation_requests(&self) -> VcPresentationRequests<'_> {
        VcPresentationRequests {
            client: self.client,
        }
    }
    /// `POST /v1/vc/offers` — Create a wallet offer for a user (pre-authorized code flow). The
    /// response carries the code once, as an openid-credential-offer:// link.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::VcCreateOfferBody`]. Returns [`types_ext::VcCreateOfferResponse`].
    pub async fn create_offer(
        &self,
        body: &types_ext::VcCreateOfferBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::VcCreateOfferResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/vc/offers",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl VcCredentials<'_> {
    /// `GET /v1/vc/credentials` — List issued credentials (most recent 200), optionally for one
    /// user.
    ///
    /// Query parameters: `user_id`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::VcCredentialsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::VcCredentialsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/vc/credentials",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/vc/credentials/{id}/revoke` — Revoke an issued credential: its status-list bit is
    /// set and later presentations are refused.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes a JSON body (the API documents it as open-ended). Returns [`types_ext::VcCredentialsRevokeResponse`].
    pub async fn revoke(
        &self,
        id: &str,
        body: Value,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::VcCredentialsRevokeResponse, BackendError> {
        let path = format!("/v1/vc/credentials/{}/revoke", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                Some(body),
                idempotency_key,
            )
            .await
    }
}

impl VcPresentationRequests<'_> {
    /// `POST /v1/vc/presentation_requests` — Start a verifier request for a credential type and
    /// claims. Show authorization_request_uri to the wallet, then read the request for the outcome.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::VcPresentationRequestsCreateBody`]. Returns [`types_ext::VcPresentationRequestsCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::VcPresentationRequestsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::VcPresentationRequestsCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/vc/presentation_requests",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/vc/presentation_requests/{id}` — Read a presentation request and its outcome.
    ///
    /// Returns [`types_ext::VcPresentationRequestsGetResponse`].
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<types_ext::VcPresentationRequestsGetResponse, BackendError> {
        let path = format!("/v1/vc/presentation_requests/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
}

impl Listen<'_> {
    /// `POST /v1/listen/sessions` — Start a local webhook forwarding session (what `atlas listen`
    /// uses). Returns a session id, a signing secret for that session only (it is unrelated to any
    /// registered endpoint's secret) and the stream URL. The session needs no storage: it expires
    /// at `expires_at` (default 1 hour, `ttl_seconds` 60 to 43200).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ListenCreateSessionBody`]. Returns [`types_ext::ListenCreateSessionResponse`].
    pub async fn create_session(
        &self,
        body: &types_ext::ListenCreateSessionBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ListenCreateSessionResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/listen/sessions",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/listen/sessions/{id}/stream` — Server-Sent Events stream of the instance's new
    /// events for a listen session. Each `webhook` event carries `{id, type, headers, body}`: the
    /// headers (`atlas-id`, `atlas-timestamp`, `atlas-signature`) and the exact JSON body of a
    /// would-be delivery, signed with the session secret. Starts at "now" unless resumed with
    /// `Last-Event-ID` or `after`. Query: `events` (comma-separated types or patterns),
    /// `max_events` and `max_wait_seconds` (end the stream early, for scripts and CI). A `:
    /// keep-alive` comment is sent every 15 seconds; an `expired` event ends the stream at the
    /// session expiry. 404 for an unknown session id, 400 once expired.
    ///
    /// Query parameters: `events`, `after`, `max_events`, `poll_ms`, `max_wait_seconds`.
    ///
    /// Returns the raw `text/event-stream` response body bytes.
    pub async fn stream_session(&self, id: &str, query: &Query) -> Result<Vec<u8>, BackendError> {
        let path = format!("/v1/listen/sessions/{}/stream", seg(id));
        self.client
            .request_bytes(HttpMethod::Get, &path, &query.as_pairs(), None)
            .await
    }
}

impl AgentRegistration<'_> {
    /// `GET /v1/agent_registration` — Read the agent registration settings (enabled, allowed
    /// identity kinds, untrusted and trusted scopes, claim code lifetime).
    ///
    /// Returns [`types_ext::AgentRegistrationGetResponse`].
    pub async fn get(&self) -> Result<types_ext::AgentRegistrationGetResponse, BackendError> {
        self.client
            .request(HttpMethod::Get, "/v1/agent_registration", &[], None, None)
            .await
    }
    /// `PUT /v1/agent_registration` — Update the agent registration settings. Partial: only the
    /// fields sent change.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AgentRegistrationReplaceBody`]. Returns nothing (`204 No Content`).
    pub async fn replace(
        &self,
        body: &types_ext::AgentRegistrationReplaceBody,
        query: &Query,
    ) -> Result<(), BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/agent_registration",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
}

impl Agents<'_> {
    /// `POST /v1/agents/{id}/claim` — Backend-assisted claim: bind an agent to a user you already
    /// know and promote it to trusted. Audited as agent.claimed.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AgentsClaimBody`]. Returns nothing (`204 No Content`).
    pub async fn claim(
        &self,
        id: &str,
        body: &types_ext::AgentsClaimBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/agents/{}/claim", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/agents` — The agent registry: every registered agent with its tier, owner and
    /// status. Filter by owner_user_id or tier; page with limit and starting_after.
    ///
    /// Query parameters: `owner_user_id`, `tier`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AgentsListResponse`].
    pub async fn list(&self, query: &Query) -> Result<types_ext::AgentsListResponse, BackendError> {
        self.client
            .request(HttpMethod::Get, "/v1/agents", &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/agents/{id}` — One agent with its currently valid access grants.
    ///
    /// Returns the response JSON (the API documents it as open-ended).
    pub async fn get(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/agents/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PUT /v1/agents/{id}/owner` — Set the owning user of an agent, or null to remove the owner
    /// (which also drops the agent back to untrusted).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AgentsSetOwnerBody`]. Returns nothing (`204 No Content`).
    pub async fn set_owner(
        &self,
        id: &str,
        body: &types_ext::AgentsSetOwnerBody,
        query: &Query,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/agents/{}/owner", seg(id));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `POST /v1/agents/{id}/revoke_access` — Revoke every grant and cancel every pending request
    /// of an agent. With disable: true the agent itself is revoked and can no longer get tokens.
    /// Emits agent.access_revoked.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AgentsRevokeAccessBody`]. Returns nothing (`204 No Content`).
    pub async fn revoke_access(
        &self,
        id: &str,
        body: &types_ext::AgentsRevokeAccessBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/agents/{}/revoke_access", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl AgentAccessRequests<'_> {
    /// `POST /v1/agent_access_requests/{id}/approve` — Approve a pending request, optionally for a
    /// limited time (expires_in_seconds). 409 when it is no longer pending. Emits
    /// agent.access_decided.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AgentAccessRequestsApproveBody`]. Returns nothing (`204 No Content`).
    pub async fn approve(
        &self,
        id: &str,
        body: &types_ext::AgentAccessRequestsApproveBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/agent_access_requests/{}/approve", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/agent_access_requests/{id}/deny` — Deny a pending request. 409 when it is no
    /// longer pending. Emits agent.access_decided.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AgentAccessRequestsDenyBody`]. Returns nothing (`204 No Content`).
    pub async fn deny(
        &self,
        id: &str,
        body: &types_ext::AgentAccessRequestsDenyBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/agent_access_requests/{}/deny", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/agent_access_requests` — List agent access requests, newest first. Filter by status
    /// (pending, approved, denied, revoked) or agent_id.
    ///
    /// Query parameters: `status`, `agent_id`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AgentAccessRequestsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::AgentAccessRequestsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/agent_access_requests",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
}

impl Actions<'_> {
    /// `GET /v1/actions/{id}/calls` — The call log of an `http` Action (an Action that calls your
    /// own endpoint), newest first, with 24 hour stats: calls, denied, failed, timeouts and p95
    /// latency. Real calls and dry-run tests are both logged (`test`). 409 for a `node` Action.
    ///
    /// Query parameters: `limit`, `status`, `test`, `starting_after`.
    ///
    /// Returns [`types_ext::ActionHttpCallList`].
    pub async fn calls(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::ActionHttpCallList, BackendError> {
        let path = format!("/v1/actions/{}/calls", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl Workflows<'_> {
    /// `GET /v1/workflows` — List lifecycle workflows: a trigger (cron, user created, inactive for
    /// N days, membership age, trial end, webhook event) plus ordered steps, run by the worker.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::WorkflowsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::WorkflowsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/workflows",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/workflows` — Create a lifecycle workflow. Steps are notify, disable, delete,
    /// invite, add_to_org, remove_from_org, add_to_team, remove_from_team, add_to_group,
    /// remove_from_group (an instance group by id or slug) and call_action (an Action with the
    /// `workflow_step` trigger, which may be an `http` Action). Each subject runs once per
    /// workflow; the first failing step stops the run.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::WorkflowsCreateBody`]. Returns [`types_ext::Workflow`].
    pub async fn create(
        &self,
        body: &types_ext::WorkflowsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::Workflow, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/workflows",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/workflows/{id}` — Read one lifecycle workflow.
    ///
    /// Returns [`types_ext::Workflow`].
    pub async fn get(&self, id: &str) -> Result<types_ext::Workflow, BackendError> {
        let path = format!("/v1/workflows/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/workflows/{id}` — Update a workflow's name, enabled flag, trigger or steps.
    /// Changing the trigger resets its cron slot and event cursor.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::WorkflowsUpdateBody`]. Returns [`types_ext::Workflow`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::WorkflowsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::Workflow, BackendError> {
        let path = format!("/v1/workflows/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/workflows/{id}` — Delete a workflow and its run history.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::WorkflowsDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::WorkflowsDeleteResponse, BackendError> {
        let path = format!("/v1/workflows/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/workflows/{id}/dry_run` — Check what a workflow would do for a user (`user_id`;
    /// none for cron) without changing anything. Every step is validated against live data and
    /// reported as `would_run` or `failed`.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::WorkflowsDryRunBody`]. Returns [`types_ext::WorkflowRun`].
    pub async fn dry_run(
        &self,
        id: &str,
        body: &types_ext::WorkflowsDryRunBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::WorkflowRun, BackendError> {
        let path = format!("/v1/workflows/{}/dry_run", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/workflows/{id}/run` — Run a workflow now for one user (`user_id`; none for cron),
    /// outside its trigger. Returns the finished run.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::WorkflowsRunBody`]. Returns [`types_ext::WorkflowRun`].
    pub async fn run(
        &self,
        id: &str,
        body: &types_ext::WorkflowsRunBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::WorkflowRun, BackendError> {
        let path = format!("/v1/workflows/{}/run", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/workflows/{id}/runs` — Run history, newest first, dry runs included (`dry_run`).
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::WorkflowsRunsResponse`].
    pub async fn runs(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::WorkflowsRunsResponse, BackendError> {
        let path = format!("/v1/workflows/{}/runs", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl PageTemplates<'_> {
    /// `GET /v1/instance/page_templates` — The hosted-page templates of the instance: for each page
    /// (sign-in, sign-up, user-profile) the live template and the draft waiting to be previewed or
    /// promoted.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::PageTemplatesListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::PageTemplatesListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/instance/page_templates",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/instance/page_templates/{page}` — Read one page's live and draft template.
    ///
    /// Returns [`types_ext::PageTemplate`].
    pub async fn get(&self, page: &str) -> Result<types_ext::PageTemplate, BackendError> {
        let path = format!("/v1/instance/page_templates/{}", seg(page));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PUT /v1/instance/page_templates/{page}` — Save a page template as the page's draft. A
    /// template is data: components (heading, text, image, link, button_link, list, divider,
    /// spacer, columns) in four regions (header, above_form, below_form, footer). It is validated
    /// on save: no raw HTML, CSS or script, https and mailto links only. The live page is unchanged
    /// until you promote.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::PageTemplatesSaveDraftBody`]. Returns [`types_ext::PageTemplate`].
    pub async fn save_draft(
        &self,
        page: &str,
        body: &types_ext::PageTemplatesSaveDraftBody,
        query: &Query,
    ) -> Result<types_ext::PageTemplate, BackendError> {
        let path = format!("/v1/instance/page_templates/{}", seg(page));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/instance/page_templates/{page}` — Drop the draft or take the live template down
    /// (`status`).
    ///
    /// Query parameters: `dry_run`, `status`.
    ///
    /// Returns [`types_ext::PageTemplate`].
    pub async fn discard(
        &self,
        page: &str,
        query: &Query,
    ) -> Result<types_ext::PageTemplate, BackendError> {
        let path = format!("/v1/instance/page_templates/{}", seg(page));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/instance/page_templates/{page}/preview` — A signed link to the hosted page with
    /// the draft template applied (valid for one hour, noindex, with a preview banner). 409 when
    /// the page has no template.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::PageTemplatePreview`].
    pub async fn preview(
        &self,
        page: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::PageTemplatePreview, BackendError> {
        let path = format!("/v1/instance/page_templates/{}/preview", seg(page));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/instance/page_templates/{page}/promote` — Make the draft the live template.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::PageTemplate`].
    pub async fn promote(
        &self,
        page: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::PageTemplate, BackendError> {
        let path = format!("/v1/instance/page_templates/{}/promote", seg(page));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
}

impl ServiceConnectors<'_> {
    /// `GET /v1/service_connector_catalog` — The services you can connect: for each kind the
    /// credential fields, the config fields and the operations with their inputs. Messaging
    /// (Twilio, SendGrid, Slack), CRM (HubSpot, Salesforce), analytics (Segment), fraud
    /// (Fingerprint, Arkose Labs, Forter, Sardine), identity verification (Persona, Onfido, Veriff,
    /// Stripe Identity) and a generic HTTPS connector.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::ServiceConnectorsCatalogResponse`].
    pub async fn catalog(
        &self,
        query: &Query,
    ) -> Result<types_ext::ServiceConnectorsCatalogResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/service_connector_catalog",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/service_connectors` — List the instance's service connectors. Credentials are never
    /// returned.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::ServiceConnectorsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::ServiceConnectorsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/service_connectors",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/service_connectors` — Connect a service. `credentials` are checked against the
    /// kind's fields and stored in the vault (never returned again); `config` holds the non-secret
    /// settings. 409 when the name is taken.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ServiceConnectorsCreateBody`]. Returns [`types_ext::ServiceConnectorsCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::ServiceConnectorsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ServiceConnectorsCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/service_connectors",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/service_connectors/{id}` — Read one service connector.
    ///
    /// Returns [`types_ext::ServiceConnectorsGetResponse`].
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<types_ext::ServiceConnectorsGetResponse, BackendError> {
        let path = format!("/v1/service_connectors/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/service_connectors/{id}` — Rename, enable or disable a connector, merge new
    /// `config` values, or replace individual `credentials` (written as a new vault version; the
    /// others are kept).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ServiceConnectorsUpdateBody`]. Returns [`types_ext::ServiceConnectorsUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::ServiceConnectorsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::ServiceConnectorsUpdateResponse, BackendError> {
        let path = format!("/v1/service_connectors/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/service_connectors/{id}` — Delete a connector and its stored credentials.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::ServiceConnectorsDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::ServiceConnectorsDeleteResponse, BackendError> {
        let path = format!("/v1/service_connectors/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/service_connectors/{id}/invoke` — Run one operation of the connector (send a
    /// message, read a fraud signal, start an identity check). `input` is checked against the
    /// operation's fields. A refusal or failure from the service is 502 CONNECTOR_UPSTREAM_ERROR
    /// with its own message. Each call is audited without its input or output.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ServiceConnectorsInvokeBody`]. Returns [`types_ext::ServiceConnectorsInvokeResponse`].
    pub async fn invoke(
        &self,
        id: &str,
        body: &types_ext::ServiceConnectorsInvokeBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ServiceConnectorsInvokeResponse, BackendError> {
        let path = format!("/v1/service_connectors/{}/invoke", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl DesktopMfa<'_> {
    /// `GET /v1/desktop_mfa/policy` — The desktop-login MFA policy: who must pass a second factor
    /// at OS login, the allowed factors and the offline grace window.
    ///
    /// Returns [`types_ext::DesktopMfaGetPolicyResponse`].
    pub async fn get_policy(&self) -> Result<types_ext::DesktopMfaGetPolicyResponse, BackendError> {
        self.client
            .request(HttpMethod::Get, "/v1/desktop_mfa/policy", &[], None, None)
            .await
    }
    /// `PUT /v1/desktop_mfa/policy` — Change the desktop-login MFA policy. Send only the fields to
    /// change. `applies_to: "selected"` needs at least one user or organization while enabled.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::DesktopMfaUpdatePolicyBody`]. Returns [`types_ext::DesktopMfaUpdatePolicyResponse`].
    pub async fn update_policy(
        &self,
        body: &types_ext::DesktopMfaUpdatePolicyBody,
        query: &Query,
    ) -> Result<types_ext::DesktopMfaUpdatePolicyResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/desktop_mfa/policy",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `POST /v1/desktop_mfa/enrolment_codes` — Issue a single-use code a user types into the
    /// workstation agent to enrol it. Valid for `expires_in_minutes` (default 60, at most 7 days).
    /// Shown once.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::DesktopMfaCreateEnrolmentCodeBody`]. Returns [`types_ext::DesktopMfaCreateEnrolmentCodeResponse`].
    pub async fn create_enrolment_code(
        &self,
        body: &types_ext::DesktopMfaCreateEnrolmentCodeBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::DesktopMfaCreateEnrolmentCodeResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/desktop_mfa/enrolment_codes",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/desktop_mfa/devices` — List enrolled workstations, optionally for one `user_id`.
    ///
    /// Query parameters: `user_id`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::DesktopMfaListDevicesResponse`].
    pub async fn list_devices(
        &self,
        query: &Query,
    ) -> Result<types_ext::DesktopMfaListDevicesResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/desktop_mfa/devices",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/desktop_mfa/devices/{id}` — Read one workstation with the offline verifiers issued
    /// to it.
    ///
    /// Returns [`types_ext::DesktopMfaGetDeviceResponse`].
    pub async fn get_device(
        &self,
        id: &str,
    ) -> Result<types_ext::DesktopMfaGetDeviceResponse, BackendError> {
        let path = format!("/v1/desktop_mfa/devices/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `DELETE /v1/desktop_mfa/devices/{id}` — Delete a workstation and its device key.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::DesktopMfaDeleteDeviceResponse`].
    pub async fn delete_device(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::DesktopMfaDeleteDeviceResponse, BackendError> {
        let path = format!("/v1/desktop_mfa/devices/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/desktop_mfa/devices/{id}/revoke` — Revoke a workstation. Its next call is refused
    /// with `device_status: revoked` and it wipes its offline cache; offline unlock stops working
    /// at the latest when the cached verifier expires.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::DesktopMfaRevokeDeviceResponse`].
    pub async fn revoke_device(
        &self,
        id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::DesktopMfaRevokeDeviceResponse, BackendError> {
        let path = format!("/v1/desktop_mfa/devices/{}/revoke", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/desktop_mfa/devices/{id}/revoke_offline_cache` — Void every offline verifier
    /// issued to the workstation without revoking it. It receives a fresh one on its next sync.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::DesktopMfaRevokeOfflineCacheResponse`].
    pub async fn revoke_offline_cache(
        &self,
        id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::DesktopMfaRevokeOfflineCacheResponse, BackendError> {
        let path = format!("/v1/desktop_mfa/devices/{}/revoke_offline_cache", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
}

impl IdentityVerification<'_> {
    /// `GET /v1/identity_verification/settings` — Whether identity verification is on, and which
    /// connector does the checking.
    ///
    /// Returns [`types_ext::IdentityVerificationSettingsResponse`].
    pub async fn settings(
        &self,
    ) -> Result<types_ext::IdentityVerificationSettingsResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/identity_verification/settings",
                &[],
                None,
                None,
            )
            .await
    }
    /// `PUT /v1/identity_verification/settings` — Turn identity verification on or off and choose
    /// the connector (a Persona, Onfido, Veriff or Stripe Identity service connector; its
    /// credentials stay in the vault). `as_challenge` offers a verified identity as the custom
    /// second step of sign-in (the custom challenge factor must be enabled).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IdentityVerificationUpdateSettingsBody`]. Returns [`types_ext::IdentityVerificationUpdateSettingsResponse`].
    pub async fn update_settings(
        &self,
        body: &types_ext::IdentityVerificationUpdateSettingsBody,
        query: &Query,
    ) -> Result<types_ext::IdentityVerificationUpdateSettingsResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/identity_verification/settings",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `GET /v1/identity_verifications` — List checks by status (default `needs_review`, the review
    /// queue), newest first.
    ///
    /// Query parameters: `status`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::IdentityVerificationListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::IdentityVerificationListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/identity_verifications",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/identity_verifications/{id}` — Read one check. A pending check is refreshed from
    /// the verification service first.
    ///
    /// Returns [`types_ext::IdentityVerificationGetResponse`].
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<types_ext::IdentityVerificationGetResponse, BackendError> {
        let path = format!("/v1/identity_verifications/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `POST /v1/identity_verifications/{id}/decide` — Decide a check that is waiting for review
    /// (or override a pending one) as `approved` or `declined`. The outcome is written to the user
    /// as `verification.identity`. 409 when the check is already approved or declined.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IdentityVerificationDecideBody`]. Returns [`types_ext::IdentityVerificationDecideResponse`].
    pub async fn decide(
        &self,
        id: &str,
        body: &types_ext::IdentityVerificationDecideBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IdentityVerificationDecideResponse, BackendError> {
        let path = format!("/v1/identity_verifications/{}/decide", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/users/{id}/identity_verifications` — A user's identity checks, newest first.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::IdentityVerificationForUserResponse`].
    pub async fn for_user(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::IdentityVerificationForUserResponse, BackendError> {
        let path = format!("/v1/users/{}/identity_verifications", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/users/{id}/identity_verifications` — Start an identity check for a user and get
    /// the verification service's hosted page (`url`) to send them to. A check started in the last
    /// 30 minutes and still pending is returned instead of a new one; at most 5 checks per user per
    /// hour. 409 when identity verification is not turned on.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IdentityVerificationStartBody`]. Returns [`types_ext::IdentityVerificationStartResponse`].
    pub async fn start(
        &self,
        id: &str,
        body: &types_ext::IdentityVerificationStartBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IdentityVerificationStartResponse, BackendError> {
        let path = format!("/v1/users/{}/identity_verifications", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl IgaEntitlements<'_> {
    /// `GET /v1/iga/entitlements` — List the governed entitlement catalog.
    ///
    /// Query parameters: `kind`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::IgaEntitlementsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::IgaEntitlementsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/iga/entitlements",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/iga/entitlements` — Add an entitlement to the catalog: a role, organization
    /// membership, group, resource role, installed-app assignment or custom item, with an owner, a
    /// risk level and approval rules. The target must exist. 409 for a key already in use.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaEntitlementsCreateBody`]. Returns [`types_ext::IgaEntitlementsCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::IgaEntitlementsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaEntitlementsCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/iga/entitlements",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/iga/entitlements/{id}` — Read one entitlement by id or key.
    ///
    /// Returns [`types_ext::IgaEntitlementsGetResponse`].
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<types_ext::IgaEntitlementsGetResponse, BackendError> {
        let path = format!("/v1/iga/entitlements/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/iga/entitlements/{id}` — Change an entitlement (its kind cannot change). A change
    /// to the approval rules applies to requests filed afterwards.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaEntitlementsUpdateBody`]. Returns [`types_ext::IgaEntitlementsUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::IgaEntitlementsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::IgaEntitlementsUpdateResponse, BackendError> {
        let path = format!("/v1/iga/entitlements/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/iga/entitlements/{id}` — Remove an entitlement. 409 while it still has active
    /// grants.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::IgaEntitlementsDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::IgaEntitlementsDeleteResponse, BackendError> {
        let path = format!("/v1/iga/entitlements/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl IgaRequests<'_> {
    /// `GET /v1/iga/requests` — List access requests, newest first.
    ///
    /// Query parameters: `status`, `user_id`, `requester_user_id`, `entitlement`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::IgaRequestsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::IgaRequestsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/iga/requests",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/iga/requests` — File an access request on behalf of a user. It follows the
    /// entitlement's approval steps (and any extra step a separation-of-duties rule adds); with no
    /// steps it is fulfilled at once. A blocking separation-of-duties conflict, a user who already
    /// holds the access, or a pending duplicate is a 409. `duration_seconds` makes the grant
    /// time-bound (default and maximum: the entitlement's limit).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaRequestsCreateBody`]. Returns [`types_ext::IgaRequestsCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::IgaRequestsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaRequestsCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/iga/requests",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/iga/requests/{id}` — Read one request with its steps and the approvals recorded so
    /// far.
    ///
    /// Returns [`types_ext::IgaRequestsGetResponse`].
    pub async fn get(&self, id: &str) -> Result<types_ext::IgaRequestsGetResponse, BackendError> {
        let path = format!("/v1/iga/requests/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `POST /v1/iga/requests/{id}/decide` — Decide the open step. With `approver_user_id` the
    /// decision is recorded as that person (who must be an approver of the step or hold a
    /// delegation); without it the call is an administrator override that settles the step. A
    /// denial ends the request. 409 when it is no longer pending.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaRequestsDecideBody`]. Returns [`types_ext::IgaRequestsDecideResponse`].
    pub async fn decide(
        &self,
        id: &str,
        body: &types_ext::IgaRequestsDecideBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaRequestsDecideResponse, BackendError> {
        let path = format!("/v1/iga/requests/{}/decide", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/iga/requests/{id}/cancel` — Cancel a pending request.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::IgaRequestsCancelResponse`].
    pub async fn cancel(
        &self,
        id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaRequestsCancelResponse, BackendError> {
        let path = format!("/v1/iga/requests/{}/cancel", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/iga/approvals` — The requests waiting on one person's decision, including those
    /// delegated to them.
    ///
    /// Query parameters: `approver_user_id`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::IgaRequestsInboxResponse`].
    pub async fn inbox(
        &self,
        query: &Query,
    ) -> Result<types_ext::IgaRequestsInboxResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/iga/approvals",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
}

impl IgaGrants<'_> {
    /// `GET /v1/iga/grants` — List grants (what each user was given through governance), newest
    /// first.
    ///
    /// Query parameters: `user_id`, `entitlement`, `status`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::IgaGrantsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::IgaGrantsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/iga/grants",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/iga/grants` — Give a user an entitlement now, without a request. `expires_at`
    /// makes it time-bound. A blocking separation-of-duties rule refuses it; a require-approval
    /// rule refuses unless `override_reason` is given, which records an accepted violation.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaGrantsCreateBody`]. Returns [`types_ext::IgaGrantsCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::IgaGrantsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaGrantsCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/iga/grants",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/iga/grants/{id}/revoke` — Take the access away and close the grant, including
    /// access that existed before governance adopted it (an expiry, by contrast, leaves adopted
    /// access in place).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaGrantsRevokeBody`]. Returns [`types_ext::IgaGrantsRevokeResponse`].
    pub async fn revoke(
        &self,
        id: &str,
        body: &types_ext::IgaGrantsRevokeBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaGrantsRevokeResponse, BackendError> {
        let path = format!("/v1/iga/grants/{}/revoke", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl IgaDelegations<'_> {
    /// `GET /v1/iga/delegations` — List approval delegations.
    ///
    /// Query parameters: `delegator_user_id`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::IgaDelegationsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::IgaDelegationsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/iga/delegations",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/iga/delegations` — Let another user decide a person's approvals (and reviews) for
    /// a period of up to a year.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaDelegationsCreateBody`]. Returns [`types_ext::IgaDelegationsCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::IgaDelegationsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaDelegationsCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/iga/delegations",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `DELETE /v1/iga/delegations/{id}` — End an approval delegation.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::IgaDelegationsDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::IgaDelegationsDeleteResponse, BackendError> {
        let path = format!("/v1/iga/delegations/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl IgaSod<'_> {
    /// `GET /v1/iga/sod_rules` — List separation-of-duties rules: pairs of entitlements one person
    /// should not hold together.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::IgaSodListRulesResponse`].
    pub async fn list_rules(
        &self,
        query: &Query,
    ) -> Result<types_ext::IgaSodListRulesResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/iga/sod_rules",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/iga/sod_rules` — Create a rule. `mode` is `block` (refuse) or `require_approval`
    /// (an extra approval step on a request; `approver` names who, default the owner).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaSodCreateRuleBody`]. Returns [`types_ext::IgaSodCreateRuleResponse`].
    pub async fn create_rule(
        &self,
        body: &types_ext::IgaSodCreateRuleBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaSodCreateRuleResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/iga/sod_rules",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `PATCH /v1/iga/sod_rules/{id}` — Change a separation-of-duties rule.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaSodUpdateRuleBody`]. Returns [`types_ext::IgaSodUpdateRuleResponse`].
    pub async fn update_rule(
        &self,
        id: &str,
        body: &types_ext::IgaSodUpdateRuleBody,
        query: &Query,
    ) -> Result<types_ext::IgaSodUpdateRuleResponse, BackendError> {
        let path = format!("/v1/iga/sod_rules/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/iga/sod_rules/{id}` — Delete a rule and its recorded violations.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::IgaSodDeleteRuleResponse`].
    pub async fn delete_rule(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::IgaSodDeleteRuleResponse, BackendError> {
        let path = format!("/v1/iga/sod_rules/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/iga/sod_violations` — The violations report: users who hold both sides of a rule
    /// (found by a scan, or accepted at request or assignment time).
    ///
    /// Query parameters: `status`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::IgaSodViolationsResponse`].
    pub async fn violations(
        &self,
        query: &Query,
    ) -> Result<types_ext::IgaSodViolationsResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/iga/sod_violations",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/iga/sod_violations/scan` — Check every rule against what people hold right now:
    /// record new conflicts and resolve those that cleared.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::IgaSodScanResponse`].
    pub async fn scan(
        &self,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaSodScanResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/iga/sod_violations/scan",
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
}

impl IgaLifecycle<'_> {
    /// `GET /v1/iga/birthright_rules` — List birthright rules.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::IgaLifecycleListBirthrightRulesResponse`].
    pub async fn list_birthright_rules(
        &self,
        query: &Query,
    ) -> Result<types_ext::IgaLifecycleListBirthrightRulesResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/iga/birthright_rules",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/iga/birthright_rules` — Create a birthright rule: everyone matching `match` (a
    /// group, organization and role, app role or verified email domain; all conditions must hold)
    /// holds the listed entitlements. When someone stops matching, the grants the rule gave are
    /// revoked unless `revoke_on_unmatch` is false.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaLifecycleCreateBirthrightRuleBody`]. Returns [`types_ext::IgaLifecycleCreateBirthrightRuleResponse`].
    pub async fn create_birthright_rule(
        &self,
        body: &types_ext::IgaLifecycleCreateBirthrightRuleBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaLifecycleCreateBirthrightRuleResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/iga/birthright_rules",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `PATCH /v1/iga/birthright_rules/{id}` — Change a birthright rule.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaLifecycleUpdateBirthrightRuleBody`]. Returns [`types_ext::IgaLifecycleUpdateBirthrightRuleResponse`].
    pub async fn update_birthright_rule(
        &self,
        id: &str,
        body: &types_ext::IgaLifecycleUpdateBirthrightRuleBody,
        query: &Query,
    ) -> Result<types_ext::IgaLifecycleUpdateBirthrightRuleResponse, BackendError> {
        let path = format!("/v1/iga/birthright_rules/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/iga/birthright_rules/{id}` — Delete a birthright rule (grants it already gave
    /// stay until revoked).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::IgaLifecycleDeleteBirthrightRuleResponse`].
    pub async fn delete_birthright_rule(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::IgaLifecycleDeleteBirthrightRuleResponse, BackendError> {
        let path = format!("/v1/iga/birthright_rules/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/iga/users/{id}/reconcile` — Re-evaluate one user's birthright access now (joiner
    /// or mover).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::IgaLifecycleReconcileResponse`].
    pub async fn reconcile(
        &self,
        id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaLifecycleReconcileResponse, BackendError> {
        let path = format!("/v1/iga/users/{}/reconcile", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/iga/users/{id}/offboard` — Offboard a leaver: revoke every grant, cancel pending
    /// requests and delegations, and with `close_account` schedule the account closure through the
    /// data-rights path (so downstream erasure webhooks and any DSAR orchestrator run as for any
    /// deletion). `grace_seconds` sets the cancellation window.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaLifecycleOffboardBody`]. Returns [`types_ext::IgaLifecycleOffboardResponse`].
    pub async fn offboard(
        &self,
        id: &str,
        body: &types_ext::IgaLifecycleOffboardBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaLifecycleOffboardResponse, BackendError> {
        let path = format!("/v1/iga/users/{}/offboard", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/iga/settings` — Joiner/mover/leaver settings.
    ///
    /// Returns [`types_ext::IgaLifecycleSettingsResponse`].
    pub async fn settings(&self) -> Result<types_ext::IgaLifecycleSettingsResponse, BackendError> {
        self.client
            .request(HttpMethod::Get, "/v1/iga/settings", &[], None, None)
            .await
    }
    /// `PUT /v1/iga/settings` — Turn the joiner/mover/leaver automation on or off and choose what a
    /// deactivated account triggers: `revoke` (end the grants) or `revoke_and_close` (also schedule
    /// the closure after `leaver_close_grace_seconds`).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaLifecycleUpdateSettingsBody`]. Returns [`types_ext::IgaLifecycleUpdateSettingsResponse`].
    pub async fn update_settings(
        &self,
        body: &types_ext::IgaLifecycleUpdateSettingsBody,
        query: &Query,
    ) -> Result<types_ext::IgaLifecycleUpdateSettingsResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/iga/settings",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
}

impl IgaCampaigns<'_> {
    /// `GET /v1/iga/campaigns` — List certification (access review) campaigns.
    ///
    /// Query parameters: `status`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::IgaCampaignsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::IgaCampaignsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/iga/campaigns",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/iga/campaigns` — Create a draft campaign scoped to everything, specific
    /// entitlements, or the entitlements for an app, role, group or organization, with reviewers
    /// (the person's manager, the entitlement owner, or named users), a due date and reminder days.
    /// With `auto_revoke` the access reviewers mark for revocation is removed when the campaign
    /// closes.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaCampaignsCreateBody`]. Returns [`types_ext::IgaCampaignsCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::IgaCampaignsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaCampaignsCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/iga/campaigns",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/iga/campaigns/{id}` — Read a campaign with its progress.
    ///
    /// Returns [`types_ext::IgaCampaignsGetResponse`].
    pub async fn get(&self, id: &str) -> Result<types_ext::IgaCampaignsGetResponse, BackendError> {
        let path = format!("/v1/iga/campaigns/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `DELETE /v1/iga/campaigns/{id}` — Delete a draft or closed campaign.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::IgaCampaignsDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::IgaCampaignsDeleteResponse, BackendError> {
        let path = format!("/v1/iga/campaigns/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/iga/campaigns/{id}/launch` — Launch a draft campaign: it adopts access that exists
    /// in Atlas but was never granted through governance, freezes the review list and notifies
    /// reviewers.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::IgaCampaignsLaunchResponse`].
    pub async fn launch(
        &self,
        id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaCampaignsLaunchResponse, BackendError> {
        let path = format!("/v1/iga/campaigns/{}/launch", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/iga/campaigns/{id}/close` — Close a campaign and apply its revoke decisions (with
    /// `auto_revoke`). Items nobody reviewed are left in place and reported as pending.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::IgaCampaignsCloseResponse`].
    pub async fn close(
        &self,
        id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaCampaignsCloseResponse, BackendError> {
        let path = format!("/v1/iga/campaigns/{}/close", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/iga/campaigns/{id}/items` — The review items of a campaign.
    ///
    /// Query parameters: `decision`, `reviewer_user_id`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::IgaCampaignsItemsResponse`].
    pub async fn items(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::IgaCampaignsItemsResponse, BackendError> {
        let path = format!("/v1/iga/campaigns/{}/items", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/iga/campaigns/{id}/progress` — Progress: totals, percent complete, whether it is
    /// overdue, and per-reviewer counts.
    ///
    /// Returns [`types_ext::IgaCampaignsProgressResponse`].
    pub async fn progress(
        &self,
        id: &str,
    ) -> Result<types_ext::IgaCampaignsProgressResponse, BackendError> {
        let path = format!("/v1/iga/campaigns/{}/progress", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `GET /v1/iga/campaigns/{id}/evidence` — The audit evidence for a campaign as JSON, or CSV
    /// with `format=csv`. People are identified by id only (an erased user is flagged), free-text
    /// comments are never included, and `masked_emails=true` adds an address reduced to its first
    /// letter and domain.
    ///
    /// Query parameters: `format`, `masked_emails`.
    ///
    /// Returns [`types_ext::IgaCampaignsEvidenceResponse`].
    pub async fn evidence(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::IgaCampaignsEvidenceResponse, BackendError> {
        let path = format!("/v1/iga/campaigns/{}/evidence", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/iga/campaign_items/{id}/decide` — Certify or revoke one review item. With
    /// `reviewer_user_id` the decision is the reviewer's (they must be allowed to review it, and
    /// may not review their own access); without it it is an administrator decision.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IgaCampaignsDecideBody`]. Returns [`types_ext::IgaCampaignsDecideResponse`].
    pub async fn decide(
        &self,
        id: &str,
        body: &types_ext::IgaCampaignsDecideBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IgaCampaignsDecideResponse, BackendError> {
        let path = format!("/v1/iga/campaign_items/{}/decide", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl ScimProvisioningPresets<'_> {
    /// `GET /v1/scim_provisioning_presets` — List the pre-built outbound provisioning targets
    /// (Slack, GitHub, Zoom, Salesforce, Atlassian) with their base-URL template and required
    /// parameters.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::ScimProvisioningPresetsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::ScimProvisioningPresetsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/scim_provisioning_presets",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
}

impl OrganizationsWebhookEndpoints<'_> {
    /// `GET /v1/organizations/{id}/webhook_endpoints` — List the organization's own webhook
    /// endpoints. Backend API. Never returns a secret.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::OrganizationsWebhookEndpointsListResponse`].
    pub async fn list(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::OrganizationsWebhookEndpointsListResponse, BackendError> {
        let path = format!("/v1/organizations/{}/webhook_endpoints", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/organizations/{id}/webhook_endpoints` — Register a webhook endpoint for one
    /// organization. It receives only that organization's events (membership, invitation, role,
    /// domain and organization events). The signing secret is returned in this response only.
    /// Backend API. At most 20 per organization.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OrganizationsWebhookEndpointsCreateBody`]. Returns [`types_ext::WebhookEndpointCreate`].
    pub async fn create(
        &self,
        id: &str,
        body: &types_ext::OrganizationsWebhookEndpointsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::WebhookEndpointCreate, BackendError> {
        let path = format!("/v1/organizations/{}/webhook_endpoints", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/organizations/{id}/webhook_endpoints/{endpointId}` — Retrieve one of the
    /// organization's webhook endpoints, with its delivery health.
    ///
    /// Returns [`types_ext::WebhookEndpoint`].
    pub async fn get(
        &self,
        id: &str,
        endpoint_id: &str,
    ) -> Result<types_ext::WebhookEndpoint, BackendError> {
        let path = format!(
            "/v1/organizations/{}/webhook_endpoints/{}",
            seg(id),
            seg(endpoint_id)
        );
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/organizations/{id}/webhook_endpoints/{endpointId}` — Update the url, subscribed
    /// events, description or active flag of one of the organization's endpoints. Never re-reveals
    /// the secret.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OrganizationsWebhookEndpointsUpdateBody`]. Returns [`types_ext::WebhookEndpoint`].
    pub async fn update(
        &self,
        id: &str,
        endpoint_id: &str,
        body: &types_ext::OrganizationsWebhookEndpointsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::WebhookEndpoint, BackendError> {
        let path = format!(
            "/v1/organizations/{}/webhook_endpoints/{}",
            seg(id),
            seg(endpoint_id)
        );
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/organizations/{id}/webhook_endpoints/{endpointId}` — Delete one of the
    /// organization's webhook endpoints and its delivery log. An id from another organization is a
    /// 404.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::OrganizationsWebhookEndpointsDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        endpoint_id: &str,
        query: &Query,
    ) -> Result<types_ext::OrganizationsWebhookEndpointsDeleteResponse, BackendError> {
        let path = format!(
            "/v1/organizations/{}/webhook_endpoints/{}",
            seg(id),
            seg(endpoint_id)
        );
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/organizations/{id}/webhook_endpoints/{endpointId}/rotate_secret` — Rotate the
    /// signing secret. The previous secret keeps signing alongside the new one for 24 hours so the
    /// receiver can switch over without dropping events.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::OrganizationsWebhookEndpointsRotateSecretResponse`].
    pub async fn rotate_secret(
        &self,
        id: &str,
        endpoint_id: &str,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::OrganizationsWebhookEndpointsRotateSecretResponse, BackendError> {
        let path = format!(
            "/v1/organizations/{}/webhook_endpoints/{}/rotate_secret",
            seg(id),
            seg(endpoint_id)
        );
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/organizations/{id}/webhook_endpoints/{endpointId}/deliveries` — The endpoint's
    /// delivery log: payload, response and retry state for each attempt, filterable by status,
    /// event type and time.
    ///
    /// Query parameters: `limit`, `starting_after`, `status`, `event_type`, `since`, `until`, `trace`.
    ///
    /// Returns [`types_ext::OrganizationsWebhookEndpointsDeliveriesResponse`].
    pub async fn deliveries(
        &self,
        id: &str,
        endpoint_id: &str,
        query: &Query,
    ) -> Result<types_ext::OrganizationsWebhookEndpointsDeliveriesResponse, BackendError> {
        let path = format!(
            "/v1/organizations/{}/webhook_endpoints/{}/deliveries",
            seg(id),
            seg(endpoint_id)
        );
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl Vault<'_> {
    /// The `vault / key_provider` operations of the Backend API.
    pub fn key_provider(&self) -> VaultKeyProvider<'_> {
        VaultKeyProvider {
            client: self.client,
        }
    }
    /// `POST /v1/vault/objects` — Store a secret. `key_context` (1–10 string labels) is mandatory
    /// and is authenticated into the encryption: the value can only be opened with the context it
    /// was written under. The value (up to 64 KiB) is sealed under a fresh data key wrapped by the
    /// instance key, or by your own cloud KMS key when one is configured. 409 when the name is
    /// taken.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::VaultCreateBody`]. Returns [`types_ext::VaultCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::VaultCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::VaultCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/vault/objects",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/vault/objects` — List vault objects (metadata only, never values), newest first.
    /// Filter by `name_prefix` or by `key_context` (a JSON object; objects whose context contains
    /// every given label).
    ///
    /// Query parameters: `name_prefix`, `key_context`, `starting_after`, `limit`.
    ///
    /// Returns [`types_ext::VaultListResponse`].
    pub async fn list(&self, query: &Query) -> Result<types_ext::VaultListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/vault/objects",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/vault/objects/{id}/metadata` — Read a vault object's metadata without its value.
    ///
    /// Returns [`types_ext::VaultMetadataResponse`].
    pub async fn metadata(
        &self,
        id: &str,
    ) -> Result<types_ext::VaultMetadataResponse, BackendError> {
        let path = format!("/v1/vault/objects/{}/metadata", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `GET /v1/vault/objects/{id}/versions` — List the versions of a vault object (number, which
    /// key protects it, when written) — never values.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::VaultVersionsResponse`].
    pub async fn versions(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::VaultVersionsResponse, BackendError> {
        let path = format!("/v1/vault/objects/{}/versions", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/vault/objects/{id}` — Read a vault object with its decrypted value (the current
    /// version, or `version`). Every read is audited. 409 if the version's wrapping key provider is
    /// no longer configured; 502 VAULT_KMS_ERROR when your KMS refuses.
    ///
    /// Query parameters: `version`.
    ///
    /// Returns [`types_ext::VaultReadResponse`].
    pub async fn read(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::VaultReadResponse, BackendError> {
        let path = format!("/v1/vault/objects/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `PUT /v1/vault/objects/{id}` — Append a new version with a new value. Earlier versions stay
    /// readable. Pass `version_check` (the version you last read) for optimistic concurrency: 409
    /// if another update landed since.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::VaultUpdateBody`]. Returns [`types_ext::VaultUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::VaultUpdateBody,
        query: &Query,
    ) -> Result<types_ext::VaultUpdateResponse, BackendError> {
        let path = format!("/v1/vault/objects/{}", seg(id));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/vault/objects/{id}` — Delete a vault object and every version of it.
    /// Irreversible.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::VaultDeleteResponse`].
    pub async fn delete(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::VaultDeleteResponse, BackendError> {
        let path = format!("/v1/vault/objects/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl VaultKeyProvider<'_> {
    /// `GET /v1/vault/key_provider` — The customer-managed key that wraps new vault data keys. 404
    /// when none is configured (the instance key is used).
    ///
    /// Returns [`types_ext::VaultKeyProviderGetResponse`].
    pub async fn get(&self) -> Result<types_ext::VaultKeyProviderGetResponse, BackendError> {
        self.client
            .request(HttpMethod::Get, "/v1/vault/key_provider", &[], None, None)
            .await
    }
    /// `PUT /v1/vault/key_provider` — Bring your own key: wrap new vault data keys with your AWS
    /// KMS (`config.region`, `config.key_id`; symmetric key), Google Cloud KMS
    /// (`config.crypto_key`; symmetric key) or Azure Key Vault (`config.vault_url`,
    /// `config.key_name`; RSA key with wrap/unwrap) key. Atlas proves access with a wrap/unwrap
    /// round trip before saving (422 or 502 on refusal). Credentials are write-only. Existing
    /// versions stay on the key that wrapped them; switching provider type is a 409 while versions
    /// remain on the old one.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::VaultKeyProviderSetBody`]. Returns [`types_ext::VaultKeyProviderSetResponse`].
    pub async fn set(
        &self,
        body: &types_ext::VaultKeyProviderSetBody,
        query: &Query,
    ) -> Result<types_ext::VaultKeyProviderSetResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/vault/key_provider",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/vault/key_provider` — Stop using your own key for new versions. 409 while any
    /// version is still wrapped by it.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::VaultKeyProviderRemoveResponse`].
    pub async fn remove(
        &self,
        query: &Query,
    ) -> Result<types_ext::VaultKeyProviderRemoveResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Delete,
                "/v1/vault/key_provider",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
}

impl Connections<'_> {
    /// The `connections / oauth_clients` operations of the Backend API.
    pub fn oauth_clients(&self) -> ConnectionsOauthClients<'_> {
        ConnectionsOauthClients {
            client: self.client,
        }
    }
    /// The `connections / webhooks` operations of the Backend API.
    pub fn webhooks(&self) -> ConnectionsWebhooks<'_> {
        ConnectionsWebhooks {
            client: self.client,
        }
    }
    /// `POST /v1/connections` — Define a connection: an owner (an organization or a user) and a
    /// third-party API. `kind` is oauth (rides a linked provider account; for an organization, the
    /// account of the member who shared it), api_key or client_credentials (a credential the owner
    /// enters). `allowed_hosts` lists the only hosts the relay may call. An owner may hold several
    /// connections of one provider (one per provider account): create one per account, then call
    /// `POST /v1/connections/{id}/connect`. A connection is never a sign-in method.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsCreateBody`]. Returns [`types_ext::ConnectionsCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::ConnectionsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ConnectionsCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/connections",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/connections` — List connections, newest first, with each one's live status. Filter
    /// by owner or provider.
    ///
    /// Query parameters: `owner_type`, `owner_id`, `provider`, `environment`, `status`, `starting_after`, `limit`.
    ///
    /// Returns [`types_ext::ConnectionsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::ConnectionsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/connections",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/connections/{id}` — Read one connection with its current status.
    ///
    /// Returns [`types_ext::ConnectionsGetResponse`].
    pub async fn get(&self, id: &str) -> Result<types_ext::ConnectionsGetResponse, BackendError> {
        let path = format!("/v1/connections/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/connections/{id}` — Rename a connection, change its allowed hosts or settings,
    /// transfer it to another owner with `owner` (the stored tokens move with it, no reconnect),
    /// change `environment` or `host_params` (an oauth connection that already holds a token
    /// becomes needs_reauth, because the token belongs to the old host), or (organization-owned
    /// oauth) set `shared_by_user_id` to copy that member's linked account into the connection.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsUpdateBody`]. Returns [`types_ext::ConnectionsUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::ConnectionsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::ConnectionsUpdateResponse, BackendError> {
        let path = format!("/v1/connections/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/connections/{id}` — Delete a connection and its stored credential (204). With
    /// `revoke=true` the token is first revoked at the provider and the answer is 200 with what the
    /// provider said (provider_revoked true, false or "unsupported", provider_error,
    /// local_cleared); the connection is deleted either way.
    ///
    /// Query parameters: `dry_run`, `revoke`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/connections/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `PUT /v1/connections/{id}/credentials` — Enter the credential for a non-OAuth connection
    /// (api_key, bearer, basic, custom_header, hmac_secret, client_credentials, jwt_bearer, oauth1,
    /// github_app_installation). Write-only: it is sealed in the vault and never returned. Replaces
    /// the earlier credential as a new vault version; use POST .../credentials/rotate to keep the
    /// old version valid for an overlap window.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsSetCredentialsBody`]. Returns [`types_ext::ConnectionsSetCredentialsResponse`].
    pub async fn set_credentials(
        &self,
        id: &str,
        body: &types_ext::ConnectionsSetCredentialsBody,
        query: &Query,
    ) -> Result<types_ext::ConnectionsSetCredentialsResponse, BackendError> {
        let path = format!("/v1/connections/{}/credentials", seg(id));
        self.client
            .request(
                HttpMethod::Put,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `POST /v1/connections/{id}/connect` — Start the provider authorization for this connection
    /// and return the URL to send the owner to. The tokens are stored on the connection itself,
    /// never on a user: no external account is created, no sign-in method is added, no email is
    /// proven and no step-up is needed. `host_params` fill the provider's host templates for this
    /// connection (validated against a per-provider allowlist; 400 `host_params.&lt;key&gt;`
    /// otherwise). Reconnecting the same provider account updates the same connection; a different
    /// account answers 409 unless `create_if_new` is true. An owner OAuth client (`PUT
    /// /v1/connections/oauth_clients`) overrides the instance client.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsConnectBody`]. Returns [`types_ext::ConnectionsConnectResponse`].
    pub async fn connect(
        &self,
        id: &str,
        body: &types_ext::ConnectionsConnectBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ConnectionsConnectResponse, BackendError> {
        let path = format!("/v1/connections/{}/connect", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/connections/{id}/revoke` — Revoke the stored token at the provider, delete it from
    /// the vault and mark the connection revoked (connection.revoked is sent once). The response is
    /// the connection plus what the provider said: provider_revoked is true only when it confirmed,
    /// "unsupported" when it has no revoke endpoint, false when it refused or was unreachable
    /// (provider_error says why). The local token is cleared in every case. Connect again to use
    /// it.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes a JSON body (the API documents it as open-ended). Returns [`types_ext::ConnectionsRevokeResponse`].
    pub async fn revoke(
        &self,
        id: &str,
        body: Value,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ConnectionsRevokeResponse, BackendError> {
        let path = format!("/v1/connections/{}/revoke", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                Some(body),
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/connections/{id}/oauth1/sign` — Have Atlas sign a request with an oauth1
    /// connection (NetSuite token-based authentication: HMAC-SHA256 with the realm; X Ads and other
    /// three-legged providers: HMAC-SHA1) and return the `Authorization: OAuth ...` header. The
    /// consumer and token secrets never leave Atlas. The URL must be https on an allowed host; a
    /// form-encoded body is part of the signature. Needs connections:sign.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsOauth1SignBody`]. Returns [`types_ext::ConnectionsOauth1SignResponse`].
    pub async fn oauth1_sign(
        &self,
        id: &str,
        body: &types_ext::ConnectionsOauth1SignBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ConnectionsOauth1SignResponse, BackendError> {
        let path = format!("/v1/connections/{}/oauth1/sign", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/connections/{id}/relay` — Make a provider API call server-side with this
    /// connection's credential, so the credential never reaches your code: Atlas injects an api_key
    /// (header or query), bearer, basic or custom header, signs with an hmac_secret or OAuth 1.0a,
    /// or sends a minted client_credentials / jwt_bearer / GitHub App installation / admin consent
    /// token. Only https calls to the connection's allowed_hosts are made, with the verbs in
    /// allowed_methods (default GET, HEAD, POST). When the connection is not connected, or the
    /// provider rejects the credential, the answer is 402 CONNECTION_REQUIRED with `meta.reason`
    /// (not_connected or needs_reauth) and, for a user-owned OAuth connection when you pass
    /// `redirect_url`, `meta.authorize_url`. The audit log records the method, host and status
    /// only.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsRelayBody`]. Returns [`types_ext::ConnectionsRelayResponse`].
    pub async fn relay(
        &self,
        id: &str,
        body: &types_ext::ConnectionsRelayBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ConnectionsRelayResponse, BackendError> {
        let path = format!("/v1/connections/{}/relay", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/connections/{id}/token` — The connection's live token for your backend. An oauth
    /// connection's token is refreshed first when it is expired or about to be (single-flight
    /// across processes, using the client that issued it and the connection's host_params). Built
    /// for sync workers: the response carries an `ETag` and `Cache-Control: private,
    /// max-age=&lt;seconds until just before expires_at&gt;`, so cache it until then; send
    /// `If-None-Match` and an unchanged, still-valid token answers 304 with no body and no vault
    /// read; `min_ttl_seconds` refreshes first when less than that much validity remains. A grant
    /// connection (client_credentials, jwt_bearer, github_app_installation, admin_consent) has its
    /// token minted from the credential Atlas holds instead, answered with `Cache-Control:
    /// no-store` (no ETag); pass `subject` to a jwt_bearer connection to act as that user (Google
    /// domain-wide delegation). Includes the captured handles (`metadata`, `token_response`) and
    /// any further named credentials. 402 CONNECTION_REQUIRED with `meta.reason` not_connected,
    /// needs_reauth, revoked or refresh_failed when there is no usable token. When the provider
    /// answers 401 to the token, call `POST /v1/connections/{id}/token/refresh` instead of
    /// re-reading. Rate limit: 6,000 reads per minute per secret key and 300 per minute per
    /// connection (RateLimit-* headers on every response, 429 with Retry-After beyond them). Reads
    /// are audited as connection.token_read once per connection per minute with the read count (a
    /// read that refreshed is always audited); the token itself is never logged.
    ///
    /// Query parameters: `min_ttl_seconds`, `subject`, `refresh`.
    ///
    /// Returns [`types_ext::ConnectionsTokenResponse`].
    pub async fn token(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::ConnectionsTokenResponse, BackendError> {
        let path = format!("/v1/connections/{}/token", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/connections/{id}/token/refresh` — Force a refresh after the provider refused the
    /// access token (401). Single-flight: however many callers saw the same 401, the provider is
    /// called once. Send `stale_token_hash` (lowercase hex SHA-256 of the access token you were
    /// refused with); if the stored token is already a different one, a peer has refreshed and the
    /// current token is returned without calling the provider (`refreshed: false`). Same body, ETag
    /// and 402 behaviour as the token read; the response is never cached. Counts against the same
    /// rate limit as the token read.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsRefreshTokenBody`]. Returns [`types_ext::ConnectionsRefreshTokenResponse`].
    pub async fn refresh_token(
        &self,
        id: &str,
        body: &types_ext::ConnectionsRefreshTokenBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ConnectionsRefreshTokenResponse, BackendError> {
        let path = format!("/v1/connections/{}/token/refresh", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/connections/tokens/batch` — Read the tokens of up to 100 connections in one call
    /// (min_ttl_seconds applies to each). Each id gets its own result: status ok with the token, or
    /// status error with a code and reason (not_connected, needs_reauth, revoked, refresh_failed,
    /// unknown_connection), so one dead connection never fails the batch. The response is never
    /// cached. Counts once against the token-read rate limit.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsTokensBody`]. Returns [`types_ext::ConnectionsTokensResponse`].
    pub async fn tokens(
        &self,
        body: &types_ext::ConnectionsTokensBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ConnectionsTokensResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/connections/tokens/batch",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/connections/import` — Bulk-import existing provider refresh tokens as connections,
    /// up to 500 rows, so nobody reconnects. Each row: provider, owner, external_id (the
    /// provider-side account: how a re-import finds the same connection), refresh_token (or
    /// access_token), and optionally scopes, metadata, environment, host_params, name,
    /// allowed_hosts. By default (validate true) each refresh token is spent once against the
    /// provider with the OAuth client that will own the connection, and the tokens the provider
    /// issues are stored, so the imported copy stops being current on a rotating provider. A
    /// failing row creates and changes nothing. dry_run checks shapes only and never calls the
    /// provider. Idempotent on Idempotency-Key. Tokens go straight to the vault and never appear in
    /// the answer or the audit log.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsImportConnectionsBody`]. Returns [`types_ext::ConnectionsImportConnectionsResponse`].
    pub async fn import_connections(
        &self,
        body: &types_ext::ConnectionsImportConnectionsBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ConnectionsImportConnectionsResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/connections/import",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/connections/export` — Export connections. Without include_secrets: metadata only
    /// (provider, owner, account, environment, scopes, status), scope connections:export. With
    /// include_secrets: needs scope connections:export_secrets, the header X-Atlas-Confirm:
    /// export-secrets and recipient_public_key (a public JWK: RSA of 3072 bits or more, or EC
    /// P-256/384/521). The tokens come back as one compact JWE sealed to that key that only its
    /// holder can open; Atlas keeps no plaintext. Pages hold up to 200 connections with secrets
    /// (500 without); follow next_cursor with starting_after. Every export is audited with its
    /// count, never the secrets. Opened, each connection is a valid import row.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsExportConnectionsBody`]. Returns [`types_ext::ConnectionsExportConnectionsResponse`].
    pub async fn export_connections(
        &self,
        body: &types_ext::ConnectionsExportConnectionsBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ConnectionsExportConnectionsResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/connections/export",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/connections/{id}/secret` — Read the credential an api_key, bearer, basic,
    /// custom_header or hmac_secret connection stores, for your backend. Needs the dedicated
    /// connections:secret_read scope; every read is audited as connection.secret.read with the
    /// caller, connection and version (never the value) and the response is `Cache-Control:
    /// no-store`. `version` is current (default), previous (only while a rotation's overlap window
    /// is open) or a version number. A signing grant's private key is never readable: 409
    /// `not_readable`. There is no browser or session route that reads a credential.
    ///
    /// Query parameters: `version`.
    ///
    /// Returns [`types_ext::ConnectionsSecretResponse`].
    pub async fn secret(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::ConnectionsSecretResponse, BackendError> {
        let path = format!("/v1/connections/{}/secret", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/connections/{id}/credentials/versions` — The vault versions of a connection's
    /// entered credential (numbers and times only, never values) and the open rotation window.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::ConnectionsSecretVersionsResponse`].
    pub async fn secret_versions(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::ConnectionsSecretVersionsResponse, BackendError> {
        let path = format!("/v1/connections/{}/credentials/versions", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/connections/{id}/credentials/rotate` — Rotate the credential: the body is the new
    /// credential (the same fields as PUT credentials). It becomes the current vault version; the
    /// replaced one stays valid for `overlap_seconds` (default 3600, up to 30 days): the relay
    /// falls back to it when the provider refuses the new one, and GET secret?version=previous
    /// returns it. `expires_at` sets the new credential's expiry. The secret never reaches the
    /// audit log.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsRotateCredentialsBody`]. Returns [`types_ext::ConnectionsRotateCredentialsResponse`].
    pub async fn rotate_credentials(
        &self,
        id: &str,
        body: &types_ext::ConnectionsRotateCredentialsBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ConnectionsRotateCredentialsResponse, BackendError> {
        let path = format!("/v1/connections/{}/credentials/rotate", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl ConnectionsOauthClients<'_> {
    /// `PUT /v1/connections/oauth_clients` — Set an owner's own OAuth client (their registered app)
    /// for a provider and environment. It overrides the instance client for that owner's
    /// connections to connect and to refresh. Write-only secret, sealed in the vault. Creates the
    /// client or replaces it.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsOauthClientsSetBody`]. Returns [`types_ext::ConnectionsOauthClientsSetResponse`].
    pub async fn set(
        &self,
        body: &types_ext::ConnectionsOauthClientsSetBody,
        query: &Query,
    ) -> Result<types_ext::ConnectionsOauthClientsSetResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/connections/oauth_clients",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `GET /v1/connections/oauth_clients` — List owner OAuth clients. The secret is never
    /// returned.
    ///
    /// Query parameters: `owner_type`, `owner_id`, `provider`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::ConnectionsOauthClientsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::ConnectionsOauthClientsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/connections/oauth_clients",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/connections/oauth_clients/{id}` — Read one owner OAuth client.
    ///
    /// Returns [`types_ext::ConnectionsOauthClientsGetResponse`].
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<types_ext::ConnectionsOauthClientsGetResponse, BackendError> {
        let path = format!("/v1/connections/oauth_clients/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `DELETE /v1/connections/oauth_clients/{id}` — Delete an owner OAuth client and its sealed
    /// secret. 409 while connections still hold tokens it issued (they could no longer refresh).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/connections/oauth_clients/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl ConnectionsWebhooks<'_> {
    /// `POST /v1/connections/{id}/webhooks/verify` — Verify a provider webhook signature with the
    /// connection's secret (the endpoint's own signing secret, else the connection's hmac_secret,
    /// else its OAuth client secret). Schemes: hubspot_v3 (needs method and url), shopify_hmac,
    /// intercom, zoom, slack_v0, calendly, stripe, generic_hmac_sha256. Constant-time comparison; a
    /// signed timestamp must be within the tolerance (5 minutes, Calendly 3); a delivery id or
    /// signature already seen on the connection answers `replayed`. Send the body exactly as
    /// received (`raw_body`, or base64 with raw_body_encoding). Zoom and Slack handshakes come back
    /// in `handshake`. Needs connections:webhook_verify.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsWebhooksVerifyBody`]. Returns [`types_ext::ConnectionsWebhooksVerifyResponse`].
    pub async fn verify(
        &self,
        id: &str,
        body: &types_ext::ConnectionsWebhooksVerifyBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ConnectionsWebhooksVerifyResponse, BackendError> {
        let path = format!("/v1/connections/{}/webhooks/verify", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/connections/{id}/webhook_endpoints` — Create a webhook ingress endpoint on a
    /// connection. Point the provider at `ingress_url`; Atlas verifies each delivery, refuses
    /// forged, stale and replayed ones, answers Zoom and Slack handshakes, and forwards only
    /// genuine deliveries to `forward_url` as Atlas-signed webhooks (atlas-id, atlas-timestamp,
    /// atlas-signature with `forward_secret`, returned once). Bodies over 1 MiB are refused; the
    /// ingress is rate limited.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsWebhooksCreateEndpointBody`]. Returns [`types_ext::ConnectionsWebhooksCreateEndpointResponse`].
    pub async fn create_endpoint(
        &self,
        id: &str,
        body: &types_ext::ConnectionsWebhooksCreateEndpointBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ConnectionsWebhooksCreateEndpointResponse, BackendError> {
        let path = format!("/v1/connections/{}/webhook_endpoints", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/connections/{id}/webhook_endpoints` — List a connection's webhook ingress
    /// endpoints.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::ConnectionsWebhooksListEndpointsResponse`].
    pub async fn list_endpoints(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::ConnectionsWebhooksListEndpointsResponse, BackendError> {
        let path = format!("/v1/connections/{}/webhook_endpoints", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `PATCH /v1/connections/{id}/webhook_endpoints/{endpointId}` — Change an endpoint's
    /// forward_url, enabled flag or signing secret.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ConnectionsWebhooksUpdateEndpointBody`]. Returns [`types_ext::ConnectionsWebhooksUpdateEndpointResponse`].
    pub async fn update_endpoint(
        &self,
        id: &str,
        endpoint_id: &str,
        body: &types_ext::ConnectionsWebhooksUpdateEndpointBody,
        query: &Query,
    ) -> Result<types_ext::ConnectionsWebhooksUpdateEndpointResponse, BackendError> {
        let path = format!(
            "/v1/connections/{}/webhook_endpoints/{}",
            seg(id),
            seg(endpoint_id)
        );
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/connections/{id}/webhook_endpoints/{endpointId}` — Delete a webhook ingress
    /// endpoint and its secrets.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete_endpoint(
        &self,
        id: &str,
        endpoint_id: &str,
        query: &Query,
    ) -> Result<(), BackendError> {
        let path = format!(
            "/v1/connections/{}/webhook_endpoints/{}",
            seg(id),
            seg(endpoint_id)
        );
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl Fga<'_> {
    /// `POST /v1/fga/stores/{id}/list-users` — List the users that have a relation on an object,
    /// filtered to one user type (or to `type#relation` usersets via `user_filters\[0\].relation`).
    /// Exact for wildcards (`type:*` plus `excluded_users` under `but not`), nested groups and
    /// contextual tuples; tuple conditions are evaluated against `context`. Pages with `page_size`
    /// / `continuation_token`; `consistency` / `consistency_token` behave as on check.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::FgaListUsersBody`]. Returns [`types_ext::FgaListUsersResponse`].
    pub async fn list_users(
        &self,
        id: &str,
        body: &types_ext::FgaListUsersBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::FgaListUsersResponse, BackendError> {
        let path = format!("/v1/fga/stores/{}/list-users", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/fga/stores/{id}/changes` — Read the store’s tuple changelog: every tuple write and
    /// delete in commit order, resumable with `continuation_token` (returned even on the last page
    /// — pass it later to receive only newer changes). Filter by object `type` and `start_time`.
    ///
    /// Query parameters: `type`, `page_size`, `continuation_token`, `start_time`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::FgaReadChangesResponse`].
    pub async fn read_changes(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::FgaReadChangesResponse, BackendError> {
        let path = format!("/v1/fga/stores/{}/changes", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl OpenFga<'_> {
    /// `POST /v1/openfga/stores/{store}/list-users` — List the users that have a relation on an
    /// object (OpenFGA-wire ListUsers): concrete users, usersets (`user_filters\[0\].relation`),
    /// and the `type:*` wildcard with `excluded_users`. Honours contextual tuples and tuple
    /// conditions; pages with `page_size` / `continuation_token`.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OpenFgaListUsersBody`]. Returns [`types_ext::OpenFgaListUsersResponse`].
    pub async fn list_users(
        &self,
        store: &str,
        body: &types_ext::OpenFgaListUsersBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::OpenFgaListUsersResponse, BackendError> {
        let path = format!("/v1/openfga/stores/{}/list-users", seg(store));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/openfga/stores/{store}/changes` — Read the tuple changelog (OpenFGA-wire
    /// ReadChanges): every tuple write and delete in order, resumable with `continuation_token`
    /// (the token is returned even on the last page — pass it later to receive only newer changes).
    ///
    /// Query parameters: `type`, `page_size`, `continuation_token`, `start_time`.
    ///
    /// Returns [`types_ext::OpenFgaReadChangesResponse`].
    pub async fn read_changes(
        &self,
        store: &str,
        query: &Query,
    ) -> Result<types_ext::OpenFgaReadChangesResponse, BackendError> {
        let path = format!("/v1/openfga/stores/{}/changes", seg(store));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl AttackProtection<'_> {
    /// `PUT /v1/attack_protection/app_attestation_secret` — Store the Play Integrity
    /// response-decryption key (base64 AES-256) for app attestation. Write-only; the public
    /// verification key is attackProtection.appAttestation.android.verificationKey.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AttackProtectionSetAppAttestationSecretBody`]. Returns [`types_ext::AttackProtectionSetAppAttestationSecretResponse`].
    pub async fn set_app_attestation_secret(
        &self,
        body: &types_ext::AttackProtectionSetAppAttestationSecretBody,
        query: &Query,
    ) -> Result<types_ext::AttackProtectionSetAppAttestationSecretResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/attack_protection/app_attestation_secret",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/attack_protection/app_attestation_secret` — Remove a stored attestation secret:
    /// the Play Integrity decryption key (default) or, with kind=devicecheck, the Apple DeviceCheck
    /// key. That platform then refuses every request.
    ///
    /// Query parameters: `dry_run`, `kind`.
    ///
    /// Returns [`types_ext::AttackProtectionRemoveAppAttestationSecretResponse`].
    pub async fn remove_app_attestation_secret(
        &self,
        query: &Query,
    ) -> Result<types_ext::AttackProtectionRemoveAppAttestationSecretResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Delete,
                "/v1/attack_protection/app_attestation_secret",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
}

impl RiskBasedMfa<'_> {
    /// `PUT /v1/risk_based_mfa/reputation_secret` — Store (write-only, encrypted) the API key of
    /// your IP-reputation provider (ipqs, spur or minfraud; minFraud uses "&lt;account
    /// id&gt;:&lt;license key&gt;"). Then set `reputation.provider` on PATCH /v1/risk_based_mfa.
    /// Lookups are cached and fail open: a provider outage never blocks a sign-in.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::RiskBasedMfaSetReputationSecretBody`]. Returns [`types_ext::RiskBasedMfaSetReputationSecretResponse`].
    pub async fn set_reputation_secret(
        &self,
        body: &types_ext::RiskBasedMfaSetReputationSecretBody,
        query: &Query,
    ) -> Result<types_ext::RiskBasedMfaSetReputationSecretResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/risk_based_mfa/reputation_secret",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/risk_based_mfa/reputation_secret` — Remove a stored IP-reputation provider key
    /// (default: the configured provider). IP lookups for that provider stop; sign-in is
    /// unaffected.
    ///
    /// Query parameters: `dry_run`, `provider`.
    ///
    /// Returns [`types_ext::RiskBasedMfaRemoveReputationSecretResponse`].
    pub async fn remove_reputation_secret(
        &self,
        query: &Query,
    ) -> Result<types_ext::RiskBasedMfaRemoveReputationSecretResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Delete,
                "/v1/risk_based_mfa/reputation_secret",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
}

impl SsfStreams<'_> {
    /// `GET /v1/ssf/streams` — List the Shared Signals streams this instance transmits on (push and
    /// poll), with their delivery method, requested events and status.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::SsfStreamsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::SsfStreamsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/ssf/streams",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/ssf/streams` — Create a stream. `delivery_method` is `push` (we POST each signed
    /// SET to `endpoint_url`, with the optional `authorization_header`) or `poll` (the receiver
    /// pulls from the returned `poll_endpoint` with the one-time `poll_token`). `events_requested`
    /// limits the events sent (empty = all supported). SETs are signed with the instance signing
    /// key.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::SsfStreamsCreateBody`]. Returns nothing (`204 No Content`).
    pub async fn create(
        &self,
        body: &types_ext::SsfStreamsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<(), BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/ssf/streams",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/ssf/streams/{id}` — Read a stream, including how many events are waiting to be
    /// delivered or acknowledged.
    ///
    /// Returns [`types_ext::SsfStreamsGetResponse`].
    pub async fn get(&self, id: &str) -> Result<types_ext::SsfStreamsGetResponse, BackendError> {
        let path = format!("/v1/ssf/streams/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/ssf/streams/{id}` — Change a stream: its events, endpoint, authorization header,
    /// description, or status (`enabled`, `paused`, `disabled`). A paused stream stops receiving
    /// new events.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::SsfStreamsUpdateBody`]. Returns nothing (`204 No Content`).
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::SsfStreamsUpdateBody,
        query: &Query,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/ssf/streams/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/ssf/streams/{id}` — Delete a stream and its queued events.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/ssf/streams/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/ssf/streams/{id}/verify` — Queue an SSF verification event carrying `state`, so a
    /// receiver can confirm the stream works end to end.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::SsfStreamsVerifyBody`]. Returns nothing (`204 No Content`).
    pub async fn verify(
        &self,
        id: &str,
        body: &types_ext::SsfStreamsVerifyBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/ssf/streams/{}/verify", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/ssf/streams/{id}/status` — The stream's delivery status: enabled, paused or
    /// disabled (SSF stream status).
    ///
    /// Returns [`types_ext::SsfStreamsGetStatusResponse`].
    pub async fn get_status(
        &self,
        id: &str,
    ) -> Result<types_ext::SsfStreamsGetStatusResponse, BackendError> {
        let path = format!("/v1/ssf/streams/{}/status", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `POST /v1/ssf/streams/{id}/status` — Set the stream's delivery status to enabled, paused or
    /// disabled. A paused stream collects nothing.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::SsfStreamsUpdateStatusBody`]. Returns [`types_ext::SsfStreamsUpdateStatusResponse`].
    pub async fn update_status(
        &self,
        id: &str,
        body: &types_ext::SsfStreamsUpdateStatusBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::SsfStreamsUpdateStatusResponse, BackendError> {
        let path = format!("/v1/ssf/streams/{}/status", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/ssf/streams/{id}/events` — The stream's recent events with delivery status,
    /// attempts and the last error (the dashboard activity view).
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::SsfStreamsEventsResponse`].
    pub async fn events(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::SsfStreamsEventsResponse, BackendError> {
        let path = format!("/v1/ssf/streams/{}/events", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl SsfReceivers<'_> {
    /// `GET /v1/ssf/receivers` — List inbound Shared Signals receivers: transmitters whose signed
    /// events act on this instance's users.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::SsfReceiversListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::SsfReceiversListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/ssf/receivers",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/ssf/receivers` — Register a transmitter. Its SETs are POSTed
    /// (`application/secevent+jwt`) to the returned `receive_endpoint` and verified against
    /// `jwks_uri`, `issuer` and the optional `audience`. `actions` maps an event type URI to
    /// `revoke_sessions`, `refresh_claims` (invalidate minted tokens so the next refresh carries
    /// fresh claims, sessions stay), `ban` or `ignore`; unmapped events are ignored. The default
    /// maps session-revoked, credential-change, credential-compromise and device-compliance-change
    /// (only when the new status is not-compliant) to `revoke_sessions`, token-claims-change to
    /// `refresh_claims` and account-disabled to `ban`.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::SsfReceiversCreateBody`]. Returns nothing (`204 No Content`).
    pub async fn create(
        &self,
        body: &types_ext::SsfReceiversCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<(), BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/ssf/receivers",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `PATCH /v1/ssf/receivers/{id}` — Change a receiver: name, JWKS URI, audience, action
    /// mapping, or enabled.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::SsfReceiversUpdateBody`]. Returns nothing (`204 No Content`).
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::SsfReceiversUpdateBody,
        query: &Query,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/ssf/receivers/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/ssf/receivers/{id}` — Delete an inbound SSF receiver; its endpoint stops
    /// accepting events.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/ssf/receivers/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl NetworkZones<'_> {
    /// `GET /v1/network_zones` — List reusable network zones — named sets of CIDRs, countries, ASNs
    /// and anonymizer classes (tor, datacenter, vpn) that network ACL rules reference by zone_id.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::NetworkZonesListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::NetworkZonesListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/network_zones",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/network_zones` — Create a network zone. `name` is unique per instance; `cidrs`,
    /// `countries` (ISO alpha-2), `asns` and `anonymizers` are unioned (any match = in the zone).
    /// Malformed entries are refused.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::NetworkZonesCreateBody`]. Returns [`types_ext::NetworkZone`].
    pub async fn create(
        &self,
        body: &types_ext::NetworkZonesCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::NetworkZone, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/network_zones",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/network_zones/{id}` — Read one network zone.
    ///
    /// Returns [`types_ext::NetworkZone`].
    pub async fn get(&self, id: &str) -> Result<types_ext::NetworkZone, BackendError> {
        let path = format!("/v1/network_zones/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/network_zones/{id}` — Update a network zone. Sending any of
    /// cidrs/countries/asns/anonymizers replaces that list; omitted lists keep their value.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::NetworkZonesUpdateBody`]. Returns [`types_ext::NetworkZone`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::NetworkZonesUpdateBody,
        query: &Query,
    ) -> Result<types_ext::NetworkZone, BackendError> {
        let path = format!("/v1/network_zones/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/network_zones/{id}` — Delete a network zone. The network ACL rules that
    /// reference it are deleted with it.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/network_zones/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/network_zones/{id}/check` — What-if: does an IP address fall inside this zone?
    /// Returns the resolved country / ASN / Tor / datacenter facts alongside the answer. Facts the
    /// instance has no IP-intelligence data for are null and never match.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::NetworkZonesCheckBody`]. Returns [`types_ext::NetworkZonesCheckResponse`].
    pub async fn check(
        &self,
        id: &str,
        body: &types_ext::NetworkZonesCheckBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::NetworkZonesCheckResponse, BackendError> {
        let path = format!("/v1/network_zones/{}/check", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl AccessPolicies<'_> {
    /// `GET /v1/access_policies` — List conditional-access policies, in evaluation order.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AccessPoliciesListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::AccessPoliciesListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/access_policies",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/access_policies` — Create a conditional-access policy. `conditions` (applications,
    /// userIds, groups, orgs, roles, networkZones {include, exclude}, countries, riskLevels,
    /// deviceTrust, authMethods, timeWindow) are ANDed; an empty condition matches anything.
    /// `grants` are allow, block, require_mfa, require_acr, require_policy_acceptance or
    /// require_action. `stages` limits it to sign_in, authorize and/or token (default all). A
    /// matching block wins; step-up grants are unioned.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AccessPoliciesCreateBody`]. Returns [`types_ext::AccessPolicy`].
    pub async fn create(
        &self,
        body: &types_ext::AccessPoliciesCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AccessPolicy, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/access_policies",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/access_policies/simulate` — What-if: describe a request (stage, ip, application,
    /// orgs, roles, country, risk level, device trust, auth methods, whether MFA was verified) and
    /// see the decision, the policies that matched and the unmet step-up requirements. Pass
    /// `policy_id` to test one policy even if it is disabled.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AccessPoliciesSimulateBody`]. Returns [`types_ext::AccessPolicySimulation`].
    pub async fn simulate(
        &self,
        body: &types_ext::AccessPoliciesSimulateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AccessPolicySimulation, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/access_policies/simulate",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/access_policies/{id}` — Read one access policy.
    ///
    /// Returns [`types_ext::AccessPolicy`].
    pub async fn get(&self, id: &str) -> Result<types_ext::AccessPolicy, BackendError> {
        let path = format!("/v1/access_policies/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/access_policies/{id}` — Update an access policy. Sent fields replace the stored
    /// value.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AccessPoliciesUpdateBody`]. Returns [`types_ext::AccessPolicy`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::AccessPoliciesUpdateBody,
        query: &Query,
    ) -> Result<types_ext::AccessPolicy, BackendError> {
        let path = format!("/v1/access_policies/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/access_policies/{id}` — Delete an access policy.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/access_policies/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl Abac<'_> {
    /// The `abac / templates` operations of the Backend API.
    pub fn templates(&self) -> AbacTemplates<'_> {
        AbacTemplates {
            client: self.client,
        }
    }
    /// The `abac / links` operations of the Backend API.
    pub fn links(&self) -> AbacLinks<'_> {
        AbacLinks {
            client: self.client,
        }
    }
    /// The `abac / schema` operations of the Backend API.
    pub fn schema(&self) -> AbacSchema<'_> {
        AbacSchema {
            client: self.client,
        }
    }
    /// `GET /v1/abac_policies` — List the ABAC policies (current version of each).
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AbacListResponse`].
    pub async fn list(&self, query: &Query) -> Result<types_ext::AbacListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/abac_policies",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/abac_policies` — Create an ABAC policy from `source` written in the Cedar-subset
    /// policy language (permit/forbid with when/unless over principal, action, resource and context
    /// attributes; `fga.check(...)` consults the policy’s FGA store). Source that does not parse is
    /// refused with the character position; with an entity schema set it is also type-checked and
    /// every problem is reported. Optional `tests` are saved with version 1.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacCreateBody`]. Returns [`types_ext::AbacPolicy`].
    pub async fn create(
        &self,
        body: &types_ext::AbacCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacPolicy, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/abac_policies",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/abac_policies/{id}` — Read one ABAC policy with its current source and tests.
    ///
    /// Returns [`types_ext::AbacPolicy`].
    pub async fn get(&self, id: &str) -> Result<types_ext::AbacPolicy, BackendError> {
        let path = format!("/v1/abac_policies/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/abac_policies/{id}` — Update an ABAC policy. Sending `source` appends a new
    /// version and makes it current; `current_version` (without `source`) rolls back to an earlier
    /// version; name, description, enabled and fga_store_id change in place.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacUpdateBody`]. Returns [`types_ext::AbacPolicy`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::AbacUpdateBody,
        query: &Query,
    ) -> Result<types_ext::AbacPolicy, BackendError> {
        let path = format!("/v1/abac_policies/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/abac_policies/{id}` — Delete an ABAC policy and all its versions.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/abac_policies/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/abac_policies/{id}/versions` — List every saved version of an ABAC policy, newest
    /// first.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AbacVersionsResponse`].
    pub async fn versions(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::AbacVersionsResponse, BackendError> {
        let path = format!("/v1/abac_policies/{}/versions", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/abac_policies/{id}/test` — Run test cases against a policy version (default: the
    /// current one), or against a draft `source` and `tests` sent in the body, without saving
    /// anything. Each test is a request plus the expected decision; the policy is evaluated on its
    /// own, not with the rest of the set. The response also carries `coverage`: which rules and
    /// `when`/`unless` clauses the tests exercised (a clause no test saw both true and false is
    /// listed as a gap), with line numbers.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacTestBody`]. Returns [`types_ext::AbacTestRun`].
    pub async fn test(
        &self,
        id: &str,
        body: &types_ext::AbacTestBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacTestRun, BackendError> {
        let path = format!("/v1/abac_policies/{}/test", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/abac/evaluate` — Policy decision point: ask whether `principal` may perform
    /// `action` on `resource` given `context` (and optional extra `entities` for hierarchy). All
    /// enabled policies are evaluated together with Cedar semantics: a matching forbid wins,
    /// otherwise a matching permit allows, otherwise deny. Each decision is written to the event
    /// feed (type authz.decision), so log streams carry it.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacEvaluateBody`]. Returns [`types_ext::AbacDecision`].
    pub async fn evaluate(
        &self,
        body: &types_ext::AbacEvaluateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacDecision, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/abac/evaluate",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/abac/partial_evaluate` — Partial evaluation (data filtering): ask what is left of
    /// the decision when an entity is unknown. With a known principal, an action and a resource
    /// TYPE, the response is a residual `filter` over the resource attributes (or constant
    /// `true`/`false`) that is equivalent to evaluating the policies on each resource. `unknowns:
    /// \["principal"\]` answers "who may do this on that resource". Relationship conditions
    /// (`fga.check`) are resolved to id lists from the policy’s FGA store unless
    /// `resolve_relations` is false. `output` asks for a ready-made parameterised SQL WHERE (`sql`:
    /// dialect and a field-to-column map) and/or a Prisma where object (`prisma`: a field map).
    /// Policies that build sets from unknown attributes cannot be expressed as a filter and are
    /// refused with a message naming the policy.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacPartialEvaluateBody`]. Returns [`types_ext::AbacResidual`].
    pub async fn partial_evaluate(
        &self,
        body: &types_ext::AbacPartialEvaluateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacResidual, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/abac/partial_evaluate",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/abac/accessible_resources` — List the resources of a type a principal may perform
    /// an action on, paged (`limit`, `starting_after`; the response carries `has_more` and
    /// `next_cursor`). Candidates are the Atlas resources of that type (their metadata are the
    /// attributes) or the `candidates` you send. The policies are reduced to one filter and applied
    /// to every candidate; `method` says whether that worked or each candidate was evaluated in
    /// full.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacAccessibleResourcesBody`]. Returns [`types_ext::AbacResourceList`].
    pub async fn accessible_resources(
        &self,
        body: &types_ext::AbacAccessibleResourcesBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacResourceList, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/abac/accessible_resources",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/abac_policies/{id}/diff` — Compare two versions of a policy: a line diff of the
    /// source and, unless `semantic=false`, the requests whose decision changes. The semantic part
    /// enumerates a bounded set of requests built from the attributes, groups and actions the
    /// policies test (from the entity schema when one is set), and lists those that come out
    /// differently, with newly-allowed and newly-denied counts per action. `exhaustive` says
    /// whether every request in the space was compared or the space was sampled.
    ///
    /// Query parameters: `from`, `to`, `semantic`, `max_requests`, `max_changes`.
    ///
    /// Returns [`types_ext::AbacPolicyDiff`].
    pub async fn diff(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::AbacPolicyDiff, BackendError> {
        let path = format!("/v1/abac_policies/{}/diff", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/abac/diff` — The same comparison for two policy sources you send (a draft against
    /// the saved version, or two templates), without saving anything.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacDiffSourcesBody`]. Returns [`types_ext::AbacPolicyDiff`].
    pub async fn diff_sources(
        &self,
        body: &types_ext::AbacDiffSourcesBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacPolicyDiff, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/abac/diff",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/authzen/access/v1/evaluation` — AuthZEN Access Evaluation: `{subject, resource,
    /// action, context}` → `{decision: boolean}`. Entity types map to PascalCase policy types.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacAuthzenEvaluationBody`]. Returns [`types_ext::AbacAuthzenEvaluationResponse`].
    pub async fn authzen_evaluation(
        &self,
        body: &types_ext::AbacAuthzenEvaluationBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacAuthzenEvaluationResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/authzen/access/v1/evaluation",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/authzen/access/v1/evaluations` — AuthZEN Access Evaluations (batch, up to 100):
    /// shared defaults plus an `evaluations` array, with `options.evaluations_semantic` of
    /// execute_all (default), deny_on_first_deny or permit_on_first_permit.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacAuthzenEvaluationsBody`]. Returns [`types_ext::AbacAuthzenEvaluationsResponse`].
    pub async fn authzen_evaluations(
        &self,
        body: &types_ext::AbacAuthzenEvaluationsBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacAuthzenEvaluationsResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/authzen/access/v1/evaluations",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/authzen/access/v1/search/subject` — AuthZEN Subject Search: which subjects of
    /// `subject.type` may perform `action` on `resource` (give the resource a `type` and `id`).
    /// Answers from the same ABAC policies as an evaluation, reduced once by partial evaluation and
    /// applied to the candidates Atlas knows: your users (type `user`, their public metadata as
    /// attributes) and the users in the FGA stores the policies consult. `page.limit` and
    /// `page.token` page the result; the response carries `page.next_token` (empty on the last
    /// page), `count` and `total`.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacAuthzenSearchSubjectBody`]. Returns [`types_ext::AbacAuthzenSearchSubjectResponse`].
    pub async fn authzen_search_subject(
        &self,
        body: &types_ext::AbacAuthzenSearchSubjectBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacAuthzenSearchSubjectResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/authzen/access/v1/search/subject",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/authzen/access/v1/search/resource` — AuthZEN Resource Search: which resources of
    /// `resource.type` the `subject` may perform `action` on. Candidates are your synced Atlas
    /// resources of that type (their metadata are the attributes) and the objects of that type in
    /// the FGA stores the policies consult. Paged with `page.limit` and `page.token`.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacAuthzenSearchResourceBody`]. Returns [`types_ext::AbacAuthzenSearchResourceResponse`].
    pub async fn authzen_search_resource(
        &self,
        body: &types_ext::AbacAuthzenSearchResourceBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacAuthzenSearchResourceResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/authzen/access/v1/search/resource",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/authzen/access/v1/search/action` — AuthZEN Action Search: which actions the
    /// `subject` may perform on the `resource`. The actions considered are the ones the policies
    /// name (and the entity schema declares), each evaluated in full; the result lists the
    /// permitted action names.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacAuthzenSearchActionBody`]. Returns [`types_ext::AbacAuthzenSearchActionResponse`].
    pub async fn authzen_search_action(
        &self,
        body: &types_ext::AbacAuthzenSearchActionBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacAuthzenSearchActionResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/authzen/access/v1/search/action",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl AbacTemplates<'_> {
    /// `GET /v1/abac_templates` — List the ABAC policy templates, with their slots and how many
    /// links each has.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AbacTemplatesListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::AbacTemplatesListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/abac_templates",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/abac_templates` — Create a policy template: policy source whose scope uses the
    /// slots `?principal` and/or `?resource` (`principal == ?principal`, `resource in ?resource`,
    /// `resource is Doc in ?resource`). Slots are filled by a link. With an entity schema set, the
    /// template is type-checked on save (a slot stands for any entity type).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacTemplatesCreateBody`]. Returns [`types_ext::AbacPolicyTemplate`].
    pub async fn create(
        &self,
        body: &types_ext::AbacTemplatesCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacPolicyTemplate, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/abac_templates",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/abac_templates/{id}` — Read one policy template.
    ///
    /// Returns [`types_ext::AbacPolicyTemplate`].
    pub async fn get(&self, id: &str) -> Result<types_ext::AbacPolicyTemplate, BackendError> {
        let path = format!("/v1/abac_templates/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/abac_templates/{id}` — Change a template. A new `source` bumps `version` and
    /// takes effect on every link at once (`links_updated` counts them). It is refused, with one
    /// error per problem and the link named, if any link could no longer be filled in or would fail
    /// the entity schema.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacTemplatesUpdateBody`]. Returns [`types_ext::AbacPolicyTemplate`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::AbacTemplatesUpdateBody,
        query: &Query,
    ) -> Result<types_ext::AbacPolicyTemplate, BackendError> {
        let path = format!("/v1/abac_templates/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/abac_templates/{id}` — Delete a template. A template with links is refused with
    /// 409 unless `force=true`, which deletes the links too.
    ///
    /// Query parameters: `dry_run`, `force`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/abac_templates/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl AbacLinks<'_> {
    /// `GET /v1/abac_policy_links` — List template links: a template with its slots filled by
    /// entities. Each link’s `source` is what the policy engine evaluates.
    ///
    /// Query parameters: `template_id`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AbacLinksListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::AbacLinksListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/abac_policy_links",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/abac_policy_links` — Link a template to entities. Every slot the template uses
    /// needs its entity (`principal` for `?principal`, `resource` for `?resource`); one it does not
    /// use is refused. The link is evaluated together with the other enabled policies, always from
    /// the template’s current source, and is type-checked against the entity schema when one is
    /// set.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacLinksCreateBody`]. Returns [`types_ext::AbacPolicyLink`].
    pub async fn create(
        &self,
        body: &types_ext::AbacLinksCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacPolicyLink, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/abac_policy_links",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/abac_policy_links/{id}` — Read one template link.
    ///
    /// Returns [`types_ext::AbacPolicyLink`].
    pub async fn get(&self, id: &str) -> Result<types_ext::AbacPolicyLink, BackendError> {
        let path = format!("/v1/abac_policy_links/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/abac_policy_links/{id}` — Rename, enable or disable a link, or point its slots at
    /// other entities.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacLinksUpdateBody`]. Returns [`types_ext::AbacPolicyLink`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::AbacLinksUpdateBody,
        query: &Query,
    ) -> Result<types_ext::AbacPolicyLink, BackendError> {
        let path = format!("/v1/abac_policy_links/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/abac_policy_links/{id}` — Delete a link; the template stays.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/abac_policy_links/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl AbacSchema<'_> {
    /// `GET /v1/abac_schema` — The instance’s ABAC entity schema (`schema` is null and `version` 0
    /// when none is set).
    ///
    /// Returns [`types_ext::AbacSchemaDoc`].
    pub async fn get(&self) -> Result<types_ext::AbacSchemaDoc, BackendError> {
        self.client
            .request(HttpMethod::Get, "/v1/abac_schema", &[], None, None)
            .await
    }
    /// `PUT /v1/abac_schema` — Set the ABAC entity schema: `entity_types` (attributes with
    /// `boolean`, `long`, `string`, `set`, `entity` and `record` types, `required: false` for
    /// optional ones, and `member_of`) and `actions` (`applies_to` principal and resource types and
    /// a `context`). Every problem is reported with its path. Once set, policies and templates are
    /// type-checked when saved: unknown attributes, optional attributes read without a `has` guard,
    /// wrong operand types, unknown entity types and actions, and actions that do not apply to the
    /// policy’s principal and resource types. The response lists the errors the schema would give
    /// the policies and links already stored.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacSchemaSetBody`]. Returns [`types_ext::AbacSchemaDoc`].
    pub async fn set(
        &self,
        body: &types_ext::AbacSchemaSetBody,
        query: &Query,
    ) -> Result<types_ext::AbacSchemaDoc, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/abac_schema",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/abac_schema` — Remove the entity schema; policies are no longer type-checked.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, query: &Query) -> Result<(), BackendError> {
        self.client
            .request(
                HttpMethod::Delete,
                "/v1/abac_schema",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/abac_schema/validate` — Type-check policy (or, with `template: true`, template)
    /// source against the saved schema, or one sent as `schema`, without saving anything. Returns
    /// every issue with its policy number, clause, character offset, line and column. A syntax
    /// error is reported as an issue too.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AbacSchemaValidateBody`]. Returns [`types_ext::AbacValidation`].
    pub async fn validate(
        &self,
        body: &types_ext::AbacSchemaValidateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::AbacValidation, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/abac_schema/validate",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl ResourcesTypes<'_> {
    /// `GET /v1/resource_types` — List the resource types (roles, permissions, parent type).
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::ResourcesTypesListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::ResourcesTypesListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/resource_types",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/resource_types` — Define a resource type: a `key`, its `roles` (each a set of
    /// permissions, optionally `includes` other roles), an optional `parent_type` resources nest
    /// under, and `inherit` (default true) controlling whether assignments on a parent flow down.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ResourcesTypesCreateBody`]. Returns [`types_ext::ResourceType`].
    pub async fn create(
        &self,
        body: &types_ext::ResourcesTypesCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ResourceType, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/resource_types",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/resource_types/{key}` — Read one resource type.
    ///
    /// Returns [`types_ext::ResourceType`].
    pub async fn get(&self, key: &str) -> Result<types_ext::ResourceType, BackendError> {
        let path = format!("/v1/resource_types/{}", seg(key));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/resource_types/{key}` — Change a resource type’s name, roles, parent type or
    /// inheritance.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ResourcesTypesUpdateBody`]. Returns [`types_ext::ResourceType`].
    pub async fn update(
        &self,
        key: &str,
        body: &types_ext::ResourcesTypesUpdateBody,
        query: &Query,
    ) -> Result<types_ext::ResourceType, BackendError> {
        let path = format!("/v1/resource_types/{}", seg(key));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/resource_types/{key}` — Delete a resource type together with its resources and
    /// their role assignments.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, key: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/resource_types/{}", seg(key));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl Resources<'_> {
    /// The `resources / types` operations of the Backend API.
    pub fn types(&self) -> ResourcesTypes<'_> {
        ResourcesTypes {
            client: self.client,
        }
    }
    /// The `resources / assignments` operations of the Backend API.
    pub fn assignments(&self) -> ResourcesAssignments<'_> {
        ResourcesAssignments {
            client: self.client,
        }
    }
    /// `GET /v1/resources` — List resources, optionally filtered by `type` or `parent_id`.
    ///
    /// Query parameters: `type`, `parent_id`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::ResourcesListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::ResourcesListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/resources",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `PUT /v1/resources` — Create or update one resource by `type` + `external_id` (your own id
    /// for it). `parent` is `{id}` or `{type, external_id}` of an existing resource, or null; it
    /// must match the type’s `parent_type`.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ResourcesUpsertBody`]. Returns [`types_ext::Resource`].
    pub async fn upsert(
        &self,
        body: &types_ext::ResourcesUpsertBody,
        query: &Query,
    ) -> Result<types_ext::Resource, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/resources",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `POST /v1/resources/sync` — Discovery sync: upsert up to 500 resources in order (list
    /// parents before children). Idempotent; call it whenever your app creates or moves resources.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ResourcesSyncBody`]. Returns [`types_ext::ResourcesSyncResponse`].
    pub async fn sync(
        &self,
        body: &types_ext::ResourcesSyncBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ResourcesSyncResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/resources/sync",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/resources/{id}` — Read one resource, with its type and parent.
    ///
    /// Returns [`types_ext::Resource`].
    pub async fn get(&self, id: &str) -> Result<types_ext::Resource, BackendError> {
        let path = format!("/v1/resources/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `DELETE /v1/resources/{id}` — Delete a resource and its role assignments. Its children are
    /// detached to the root.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/resources/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/resource_checks` — Does `subject` hold `permission` on `resource`? A user subject
    /// also holds the roles of the organizations they belong to, plus any `groups` ids you pass.
    /// The response lists the grants that allow it.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ResourcesCheckBody`]. Returns [`types_ext::ResourceCheck`].
    pub async fn check(
        &self,
        body: &types_ext::ResourcesCheckBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ResourceCheck, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/resource_checks",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/resource_checks/batch` — Up to 100 resource checks in one call.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ResourcesCheckBatchBody`]. Returns [`types_ext::ResourcesCheckBatchResponse`].
    pub async fn check_batch(
        &self,
        body: &types_ext::ResourcesCheckBatchBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ResourcesCheckBatchResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/resource_checks/batch",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/resource_checks/list` — List the resources of an optional `type` on which
    /// `subject` holds `permission`, paged with `limit` and `starting_after` (the response carries
    /// `has_more` and `next_cursor`).
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ResourcesAccessibleBody`]. Returns [`types_ext::ResourcesAccessibleResponse`].
    pub async fn accessible(
        &self,
        body: &types_ext::ResourcesAccessibleBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ResourcesAccessibleResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/resource_checks/list",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl ResourcesAssignments<'_> {
    /// `GET /v1/resource_role_assignments` — List role assignments, filtered by `resource_id`,
    /// `subject_type` or `subject_id`.
    ///
    /// Query parameters: `resource_id`, `subject_type`, `subject_id`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::ResourcesAssignmentsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::ResourcesAssignmentsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/resource_role_assignments",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/resource_role_assignments` — Assign a `role` on a `resource` to a `subject`
    /// (`{type: user|group|org, id}`). `inherit` (default true) also applies it to the resource’s
    /// descendants. Re-assigning the same role updates `inherit`.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ResourcesAssignmentsAssignBody`]. Returns [`types_ext::ResourceRoleAssignment`].
    pub async fn assign(
        &self,
        body: &types_ext::ResourcesAssignmentsAssignBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ResourceRoleAssignment, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/resource_role_assignments",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `DELETE /v1/resource_role_assignments/{id}` — Revoke a role assignment.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn revoke(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/resource_role_assignments/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl OrgRoleGrants<'_> {
    /// `GET /v1/org_role_grants` — List cross-organization role grants, filtered by grantor_org_id,
    /// grantee_org_id or status=active.
    ///
    /// Query parameters: `grantor_org_id`, `grantee_org_id`, `status`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::OrgRoleGrantsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::OrgRoleGrantsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/org_role_grants",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/org_role_grants` — Let a grantee organization hand out a bounded set of the
    /// grantor organization’s roles (role_keys) to its own members. One active grant per pair.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OrgRoleGrantsCreateBody`]. Returns [`types_ext::OrgRoleGrant`].
    pub async fn create(
        &self,
        body: &types_ext::OrgRoleGrantsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::OrgRoleGrant, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/org_role_grants",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/org_role_grants/{id}` — Fetch one cross-organization role grant.
    ///
    /// Returns [`types_ext::OrgRoleGrant`].
    pub async fn get(&self, id: &str) -> Result<types_ext::OrgRoleGrant, BackendError> {
        let path = format!("/v1/org_role_grants/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/org_role_grants/{id}` — Replace the granted role_keys. Delegations of roles no
    /// longer granted are removed.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OrgRoleGrantsUpdateBody`]. Returns [`types_ext::OrgRoleGrant`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::OrgRoleGrantsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::OrgRoleGrant, BackendError> {
        let path = format!("/v1/org_role_grants/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/org_role_grants/{id}` — Revoke a grant. Every delegation under it stops taking
    /// effect immediately.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::OrgRoleGrant`].
    pub async fn revoke(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::OrgRoleGrant, BackendError> {
        let path = format!("/v1/org_role_grants/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/org_role_grants/{id}/delegations` — List the members holding roles under a grant.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::OrgRoleGrantsListDelegationsResponse`].
    pub async fn list_delegations(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::OrgRoleGrantsListDelegationsResponse, BackendError> {
        let path = format!("/v1/org_role_grants/{}/delegations", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/org_role_grants/{id}/delegations` — Delegate one granted role_key to a member
    /// (user_id) of the grantee organization.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::OrgRoleGrantsDelegateBody`]. Returns [`types_ext::OrgRoleDelegation`].
    pub async fn delegate(
        &self,
        id: &str,
        body: &types_ext::OrgRoleGrantsDelegateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::OrgRoleDelegation, BackendError> {
        let path = format!("/v1/org_role_grants/{}/delegations", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `DELETE /v1/org_role_grants/{id}/delegations/{delegationId}` — Remove a delegation of a
    /// granted role.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn undelegate(
        &self,
        id: &str,
        delegation_id: &str,
        query: &Query,
    ) -> Result<(), BackendError> {
        let path = format!(
            "/v1/org_role_grants/{}/delegations/{}",
            seg(id),
            seg(delegation_id)
        );
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/org_role_grants/effective` — The roles and permissions a user (user_id) holds in a
    /// grantor organization (organization_id, optional) through active delegations.
    ///
    /// Query parameters: `user_id`, `organization_id`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::OrgRoleGrantsEffectiveResponse`].
    pub async fn effective(
        &self,
        query: &Query,
    ) -> Result<types_ext::OrgRoleGrantsEffectiveResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/org_role_grants/effective",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
}

impl Devices<'_> {
    /// `GET /v1/devices` — List registered devices, filtered by user_id or source.
    ///
    /// Query parameters: `user_id`, `source`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::DevicesListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::DevicesListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/devices",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `PUT /v1/devices` — Create or refresh one device by (source, external_id), reporting
    /// managed/compliant posture. Tie it to a user with user_id or a verified user_email. Access
    /// policies read the result through the deviceTrust condition: trusted = a managed, compliant
    /// device reported within 30 days.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::DevicesReportBody`]. Returns [`types_ext::Device`].
    pub async fn report(
        &self,
        body: &types_ext::DevicesReportBody,
        query: &Query,
    ) -> Result<types_ext::Device, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/devices",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `GET /v1/devices/{id}` — Fetch a device and its latest posture.
    ///
    /// Returns [`types_ext::Device`].
    pub async fn get(&self, id: &str) -> Result<types_ext::Device, BackendError> {
        let path = format!("/v1/devices/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `DELETE /v1/devices/{id}` — Remove a device from the registry.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn remove(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/devices/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/device_posture` — Posture ingestion for your MDM/EDR or its relay: up to 500
    /// device reports per call, same fields as PUT /v1/devices.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::DevicesIngestPostureBody`]. Returns [`types_ext::DevicesIngestPostureResponse`].
    pub async fn ingest_posture(
        &self,
        body: &types_ext::DevicesIngestPostureBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::DevicesIngestPostureResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/device_posture",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl AuthzDecisions<'_> {
    /// The `authz_decisions / settings` operations of the Backend API.
    pub fn settings(&self) -> AuthzDecisionsSettings<'_> {
        AuthzDecisionsSettings {
            client: self.client,
        }
    }
    /// `GET /v1/authz_decisions` — Query the authorization decision log, newest first: ABAC,
    /// AuthZEN, FGA-check and access-policy decisions with their redacted input, result, the policy
    /// revision in force and latency. Only decisions that passed sampling are stored.
    ///
    /// Query parameters: `source`, `decision`, `principal`, `action`, `resource`, `policy_revision`, `since`, `until`, `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::AuthzDecisionsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::AuthzDecisionsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/authz_decisions",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/authz_decisions/stats` — Decision counts per engine and outcome over a window (the
    /// last 24 hours by default), with a sampling-corrected estimate of the true volume and latency
    /// percentiles of the recorded decisions.
    ///
    /// Query parameters: `since`, `until`.
    ///
    /// Returns [`types_ext::AuthzDecisionsStatsResponse`].
    pub async fn stats(
        &self,
        query: &Query,
    ) -> Result<types_ext::AuthzDecisionsStatsResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/authz_decisions/stats",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `GET /v1/authz_decisions/{id}` — Read one logged decision.
    ///
    /// Returns [`types_ext::AuthzDecision`].
    pub async fn get(&self, id: &str) -> Result<types_ext::AuthzDecision, BackendError> {
        let path = format!("/v1/authz_decisions/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
}

impl AuthzDecisionsSettings<'_> {
    /// `GET /v1/authz_decision_settings` — How authorization decisions are captured: on or off,
    /// sampling per outcome, how much of each request is kept, redaction paths, event shipping and
    /// retention.
    ///
    /// Returns [`types_ext::AuthzDecisionSettings`].
    pub async fn get(&self) -> Result<types_ext::AuthzDecisionSettings, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/authz_decision_settings",
                &[],
                None,
                None,
            )
            .await
    }
    /// `PUT /v1/authz_decision_settings` — Change how decisions are captured. Fields you omit keep
    /// their value. Capture is off by default; `input_mode` defaults to `ids` (identifiers only) so
    /// nothing personal is stored until you ask for it. With `ship_to_events` each recorded
    /// decision is also an `authz.decision` event for your log streams and webhooks.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::AuthzDecisionsSettingsUpdateBody`]. Returns [`types_ext::AuthzDecisionSettings`].
    pub async fn update(
        &self,
        body: &types_ext::AuthzDecisionsSettingsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::AuthzDecisionSettings, BackendError> {
        self.client
            .request(
                HttpMethod::Put,
                "/v1/authz_decision_settings",
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
}

impl PolicyBundles<'_> {
    /// `GET /v1/policy_bundles/current` — The bundle revision the instance policy is at right now.
    /// Compare it with a deployed bundle’s revision to detect drift.
    ///
    /// Returns [`types_ext::PolicyBundlesCurrentResponse`].
    pub async fn current(&self) -> Result<types_ext::PolicyBundlesCurrentResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/policy_bundles/current",
                &[],
                None,
                None,
            )
            .await
    }
    /// `GET /v1/policy_bundles` — List the signed policy bundles exported or imported on this
    /// instance, newest first (without the archives).
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::PolicyBundlesListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::PolicyBundlesListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/policy_bundles",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/policy_bundles` — Export the instance policy — every ABAC policy (current
    /// version), the ABAC entity schema, templates and template links, and every FGA store’s latest
    /// authorization model — as a versioned tar.gz with a manifest of file digests, signed with the
    /// instance signing key (detached JWS). The same policy always has the same revision.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns [`types_ext::PolicyBundle`].
    pub async fn export(
        &self,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::PolicyBundle, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/policy_bundles",
                &query.as_pairs(),
                None,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/policy_bundles/{revision}` — Read a stored bundle by revision, with the base64
    /// archive and its signature.
    ///
    /// Returns [`types_ext::PolicyBundle`].
    pub async fn get(&self, revision: &str) -> Result<types_ext::PolicyBundle, BackendError> {
        let path = format!("/v1/policy_bundles/{}", seg(revision));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `GET /v1/policy_bundles/{revision}/archive` — Download a stored bundle as the raw tar.gz
    /// (`application/gzip`). The detached signature is in the `Atlas-Bundle-Signature` header, with
    /// `Atlas-Bundle-Revision` and `Atlas-Bundle-Key-Id`.
    ///
    /// Returns the raw `application/gzip` response body bytes.
    pub async fn archive(&self, revision: &str) -> Result<Vec<u8>, BackendError> {
        let path = format!("/v1/policy_bundles/{}/archive", seg(revision));
        self.client
            .request_raw_bytes(HttpMethod::Get, &path, &[], None)
            .await
    }
    /// `POST /v1/policy_bundles/verify` — Check a bundle without importing it: the detached
    /// signature against this instance's signing keys (plus any `trusted_jwks` you supply) and the
    /// archive's integrity. The SDK can do the same check offline.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::PolicyBundlesVerifyBody`]. Returns [`types_ext::PolicyBundlesVerifyResponse`].
    pub async fn verify(
        &self,
        body: &types_ext::PolicyBundlesVerifyBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::PolicyBundlesVerifyResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/policy_bundles/verify",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `POST /v1/policy_bundles/import` — Import a signed bundle. The signature and the archive
    /// integrity must both check out or nothing is touched (422). With `dry_run: true` it returns
    /// the diff of what would change and applies nothing (needs only policy_bundles:read).
    /// Otherwise it applies everything in one transaction: stores and models first, then the ABAC
    /// schema, templates, links and policies; a changed policy appends a version. `prune` also
    /// deletes ABAC policies, templates and links the bundle does not name (and the schema when it
    /// has none); FGA stores are never deleted.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::PolicyBundlesImportBody`]. Returns [`types_ext::PolicyBundlesImportResponse`].
    pub async fn import(
        &self,
        body: &types_ext::PolicyBundlesImportBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::PolicyBundlesImportResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/policy_bundles/import",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl ProxyApps<'_> {
    /// `GET /v1/proxy_apps` — List the identity-aware proxy apps — hostnames protected by the
    /// forward-auth endpoint, with their path rules.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::ProxyAppsListResponse`].
    pub async fn list(
        &self,
        query: &Query,
    ) -> Result<types_ext::ProxyAppsListResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Get,
                "/v1/proxy_apps",
                &query.as_pairs(),
                None,
                None,
            )
            .await
    }
    /// `POST /v1/proxy_apps` — Create a proxy app: a hostname, optional upstream URL, ordered
    /// path/method rules requiring a role, permission or entitlement, public paths, and
    /// header/token injection. The hostname is unique across the deployment.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ProxyAppsCreateBody`]. Returns [`types_ext::ProxyAppsCreateResponse`].
    pub async fn create(
        &self,
        body: &types_ext::ProxyAppsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::ProxyAppsCreateResponse, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/proxy_apps",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/proxy_apps/{id}` — Read one identity-aware proxy app.
    ///
    /// Returns [`types_ext::ProxyAppsGetResponse`].
    pub async fn get(&self, id: &str) -> Result<types_ext::ProxyAppsGetResponse, BackendError> {
        let path = format!("/v1/proxy_apps/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/proxy_apps/{id}` — Update a proxy app. Omitted fields keep their value.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::ProxyAppsUpdateBody`]. Returns [`types_ext::ProxyAppsUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::ProxyAppsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::ProxyAppsUpdateResponse, BackendError> {
        let path = format!("/v1/proxy_apps/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/proxy_apps/{id}` — Delete a proxy app. Its hostname stops resolving at the
    /// forward-auth endpoint.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/proxy_apps/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl McpGateways<'_> {
    /// The `mcp_gateways / budgets` operations of the Backend API.
    pub fn budgets(&self) -> McpGatewaysBudgets<'_> {
        McpGatewaysBudgets {
            client: self.client,
        }
    }
    /// `GET /v1/mcp_gateways` — List the MCP tool gateways of the instance.
    ///
    /// Returns the response JSON (the API documents it as open-ended).
    pub async fn list(&self) -> Result<Value, BackendError> {
        self.client
            .request(HttpMethod::Get, "/v1/mcp_gateways", &[], None, None)
            .await
    }
    /// `POST /v1/mcp_gateways` — Create an MCP gateway: one URL (`url` in the response) that fronts
    /// your MCP server. `tools` maps a tool name to its policy (allow, scopes the agent token must
    /// hold, argument conditions, approval, response masking); `default_policy` (deny by default)
    /// decides tools not listed. upstream_authorization is write-only and sent to the upstream as
    /// its Authorization header.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::McpGatewaysCreateBody`]. Returns the response JSON (the API documents it as open-ended).
    pub async fn create(
        &self,
        body: &types_ext::McpGatewaysCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<Value, BackendError> {
        self.client
            .request(
                HttpMethod::Post,
                "/v1/mcp_gateways",
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/mcp_gateways/{id}` — Read one MCP gateway.
    ///
    /// Returns the response JSON (the API documents it as open-ended).
    pub async fn get(&self, id: &str) -> Result<Value, BackendError> {
        let path = format!("/v1/mcp_gateways/{}", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/mcp_gateways/{id}` — Update an MCP gateway. Omitted fields keep their value;
    /// `tools` is replaced as a whole. `abac` turns on authorization of every tool call through the
    /// ABAC policy engine.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::McpGatewaysUpdateBody`]. Returns the response JSON (the API documents it as open-ended).
    pub async fn update(
        &self,
        id: &str,
        body: &types_ext::McpGatewaysUpdateBody,
        query: &Query,
    ) -> Result<Value, BackendError> {
        let path = format!("/v1/mcp_gateways/{}", seg(id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/mcp_gateways/{id}` — Delete an MCP gateway.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(&self, id: &str, query: &Query) -> Result<(), BackendError> {
        let path = format!("/v1/mcp_gateways/{}", seg(id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl McpGatewaysBudgets<'_> {
    /// `GET /v1/mcp_gateways/{id}/budgets` — The cross-call budgets of a gateway, newest first (at
    /// most 50): ceilings on how many calls, how much cost, or how many calls per window one agent
    /// or one session may make.
    ///
    /// Query parameters: `limit`, `starting_after`.
    ///
    /// Returns [`types_ext::McpGatewaysBudgetsListResponse`].
    pub async fn list(
        &self,
        id: &str,
        query: &Query,
    ) -> Result<types_ext::McpGatewaysBudgetsListResponse, BackendError> {
        let path = format!("/v1/mcp_gateways/{}/budgets", seg(id));
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `POST /v1/mcp_gateways/{id}/budgets` — Add a budget. `metric` is `calls` (a count), `cost`
    /// (the sum of each call's cost: `cost_per_call`, or the number found at `cost_arg` in the call
    /// arguments, such as an amount) or `rate` (calls per `window_seconds`, required). `limit` is
    /// the ceiling. `window_seconds` makes the counter reset in fixed windows; without it a counter
    /// never resets (a per-session one ends with the session). `scope` is `agent` (each agent
    /// counts separately) or `session` (each session of each agent; the client must echo the
    /// `Mcp-Session-Id` from initialize). `agent_id` limits it to one agent and `tool` to one tool.
    /// A call is charged against every budget it touches at once, or against none; only a call that
    /// is allowed and about to run is charged.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::McpGatewaysBudgetsCreateBody`]. Returns [`types_ext::McpGatewaysBudgetsCreateResponse`].
    pub async fn create(
        &self,
        id: &str,
        body: &types_ext::McpGatewaysBudgetsCreateBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::McpGatewaysBudgetsCreateResponse, BackendError> {
        let path = format!("/v1/mcp_gateways/{}/budgets", seg(id));
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
    /// `GET /v1/mcp_gateways/{id}/budgets/{budgetId}` — Read one budget of an MCP gateway.
    ///
    /// Returns [`types_ext::McpGatewaysBudgetsGetResponse`].
    pub async fn get(
        &self,
        id: &str,
        budget_id: &str,
    ) -> Result<types_ext::McpGatewaysBudgetsGetResponse, BackendError> {
        let path = format!("/v1/mcp_gateways/{}/budgets/{}", seg(id), seg(budget_id));
        self.client
            .request(HttpMethod::Get, &path, &[], None, None)
            .await
    }
    /// `PATCH /v1/mcp_gateways/{id}/budgets/{budgetId}` — Change a budget. Omitted fields keep
    /// their value. Raising the limit takes effect on the next call; counters are kept.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::McpGatewaysBudgetsUpdateBody`]. Returns [`types_ext::McpGatewaysBudgetsUpdateResponse`].
    pub async fn update(
        &self,
        id: &str,
        budget_id: &str,
        body: &types_ext::McpGatewaysBudgetsUpdateBody,
        query: &Query,
    ) -> Result<types_ext::McpGatewaysBudgetsUpdateResponse, BackendError> {
        let path = format!("/v1/mcp_gateways/{}/budgets/{}", seg(id), seg(budget_id));
        self.client
            .request(
                HttpMethod::Patch,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                None,
            )
            .await
    }
    /// `DELETE /v1/mcp_gateways/{id}/budgets/{budgetId}` — Delete a budget and stop counting
    /// against it.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Returns nothing (`204 No Content`).
    pub async fn delete(
        &self,
        id: &str,
        budget_id: &str,
        query: &Query,
    ) -> Result<(), BackendError> {
        let path = format!("/v1/mcp_gateways/{}/budgets/{}", seg(id), seg(budget_id));
        self.client
            .request(HttpMethod::Delete, &path, &query.as_pairs(), None, None)
            .await
    }
    /// `GET /v1/mcp_gateways/{id}/budgets/{budgetId}/usage` — What one agent has used of a budget
    /// right now, with the room left and when the window resets. A per-session budget also needs
    /// the `session_id` (the Mcp-Session-Id of that session).
    ///
    /// Query parameters: `agent_id`, `session_id`.
    ///
    /// Returns [`types_ext::McpGatewaysBudgetsUsageResponse`].
    pub async fn usage(
        &self,
        id: &str,
        budget_id: &str,
        query: &Query,
    ) -> Result<types_ext::McpGatewaysBudgetsUsageResponse, BackendError> {
        let path = format!(
            "/v1/mcp_gateways/{}/budgets/{}/usage",
            seg(id),
            seg(budget_id)
        );
        self.client
            .request(HttpMethod::Get, &path, &query.as_pairs(), None, None)
            .await
    }
}

impl InstanceIntegrations<'_> {
    /// `POST /v1/instance/integrations/{product}/events_secret/rotate` — Rotate the signing secret
    /// of the integration's event receiver. The new secret is revealed exactly once. By default
    /// (`overlap_seconds` 0) the old secret stops signing at once. With `overlap_seconds` (at most
    /// 604800 = 7 days) every delivery carries two signatures in `Atlas-Signature` (`v1,&lt;new&gt;
    /// v1,&lt;old&gt;`, the new one first), so the service verifies with either secret while it
    /// deploys the new one; after that only the new secret signs. `previous_secret_expires_at` says
    /// when the old secret stops signing (epoch ms), or null when it already has. Audited as
    /// integration.&lt;id&gt;.events_secret_rotated. 404 when the integration has no event
    /// receiver.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::InstanceIntegrationsRotateEventsSecretBody`]. Returns [`types_ext::InstanceIntegrationsRotateEventsSecretResponse`].
    pub async fn rotate_events_secret(
        &self,
        product: &str,
        body: &types_ext::InstanceIntegrationsRotateEventsSecretBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::InstanceIntegrationsRotateEventsSecretResponse, BackendError> {
        let path = format!(
            "/v1/instance/integrations/{}/events_secret/rotate",
            seg(product)
        );
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl Integrations<'_> {
    /// `POST /v1/integrations/{integration}/card/actions/{action}` — Run a card action.
    /// revoke_sessions signs the user out of every device (their sessions end, back-channel logouts
    /// go out) and is audited with the agent the integration names. Partner link with
    /// sessions:write, or the secret key.
    ///
    /// Query parameters: `dry_run`.
    ///
    /// Takes [`types_ext::IntegrationsRunCardActionBody`]. Returns [`types_ext::IntegrationsRunCardActionResponse`].
    pub async fn run_card_action(
        &self,
        integration: &str,
        action: &str,
        body: &types_ext::IntegrationsRunCardActionBody,
        query: &Query,
        idempotency_key: Option<&str>,
    ) -> Result<types_ext::IntegrationsRunCardActionResponse, BackendError> {
        let path = format!(
            "/v1/integrations/{}/card/actions/{}",
            seg(integration),
            seg(action)
        );
        self.client
            .request(
                HttpMethod::Post,
                &path,
                &query.as_pairs(),
                body_of(body)?,
                idempotency_key,
            )
            .await
    }
}

impl Iga<'_> {
    /// The `iga / entitlements` operations of the Backend API.
    pub fn entitlements(&self) -> IgaEntitlements<'_> {
        IgaEntitlements {
            client: self.client,
        }
    }
    /// The `iga / requests` operations of the Backend API.
    pub fn requests(&self) -> IgaRequests<'_> {
        IgaRequests {
            client: self.client,
        }
    }
    /// The `iga / grants` operations of the Backend API.
    pub fn grants(&self) -> IgaGrants<'_> {
        IgaGrants {
            client: self.client,
        }
    }
    /// The `iga / delegations` operations of the Backend API.
    pub fn delegations(&self) -> IgaDelegations<'_> {
        IgaDelegations {
            client: self.client,
        }
    }
    /// The `iga / sod` operations of the Backend API.
    pub fn sod(&self) -> IgaSod<'_> {
        IgaSod {
            client: self.client,
        }
    }
    /// The `iga / lifecycle` operations of the Backend API.
    pub fn lifecycle(&self) -> IgaLifecycle<'_> {
        IgaLifecycle {
            client: self.client,
        }
    }
    /// The `iga / campaigns` operations of the Backend API.
    pub fn campaigns(&self) -> IgaCampaigns<'_> {
        IgaCampaigns {
            client: self.client,
        }
    }
}

impl Ssf<'_> {
    /// The `ssf / streams` operations of the Backend API.
    pub fn streams(&self) -> SsfStreams<'_> {
        SsfStreams {
            client: self.client,
        }
    }
    /// The `ssf / receivers` operations of the Backend API.
    pub fn receivers(&self) -> SsfReceivers<'_> {
        SsfReceivers {
            client: self.client,
        }
    }
}

impl Instance<'_> {
    /// The `instance / integrations` operations of the Backend API.
    pub fn integrations(&self) -> InstanceIntegrations<'_> {
        InstanceIntegrations {
            client: self.client,
        }
    }
}

impl BackendClient {
    /// The `app_catalog` operations of the Backend API.
    pub fn app_catalog(&self) -> AppCatalog<'_> {
        AppCatalog { client: self }
    }
    /// The `ldap_server_clients` operations of the Backend API.
    pub fn ldap_server_clients(&self) -> LdapServerClients<'_> {
        LdapServerClients { client: self }
    }
    /// The `journeys` operations of the Backend API.
    pub fn journeys(&self) -> Journeys<'_> {
        Journeys { client: self }
    }
    /// The `groups` operations of the Backend API.
    pub fn groups(&self) -> Groups<'_> {
        Groups { client: self }
    }
    /// The `migrations` operations of the Backend API.
    pub fn migrations(&self) -> Migrations<'_> {
        Migrations { client: self }
    }
    /// The `managed_grants` operations of the Backend API.
    pub fn managed_grants(&self) -> ManagedGrants<'_> {
        ManagedGrants { client: self }
    }
    /// The `least_privilege` operations of the Backend API.
    pub fn least_privilege(&self) -> LeastPrivilege<'_> {
        LeastPrivilege { client: self }
    }
    /// The `delivery_health` operations of the Backend API.
    pub fn delivery_health(&self) -> DeliveryHealth<'_> {
        DeliveryHealth { client: self }
    }
    /// The `flags` operations of the Backend API.
    pub fn flags(&self) -> Flags<'_> {
        Flags { client: self }
    }
    /// The `mfa_factors` operations of the Backend API.
    pub fn mfa_factors(&self) -> MfaFactors<'_> {
        MfaFactors { client: self }
    }
    /// The `analytics` operations of the Backend API.
    pub fn analytics(&self) -> Analytics<'_> {
        Analytics { client: self }
    }
    /// The `marketing` operations of the Backend API.
    pub fn marketing(&self) -> Marketing<'_> {
        Marketing { client: self }
    }
    /// The `audit_event_schemas` operations of the Backend API.
    pub fn audit_event_schemas(&self) -> AuditEventSchemas<'_> {
        AuditEventSchemas { client: self }
    }
    /// The `directory_pull_sources` operations of the Backend API.
    pub fn directory_pull_sources(&self) -> DirectoryPullSources<'_> {
        DirectoryPullSources { client: self }
    }
    /// The `relay_agents` operations of the Backend API.
    pub fn relay_agents(&self) -> RelayAgents<'_> {
        RelayAgents { client: self }
    }
    /// The `oauth_client_profiles` operations of the Backend API.
    pub fn oauth_client_profiles(&self) -> OauthClientProfiles<'_> {
        OauthClientProfiles { client: self }
    }
    /// The `passkey_api` operations of the Backend API.
    pub fn passkey_api(&self) -> PasskeyApi<'_> {
        PasskeyApi { client: self }
    }
    /// The `vc` operations of the Backend API.
    pub fn vc(&self) -> Vc<'_> {
        Vc { client: self }
    }
    /// The `listen` operations of the Backend API.
    pub fn listen(&self) -> Listen<'_> {
        Listen { client: self }
    }
    /// The `agent_registration` operations of the Backend API.
    pub fn agent_registration(&self) -> AgentRegistration<'_> {
        AgentRegistration { client: self }
    }
    /// The `agents` operations of the Backend API.
    pub fn agents(&self) -> Agents<'_> {
        Agents { client: self }
    }
    /// The `agent_access_requests` operations of the Backend API.
    pub fn agent_access_requests(&self) -> AgentAccessRequests<'_> {
        AgentAccessRequests { client: self }
    }
    /// The `workflows` operations of the Backend API.
    pub fn workflows(&self) -> Workflows<'_> {
        Workflows { client: self }
    }
    /// The `page_templates` operations of the Backend API.
    pub fn page_templates(&self) -> PageTemplates<'_> {
        PageTemplates { client: self }
    }
    /// The `service_connectors` operations of the Backend API.
    pub fn service_connectors(&self) -> ServiceConnectors<'_> {
        ServiceConnectors { client: self }
    }
    /// The `desktop_mfa` operations of the Backend API.
    pub fn desktop_mfa(&self) -> DesktopMfa<'_> {
        DesktopMfa { client: self }
    }
    /// The `identity_verification` operations of the Backend API.
    pub fn identity_verification(&self) -> IdentityVerification<'_> {
        IdentityVerification { client: self }
    }
    /// The `iga` operations of the Backend API.
    pub fn iga(&self) -> Iga<'_> {
        Iga { client: self }
    }
    /// The `scim_provisioning_presets` operations of the Backend API.
    pub fn scim_provisioning_presets(&self) -> ScimProvisioningPresets<'_> {
        ScimProvisioningPresets { client: self }
    }
    /// The `vault` operations of the Backend API.
    pub fn vault(&self) -> Vault<'_> {
        Vault { client: self }
    }
    /// The `connections` operations of the Backend API.
    pub fn connections(&self) -> Connections<'_> {
        Connections { client: self }
    }
    /// The `ssf` operations of the Backend API.
    pub fn ssf(&self) -> Ssf<'_> {
        Ssf { client: self }
    }
    /// The `network_zones` operations of the Backend API.
    pub fn network_zones(&self) -> NetworkZones<'_> {
        NetworkZones { client: self }
    }
    /// The `access_policies` operations of the Backend API.
    pub fn access_policies(&self) -> AccessPolicies<'_> {
        AccessPolicies { client: self }
    }
    /// The `abac` operations of the Backend API.
    pub fn abac(&self) -> Abac<'_> {
        Abac { client: self }
    }
    /// The `resources` operations of the Backend API.
    pub fn resources(&self) -> Resources<'_> {
        Resources { client: self }
    }
    /// The `org_role_grants` operations of the Backend API.
    pub fn org_role_grants(&self) -> OrgRoleGrants<'_> {
        OrgRoleGrants { client: self }
    }
    /// The `devices` operations of the Backend API.
    pub fn devices(&self) -> Devices<'_> {
        Devices { client: self }
    }
    /// The `authz_decisions` operations of the Backend API.
    pub fn authz_decisions(&self) -> AuthzDecisions<'_> {
        AuthzDecisions { client: self }
    }
    /// The `policy_bundles` operations of the Backend API.
    pub fn policy_bundles(&self) -> PolicyBundles<'_> {
        PolicyBundles { client: self }
    }
    /// The `proxy_apps` operations of the Backend API.
    pub fn proxy_apps(&self) -> ProxyApps<'_> {
        ProxyApps { client: self }
    }
    /// The `mcp_gateways` operations of the Backend API.
    pub fn mcp_gateways(&self) -> McpGateways<'_> {
        McpGateways { client: self }
    }
}
