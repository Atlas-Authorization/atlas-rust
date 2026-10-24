//! Atlas-specific claims on the ID tokens and userinfo of an OIDC relying party:
//! the organization a sign-in was made in (`org_id`, `org_slug`, `org_role`,
//! `org_permissions`), every membership (`orgs`, with the `organizations` scope)
//! and the enterprise SSO connection (`sso_connection_id`, `sso_organization_id`,
//! `sso_connection_type`, `sso_tenant_id`, `sso_issuer`, `sso_domain`). Pass the
//! verified claims of the token.

use serde_json::{Map, Value};

/// The scope that adds the `orgs` membership list to the ID token and userinfo.
pub const OIDC_SCOPE_ORGANIZATIONS: &str = "organizations";
/// The authorize parameter that pins the organization (id or slug) a sign-in is made in.
pub const OIDC_ORGANIZATION_PARAM: &str = "organization";

/// The organization a sign-in was made in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcOrganization {
    pub id: String,
    pub slug: String,
    pub role: String,
    pub permissions: Vec<String>,
}

/// One membership from the `orgs` claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcOrganizationMembership {
    pub id: String,
    pub slug: String,
    pub role: String,
}

/// The enterprise SSO context of a sign-in (the token's `sso_*` claims).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcSsoContext {
    /// `sso_connection_id`: the connection the user signed in through.
    pub connection_id: String,
    /// `sso_organization_id`: the Atlas organization that owns the connection,
    /// or `None` for an instance-wide connection. Independent of the `org_*`
    /// claims: scope a per-organization "require SSO" rule on this, never on
    /// "signed in via SSO".
    pub organization_id: Option<String>,
    /// `sso_connection_type`: `saml` or `oidc` (`None` when absent).
    pub connection_type: Option<String>,
    /// `sso_tenant_id`: the IdP-side tenant, when known.
    pub tenant_id: Option<String>,
    /// `sso_issuer`: the IdP issuer, when known.
    pub issuer: Option<String>,
    /// `sso_domain`: the connection domain matching the user's email.
    pub domain: Option<String>,
}

fn string(claims: &Map<String, Value>, key: &str) -> Option<String> {
    claims.get(key).and_then(Value::as_str).map(str::to_string)
}

/// The organization a sign-in was made in, or `None` when none was involved.
pub fn oidc_organization_of(claims: &Map<String, Value>) -> Option<OidcOrganization> {
    let id = string(claims, "org_id")?;
    Some(OidcOrganization {
        id,
        slug: string(claims, "org_slug").unwrap_or_default(),
        role: string(claims, "org_role").unwrap_or_default(),
        permissions: claims
            .get("org_permissions")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|p| p.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
    })
}

/// Every membership (the `orgs` claim), or `None` when the `organizations`
/// scope was not requested.
pub fn oidc_organizations_of(claims: &Map<String, Value>) -> Option<Vec<OidcOrganizationMembership>> {
    let orgs = claims.get("orgs")?.as_array()?;
    Some(
        orgs.iter()
            .filter_map(|o| {
                let o = o.as_object()?;
                Some(OidcOrganizationMembership {
                    id: string(o, "id")?,
                    slug: string(o, "slug").unwrap_or_default(),
                    role: string(o, "role").unwrap_or_default(),
                })
            })
            .collect(),
    )
}

/// The enterprise SSO connection the user signed in through, or `None`.
pub fn oidc_sso_of(claims: &Map<String, Value>) -> Option<OidcSsoContext> {
    let connection_id = string(claims, "sso_connection_id")?;
    let connection_type = string(claims, "sso_connection_type").filter(|t| t == "saml" || t == "oidc");
    Some(OidcSsoContext {
        connection_id,
        organization_id: string(claims, "sso_organization_id"),
        connection_type,
        tenant_id: string(claims, "sso_tenant_id"),
        issuer: string(claims, "sso_issuer"),
        domain: string(claims, "sso_domain"),
    })
}

/// Add (or replace) the `organization` authorize parameter: the sign-in must be
/// made in that organization (a user who is not a member gets `access_denied`)
/// and the token's `org_*` claims are that organization's.
pub fn oidc_authorize_url_with_organization(authorize_url: &str, organization: &str) -> String {
    let (base, fragment) = match authorize_url.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (authorize_url, None),
    };
    let (path, query) = match base.split_once('?') {
        Some((p, q)) => (p, q),
        None => (base, ""),
    };
    let mut pairs: Vec<String> = query
        .split('&')
        .filter(|p| !p.is_empty() && p.split('=').next() != Some(OIDC_ORGANIZATION_PARAM))
        .map(str::to_string)
        .collect();
    let mut enc = String::new();
    for b in organization.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => enc.push(b as char),
            _ => enc.push_str(&format!("%{b:02X}")),
        }
    }
    pairs.push(format!("{OIDC_ORGANIZATION_PARAM}={enc}"));
    let mut out = format!("{path}?{}", pairs.join("&"));
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(f);
    }
    out
}
