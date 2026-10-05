//! Typed user / identity / email helpers.
//!
//! The shapes mirror the Backend API `User` serialization (`email_addresses`,
//! `primary_email_address_id`, `primary_email`) and `atlas-go`'s `User` /
//! `EmailAddress`. The point of the helpers is to answer "what is this user's
//! real email?" correctly — which means treating the `@no-email.invalid`
//! placeholder, seeded for an OAuth provider that shares no email, as *no real
//! email* rather than a usable address.

use serde::Deserialize;
use serde_json::{Map, Value};

/// The domain Atlas appends when a provider shares no email: the address is
/// shaped `"<provider>-<provider_user_id>@no-email.invalid"`. It is never a
/// deliverable address and must never be shown to a user or used as an identity.
pub const NO_EMAIL_SENTINEL_DOMAIN: &str = "@no-email.invalid";

/// Returns `Some(email)` when `email` is a real address, or `None` when it is
/// empty or the `@no-email.invalid` placeholder. The one function every other
/// email helper funnels through.
pub fn real_email(email: &str) -> Option<&str> {
    if email.is_empty() || email.ends_with(NO_EMAIL_SENTINEL_DOMAIN) {
        None
    } else {
        Some(email)
    }
}

/// A user's email-address record, as the Backend API serializes it.
#[derive(Debug, Clone, Deserialize)]
pub struct EmailAddress {
    #[serde(default)]
    pub id: Option<String>,
    pub email_address: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub primary: bool,
}

impl EmailAddress {
    /// This record's address, or `None` if it is the `@no-email.invalid`
    /// placeholder.
    pub fn real_address(&self) -> Option<&str> {
        real_email(&self.email_address)
    }
}

/// A user as the Backend API serializes it (`GET /v1/users/:id`). `private`/
/// `unsafe` metadata are never part of this surface. Unknown fields are kept in
/// [`User::extra`].
#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub id: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub image_url: Option<String>,
    #[serde(default)]
    pub email_addresses: Vec<EmailAddress>,
    #[serde(default)]
    pub primary_email_address_id: Option<String>,
    /// The primary address as a flat string, as the API provides it. The API
    /// only ever points this at a *verified* primary, so it is never the
    /// `@no-email.invalid` placeholder — but [`User::primary_email`] still
    /// filters it, so the helper is correct even against hand-built values.
    #[serde(default)]
    pub primary_email: Option<String>,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl User {
    /// The user's real primary email, or `None` when they have none worth using
    /// (no addresses, or only the `@no-email.invalid` placeholder).
    ///
    /// Resolution order mirrors how the API composes the user: the flat
    /// `primary_email` first, then `primary_email_address_id` against
    /// `email_addresses`, then the `primary`-flagged address, then the first
    /// address. Whatever resolves is run through [`real_email`], so the
    /// placeholder always comes back as `None`.
    pub fn primary_email(&self) -> Option<&str> {
        if let Some(flat) = self.primary_email.as_deref() {
            return real_email(flat);
        }
        if let Some(id) = &self.primary_email_address_id {
            if let Some(ea) = self
                .email_addresses
                .iter()
                .find(|e| e.id.as_deref() == Some(id.as_str()))
            {
                return ea.real_address();
            }
        }
        self.email_addresses
            .iter()
            .find(|e| e.primary)
            .or_else(|| self.email_addresses.first())
            .and_then(|e| e.real_address())
    }

    /// The user's real email addresses, with the `@no-email.invalid` placeholder
    /// filtered out.
    pub fn real_emails(&self) -> impl Iterator<Item = &str> {
        self.email_addresses.iter().filter_map(|e| e.real_address())
    }

    /// Whether the user has at least one real (non-placeholder) email address.
    pub fn has_real_email(&self) -> bool {
        self.real_emails().next().is_some()
    }
}
