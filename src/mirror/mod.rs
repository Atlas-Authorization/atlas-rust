//! Local mirrors of Atlas authorization state, for a request path that must not make a network call
//! (feature `backend`): end-user API keys ([`KeyMirror`]), revoked session ids ([`SidRevocationList`]) and
//! resource-scoped role assignments ([`ResourceRoleMirror`]).
//!
//! Each mirror keeps its data in a small store trait with an in-memory implementation for tests and
//! single-process apps; back it with a table in production. The store traits are synchronous on purpose:
//! a database-backed store should use a pooled blocking connection (or `spawn_blocking`), which keeps the
//! hot-path checks (`verify`, `can`, `is_revoked`) free of `.await`. Atlas stays the minting and revocation
//! backstop, and a `sync()` on a timer (or a verified webhook) brings revocations in.
//!
//! A mirror that has not synced within `max_staleness_ms` refuses to answer (`Stale`) rather than trust
//! data a revocation may not have reached; `serve_stale_for_ms` keeps answering from the last data for a
//! short grace and says so.

mod keys;
mod roles;
mod sid;
mod status_list;

pub use keys::{
    hash_api_key_secret, intersect_scopes_with_permissions, ip_in_allowlist, permission_covers_scope, ApiKeyOrganization,
    InvalidCode, KeyMirror, KeyMirrorOptions, KeyMirrorStore, MemoryKeyMirrorStore, MirrorImport, MirrorVerification,
    MirroredApiKey,
};
pub use roles::{
    resolve_mirror_grants, MemoryResourceRoleMirrorStore, MirrorAssignmentChange, MirrorGrant, MirrorSubject,
    ChainLink, MirroredAssignment, MirroredResource, MirroredResourceType, ResourceRef, ResourceRoleCheck, ResourceRoleCheckOptions,
    ResourceRoleDef, ResourceRoleMirror, ResourceRoleMirrorOptions, ResourceRoleMirrorStore, SubjectKind,
};
pub use sid::{SidListRevocation, SidRevocationList, SidStaleAction};
pub use status_list::{verify_status_list_token, StatusListError, StatusListSource, VerifiedStatusList};

use crate::backend::BackendError;

/// A store failure (a database error, a poisoned lock).
#[derive(Debug, Clone, thiserror::Error)]
#[error("atlas mirror store: {0}")]
pub struct StoreError(pub String);

/// Why a mirror operation failed.
#[derive(Debug, thiserror::Error)]
pub enum MirrorError {
    /// The Atlas call failed (the mirror is unchanged unless the doc says otherwise).
    #[error(transparent)]
    Backend(#[from] BackendError),
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The input was unusable, or Atlas answered a shape the mirror cannot read.
    #[error("atlas mirror: {0}")]
    Invalid(String),
}

/// How fresh a mirror is, for the staleness rule shared by the key and role mirrors.
pub(crate) enum Freshness {
    Fresh,
    /// Past `max_staleness_ms` but inside the grace: answer, flag `stale`, call the hook.
    ServedStale { behind_ms: i64 },
    Refuse,
}

pub(crate) fn freshness(last_sync_at: Option<i64>, now: i64, max_staleness_ms: Option<u64>, serve_stale_for_ms: u64) -> Freshness {
    let Some(max) = max_staleness_ms else { return Freshness::Fresh };
    let Some(last) = last_sync_at else { return Freshness::Refuse };
    let behind = now - last - max as i64;
    if behind <= 0 {
        Freshness::Fresh
    } else if behind > serve_stale_for_ms as i64 {
        Freshness::Refuse
    } else {
        Freshness::ServedStale { behind_ms: behind }
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
