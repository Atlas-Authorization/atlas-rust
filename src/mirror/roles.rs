//! A local mirror of resource-scoped role assignments, so `can(subject, permission, resource)` is answered
//! with no network call and the SAME inheritance rules as `POST /v1/resource_checks`.
//!
//! It keeps the resource types (roles, `includes`, `inherit`), the resource tree (type, external id, parent)
//! and the role assignments. [`ResourceRoleMirror::sync`] pulls the types and the tree, then consumes
//! `GET /v1/resource_role_assignments/changes` from the stored cursor;
//! [`ResourceRoleMirror::apply_webhook`] applies the `resource_role_assignment.created` / `.deleted` events
//! between syncs. One difference from the server: Atlas adds the user's organizations and groups to the
//! subject itself. Offline you pass them in [`ResourceRoleCheckOptions`].

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use super::{freshness, Freshness, MirrorError, StoreError};
use crate::backend::BackendClient;
use crate::clock::{system_clock, Clock};
use crate::http::HttpMethod;

/// The kind of a subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectKind {
    User,
    Group,
    Org,
}

impl SubjectKind {
    fn as_str(&self) -> &'static str {
        match self {
            SubjectKind::User => "user",
            SubjectKind::Group => "group",
            SubjectKind::Org => "org",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorSubject {
    pub kind: SubjectKind,
    pub id: String,
}

impl MirrorSubject {
    pub fn user(id: impl Into<String>) -> Self {
        MirrorSubject { kind: SubjectKind::User, id: id.into() }
    }
    fn key(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.id)
    }
}

/// A resource reference: the Atlas `id`, or your own `type` + `external_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceRef {
    Id(String),
    External { resource_type: String, external_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourceRoleDef {
    pub key: String,
    /// `*` grants every permission.
    pub permissions: Vec<String>,
    /// Other roles of the same type this role also grants.
    pub includes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirroredResourceType {
    pub key: String,
    pub inherit: bool,
    pub roles: Vec<ResourceRoleDef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirroredResource {
    pub id: String,
    pub resource_type: String,
    pub external_id: String,
    pub parent_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirroredAssignment {
    pub id: String,
    pub resource_id: String,
    /// `user:usr_1`, `group:eng`, `org:org_1`.
    pub subject: String,
    pub role: String,
    pub inherit: bool,
}

/// One entry of the assignment change feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorAssignmentChange {
    /// `true` for created (or an `inherit` update), `false` for deleted.
    pub created: bool,
    pub assignment: MirroredAssignment,
}

pub trait ResourceRoleMirrorStore: Send + Sync {
    fn cursor(&self) -> Result<Option<String>, StoreError>;
    fn set_cursor(&self, cursor: &str) -> Result<(), StoreError>;
    fn get_type(&self, key: &str) -> Result<Option<MirroredResourceType>, StoreError>;
    fn get_resource(&self, r: &ResourceRef) -> Result<Option<MirroredResource>, StoreError>;
    /// Every assignment sitting on any of these resources.
    fn assignments_on(&self, resource_ids: &[String]) -> Result<Vec<MirroredAssignment>, StoreError>;
    /// Replace the whole type registry.
    fn replace_types(&self, types: Vec<MirroredResourceType>) -> Result<(), StoreError>;
    /// Replace the whole resource tree.
    fn replace_resources(&self, resources: Vec<MirroredResource>) -> Result<(), StoreError>;
    /// `created` upserts by assignment id; deleted removes it.
    fn apply_changes(&self, changes: Vec<MirrorAssignmentChange>) -> Result<(), StoreError>;
    fn last_sync_at(&self) -> Result<Option<i64>, StoreError> {
        Ok(None)
    }
    fn set_last_sync_at(&self, at: i64) -> Result<(), StoreError> {
        let _ = at;
        Ok(())
    }
}

#[derive(Default)]
struct MemInner {
    assignments: HashMap<String, MirroredAssignment>,
    resources: HashMap<String, MirroredResource>,
    types: HashMap<String, MirroredResourceType>,
    cursor: Option<String>,
    last_sync_at: Option<i64>,
}

/// An in-memory store, for tests and single-process apps.
#[derive(Default)]
pub struct MemoryResourceRoleMirrorStore(Mutex<MemInner>);

impl MemoryResourceRoleMirrorStore {
    pub fn new() -> Self {
        Self::default()
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MemInner>, StoreError> {
        self.0.lock().map_err(|_| StoreError("lock poisoned".into()))
    }
    /// How many assignments are held.
    pub fn assignment_count(&self) -> usize {
        self.0.lock().map(|g| g.assignments.len()).unwrap_or(0)
    }
}

impl ResourceRoleMirrorStore for MemoryResourceRoleMirrorStore {
    fn cursor(&self) -> Result<Option<String>, StoreError> {
        Ok(self.lock()?.cursor.clone())
    }
    fn set_cursor(&self, c: &str) -> Result<(), StoreError> {
        self.lock()?.cursor = Some(c.to_string());
        Ok(())
    }
    fn get_type(&self, key: &str) -> Result<Option<MirroredResourceType>, StoreError> {
        Ok(self.lock()?.types.get(key).cloned())
    }
    fn get_resource(&self, r: &ResourceRef) -> Result<Option<MirroredResource>, StoreError> {
        let g = self.lock()?;
        Ok(match r {
            ResourceRef::Id(id) => g.resources.get(id).cloned(),
            ResourceRef::External { resource_type, external_id } => {
                g.resources.values().find(|x| &x.resource_type == resource_type && &x.external_id == external_id).cloned()
            }
        })
    }
    fn assignments_on(&self, ids: &[String]) -> Result<Vec<MirroredAssignment>, StoreError> {
        let want: HashSet<&String> = ids.iter().collect();
        Ok(self.lock()?.assignments.values().filter(|a| want.contains(&a.resource_id)).cloned().collect())
    }
    fn replace_types(&self, types: Vec<MirroredResourceType>) -> Result<(), StoreError> {
        self.lock()?.types = types.into_iter().map(|t| (t.key.clone(), t)).collect();
        Ok(())
    }
    fn replace_resources(&self, resources: Vec<MirroredResource>) -> Result<(), StoreError> {
        self.lock()?.resources = resources.into_iter().map(|r| (r.id.clone(), r)).collect();
        Ok(())
    }
    fn apply_changes(&self, changes: Vec<MirrorAssignmentChange>) -> Result<(), StoreError> {
        let mut g = self.lock()?;
        for c in changes {
            if c.created {
                g.assignments.insert(c.assignment.id.clone(), c.assignment);
            } else {
                g.assignments.remove(&c.assignment.id);
            }
        }
        Ok(())
    }
    fn last_sync_at(&self) -> Result<Option<i64>, StoreError> {
        Ok(self.lock()?.last_sync_at)
    }
    fn set_last_sync_at(&self, at: i64) -> Result<(), StoreError> {
        self.lock()?.last_sync_at = Some(at);
        Ok(())
    }
}

/// Settings of a [`ResourceRoleMirror`].
#[derive(Clone, Default)]
pub struct ResourceRoleMirrorOptions {
    /// When set, `check` / `can` answer "not allowed" (`stale`) if the mirror has never completed a `sync()` or
    /// the last one finished longer ago than this. `None` turns the check off (webhook-only mirrors).
    pub max_staleness_ms: Option<u64>,
    /// Keep answering for this many extra ms after `max_staleness_ms`, flagging `stale`.
    pub serve_stale_for_ms: u64,
    pub on_serve_stale: Option<Arc<dyn Fn(Option<i64>, i64) + Send + Sync>>,
    /// Re-pull the types and the tree on a `sync()` only when this long has passed since the last pull
    /// (default 0: every sync).
    pub tree_refresh_ms: u64,
}

/// Organization and group ids the subject belongs to (the server adds these itself).
#[derive(Debug, Clone, Default)]
pub struct ResourceRoleCheckOptions {
    pub orgs: Vec<String>,
    pub groups: Vec<String>,
}

/// One grant behind an allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorGrant {
    pub resource_id: String,
    pub role: String,
    pub subject: String,
    pub inherited: bool,
}

/// The verdict of [`ResourceRoleMirror::check`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourceRoleCheck {
    pub allowed: bool,
    pub resource_id: Option<String>,
    pub grants: Vec<MirrorGrant>,
    /// The mirror does not hold that resource.
    pub unknown_resource: bool,
    /// The mirror is not fresh enough to answer (see `max_staleness_ms`).
    pub stale_refused: bool,
    /// Answered from data past `max_staleness_ms`, inside the grace.
    pub served_stale: bool,
}

// Same cap as the server's ancestor walk.
const MAX_DEPTH: usize = 16;

fn role_permissions(t: &MirroredResourceType, role_key: &str, seen: &mut HashSet<String>) -> HashSet<String> {
    let mut out = HashSet::new();
    if !seen.insert(role_key.to_string()) {
        return out;
    }
    let Some(role) = t.roles.iter().find(|r| r.key == role_key) else { return out };
    out.extend(role.permissions.iter().cloned());
    for inc in &role.includes {
        out.extend(role_permissions(t, inc, seen));
    }
    out
}

/// One link of a resource chain: the resource, its type and the assignments on it.
pub struct ChainLink {
    pub resource_id: String,
    pub resource_type: MirroredResourceType,
    /// `(subject, role key, inherit)`.
    pub assignments: Vec<(String, String, bool)>,
}

/// The server's `resolveResourceGrants`, over a chain of links, the resource first.
pub fn resolve_mirror_grants(chain: &[ChainLink], subjects: &HashSet<String>, permission: &str) -> Vec<MirrorGrant> {
    let mut grants = Vec::new();
    for (i, link) in chain.iter().enumerate() {
        for (subject, role, inherit) in &link.assignments {
            if !subjects.contains(subject) || (i > 0 && !inherit) {
                continue;
            }
            let perms = role_permissions(&link.resource_type, role, &mut HashSet::new());
            if perms.contains(permission) || perms.contains("*") {
                grants.push(MirrorGrant { resource_id: link.resource_id.clone(), role: role.clone(), subject: subject.clone(), inherited: i > 0 });
            }
        }
        // The next link up is only reachable when this resource's type inherits.
        if !link.resource_type.inherit {
            break;
        }
    }
    grants
}

fn str_of(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

fn assignment_of_change(c: &Value) -> Option<MirrorAssignmentChange> {
    let subject = c.get("subject")?;
    Some(MirrorAssignmentChange {
        created: c.get("change").and_then(Value::as_str) != Some("deleted"),
        assignment: MirroredAssignment {
            id: str_of(c, "assignment_id")?,
            resource_id: str_of(c, "resource_id")?,
            subject: format!("{}:{}", str_of(subject, "type")?, str_of(subject, "id")?),
            role: str_of(c, "role")?,
            inherit: c.get("inherit").and_then(Value::as_bool) != Some(false),
        },
    })
}

/// The mirror.
pub struct ResourceRoleMirror {
    store: Arc<dyn ResourceRoleMirrorStore>,
    client: BackendClient,
    opts: ResourceRoleMirrorOptions,
    now: Clock,
    memory_sync_at: Mutex<Option<i64>>,
    tree_at: Mutex<Option<i64>>,
}

impl ResourceRoleMirror {
    pub fn new(store: Arc<dyn ResourceRoleMirrorStore>, client: BackendClient, opts: ResourceRoleMirrorOptions) -> Self {
        ResourceRoleMirror { store, client, opts, now: system_clock(), memory_sync_at: Mutex::new(None), tree_at: Mutex::new(None) }
    }

    /// Inject a clock (epoch ms), for tests.
    pub fn with_clock(mut self, now: Clock) -> Self {
        self.now = now;
        self
    }

    fn now_ms(&self) -> i64 {
        (self.now)() as i64
    }

    /// Epoch ms of the last completed `sync()`; `None`: never.
    pub fn last_sync_at(&self) -> Result<Option<i64>, MirrorError> {
        Ok(self.store.last_sync_at()?.or(*self.memory_sync_at.lock().unwrap()))
    }

    fn chain_of(&self, resource: &MirroredResource) -> Result<Vec<ChainLink>, MirrorError> {
        // The resource, then its ancestors (cycle-safe, depth-capped), exactly like the server. The ancestors
        // dedupe among themselves only, so a cycle yields the start resource once more, as the server's chain does.
        let mut ancestors: Vec<MirroredResource> = Vec::new();
        let mut id = resource.parent_id.clone();
        let mut i = 0;
        while i < MAX_DEPTH {
            let Some(cur) = id.take() else { break };
            let Some(row) = self.store.get_resource(&ResourceRef::Id(cur))? else { break };
            if ancestors.iter().any(|r| r.id == row.id) {
                break;
            }
            id = row.parent_id.clone();
            ancestors.push(row);
            i += 1;
        }
        let mut rows = vec![resource.clone()];
        rows.extend(ancestors);
        let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
        let assignments = self.store.assignments_on(&ids)?;
        rows.iter()
            .map(|r| -> Result<ChainLink, MirrorError> {
                let t = self.store.get_type(&r.resource_type)?;
                Ok(ChainLink {
                    resource_id: r.id.clone(),
                    resource_type: MirroredResourceType {
                        key: r.resource_type.clone(),
                        inherit: t.as_ref().map(|t| t.inherit).unwrap_or(true),
                        roles: t.map(|t| t.roles).unwrap_or_default(),
                    },
                    assignments: assignments.iter().filter(|a| a.resource_id == r.id).map(|a| (a.subject.clone(), a.role.clone(), a.inherit)).collect(),
                })
            })
            .collect()
    }

    /// The verdict and the grants behind it, in the shape of `POST /v1/resource_checks`. Answered locally.
    pub fn check(&self, subject: &MirrorSubject, permission: &str, resource: &ResourceRef, opts: &ResourceRoleCheckOptions) -> Result<ResourceRoleCheck, MirrorError> {
        let mut served_stale = false;
        let last = self.last_sync_at()?;
        match freshness(last, self.now_ms(), self.opts.max_staleness_ms, self.opts.serve_stale_for_ms) {
            Freshness::Fresh => {}
            Freshness::Refuse => return Ok(ResourceRoleCheck { stale_refused: true, ..Default::default() }),
            Freshness::ServedStale { behind_ms } => {
                served_stale = true;
                if let Some(h) = &self.opts.on_serve_stale {
                    h(last, behind_ms);
                }
            }
        }
        let Some(row) = self.store.get_resource(resource)? else {
            return Ok(ResourceRoleCheck { unknown_resource: true, ..Default::default() });
        };
        if permission.is_empty() {
            return Ok(ResourceRoleCheck { resource_id: Some(row.id), ..Default::default() });
        }
        let mut subjects: HashSet<String> = HashSet::new();
        subjects.insert(subject.key());
        subjects.extend(opts.groups.iter().map(|g| format!("group:{g}")));
        subjects.extend(opts.orgs.iter().map(|o| format!("org:{o}")));
        let grants = resolve_mirror_grants(&self.chain_of(&row)?, &subjects, permission);
        Ok(ResourceRoleCheck { allowed: !grants.is_empty(), resource_id: Some(row.id), grants, served_stale, ..Default::default() })
    }

    /// May `subject` hold `permission` on `resource`? Answered locally.
    pub fn can(&self, subject: &MirrorSubject, permission: &str, resource: &ResourceRef, opts: &ResourceRoleCheckOptions) -> Result<bool, MirrorError> {
        Ok(self.check(subject, permission, resource, opts)?.allowed)
    }

    /// Pull the types and the resource tree (when `tree_refresh_ms` has passed), then consume the assignment
    /// change feed from the stored cursor. Call it on a timer and at startup. Returns how many changes it applied.
    pub async fn sync(&self) -> Result<usize, MirrorError> {
        let due = match *self.tree_at.lock().unwrap() {
            None => true,
            Some(t) => self.now_ms() - t >= self.opts.tree_refresh_ms as i64,
        };
        if due {
            // Tree first: an assignment the feed then delivers never names a resource this mirror lacks.
            let types_page = self.client.request_value(HttpMethod::Get, "/v1/resource_types", &[], None).await?;
            let types: Vec<MirroredResourceType> = types_page
                .get("data")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|t| {
                    Some(MirroredResourceType {
                        key: str_of(t, "key")?,
                        inherit: t.get("inherit").and_then(Value::as_bool).unwrap_or(true),
                        roles: t
                            .get("roles")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(|r| {
                                let list = |k: &str| -> Vec<String> { r.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default() };
                                Some(ResourceRoleDef { key: str_of(r, "key")?, permissions: list("permissions"), includes: list("includes") })
                            })
                            .collect(),
                    })
                })
                .collect();
            let mut tree: Vec<MirroredResource> = Vec::new();
            let mut cursor: Option<String> = None;
            loop {
                let mut q: Vec<(&str, String)> = vec![("limit", "1000".into())];
                if let Some(c) = &cursor {
                    q.push(("starting_after", c.clone()));
                }
                let page = self.client.request_value(HttpMethod::Get, "/v1/resources", &q, None).await?;
                for r in page.get("data").and_then(Value::as_array).into_iter().flatten() {
                    if let (Some(id), Some(t), Some(ext)) = (str_of(r, "id"), str_of(r, "type"), str_of(r, "external_id")) {
                        tree.push(MirroredResource { id, resource_type: t, external_id: ext, parent_id: str_of(r, "parent_id") });
                    }
                }
                match (page.get("has_more").and_then(Value::as_bool), str_of(&page, "next_cursor")) {
                    (Some(true), Some(c)) => cursor = Some(c),
                    _ => break,
                }
            }
            self.store.replace_types(types)?;
            self.store.replace_resources(tree)?;
            *self.tree_at.lock().unwrap() = Some(self.now_ms());
        }
        let mut after = self.store.cursor()?;
        let mut applied = 0usize;
        loop {
            let mut q: Vec<(&str, String)> = vec![("limit", "500".into())];
            if let Some(a) = &after {
                q.push(("after", a.clone()));
            }
            let page = self.client.request_value(HttpMethod::Get, "/v1/resource_role_assignments/changes", &q, None).await?;
            let changes: Vec<MirrorAssignmentChange> = page.get("data").and_then(Value::as_array).into_iter().flatten().filter_map(assignment_of_change).collect();
            applied += changes.len();
            self.store.apply_changes(changes)?;
            if let Some(n) = str_of(&page, "next_cursor") {
                self.store.set_cursor(&n)?;
                after = Some(n);
            }
            if page.get("has_more").and_then(Value::as_bool) != Some(true) {
                let at = self.now_ms();
                *self.memory_sync_at.lock().unwrap() = Some(at);
                self.store.set_last_sync_at(at)?;
                return Ok(applied);
            }
        }
    }

    /// Apply a VERIFIED `resource_role_assignment.created` / `.deleted` webhook (check the signature first).
    /// Returns whether the event changed the mirror.
    pub fn apply_webhook(&self, event_type: &str, data: &Value) -> Result<bool, MirrorError> {
        if event_type != "resource_role_assignment.created" && event_type != "resource_role_assignment.deleted" {
            return Ok(false);
        }
        let (Some(id), Some(resource_id), Some(role), Some(st), Some(sid)) = (
            str_of(data, "id"),
            str_of(data, "resource_id"),
            str_of(data, "role"),
            data.get("subject").and_then(|s| str_of(s, "type")),
            data.get("subject").and_then(|s| str_of(s, "id")),
        ) else {
            return Ok(false);
        };
        self.store.apply_changes(vec![MirrorAssignmentChange {
            created: event_type == "resource_role_assignment.created",
            assignment: MirroredAssignment { id, resource_id, subject: format!("{st}:{sid}"), role, inherit: data.get("inherit").and_then(Value::as_bool) != Some(false) },
        }])?;
        Ok(true)
    }
}
