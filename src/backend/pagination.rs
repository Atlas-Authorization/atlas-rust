//! Cursor-pagination helpers.
//!
//! Every cursor-paginated BAPI list returns the same `{ data, has_more,
//! next_cursor }` page and takes a `{ limit?, starting_after? }` query. Rather
//! than bolt an auto-paginator onto every return value — the page is the
//! primitive most callers want — this exposes a free walker a caller opts into,
//! mirroring the TS `paginate`/`collect` and the Java/Go `Pagination` peers.

use serde::de::DeserializeOwned;
use serde::Deserialize;

use super::error::BackendError;

/// The `GET /v1/users`-style cursor page: no total, a boolean `has_more`, and an
/// opaque `next_cursor` to pass back as `starting_after`.
#[derive(Debug, Clone, Deserialize)]
pub struct CursorPage<T> {
    #[serde(default = "Vec::new")]
    pub data: Vec<T>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Common cursor-pagination params. The server clamps `limit` to its own
/// maximum; `starting_after` is an opaque cursor from a prior page's
/// `next_cursor`.
#[derive(Debug, Clone, Default)]
pub struct CursorParams {
    pub limit: Option<u32>,
    pub starting_after: Option<String>,
}

impl CursorParams {
    /// Render as a query list, dropping unset fields. Used by `list` methods.
    pub(crate) fn to_query(&self) -> Vec<(&'static str, String)> {
        let mut q = Vec::new();
        if let Some(limit) = self.limit {
            q.push(("limit", limit.to_string()));
        }
        if let Some(after) = &self.starting_after {
            q.push(("starting_after", after.clone()));
        }
        q
    }
}

/// Walk every page of a cursor-paginated list, collecting all items.
///
/// `fetch` is called with the next cursor (`None` first) and returns one page;
/// the walker follows `next_cursor` until `has_more` is false. Kept as a free
/// function over a closure so it composes with any resource's `list`:
///
/// ```no_run
/// # async fn demo(atlas: &atlasauth::backend::BackendClient) -> Result<(), atlasauth::backend::BackendError> {
/// use atlasauth::backend::{collect, CursorParams};
/// let all_users = collect(|cursor| {
///     let atlas = &atlas;
///     async move {
///         atlas.users().list(CursorParams { starting_after: cursor, ..Default::default() }).await
///     }
/// }).await?;
/// # let _ = all_users; Ok(()) }
/// ```
pub async fn collect<T, F, Fut>(mut fetch: F) -> Result<Vec<T>, BackendError>
where
    T: DeserializeOwned,
    F: FnMut(Option<String>) -> Fut,
    Fut: std::future::Future<Output = Result<CursorPage<T>, BackendError>>,
{
    let mut out = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = fetch(cursor.take()).await?;
        out.extend(page.data);
        match (page.has_more, page.next_cursor) {
            (true, Some(next)) => cursor = Some(next),
            _ => return Ok(out),
        }
    }
}

/// A free-form query string for the list and lookup methods that take filters
/// (`?limit=`, `?status=`, `?user_id=`, …). Build it fluently; pairs are
/// percent-encoded when sent, and a key may repeat (`provider=a&provider=b`).
///
/// ```
/// use atlasauth::backend::Query;
/// let q = Query::new().set("limit", 20).set("status", "pending");
/// assert_eq!(q.len(), 2);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    pairs: Vec<(String, String)>,
}

impl Query {
    /// An empty query.
    pub fn new() -> Self {
        Query::default()
    }

    /// Append `key=value`. Chainable.
    pub fn set(mut self, key: impl Into<String>, value: impl ToString) -> Self {
        self.pairs.push((key.into(), value.to_string()));
        self
    }

    /// Append `key=value` only when `value` is `Some`. Chainable.
    pub fn set_opt<V: ToString>(self, key: impl Into<String>, value: Option<V>) -> Self {
        match value {
            Some(v) => self.set(key, v),
            None => self,
        }
    }

    /// Append `key=value` in place.
    pub fn push(&mut self, key: impl Into<String>, value: impl ToString) {
        self.pairs.push((key.into(), value.to_string()));
    }

    /// The number of pairs.
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// Whether no pair is set.
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// The pairs, in insertion order.
    pub fn pairs(&self) -> &[(String, String)] {
        &self.pairs
    }

    /// Borrowed pairs in the shape the request core takes.
    pub(crate) fn as_pairs(&self) -> Vec<(&str, String)> {
        self.pairs.iter().map(|(k, v)| (k.as_str(), v.clone())).collect()
    }
}

impl From<CursorParams> for Query {
    fn from(p: CursorParams) -> Self {
        let mut q = Query::new();
        for (k, v) in p.to_query() {
            q.push(k, v);
        }
        q
    }
}
