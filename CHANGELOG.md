# Changelog

All notable changes to the `atlasauth` crate are documented here.

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
