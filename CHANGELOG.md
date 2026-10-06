# Changelog

All notable changes to the `atlasauth` crate are documented here.

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
