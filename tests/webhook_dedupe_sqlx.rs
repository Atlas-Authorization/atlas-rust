//! The SQL dedupe store against an in-memory SQLite database (the Postgres and MySQL statements are the
//! same ones the other Atlas SDKs run; only SQLite is exercisable without a server).
#![cfg(feature = "webhook-dedupe-sqlx")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use atlasauth::webhook_dedupe::sqlx_store::{SqlDialect, SqlxWebhookStore};
use atlasauth::webhook_dedupe::WebhookDedupeStore;
use atlasauth::Clock;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claims_once_expires_and_releases() {
    sqlx::any::install_default_drivers();
    // One connection: every connection to `sqlite::memory:` is its own database.
    let pool = sqlx::any::AnyPoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
    sqlx::query("create table atlas_webhook_seen (key text primary key, expires_at integer not null)").execute(&pool).await.unwrap();

    let now = Arc::new(AtomicU64::new(1_000_000));
    let c = now.clone();
    let clock: Clock = Arc::new(move || c.load(Ordering::SeqCst));
    let store = SqlxWebhookStore::with_clock(pool, SqlDialect::Sqlite, clock);

    assert!(store.set_if_absent("evt_1", 60).unwrap(), "first claim wins");
    assert!(!store.set_if_absent("evt_1", 60).unwrap(), "a retry is a duplicate");
    assert!(store.set_if_absent("evt_2", 60).unwrap(), "another id is independent");

    now.fetch_add(61_000, Ordering::SeqCst);
    assert!(store.set_if_absent("evt_1", 60).unwrap(), "an expired row counts as unseen");

    store.delete("evt_1").unwrap();
    assert!(store.set_if_absent("evt_1", 60).unwrap(), "a released id is claimed again");
}
