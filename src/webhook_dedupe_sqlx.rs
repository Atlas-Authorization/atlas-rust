//! A [`WebhookDedupeStore`] on SQL through `sqlx` (feature `webhook-dedupe-sqlx`): PostgreSQL, SQLite or
//! MySQL, with the same statements as the other Atlas SDKs. Create the table once:
//!
//! ```text
//! postgres: create table atlas_webhook_seen (key text primary key, expires_at timestamptz not null);
//! sqlite:   create table atlas_webhook_seen (key text primary key, expires_at integer not null);  -- epoch ms
//! mysql:    create table atlas_webhook_seen (`key` varchar(255) primary key, expires_at datetime not null);
//! ```
//!
//! A key whose row has expired counts as unseen and is claimed again. The store trait is synchronous, so
//! each call blocks on the pool: use it from a multi-thread tokio runtime (it parks the worker with
//! `block_in_place`), or from plain synchronous code.
//!
//! ```no_run
//! # async fn demo() -> Result<(), sqlx::Error> {
//! use atlasauth::webhook_dedupe::sqlx_store::{SqlDialect, SqlxWebhookStore};
//! sqlx::any::install_default_drivers();
//! let pool = sqlx::AnyPool::connect("postgres://localhost/app").await?;
//! let store = SqlxWebhookStore::new(pool, SqlDialect::Postgres);
//! # let _ = store; Ok(()) }
//! ```

use std::future::Future;

use sqlx::AnyPool;

use crate::clock::{system_clock, Clock};
use crate::mirror::StoreError;
use crate::webhook_dedupe::WebhookDedupeStore;

/// Which SQL the store speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SqlDialect {
    #[default]
    Postgres,
    Sqlite,
    Mysql,
}

/// The SQL-backed store. Cheap to clone the pool into.
pub struct SqlxWebhookStore {
    pool: AnyPool,
    dialect: SqlDialect,
    handle: tokio::runtime::Handle,
    now: Clock,
}

impl SqlxWebhookStore {
    /// Must be created inside a tokio runtime (it keeps that runtime's handle to run the queries on).
    pub fn new(pool: AnyPool, dialect: SqlDialect) -> Self {
        Self::with_clock(pool, dialect, system_clock())
    }

    /// With an injected clock (epoch ms), used for the SQLite expiry comparison.
    pub fn with_clock(pool: AnyPool, dialect: SqlDialect, now: Clock) -> Self {
        SqlxWebhookStore { pool, dialect, handle: tokio::runtime::Handle::current(), now }
    }

    fn block<T>(&self, fut: impl Future<Output = T>) -> T {
        // shortcut: needs a multi-thread runtime when called from async code, a current-thread one would panic.
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| self.handle.block_on(fut))
        } else {
            self.handle.block_on(fut)
        }
    }
}

fn err(e: sqlx::Error) -> StoreError {
    StoreError(e.to_string())
}

impl WebhookDedupeStore for SqlxWebhookStore {
    fn set_if_absent(&self, key: &str, ttl_seconds: u64) -> Result<bool, StoreError> {
        self.block(async {
            match self.dialect {
                SqlDialect::Sqlite => {
                    let now = (self.now)() as i64;
                    let rows = sqlx::query(
                        "insert into atlas_webhook_seen (key, expires_at) values (?, ?) \
                         on conflict (key) do update set expires_at = excluded.expires_at where atlas_webhook_seen.expires_at <= ? returning key",
                    )
                    .bind(key.to_string())
                    .bind(now + ttl_seconds as i64 * 1000)
                    .bind(now)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(err)?;
                    Ok(!rows.is_empty())
                }
                SqlDialect::Mysql => {
                    sqlx::query("delete from atlas_webhook_seen where `key` = ? and expires_at <= now()")
                        .bind(key.to_string())
                        .execute(&self.pool)
                        .await
                        .map_err(err)?;
                    let res = sqlx::query("insert ignore into atlas_webhook_seen (`key`, expires_at) values (?, now() + interval ? second)")
                        .bind(key.to_string())
                        .bind(ttl_seconds as i64)
                        .execute(&self.pool)
                        .await
                        .map_err(err)?;
                    Ok(res.rows_affected() > 0)
                }
                SqlDialect::Postgres => {
                    let rows = sqlx::query(
                        "insert into atlas_webhook_seen (key, expires_at) values ($1, now() + ($2 || ' seconds')::interval) \
                         on conflict (key) do update set expires_at = excluded.expires_at where atlas_webhook_seen.expires_at <= now() \
                         returning key",
                    )
                    .bind(key.to_string())
                    .bind(ttl_seconds.to_string())
                    .fetch_all(&self.pool)
                    .await
                    .map_err(err)?;
                    Ok(!rows.is_empty())
                }
            }
        })
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        let sql = match self.dialect {
            SqlDialect::Postgres => "delete from atlas_webhook_seen where key = $1",
            SqlDialect::Mysql => "delete from atlas_webhook_seen where `key` = ?",
            SqlDialect::Sqlite => "delete from atlas_webhook_seen where key = ?",
        };
        self.block(async { sqlx::query(sql).bind(key.to_string()).execute(&self.pool).await.map(|_| ()).map_err(err) })
    }
}
