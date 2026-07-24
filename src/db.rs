use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;

/// All DB access goes through one connection behind a mutex. SQLite in WAL
/// mode handles this workload (single-user batches, small rows) without
/// needing a pool.
pub struct Db {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
  pubkey     TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ops (
  pubkey     TEXT    NOT NULL,
  seq        INTEGER NOT NULL,
  op_id      TEXT    NOT NULL,
  collection TEXT    NOT NULL,
  record_id  TEXT    NOT NULL,
  hlc        TEXT    NOT NULL,
  payload    BLOB    NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (pubkey, seq),
  UNIQUE (pubkey, op_id)
);
CREATE INDEX IF NOT EXISTS ops_pull ON ops (pubkey, collection, seq);
"#;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Op {
    pub op_id: String,
    pub collection: String,
    pub record_id: String,
    pub hlc: String,
    /// base64 of nonce || ciphertext
    pub payload: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredOp {
    pub seq: i64,
    #[serde(flatten)]
    pub op: Op,
}

pub struct PushResult {
    pub results: Vec<(String, i64)>, // (op_id, seq)
    pub head: i64,
    pub appended: usize,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// In-memory database, used by tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Append a batch atomically. Existing op_ids are returned with their
    /// stored seq instead of being re-appended.
    pub fn push(&self, pubkey: &str, ops: &[Op], now: i64) -> Result<PushResult> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        tx.execute(
            "INSERT OR IGNORE INTO users (pubkey, created_at) VALUES (?1, ?2)",
            params![pubkey, now],
        )?;

        let mut head: i64 = tx.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM ops WHERE pubkey = ?1",
            params![pubkey],
            |r| r.get(0),
        )?;

        let mut results = Vec::with_capacity(ops.len());
        let mut appended = 0usize;
        for op in ops {
            let existing: Option<i64> = tx
                .query_row(
                    "SELECT seq FROM ops WHERE pubkey = ?1 AND op_id = ?2",
                    params![pubkey, op.op_id],
                    |r| r.get(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    e => Err(e),
                })?;
            let seq = match existing {
                Some(seq) => seq,
                None => {
                    head += 1;
                    appended += 1;
                    tx.execute(
                        "INSERT INTO ops (pubkey, seq, op_id, collection, record_id, hlc, payload, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![pubkey, head, op.op_id, op.collection, op.record_id, op.hlc, op.payload, now],
                    )?;
                    head
                }
            };
            results.push((op.op_id.clone(), seq));
        }
        tx.commit()?;
        Ok(PushResult { results, head, appended })
    }

    pub fn pull(
        &self,
        pubkey: &str,
        since: i64,
        collection: Option<&str>,
        limit: i64,
    ) -> Result<(Vec<StoredOp>, i64)> {
        let conn = self.conn.lock().unwrap();
        let head: i64 = conn.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM ops WHERE pubkey = ?1",
            params![pubkey],
            |r| r.get(0),
        )?;

        let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<StoredOp> {
            Ok(StoredOp {
                seq: r.get(0)?,
                op: Op {
                    op_id: r.get(1)?,
                    collection: r.get(2)?,
                    record_id: r.get(3)?,
                    hlc: r.get(4)?,
                    payload: r.get(5)?,
                },
            })
        };

        let ops = match collection {
            Some(c) => {
                let mut stmt = conn.prepare_cached(
                    "SELECT seq, op_id, collection, record_id, hlc, payload FROM ops
                     WHERE pubkey = ?1 AND collection = ?2 AND seq > ?3
                     ORDER BY seq LIMIT ?4",
                )?;
                let rows = stmt.query_map(params![pubkey, c, since, limit], map_row)?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            }
            None => {
                let mut stmt = conn.prepare_cached(
                    "SELECT seq, op_id, collection, record_id, hlc, payload FROM ops
                     WHERE pubkey = ?1 AND seq > ?2
                     ORDER BY seq LIMIT ?3",
                )?;
                let rows = stmt.query_map(params![pubkey, since, limit], map_row)?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            }
        };
        Ok((ops, head))
    }
}
