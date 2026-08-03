use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

/// Bumped whenever the on-disk layout changes. Stored in `PRAGMA user_version`.
pub const SCHEMA_VERSION: i64 = 2;

/// All DB access goes through one connection behind a mutex. SQLite in WAL
/// mode handles this workload (single-user batches, small rows) without
/// needing a pool.
pub struct Db {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
  pubkey     TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  -- Highest seq ever assigned. Never decreases, so a client cursor stays
  -- meaningful after compaction removes rows below it.
  head       INTEGER NOT NULL DEFAULT 0,
  -- Rows currently stored. Tracked rather than counted because compaction
  -- leaves gaps, which makes MAX(seq) an overcount.
  op_count   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ops (
  pubkey     TEXT    NOT NULL REFERENCES users(pubkey),
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

/// An op as it arrives on the wire. `payload` is base64; it is decoded once at
/// the HTTP boundary so malformed input is rejected rather than stored.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Op {
    pub op_id: String,
    pub collection: String,
    pub record_id: String,
    pub hlc: String,
    /// base64 of nonce || ciphertext.
    pub payload: String,
}

/// An op ready for storage, with the payload as raw bytes.
#[derive(Debug, Clone)]
pub struct StoreOp {
    pub op_id: String,
    pub collection: String,
    pub record_id: String,
    pub hlc: String,
    pub payload: Vec<u8>,
}

impl Op {
    /// Decodes the payload. Clients have historically emitted base64url
    /// without padding, so every common alphabet is accepted on the way in.
    /// Everything is re-emitted as base64url-unpadded on the way out.
    pub fn into_store(self) -> Option<StoreOp> {
        Some(StoreOp {
            op_id: self.op_id,
            collection: self.collection,
            record_id: self.record_id,
            hlc: self.hlc,
            payload: decode_payload(&self.payload)?,
        })
    }
}

pub fn decode_payload(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| STANDARD.decode(s))
        .ok()
}

pub fn encode_payload(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredOp {
    pub seq: i64,
    pub op_id: String,
    pub collection: String,
    pub record_id: String,
    pub hlc: String,
    pub payload: String,
}

pub struct PushResult {
    pub results: Vec<(String, i64)>, // (op_id, seq)
    pub head: i64,
    pub appended: usize,
}

/// Storage ceilings, checked inside the push transaction so concurrent
/// batches cannot race past them.
#[derive(Clone, Copy, Debug)]
pub struct Caps {
    /// Stored ops for the pushing user. 0 disables the check.
    pub max_ops_per_user: i64,
    /// Stored ops across every user. 0 disables the check.
    pub max_total_ops: i64,
    /// Distinct users. Only checked when the push would create one. 0 disables.
    pub max_users: i64,
}

impl Caps {
    pub fn unlimited() -> Self {
        Self {
            max_ops_per_user: 0,
            max_total_ops: 0,
            max_users: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct CompactResult {
    /// Ops removed by this call.
    pub removed: i64,
    /// Ops the user still has stored, across every collection.
    pub remaining: i64,
    /// Unchanged by compaction, and still the pull cursor ceiling.
    pub head: i64,
}

/// Why a push was refused, or the result if it was not.
pub enum PushOutcome {
    Stored(PushResult),
    UserOpCap,
    TotalOpCap,
    UserCap,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// In-memory database, used by tests. Mirrors `open`'s pragmas so tests
    /// exercise the same foreign key behaviour as production.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Append a batch atomically. Existing op_ids are returned with their
    /// stored seq instead of being re-appended. Caps are evaluated inside the
    /// transaction, so two concurrent batches cannot both pass a check that
    /// only one of them fits under.
    pub fn push(&self, pubkey: &str, ops: &[StoreOp], now: i64, caps: Caps) -> Result<PushOutcome> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let existing_user: Option<(i64, i64)> = tx
            .query_row(
                "SELECT head, op_count FROM users WHERE pubkey = ?1",
                params![pubkey],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (mut head, mut op_count) = existing_user.unwrap_or((0, 0));

        if existing_user.is_none() && caps.max_users > 0 {
            let users: i64 = tx.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
            if users >= caps.max_users {
                return Ok(PushOutcome::UserCap);
            }
        }

        // Worst case every op in the batch is new. Checking against that up
        // front keeps the check cheap; a batch of pure duplicates is only
        // ever refused when it is genuinely near the ceiling.
        let incoming = ops.len() as i64;
        if caps.max_ops_per_user > 0 && op_count + incoming > caps.max_ops_per_user {
            return Ok(PushOutcome::UserOpCap);
        }
        if caps.max_total_ops > 0 {
            let total = total_ops(&tx)?;
            if total + incoming > caps.max_total_ops {
                return Ok(PushOutcome::TotalOpCap);
            }
        }

        tx.execute(
            "INSERT OR IGNORE INTO users (pubkey, created_at, head, op_count) VALUES (?1, ?2, 0, 0)",
            params![pubkey, now],
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
                    op_count += 1;
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
        tx.execute(
            "UPDATE users SET head = ?2, op_count = ?3 WHERE pubkey = ?1",
            params![pubkey, head, op_count],
        )?;
        tx.commit()?;
        Ok(PushOutcome::Stored(PushResult {
            results,
            head,
            appended,
        }))
    }

    /// Stored op count for one user. Not the same as `head` once anything has
    /// been compacted away.
    pub fn user_op_count(&self, pubkey: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT op_count FROM users WHERE pubkey = ?1",
                params![pubkey],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    /// Highest seq ever assigned to a user, which is what a pull cursor is
    /// compared against.
    pub fn user_head(&self, pubkey: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .query_row(
                "SELECT head FROM users WHERE pubkey = ?1",
                params![pubkey],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    /// Drops ops that later ops have superseded.
    ///
    /// Within one collection, and only at or below `through`, every record
    /// keeps its highest-`hlc` op and loses the rest. Correctness rests on the
    /// client contract that ops carry full record state: under last-writer-
    /// wins only the newest op per record can ever be applied, so the ones
    /// removed here could not have changed any client's final state. A client
    /// still behind the removed range converges to the same result, having
    /// skipped intermediate values that LWW would have discarded anyway.
    ///
    /// This is wrong for a collection merged as append-only, where every op is
    /// meaningful. Callers scope the request to a collection precisely so an
    /// app that compacts cannot damage one that must not.
    ///
    /// `head` is untouched, so cursors stay valid and no seq is ever reused.
    pub fn compact(&self, pubkey: &str, collection: &str, through: i64) -> Result<CompactResult> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let removed = tx.execute(
            "DELETE FROM ops
             WHERE pubkey = ?1 AND collection = ?2 AND seq <= ?3
               AND seq NOT IN (
                 SELECT seq FROM (
                   SELECT seq, ROW_NUMBER() OVER (
                     PARTITION BY record_id ORDER BY hlc DESC, seq DESC
                   ) AS rn
                   FROM ops
                   WHERE pubkey = ?1 AND collection = ?2 AND seq <= ?3
                 ) WHERE rn = 1
               )",
            params![pubkey, collection, through],
        )? as i64;

        tx.execute(
            "UPDATE users SET op_count = MAX(0, op_count - ?2) WHERE pubkey = ?1",
            params![pubkey, removed],
        )?;

        let (head, remaining): (i64, i64) = tx
            .query_row(
                "SELECT head, op_count FROM users WHERE pubkey = ?1",
                params![pubkey],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or((0, 0));

        tx.commit()?;
        Ok(CompactResult {
            removed,
            remaining,
            head,
        })
    }

    pub fn total_ops(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        total_ops(&conn)
    }

    pub fn user_count(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?)
    }

    pub fn user_exists(&self, pubkey: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM users WHERE pubkey = ?1",
            params![pubkey],
            |r| r.get::<_, i64>(0),
        )? > 0)
    }

    pub fn pull(
        &self,
        pubkey: &str,
        since: i64,
        collection: Option<&str>,
        limit: i64,
    ) -> Result<(Vec<StoredOp>, i64)> {
        let conn = self.conn.lock().unwrap();
        // The stored head, not MAX(seq): compaction can remove the highest
        // row, and a head that moved backwards would make every client's
        // cursor look ahead of the server.
        let head: i64 = conn
            .query_row(
                "SELECT head FROM users WHERE pubkey = ?1",
                params![pubkey],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);

        let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<StoredOp> {
            let payload: Vec<u8> = r.get(5)?;
            Ok(StoredOp {
                seq: r.get(0)?,
                op_id: r.get(1)?,
                collection: r.get(2)?,
                record_id: r.get(3)?,
                hlc: r.get(4)?,
                payload: encode_payload(&payload),
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

/// Total stored ops, summed from the per-user counters rather than counted
/// from `ops`, which makes it O(users) instead of O(ops) and stays correct
/// once compaction has left gaps in the seq space.
fn total_ops(conn: &Connection) -> Result<i64> {
    Ok(
        conn.query_row("SELECT COALESCE(SUM(op_count), 0) FROM users", [], |r| {
            r.get(0)
        })?,
    )
}

fn user_version(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        params![name],
        |r| r.get::<_, i64>(0),
    )? > 0)
}

/// Brings the database up to `SCHEMA_VERSION`.
///
/// A fresh file gets the current schema directly. A v0 file (payloads stored
/// as base64 text, no foreign key on `ops.pubkey`) is rebuilt in one
/// transaction. A payload that fails to decode aborts the migration rather
/// than being written back mangled, because the operator can still recover
/// from a backup at that point.
fn migrate(conn: &Connection) -> Result<()> {
    let mut version = user_version(conn)?;
    if version >= SCHEMA_VERSION {
        return Ok(());
    }

    if !table_exists(conn, "ops")? {
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        return Ok(());
    }

    tracing::info!(
        from = version,
        to = SCHEMA_VERSION,
        "migrating shoal database"
    );

    if version < 1 {
        // Foreign keys cannot be toggled inside a transaction, and the rebuild
        // renames the table the constraint points at.
        conn.pragma_update(None, "foreign_keys", "OFF")?;
        let result = migrate_v0_to_v1(conn);
        conn.pragma_update(None, "foreign_keys", "ON")?;
        result?;
        version = 1;
        conn.pragma_update(None, "user_version", version)?;
    }

    if version < 2 {
        migrate_v1_to_v2(conn)?;
        version = 2;
        conn.pragma_update(None, "user_version", version)?;
    }

    tracing::info!("migration complete");
    Ok(())
}

/// Adds the `head` and `op_count` counters and backfills them from `ops`.
///
/// Before compaction existed both were derivable (`MAX(seq)` was each), so
/// nothing is lost by computing them once here.
fn migrate_v1_to_v2(conn: &Connection) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    let result = (|| -> Result<()> {
        conn.execute_batch(
            "ALTER TABLE users ADD COLUMN head INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE users ADD COLUMN op_count INTEGER NOT NULL DEFAULT 0;",
        )?;
        conn.execute(
            "UPDATE users SET
               head = COALESCE((SELECT MAX(seq) FROM ops WHERE ops.pubkey = users.pubkey), 0),
               op_count = COALESCE((SELECT COUNT(*) FROM ops WHERE ops.pubkey = users.pubkey), 0)",
            [],
        )?;
        Ok(())
    })();

    if let Err(e) = result {
        conn.execute_batch("ROLLBACK").ok();
        bail!("shoal database migration to v2 failed and was rolled back: {e:#}");
    }
    conn.execute_batch("COMMIT")?;
    tracing::info!("added per-user head and op_count counters");
    Ok(())
}

fn migrate_v0_to_v1(conn: &Connection) -> Result<()> {
    conn.execute_batch("BEGIN")?;
    let migrated = (|| -> Result<usize> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
               pubkey     TEXT PRIMARY KEY,
               created_at INTEGER NOT NULL
             )",
        )?;
        // v0 never enforced this relationship, so an ops row could reference a
        // pubkey with no users row. Backfill before the constraint exists.
        conn.execute(
            "INSERT OR IGNORE INTO users (pubkey, created_at)
             SELECT pubkey, MIN(created_at) FROM ops GROUP BY pubkey",
            [],
        )?;

        conn.execute_batch(
            "CREATE TABLE ops_v1 (
               pubkey     TEXT    NOT NULL REFERENCES users(pubkey),
               seq        INTEGER NOT NULL,
               op_id      TEXT    NOT NULL,
               collection TEXT    NOT NULL,
               record_id  TEXT    NOT NULL,
               hlc        TEXT    NOT NULL,
               payload    BLOB    NOT NULL,
               created_at INTEGER NOT NULL,
               PRIMARY KEY (pubkey, seq),
               UNIQUE (pubkey, op_id)
             )",
        )?;

        let mut read = conn.prepare(
            "SELECT pubkey, seq, op_id, collection, record_id, hlc, payload, created_at
             FROM ops ORDER BY pubkey, seq",
        )?;
        let mut write = conn.prepare(
            "INSERT INTO ops_v1 (pubkey, seq, op_id, collection, record_id, hlc, payload, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;

        let mut rows = read.query([])?;
        let mut count = 0usize;
        while let Some(row) = rows.next()? {
            let pubkey: String = row.get(0)?;
            let seq: i64 = row.get(1)?;
            let op_id: String = row.get(2)?;
            let collection: String = row.get(3)?;
            let record_id: String = row.get(4)?;
            let hlc: String = row.get(5)?;
            let created_at: i64 = row.get(7)?;

            // v0 bound payload as a Rust String, so every row reads back as
            // text. A blob here means the file was already partly migrated.
            let payload: Vec<u8> = match row.get::<_, String>(6) {
                Ok(text) => decode_payload(&text).with_context(|| {
                    format!(
                        "op {op_id} (user {pubkey}, seq {seq}) has an undecodable base64 payload"
                    )
                })?,
                Err(_) => row.get::<_, Vec<u8>>(6)?,
            };

            write.execute(params![
                pubkey, seq, op_id, collection, record_id, hlc, payload, created_at
            ])?;
            count += 1;
        }
        Ok(count)
    })();

    let migrated = match migrated {
        Ok(n) => n,
        Err(e) => {
            conn.execute_batch("ROLLBACK").ok();
            bail!(
                "shoal database migration failed and was rolled back, the file is unchanged: {e:#}"
            );
        }
    };

    conn.execute_batch(
        "DROP TABLE ops;
         ALTER TABLE ops_v1 RENAME TO ops;
         CREATE INDEX IF NOT EXISTS ops_pull ON ops (pubkey, collection, seq);
         COMMIT",
    )?;
    tracing::info!(ops = migrated, "rewrote payloads as blobs");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(id: &str, payload: &[u8]) -> StoreOp {
        StoreOp {
            op_id: id.into(),
            collection: "mnemonic".into(),
            record_id: "card/1".into(),
            hlc: "000000000001-0000-00000001".into(),
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn payload_round_trips_as_bytes() {
        let db = Db::open_in_memory().unwrap();
        let raw = vec![0u8, 1, 2, 250, 251, 255];
        db.push("alice", &[op("a", &raw)], 1, Caps::unlimited())
            .unwrap();
        let (ops, _) = db.pull("alice", 0, None, 10).unwrap();
        assert_eq!(decode_payload(&ops[0].payload).unwrap(), raw);
    }

    #[test]
    fn user_op_count_matches_pushed_ops() {
        let db = Db::open_in_memory().unwrap();
        let batch: Vec<_> = (0..5).map(|i| op(&format!("op{i}"), b"x")).collect();
        db.push("alice", &batch, 1, Caps::unlimited()).unwrap();
        assert_eq!(db.user_op_count("alice").unwrap(), 5);
        assert_eq!(db.total_ops().unwrap(), 5);
        // Re-pushing the same batch is idempotent and must not inflate counts.
        db.push("alice", &batch, 1, Caps::unlimited()).unwrap();
        assert_eq!(db.user_op_count("alice").unwrap(), 5);
    }

    #[test]
    fn caps_refuse_before_writing_anything() {
        let db = Db::open_in_memory().unwrap();
        let caps = Caps {
            max_ops_per_user: 2,
            max_total_ops: 0,
            max_users: 0,
        };
        db.push("alice", &[op("a", b"x"), op("b", b"x")], 1, caps)
            .unwrap();
        assert!(matches!(
            db.push("alice", &[op("c", b"x")], 1, caps).unwrap(),
            PushOutcome::UserOpCap
        ));
        assert_eq!(db.user_op_count("alice").unwrap(), 2);
    }

    #[test]
    fn user_cap_blocks_new_users_only() {
        let db = Db::open_in_memory().unwrap();
        let caps = Caps {
            max_ops_per_user: 0,
            max_total_ops: 0,
            max_users: 1,
        };
        db.push("alice", &[op("a", b"x")], 1, caps).unwrap();
        assert!(matches!(
            db.push("bob", &[op("b", b"x")], 1, caps).unwrap(),
            PushOutcome::UserCap
        ));
        // Alice already exists, so she is unaffected by the user ceiling.
        assert!(matches!(
            db.push("alice", &[op("c", b"x")], 1, caps).unwrap(),
            PushOutcome::Stored(_)
        ));
    }

    #[test]
    fn total_op_cap_spans_users() {
        let db = Db::open_in_memory().unwrap();
        let caps = Caps {
            max_ops_per_user: 0,
            max_total_ops: 2,
            max_users: 0,
        };
        db.push("alice", &[op("a", b"x")], 1, caps).unwrap();
        db.push("bob", &[op("b", b"x")], 1, caps).unwrap();
        assert!(matches!(
            db.push("carol", &[op("c", b"x")], 1, caps).unwrap(),
            PushOutcome::TotalOpCap
        ));
    }

    fn op_at(id: &str, record: &str, hlc: &str) -> StoreOp {
        StoreOp {
            op_id: id.into(),
            collection: "mnemonic".into(),
            record_id: record.into(),
            hlc: hlc.into(),
            payload: b"x".to_vec(),
        }
    }

    #[test]
    fn compaction_keeps_the_newest_op_per_record() {
        let db = Db::open_in_memory().unwrap();
        db.push(
            "alice",
            &[
                op_at("a", "card/1", "0001"),
                op_at("b", "card/1", "0002"),
                op_at("c", "card/1", "0003"),
                op_at("d", "card/2", "0001"),
            ],
            1,
            Caps::unlimited(),
        )
        .unwrap();

        let r = db.compact("alice", "mnemonic", 4).unwrap();
        assert_eq!(r.removed, 2, "two superseded card/1 ops");
        assert_eq!(r.remaining, 2);

        let (ops, _) = db.pull("alice", 0, None, 100).unwrap();
        let mut kept: Vec<_> = ops
            .iter()
            .map(|o| (o.record_id.as_str(), o.hlc.as_str()))
            .collect();
        kept.sort();
        assert_eq!(kept, vec![("card/1", "0003"), ("card/2", "0001")]);
    }

    #[test]
    fn compaction_never_moves_head_backwards() {
        let db = Db::open_in_memory().unwrap();
        db.push(
            "alice",
            &[op_at("a", "card/1", "0009"), op_at("b", "card/1", "0001")],
            1,
            Caps::unlimited(),
        )
        .unwrap();

        // The highest seq holds the LOWER hlc, so compaction drops the last
        // row written. head must not follow it down, or every client cursor
        // would suddenly look ahead of the server.
        let r = db.compact("alice", "mnemonic", 2).unwrap();
        assert_eq!(r.removed, 1);
        assert_eq!(r.head, 2, "head is the high-water mark, not MAX(seq)");
        assert_eq!(db.user_head("alice").unwrap(), 2);

        let (_, pulled_head) = db.pull("alice", 0, None, 100).unwrap();
        assert_eq!(pulled_head, 2);

        // A later push continues from the old head; no seq is ever reused.
        db.push(
            "alice",
            &[op_at("c", "card/2", "0002")],
            2,
            Caps::unlimited(),
        )
        .unwrap();
        let (ops, _) = db.pull("alice", 2, None, 100).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].seq, 3);
    }

    #[test]
    fn compaction_respects_the_through_watermark() {
        let db = Db::open_in_memory().unwrap();
        db.push(
            "alice",
            &[
                op_at("a", "card/1", "0001"),
                op_at("b", "card/1", "0002"),
                op_at("c", "card/1", "0003"),
            ],
            1,
            Caps::unlimited(),
        )
        .unwrap();

        // Only the first two are in range, so only the first is superseded
        // within it. The op above the watermark is left alone.
        let r = db.compact("alice", "mnemonic", 2).unwrap();
        assert_eq!(r.removed, 1);
        assert_eq!(r.remaining, 2);
    }

    #[test]
    fn compaction_does_not_cross_collections() {
        let db = Db::open_in_memory().unwrap();
        let mut habits = op_at("h1", "day/1", "0001");
        habits.collection = "habits".into();
        let mut habits2 = op_at("h2", "day/1", "0002");
        habits2.collection = "habits".into();

        db.push(
            "alice",
            &[
                op_at("m1", "card/1", "0001"),
                op_at("m2", "card/1", "0002"),
                habits,
                habits2,
            ],
            1,
            Caps::unlimited(),
        )
        .unwrap();

        // An append-only collection must survive a neighbour compacting.
        let r = db.compact("alice", "mnemonic", 4).unwrap();
        assert_eq!(r.removed, 1);
        let (ops, _) = db.pull("alice", 0, Some("habits"), 100).unwrap();
        assert_eq!(ops.len(), 2, "the other collection is untouched");
    }

    #[test]
    fn compaction_does_not_touch_other_users() {
        let db = Db::open_in_memory().unwrap();
        db.push(
            "alice",
            &[op_at("a1", "card/1", "0001"), op_at("a2", "card/1", "0002")],
            1,
            Caps::unlimited(),
        )
        .unwrap();
        db.push(
            "bob",
            &[op_at("b1", "card/1", "0001"), op_at("b2", "card/1", "0002")],
            1,
            Caps::unlimited(),
        )
        .unwrap();

        db.compact("alice", "mnemonic", 100).unwrap();
        assert_eq!(db.user_op_count("alice").unwrap(), 1);
        assert_eq!(db.user_op_count("bob").unwrap(), 2);
    }

    #[test]
    fn op_count_tracks_compaction_so_caps_stay_honest() {
        let db = Db::open_in_memory().unwrap();
        let caps = Caps {
            max_ops_per_user: 3,
            max_total_ops: 0,
            max_users: 0,
        };
        db.push(
            "alice",
            &[
                op_at("a", "card/1", "0001"),
                op_at("b", "card/1", "0002"),
                op_at("c", "card/1", "0003"),
            ],
            1,
            caps,
        )
        .unwrap();
        // At the ceiling: nothing more fits.
        assert!(matches!(
            db.push("alice", &[op_at("d", "card/2", "0004")], 1, caps)
                .unwrap(),
            PushOutcome::UserOpCap
        ));

        // Compaction frees real room, and the cap must notice. Counting by
        // MAX(seq) would still read 3 here and refuse forever.
        db.compact("alice", "mnemonic", 3).unwrap();
        assert_eq!(db.user_op_count("alice").unwrap(), 1);
        assert_eq!(db.total_ops().unwrap(), 1);
        assert!(matches!(
            db.push("alice", &[op_at("d", "card/2", "0004")], 1, caps)
                .unwrap(),
            PushOutcome::Stored(_)
        ));
    }

    #[test]
    fn compacting_twice_is_a_no_op() {
        let db = Db::open_in_memory().unwrap();
        db.push(
            "alice",
            &[op_at("a", "card/1", "0001"), op_at("b", "card/1", "0002")],
            1,
            Caps::unlimited(),
        )
        .unwrap();
        assert_eq!(db.compact("alice", "mnemonic", 2).unwrap().removed, 1);
        assert_eq!(db.compact("alice", "mnemonic", 2).unwrap().removed, 0);
        assert_eq!(db.user_op_count("alice").unwrap(), 1);
    }

    #[test]
    fn a_lagging_client_still_converges_after_compaction() {
        // The property compaction rests on: a client behind the compacted
        // range ends up with the same records as one that saw every op.
        let db = Db::open_in_memory().unwrap();
        db.push(
            "alice",
            &[
                op_at("a", "card/1", "0001"),
                op_at("b", "card/1", "0002"),
                op_at("c", "card/1", "0003"),
                op_at("d", "card/2", "0007"),
            ],
            1,
            Caps::unlimited(),
        )
        .unwrap();

        db.compact("alice", "mnemonic", 4).unwrap();

        // A device that never synced pulls from zero and still sees the
        // winning value for every record.
        let (ops, _) = db.pull("alice", 0, None, 100).unwrap();
        let mut winners: Vec<_> = ops
            .iter()
            .map(|o| (o.record_id.as_str(), o.hlc.as_str()))
            .collect();
        winners.sort();
        assert_eq!(winners, vec![("card/1", "0003"), ("card/2", "0007")]);
    }

    #[test]
    fn migrates_a_v1_database_and_backfills_counters() {
        let dir = std::env::temp_dir().join(format!("shoal-migrate-v1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v1.db");
        let _ = std::fs::remove_file(&path);

        // A v1 file: blob payloads and the foreign key, but no counters.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE users (pubkey TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
                 CREATE TABLE ops (
                   pubkey TEXT NOT NULL REFERENCES users(pubkey), seq INTEGER NOT NULL,
                   op_id TEXT NOT NULL, collection TEXT NOT NULL, record_id TEXT NOT NULL,
                   hlc TEXT NOT NULL, payload BLOB NOT NULL, created_at INTEGER NOT NULL,
                   PRIMARY KEY (pubkey, seq), UNIQUE (pubkey, op_id));
                 INSERT INTO users VALUES ('alice', 1);
                 INSERT INTO ops VALUES ('alice', 1, 'a', 'mnemonic', 'card/1', 'h1', x'01', 1);
                 INSERT INTO ops VALUES ('alice', 2, 'b', 'mnemonic', 'card/1', 'h2', x'02', 1);
                 INSERT INTO ops VALUES ('alice', 3, 'c', 'mnemonic', 'card/2', 'h1', x'03', 1);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        }

        let db = Db::open(&path).unwrap();
        assert_eq!(db.user_head("alice").unwrap(), 3, "head backfilled");
        assert_eq!(db.user_op_count("alice").unwrap(), 3, "count backfilled");
        assert_eq!(db.total_ops().unwrap(), 3);

        // The counters are live, not just backfilled once.
        let r = db.compact("alice", "mnemonic", 3).unwrap();
        assert_eq!(r.removed, 1);
        assert_eq!(db.user_op_count("alice").unwrap(), 2);
        assert_eq!(db.user_head("alice").unwrap(), 3);

        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn migrates_a_v0_database_in_place() {
        let dir = std::env::temp_dir().join(format!("shoal-migrate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v0.db");
        let _ = std::fs::remove_file(&path);

        // Build a v0 file: base64 text payloads, no foreign key, user_version 0.
        let raw = vec![9u8, 8, 7, 255, 0];
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE users (pubkey TEXT PRIMARY KEY, created_at INTEGER NOT NULL);
                 CREATE TABLE ops (
                   pubkey TEXT NOT NULL, seq INTEGER NOT NULL, op_id TEXT NOT NULL,
                   collection TEXT NOT NULL, record_id TEXT NOT NULL, hlc TEXT NOT NULL,
                   payload BLOB NOT NULL, created_at INTEGER NOT NULL,
                   PRIMARY KEY (pubkey, seq), UNIQUE (pubkey, op_id));",
            )
            .unwrap();
            // Deliberately no users row, to exercise the backfill.
            conn.execute(
                "INSERT INTO ops VALUES ('alice', 1, 'a', 'mnemonic', 'card/1', 'h1', ?1, 100)",
                params![encode_payload(&raw)],
            )
            .unwrap();
            assert_eq!(user_version(&conn).unwrap(), 0);
        }

        let db = Db::open(&path).unwrap();
        let (ops, head) = db.pull("alice", 0, None, 10).unwrap();
        assert_eq!(head, 1);
        assert_eq!(decode_payload(&ops[0].payload).unwrap(), raw);
        assert_eq!(db.user_count().unwrap(), 1, "users row was backfilled");

        // Reopening is a no-op once user_version is current.
        drop(db);
        let db = Db::open(&path).unwrap();
        assert_eq!(db.total_ops().unwrap(), 1);

        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}
