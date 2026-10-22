//! Persistensi SQLite: blok, UTXO set, mempool, dan wallet.
//!
//! Strategi: setiap blok disimpan utuh sebagai JSON, lalu tabel `utxos`
//! dan `mempool` di-sync penuh dalam satu transaksi SQLite — sederhana,
//! bebas bug delta, cukup cepat untuk skala demo/node tunggal.

use std::collections::HashMap;

use rusqlite::{params, Connection};
use serde::Serialize;

use crate::block::Block;
use crate::transaction::{OutPoint, Transaction, Utxo};

/// Baris wallet tersimpan.
#[derive(Serialize)]
pub struct WalletRow {
    pub address: String,
    pub label: Option<String>,
    pub created_at: i64,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Buka (atau buat) database dan pastikan skema siap.
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        // WAL: penulisan tidak memblokir pembaca.
        let _mode: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .map_err(|e| e.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS blocks (
                height INTEGER PRIMARY KEY,
                hash   TEXT NOT NULL UNIQUE,
                raw    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS utxos (
                txid TEXT NOT NULL,
                vout INTEGER NOT NULL,
                raw  TEXT NOT NULL,
                PRIMARY KEY (txid, vout)
            );
            CREATE TABLE IF NOT EXISTS mempool (
                txid TEXT PRIMARY KEY,
                raw  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS wallets (
                address    TEXT PRIMARY KEY,
                secret_hex TEXT NOT NULL UNIQUE,
                label      TEXT,
                created_at INTEGER NOT NULL
            );",
        )
        .map_err(|e| e.to_string())?;
        Ok(Store { conn })
    }

    /// Simpan blok baru + sync UTXO & mempool dalam satu transaksi SQLite.
    pub fn persist_block(
        &mut self,
        height: u64,
        block: &Block,
        utxos: &HashMap<OutPoint, Utxo>,
        mempool: &[Transaction],
    ) -> Result<(), String> {
        let raw = serde_json::to_string(block).map_err(|e| e.to_string())?;
        let tx = self.conn.transaction().map_err(|e| e.to_string())?;

        tx.execute(
            "INSERT OR REPLACE INTO blocks (height, hash, raw) VALUES (?1, ?2, ?3)",
            params![height as i64, block.hash, raw],
        )
        .map_err(|e| e.to_string())?;

        sync_utxos(&tx, utxos)?;
        sync_mempool(&tx, mempool)?;

        tx.commit().map_err(|e| e.to_string())
    }

    /// Persist seluruh state (dipakai saat chain baru pertama kali dibuat).
    pub fn persist_full(
        &mut self,
        blocks: &[Block],
        utxos: &HashMap<OutPoint, Utxo>,
        mempool: &[Transaction],
    ) -> Result<(), String> {
        let tx = self.conn.transaction().map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM blocks", []).map_err(|e| e.to_string())?;
        {
            let mut stmt = tx
                .prepare("INSERT INTO blocks (height, hash, raw) VALUES (?1, ?2, ?3)")
                .map_err(|e| e.to_string())?;
            for (height, block) in blocks.iter().enumerate() {
                let raw = serde_json::to_string(block).map_err(|e| e.to_string())?;
                stmt.execute(params![height as i64, block.hash, raw])
                    .map_err(|e| e.to_string())?;
            }
        }
        sync_utxos(&tx, utxos)?;
        sync_mempool(&tx, mempool)?;
        tx.commit().map_err(|e| e.to_string())
    }

    /// Tambah satu transaksi ke tabel mempool.
    pub fn insert_mempool_tx(&self, tx: &Transaction) -> Result<(), String> {
        let raw = serde_json::to_string(tx).map_err(|e| e.to_string())?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO mempool (txid, raw) VALUES (?1, ?2)",
                params![tx.txid(), raw],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Muat state chain dari database. `None` bila belum ada blok.
    pub fn load(
        &self,
    ) -> Result<Option<(Vec<Block>, Vec<(OutPoint, Utxo)>, Vec<Transaction>)>, String> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        if count == 0 {
            return Ok(None);
        }

        let mut blocks = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT raw FROM blocks ORDER BY height ASC")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| e.to_string())?;
            for row in rows {
                let raw = row.map_err(|e| e.to_string())?;
                let block: Block =
                    serde_json::from_str(&raw).map_err(|e| e.to_string())?;
                blocks.push(block);
            }
        }

        let mut utxos = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT txid, vout, raw FROM utxos")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            for row in rows {
                let (txid, vout, raw) = row.map_err(|e| e.to_string())?;
                let utxo: Utxo =
                    serde_json::from_str(&raw).map_err(|e| e.to_string())?;
                utxos.push((OutPoint::new(&txid, vout as u32), utxo));
            }
        }

        let mut mempool = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT raw FROM mempool")
                .map_err(|e| e.to_string())?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|e| e.to_string())?;
            for row in rows {
                let raw = row.map_err(|e| e.to_string())?;
                let tx: Transaction =
                    serde_json::from_str(&raw).map_err(|e| e.to_string())?;
                mempool.push(tx);
            }
        }

        Ok(Some((blocks, utxos, mempool)))
    }

    /// Simpan wallet (idempoten — address sama tidak diduplikasi).
    pub fn save_wallet(
        &self,
        address: &str,
        secret_hex: &str,
        label: Option<&str>,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO wallets (address, secret_hex, label, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![address, secret_hex, label, crate::block::now()],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Daftar wallet tersimpan (terbaru dulu).
    pub fn list_wallets(&self) -> Result<Vec<WalletRow>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT address, label, created_at FROM wallets ORDER BY created_at DESC")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(WalletRow {
                    address: row.get(0)?,
                    label: row.get(1)?,
                    created_at: row.get(2)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }
}

/// Hapus & tulis ulang tabel UTXO agar identik dengan state.
fn sync_utxos(tx: &rusqlite::Transaction, utxos: &HashMap<OutPoint, Utxo>) -> Result<(), String> {
    tx.execute("DELETE FROM utxos", []).map_err(|e| e.to_string())?;
    let mut stmt = tx
        .prepare("INSERT INTO utxos (txid, vout, raw) VALUES (?1, ?2, ?3)")
        .map_err(|e| e.to_string())?;
    for (op, u) in utxos {
        let raw = serde_json::to_string(u).map_err(|e| e.to_string())?;
        stmt.execute(params![op.txid, op.vout as i64, raw])
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Hapus & tulis ulang tabel mempool agar identik dengan state.
fn sync_mempool(tx: &rusqlite::Transaction, mempool: &[Transaction]) -> Result<(), String> {
    tx.execute("DELETE FROM mempool", []).map_err(|e| e.to_string())?;
    let mut stmt = tx
        .prepare("INSERT INTO mempool (txid, raw) VALUES (?1, ?2)")
        .map_err(|e| e.to_string())?;
    for t in mempool {
        let raw = serde_json::to_string(t).map_err(|e| e.to_string())?;
        stmt.execute(params![t.txid(), raw]).map_err(|e| e.to_string())?;
    }
    Ok(())
}
