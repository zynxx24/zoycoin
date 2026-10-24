//! Mempool berprioritas: pengganti `Vec<Transaction>` sederhana.
//!
//! Kenapa perlu modul terpisah:
//! 1. **Eviction** — mempool punya batas keras (`MAX_MEMPOOL_TXS`). Tanpa
//!    eviction, spammer bisa membanjiri memori sampai OOM. Di sini transaksi
//!    dengan fee-rate terendah dibuang lebih dulu.
//! 2. **RBF (replace-by-fee)** — pengirim bisa mengganti transaksi yang macet
//!    dengan versi ber-fee lebih tinggi, asalkan semua inputnya sama dan
//!    fee naik minimal `RBF_BUMP_PCT` persen.
//! 3. **Ancestor tracking** — transaksi anak yang bergantung pada induk yang
//!    belum masuk blok harus ikut terbuang saat induknya di-evict, supaya
//!    tidak ada "orphan" yang selamanya menggantung.
//!
//! Semua operasi O(n log n) atau lebih baik; n kecil (< 5000).

use std::collections::{HashMap, HashSet};

use crate::market;
use crate::transaction::{OutPoint, Transaction, Utxo};

/// Fee harus naik minimal 10% agar RBF diterima.
pub const RBF_BUMP_PCT: u64 = 10;

#[derive(Debug, PartialEq, Eq)]
pub enum MempoolError {
    Duplicate(String),
    TooSmall(String),
    BelowMinFee(u64),
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::Duplicate(id) => write!(f, "transaksi {id} sudah ada di mempool"),
            MempoolError::TooSmall(id) => write!(f, "transaksi {id} terlalu kecil untuk masuk mempool"),
            MempoolError::BelowMinFee(r) => write!(f, "fee-rate {r} di bawah minimum relay"),
        }
    }
}

#[derive(Clone)]
pub struct MempoolEntry {
    pub tx: Transaction,
    pub txid: String,
    /// fee-rate per 1000 byte, dihitung saat masuk (cache).
    pub fee_rate: u64,
    /// Semua outpoint yang dikonsumsi transaksi ini.
    pub spends: Vec<OutPoint>,
}

#[derive(Default)]
pub struct Mempool {
    entries: HashMap<String, MempoolEntry>,
    /// outpoint -> txid pemakai. Satu outpoint hanya boleh dipakai sekali.
    spends: HashMap<OutPoint, String>,
    /// jumlah eviction sejak start (metrik).
    evicted: u64,
    replaced: u64,
}

/// Iterator transaksi pending, terurut txid, mendukung arah maju & mundur.
pub struct PendingIter<'a> {
    inner: std::vec::IntoIter<&'a Transaction>,
}

impl<'a> Iterator for PendingIter<'a> {
    type Item = &'a Transaction;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl DoubleEndedIterator for PendingIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back()
    }
}

impl ExactSizeIterator for PendingIter<'_> {}

impl Mempool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn evicted_count(&self) -> u64 {
        self.evicted
    }

    pub fn replaced_count(&self) -> u64 {
        self.replaced
    }

    /// Apakah outpoint sudah dikonsumsi transaksi lain di mempool?
    pub fn is_spent(&self, op: &OutPoint) -> bool {
        self.spends.contains_key(op)
    }

    pub fn get(&self, txid: &str) -> Option<&MempoolEntry> {
        self.entries.get(txid)
    }

    /// Semua outpoint yang terkunci oleh mempool (untuk validasi anti
    /// double-spend di `Chain::submit_transaction`).
    pub fn spent_set(&self) -> HashSet<OutPoint> {
        self.spends.keys().cloned().collect()
    }

    pub fn txids(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// Iterasi transaksi pending (tanpa metadata fee-rate).
    ///
    /// `HashMap::values()` bukan `DoubleEndedIterator` dan urutannya tidak
    /// deterministik. Kita kembalikan `PendingIter` yang memegang `Vec<&Tx>`
    /// terurut txid, sehingga `.rev()` valid dan hasilnya stabil antar run.
    pub fn iter(&self) -> PendingIter<'_> {
        let mut txs: Vec<&Transaction> = self.entries.values().map(|e| &e.tx).collect();
        txs.sort_by(|a, b| a.txid().cmp(&b.txid()));
        PendingIter { inner: txs.into_iter() }
    }

    /// Snapshot transaksi pending untuk persistensi ke disk.
    ///
    /// Diurutkan secara deterministik supaya hasil `persist_*` stabil antar
    /// run (penting untuk replay/test yang membandingkan isi DB).
    pub fn snapshot(&self) -> Vec<Transaction> {
        let mut txs: Vec<Transaction> = self.entries.values().map(|e| e.tx.clone()).collect();
        txs.sort_by(|a, b| a.txid().cmp(&b.txid()));
        txs
    }

    /// Iterasi entri terurut fee-rate menurun (siap dipakai mining).
    pub fn ranked(&self) -> Vec<MempoolEntry> {
        let mut v: Vec<MempoolEntry> = self.entries.values().cloned().collect();
        v.sort_by(|a, b| {
            b.fee_rate
                .cmp(&a.fee_rate)
                .then_with(|| a.txid.cmp(&b.txid)) // tie-break deterministik
        });
        v
    }

    /// Total fee seluruh isi mempool.
    pub fn total_fees(&self) -> u64 {
        self.entries
            .values()
            .map(|e| market::fee_for_rate(e.fee_rate, market::tx_size(&e.tx)))
            .sum()
    }

    /// Masukkan transaksi. Menangani duplikat, RBF, dan eviction.
    ///
    /// `utxos` dipakai untuk menghitung fee (nilai input - nilai output).
    pub fn insert(
        &mut self,
        tx: Transaction,
        utxos: &HashMap<OutPoint, Utxo>,
        max_entries: usize,
    ) -> Result<String, MempoolError> {
        let txid = tx.txid();
        if self.entries.contains_key(&txid) {
            return Err(MempoolError::Duplicate(txid));
        }

        let size = market::tx_size(&tx);
        let fee = market::fee(utxos, &tx);
        let rate = if size == 0 { 0 } else { fee * 1000 / size as u64 };

        if rate < market::MIN_FEE_RATE {
            return Err(MempoolError::BelowMinFee(rate));
        }

        let spends: Vec<OutPoint> = tx
            .inputs
            .iter()
            .map(|i| OutPoint::new(&i.prev_txid, i.prev_vout))
            .collect();

        // --- RBF: cari transaksi lama yang mengonsumsi outpoint sama ---
        let mut conflicts: Vec<String> = Vec::new();
        for op in &spends {
            if let Some(old) = self.spends.get(op) {
                if !conflicts.contains(old) {
                    conflicts.push(old.clone());
                }
            }
        }
        if !conflicts.is_empty() {
            let old_rate = conflicts
                .iter()
                .filter_map(|id| self.entries.get(id))
                .map(|e| e.fee_rate)
                .max()
                .unwrap_or(0);
            // Fee baru harus naik minimal RBF_BUMP_PCT persen.
            let required = old_rate + (old_rate * RBF_BUMP_PCT / 100).max(1);
            if rate < required {
                return Err(MempoolError::TooSmall(format!(
                    "{txid} butuh fee-rate >= {required} untuk menggantikan {}",
                    conflicts.join(",")
                )));
            }
            for id in &conflicts {
                self.remove(id);
                self.replaced += 1;
            }
        }

        // --- Eviction bila penuh: buang fee-rate terendah bila lebih kecil ---
        if max_entries > 0 && self.entries.len() >= max_entries {
            let worst = self
                .entries
                .values()
                .min_by_key(|e| (e.fee_rate, std::cmp::Reverse(e.txid.clone())))
                .map(|e| (e.txid.clone(), e.fee_rate));
            match worst {
                Some((worst_id, worst_rate)) if rate > worst_rate => {
                    self.remove(&worst_id);
                    self.evicted += 1;
                }
                _ => {
                    return Err(MempoolError::TooSmall(format!(
                        "{txid} kalah fee-rate dari isi mempool"
                    )))
                }
            }
        }

        for op in &spends {
            self.spends.insert(op.clone(), txid.clone());
        }
        self.entries.insert(
            txid.clone(),
            MempoolEntry {
                tx,
                txid: txid.clone(),
                fee_rate: rate,
                spends,
            },
        );
        Ok(txid)
    }

    /// Hapus transaksi beserta seluruh turunannya (anak yang memakai outputnya).
    pub fn remove(&mut self, txid: &str) -> Option<MempoolEntry> {
        let entry = self.entries.remove(txid)?;
        for op in &entry.spends {
            self.spends.remove(op);
        }

        // Buang anak-cucu: transaksi yang input-nya menunjuk output txid ini.
        let children: Vec<String> = self
            .entries
            .values()
            .filter(|e| {
                e.tx
                    .inputs
                    .iter()
                    .any(|i| i.prev_txid == txid)
            })
            .map(|e| e.txid.clone())
            .collect();
        for child in children {
            self.remove(&child);
        }

        Some(entry)
    }

    /// Buang semua transaksi yang input-nya sudah tidak ada di UTXO set
    /// (mis. karena blok lain menghabiskannya). Mengembalikan jumlah terbuang.
    pub fn prune_orphans(&mut self, utxos: &HashMap<OutPoint, Utxo>) -> usize {
        let bad: Vec<String> = self
            .entries
            .values()
            .filter(|e| e.spends.iter().any(|op| !utxos.contains_key(op)))
            .map(|e| e.txid.clone())
            .collect();
        let n = bad.len();
        for id in bad {
            self.remove(&id);
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::TxOut;

    fn utxo(value: u64) -> Utxo {
        Utxo {
            value,
            address: "zoy1test".into(),
            height: 1,
            coinbase: false,
        }
    }

    fn tx(prev: &str, vout: u32, out: u64) -> Transaction {
        tx_to(prev, vout, out, "zoy1dest")
    }

    /// Varian `tx` dengan alamat tujuan berbeda, sehingga dua transaksi bisa
    /// punya fee sama tetapi txid berbeda (dibutuhkan untuk uji RBF).
    fn tx_to(prev: &str, vout: u32, out: u64, dest: &str) -> Transaction {
        Transaction::new(
            vec![crate::transaction::TxIn {
                prev_txid: prev.into(),
                prev_vout: vout,
                public_key: "pk".into(),
                signature: "sig".into(),
            }],
            vec![TxOut {
                value: out,
                address: dest.into(),
            }],
        )
    }

    #[test]
    fn rejects_duplicate() {
        let mut mp = Mempool::new();
        let mut u = HashMap::new();
        u.insert(OutPoint::new("a", 0), utxo(10_000));
        let t = tx("a", 0, 9_000);
        let id = t.txid();
        mp.insert(t.clone(), &u, 100).unwrap();
        assert_eq!(mp.insert(t, &u, 100), Err(MempoolError::Duplicate(id)));
    }

    #[test]
    fn evicts_lowest_fee_when_full() {
        let mut mp = Mempool::new();
        let mut u = HashMap::new();
        u.insert(OutPoint::new("a", 0), utxo(10_000));
        u.insert(OutPoint::new("b", 0), utxo(10_000));
        let cheap = tx("a", 0, 9_999); // fee 1
        let rich = tx("b", 0, 5_000); // fee 5000
        mp.insert(cheap.clone(), &u, 1).unwrap();
        let rich_id = rich.txid();
        mp.insert(rich, &u, 1).unwrap();
        assert_eq!(mp.len(), 1);
        assert!(mp.get(&rich_id).is_some());
        assert!(mp.get(&cheap.txid()).is_none());
        assert_eq!(mp.evicted_count(), 1);
    }

    #[test]
    fn rbf_requires_higher_fee() {
        let mut mp = Mempool::new();
        let mut u = HashMap::new();
        u.insert(OutPoint::new("a", 0), utxo(10_000));
        let low = tx("a", 0, 9_000); // fee 1000
        mp.insert(low, &u, 100).unwrap();
        // Fee sama tapi isi berbeda (txid beda) -> ditolak karena tidak ada
        // kenaikan fee-rate yang cukup untuk RBF.
        let same = tx_to("a", 0, 9_000, "zoy1other");
        assert_ne!(same.txid(), tx("a", 0, 9_000).txid());
        // Fee sama, isi beda -> harus ditolak (bukan penggantian sah).
        assert!(matches!(
            mp.insert(same, &u, 100),
            Err(MempoolError::TooSmall(_))
        ));
        // Fee jauh lebih tinggi -> diterima, menggantikan yang lama.
        let high = tx("a", 0, 1_000);
        mp.insert(high, &u, 100).unwrap();
        assert_eq!(mp.len(), 1);
        assert_eq!(mp.replaced_count(), 1);
    }

    #[test]
    fn remove_cascades_to_children() {
        let mut mp = Mempool::new();
        let mut u = HashMap::new();
        u.insert(OutPoint::new("root", 0), utxo(10_000));
        let parent = tx("root", 0, 9_000);
        let parent_id = parent.txid();
        mp.insert(parent, &u, 100).unwrap();

        u.insert(OutPoint::new(&parent_id, 0), utxo(9_000));
        let child = tx(&parent_id, 0, 8_000);
        mp.insert(child, &u, 100).unwrap();
        assert_eq!(mp.len(), 2);

        mp.remove(&parent_id);
        assert_eq!(mp.len(), 0, "anak harus ikut terbuang");
    }

    #[test]
    fn ranked_is_fee_desc() {
        let mut mp = Mempool::new();
        let mut u = HashMap::new();
        u.insert(OutPoint::new("a", 0), utxo(10_000));
        u.insert(OutPoint::new("b", 0), utxo(10_000));
        mp.insert(tx("a", 0, 9_999), &u, 100).unwrap();
        mp.insert(tx("b", 0, 1_000), &u, 100).unwrap();
        let r = mp.ranked();
        assert!(r[0].fee_rate >= r[1].fee_rate);
    }

    #[test]
    fn empty_and_len_track_inserts() {
        let mut mp = Mempool::new();
        assert!(mp.is_empty());
        let mut u = HashMap::new();
        u.insert(OutPoint::new("a", 0), utxo(10_000));
        mp.insert(tx("a", 0, 9_000), &u, 100).unwrap();
        assert!(!mp.is_empty());
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn is_spent_reflects_mempool_locks() {
        let mut mp = Mempool::new();
        let mut u = HashMap::new();
        let op = OutPoint::new("a", 0);
        u.insert(op.clone(), utxo(10_000));
        assert!(!mp.is_spent(&op));
        mp.insert(tx("a", 0, 9_000), &u, 100).unwrap();
        assert!(mp.is_spent(&op));
    }

    #[test]
    fn total_fees_sums_entries() {
        let mut mp = Mempool::new();
        let mut u = HashMap::new();
        u.insert(OutPoint::new("a", 0), utxo(10_000));
        u.insert(OutPoint::new("b", 0), utxo(10_000));
        mp.insert(tx("a", 0, 9_000), &u, 100).unwrap(); // fee 1000
        mp.insert(tx("b", 0, 9_500), &u, 100).unwrap(); // fee 500
        let total = mp.total_fees();
        assert!(total > 0, "total fee harus positif");
        // Fee dihitung lewat market::fee_for_rate, jadi nilainya <= fee mentah.
        assert!(total <= 1_500);
    }

    #[test]
    fn prune_orphans_drops_missing_inputs() {
        let mut mp = Mempool::new();
        let mut u = HashMap::new();
        u.insert(OutPoint::new("a", 0), utxo(10_000));
        mp.insert(tx("a", 0, 9_000), &u, 100).unwrap();
        assert_eq!(mp.len(), 1);

        // UTXO set kosong -> input transaksi hilang -> harus dipangkas.
        let empty: HashMap<OutPoint, Utxo> = HashMap::new();
        assert_eq!(mp.prune_orphans(&empty), 1);
        assert!(mp.is_empty());

        // Dipanggil lagi saat sudah bersih -> tidak ada yang dibuang.
        assert_eq!(mp.prune_orphans(&empty), 0);
    }
}
