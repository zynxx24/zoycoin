//! Lapisan "modern chain" ala Solana/BNB di atas UTXO:
//! - fee market berbasis fee-rate (bukan sekadar urutan datang)
//! - batas ukuran blok agar propagasi tetap cepat
//! - estimasi fee per target blok
//! - rich list & histogram fee untuk explorer/dashboard
//!
//! Semua fungsi read-only kecuali yang dipakai `mine_block`.

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::chain::Chain;
use crate::transaction::{OutPoint, Transaction, Utxo};

/// Batas transaksi per blok. Blok kecil = latensi rendah & propagasi cepat.
pub const MAX_BLOCK_TXS: usize = 2_000;

/// Fee minimum per 1000 byte. Sangat murah (low gas).
pub const MIN_FEE_RATE: u64 = 1;

/// Perkiraan ukuran transaksi dalam byte (untuk menghitung fee-rate).
pub fn tx_size(tx: &Transaction) -> usize {
    10 + tx.inputs.len() * 148 + tx.outputs.len() * 34
}

/// Fee absolut sebuah transaksi dari UTXO set. 0 bila input tidak diketahui.
pub fn fee(utxos: &HashMap<OutPoint, Utxo>, tx: &Transaction) -> u64 {
    let mut sum: u64 = 0;
    for input in &tx.inputs {
        match utxos.get(&OutPoint::new(&input.prev_txid, input.prev_vout)) {
            Some(u) => sum = sum.saturating_add(u.value),
            None => return 0,
        }
    }
    let out = tx.total_output().unwrap_or(u64::MAX);
    sum.saturating_sub(out)
}

/// Fee-rate: fee per 1000 byte. Dipakai untuk prioritas masuk blok.
pub fn fee_rate(utxos: &HashMap<OutPoint, Utxo>, tx: &Transaction) -> u64 {
    let size = tx_size(tx).max(1) as u64;
    fee(utxos, tx).saturating_mul(1000) / size
}

/// Kebalikan dari `fee_rate`: fee absolut yang diperlukan agar sebuah tx
/// berukuran `size` byte mencapai `rate` per 1000 byte.
/// Dibulatkan ke atas supaya tidak pernah jatuh di bawah ambang policy.
pub fn fee_for_rate(rate: u64, size: usize) -> u64 {
    let size = size.max(1) as u64;
    rate.saturating_mul(size).saturating_add(999) / 1000
}

impl Chain {
    /// Statistik mempool: jumlah, total fee, dan fee-rate tertinggi.
    pub fn mempool_stats(&self) -> Value {
        let mut total_fee: u64 = 0;
        let mut best_rate: u64 = 0;
        for tx in self.mempool.iter() {
            total_fee = total_fee.saturating_add(fee(&self.utxos, tx));
            best_rate = best_rate.max(fee_rate(&self.utxos, tx));
        }
        json!({
            "size": self.mempool.len(),
            "capacity": MAX_BLOCK_TXS,
            "total_fees": total_fee,
            "best_fee_rate": best_rate,
            "min_fee_rate": MIN_FEE_RATE,
        })
    }

    /// Estimasi fee-rate untuk masuk dalam `target_blocks` blok ke depan.
    /// Pendekatan: ambil fee-rate tx ke-`capacity` dari atas; bila mempool
    /// lebih kecil dari kapasitas blok, cukup bayar minimum.
    pub fn estimate_fee(&self, target_blocks: u64) -> u64 {
        let capacity = (MAX_BLOCK_TXS as u64).saturating_mul(target_blocks.max(1)) as usize;
        if self.mempool.len() <= capacity {
            return MIN_FEE_RATE;
        }
        let mut rates: Vec<u64> = self
            .mempool
            .iter()
            .map(|tx| fee_rate(&self.utxos, tx))
            .collect();
        rates.sort_unstable_by(|a, b| b.cmp(a));
        rates.get(capacity).copied().unwrap_or(MIN_FEE_RATE).max(MIN_FEE_RATE)
    }

    /// Histogram fee-rate untuk grafik mempool (bucket pangkat dua).
    pub fn fee_histogram(&self) -> Value {
        let mut buckets: HashMap<u32, usize> = HashMap::new();
        for tx in self.mempool.iter() {
            let rate = fee_rate(&self.utxos, tx);
            let bucket = if rate == 0 { 0 } else { 64 - rate.leading_zeros() };
            *buckets.entry(bucket).or_insert(0) += 1;
        }
        let mut keys: Vec<u32> = buckets.keys().copied().collect();
        keys.sort_unstable();
        let list: Vec<Value> = keys
            .into_iter()
            .map(|k| {
                let low = if k == 0 { 0 } else { 1u64 << (k - 1) };
                json!({ "rate_from": low, "count": buckets[&k] })
            })
            .collect();
        json!({ "buckets": list, "min_fee_rate": MIN_FEE_RATE })
    }

    /// Preview blok berikutnya: berapa tx & total fee yang akan masuk.
    pub fn block_template(&self) -> Value {
        let mut rates: Vec<u64> = self
            .mempool
            .iter()
            .map(|tx| fee_rate(&self.utxos, tx))
            .collect();
        rates.sort_unstable_by(|a, b| b.cmp(a));
        let take = rates.len().min(MAX_BLOCK_TXS);
        let total_fees: u64 = self
            .mempool
            .iter()
            .map(|tx| fee(&self.utxos, tx))
            .fold(0u64, |a, b| a.saturating_add(b));
        json!({
            "height": self.height(),
            "difficulty": self.current_difficulty(),
            "block_reward": self.block_reward(self.height()),
            "tx_available": self.mempool.len(),
            "tx_selected": take,
            "max_block_txs": MAX_BLOCK_TXS,
            "mempool_fees": total_fees,
            "min_fee_rate_in_block": rates.get(take.saturating_sub(1)).copied().unwrap_or(0),
        })
    }

    /// Rich list: address dengan saldo terbesar (mirip top accounts BNB).
    pub fn rich_list(&self, limit: usize) -> Vec<Value> {
        let mut by_address: HashMap<String, (u64, usize)> = HashMap::new();
        for (_, utxo) in self.utxos.iter() {
            let entry = by_address
                .entry(utxo.address.clone())
                .or_insert((0u64, 0usize));
            entry.0 = entry.0.saturating_add(utxo.value);
            entry.1 += 1;
        }
        let mut list: Vec<(String, u64, usize)> = by_address
            .into_iter()
            .map(|(a, (v, n))| (a, v, n))
            .collect();
        list.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        let total = self.total_supply().max(1);
        list.into_iter()
            .take(limit)
            .enumerate()
            .map(|(rank, (address, balance, utxo_count))| {
                json!({
                    "rank": rank + 1,
                    "address": address,
                    "balance": balance,
                    "utxo_count": utxo_count,
                    "share_pct": (balance as f64 / total as f64) * 100.0,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn empty_mempool_estimates_minimum() {
        let chain = Chain::new(4);
        assert_eq!(chain.estimate_fee(1), MIN_FEE_RATE);
        assert_eq!(chain.mempool_stats()["size"], 0);
        assert_eq!(chain.block_template()["tx_selected"], 0);
    }

    #[test]
    fn rich_list_contains_miner_after_mining() {
        let mut chain = Chain::new(4);
        let miner = KeyPair::random();
        chain.mine_block(&miner.address()).unwrap();
        let rich = chain.rich_list(10);
        assert_eq!(rich.len(), 1);
        assert_eq!(rich[0]["address"], miner.address());
    }

    /// `fee_for_rate` harus kebalikan dari `fee_rate`: fee hasil konversi
    /// tidak boleh menghasilkan rate di bawah target (dibulatkan ke atas).
    #[test]
    fn fee_for_rate_never_falls_below_target() {
        for size in [1usize, 10, 192, 250, 1_000, 4_096] {
            for rate in [1u64, 2, 7, 100, 1_000] {
                let fee = fee_for_rate(rate, size);
                let achieved = fee.saturating_mul(1000) / size as u64;
                assert!(
                    achieved >= rate,
                    "size={size} rate={rate} fee={fee} achieved={achieved}"
                );
            }
        }
    }

    /// Tx berukuran kecil dengan fee minimum yang dihitung dari
    /// `fee_for_rate` harus lolos ambang MIN_FEE_RATE.
    #[test]
    fn fee_for_rate_meets_minimum_policy() {
        let size = 10 + 148 + 2 * 34;
        let fee = fee_for_rate(MIN_FEE_RATE, size);
        assert!(fee >= 1);
        assert!(fee.saturating_mul(1000) / size as u64 >= MIN_FEE_RATE);
    }
}
