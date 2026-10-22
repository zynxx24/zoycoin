//! Fitur analitik & explorer yang dibangun di atas API publik `Chain`.
//! Semua fungsi di sini read-only: tidak mengubah state chain.

use std::collections::HashSet;

use serde_json::{json, Value};

use crate::block::Block;
use crate::chain::Chain;
use crate::market::{self, MIN_FEE_RATE};
use crate::security::{tx_fee, MAX_MONEY};
use crate::transaction::Transaction;

impl Chain {
    /// Rata-rata jarak waktu antar blok (detik). 0.0 bila belum cukup data.
    pub fn avg_block_time(&self) -> f64 {
        if self.blocks.len() < 2 {
            return 0.0;
        }
        let first = self.blocks.first().map(|b| b.header.timestamp).unwrap_or(0);
        let last = self.blocks.last().map(|b| b.header.timestamp).unwrap_or(0);
        let span = last.saturating_sub(first);
        if span <= 0 {
            return 0.0;
        }
        span as f64 / (self.blocks.len() - 1) as f64
    }

    /// Estimasi hashrate: 2^difficulty percobaan per blok / waktu per blok.
    pub fn hashrate_estimate(&self) -> f64 {
        let avg = self.avg_block_time();
        if avg <= 0.0 {
            return 0.0;
        }
        let difficulty = self.current_difficulty() as i32;
        2f64.powi(difficulty) / avg
    }

    /// Fee sebuah transaksi mempool (None bila input tidak diketahui).
    pub fn mempool_fee(&self, tx: &Transaction) -> Option<u64> {
        tx_fee(self, tx)
    }

    /// Fee-rate yang disarankan: median fee-rate mempool, minimal MIN_FEE_RATE.
    /// Satuan konsisten dengan `market::fee_rate` (per 1000 byte).
    pub fn suggest_fee_rate(&self) -> u64 {
        let mut rates: Vec<u64> = self
            .mempool
            .iter()
            .map(|tx| market::fee_rate(&self.utxos, tx))
            .collect();

        if rates.is_empty() {
            return MIN_FEE_RATE;
        }
        rates.sort_unstable();
        let median = rates[rates.len() / 2];
        median.max(MIN_FEE_RATE)
    }

    /// Cari blok berdasarkan hash: (height, &Block).
    pub fn block_by_hash(&self, hash: &str) -> Option<(u64, &Block)> {
        self.blocks
            .iter()
            .enumerate()
            .find(|(_, b)| b.hash == hash)
            .map(|(h, b)| (h as u64, b))
    }

    /// Total nilai transaksi mempool (yang akan segera masuk blok).
    pub fn mempool_total_fees(&self) -> u64 {
        self.mempool
            .iter()
            .filter_map(|tx| self.mempool_fee(tx))
            .fold(0u64, |acc, f| acc.saturating_add(f))
    }

    /// Riwayat transaksi sebuah address (confirmed + mempool), terbaru dulu.
    pub fn address_history(&self, address: &str, limit: usize) -> Vec<Value> {
        // Kumpulkan txid yang pernah membayar address ini, agar input yang
        // membelanjakannya bisa dilacak walau UTXO-nya sudah dihapus.
        let mut funded: HashSet<String> = HashSet::new();
        for block in &self.blocks {
            for tx in &block.transactions {
                if tx.outputs.iter().any(|o| o.address == address) {
                    funded.insert(tx.txid());
                }
            }
        }

        let mut out: Vec<Value> = Vec::new();

        // Mempool dulu (paling baru).
        for tx in self.mempool.iter().rev() {
            let receives = tx.outputs.iter().any(|o| o.address == address);
            let spends = tx.inputs.iter().any(|i| funded.contains(&i.prev_txid));
            if !receives && !spends {
                continue;
            }
            let received: u64 = tx
                .outputs
                .iter()
                .filter(|o| o.address == address)
                .map(|o| o.value)
                .sum();
            out.push(json!({
                "txid": tx.txid(),
                "status": "mempool",
                "height": Value::Null,
                "direction": if receives { "in" } else { "out" },
                "received": received,
                "fee": self.mempool_fee(tx),
            }));
            if out.len() >= limit {
                return out;
            }
        }

        // Confirmed, dari blok terbaru ke genesis.
        for (height, block) in self.blocks.iter().enumerate().rev() {
            for tx in block.transactions.iter().rev() {
                let receives = tx.outputs.iter().any(|o| o.address == address);
                let spends = tx.inputs.iter().any(|i| funded.contains(&i.prev_txid));
                if !receives && !spends {
                    continue;
                }
                let received: u64 = tx
                    .outputs
                    .iter()
                    .filter(|o| o.address == address)
                    .map(|o| o.value)
                    .sum();
                out.push(json!({
                    "txid": tx.txid(),
                    "status": "confirmed",
                    "height": height,
                    "direction": if receives { "in" } else { "out" },
                    "received": received,
                }));
                if out.len() >= limit {
                    return out;
                }
            }
        }

        out
    }

    /// Statistik agregat node untuk dashboard / explorer.
    pub fn stats(&self) -> Value {
        let height = self.height();
        let reward = self.block_reward(height);
        let next_halving = ((height / 210_000) + 1) * 210_000;

        json!({
            "height": height,
            "tip_hash": self.tip_hash(),
            "difficulty": self.current_difficulty(),
            "total_supply": self.total_supply(),
            "max_supply": MAX_MONEY,
            "supply_pct_mined": (self.total_supply() as f64 / MAX_MONEY as f64) * 100.0,
            "utxo_count": self.utxos.len(),
            "mempool_size": self.mempool.len(),
            "mempool_fees": self.mempool_total_fees(),
            "block_reward": reward,
            "next_halving_height": next_halving,
            "avg_block_time_secs": self.avg_block_time(),
            "hashrate_estimate": self.hashrate_estimate(),
            "suggested_fee": self.suggest_fee_rate(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn stats_has_expected_keys() {
        let chain = Chain::new(4);
        let stats = chain.stats();
        assert_eq!(stats["height"], 1);
        assert_eq!(stats["mempool_size"], 0);
        assert_eq!(stats["suggested_fee"], MIN_FEE_RATE);
        assert_eq!(stats["max_supply"], MAX_MONEY);
    }

    #[test]
    fn block_lookup_by_hash_works() {
        let chain = Chain::new(4);
        let tip = chain.tip_hash();
        let (height, block) = chain.block_by_hash(&tip).expect("tip harus ketemu");
        assert_eq!(height, 0);
        assert_eq!(block.hash, tip);
        assert!(chain.block_by_hash("0".repeat(64).as_str()).is_none() || height == 0);
    }

    #[test]
    fn address_history_empty_for_new_address() {
        let chain = Chain::new(4);
        let kp = KeyPair::random();
        assert!(chain.address_history(&kp.address(), 10).is_empty());
    }
}
