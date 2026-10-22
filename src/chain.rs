//! State blockchain: UTXO set, mempool, mining, dan konsensus dasar.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::block::{
    meets_difficulty, merkle_root, now, Block, BlockHeader, MAX_DIFFICULTY_BITS,
    MIN_DIFFICULTY_BITS,
};
use crate::crypto::{self, KeyPair};
use crate::store::{Store, WalletRow};
use crate::transaction::{
    validate_transaction, OutPoint, Transaction, TxIn, TxError, TxOut, Utxo,
    COINBASE_MATURITY,
};

const INITIAL_REWARD: u64 = 50 * 100_000_000; // 50 koin, 8 desimal
const HALVING_INTERVAL: u64 = 210_000;
const RETARGET_INTERVAL: u64 = 20;
const TARGET_BLOCK_SECS: i64 = 5;

#[derive(Debug)]
pub enum ChainError {
    Validation(String),
    InvalidAddress(String),
    Internal(String),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::Validation(m) => write!(f, "{m}"),
            ChainError::InvalidAddress(a) => write!(f, "address tidak valid: {a}"),
            ChainError::Internal(m) => write!(f, "kesalahan internal: {m}"),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<TxError> for ChainError {
    fn from(err: TxError) -> Self {
        ChainError::Validation(err.to_string())
    }
}

#[derive(Serialize, Deserialize)]
pub struct ChainInfo {
    pub height: u64,
    pub tip_hash: String,
    pub difficulty: u32,
    pub mempool_size: usize,
    pub utxo_count: usize,
    pub total_supply: u64,
}

pub struct Chain {
    pub blocks: Vec<Block>,
    pub utxos: HashMap<OutPoint, Utxo>,
    pub mempool: Vec<Transaction>,
    initial_difficulty: u32,
    /// Persistensi opsional; None = chain murni in-memory (mis. saat test).
    store: Option<Store>,
}

impl Chain {
    pub fn new(initial_difficulty: u32) -> Self {
        let difficulty = initial_difficulty.clamp(MIN_DIFFICULTY_BITS, MAX_DIFFICULTY_BITS);
        let mut chain = Self {
            blocks: Vec::new(),
            utxos: HashMap::new(),
            mempool: Vec::new(),
            initial_difficulty: difficulty,
            store: None,
        };
        chain.create_genesis();
        chain
    }

    fn create_genesis(&mut self) {
        let header = BlockHeader {
            version: 1,
            prev_hash: "0".repeat(64),
            merkle_root: merkle_root(&[]),
            timestamp: 1_700_000_000,
            difficulty: self.initial_difficulty,
            nonce: 0,
        };
        let hash = header.compute_hash();
        self.blocks.push(Block {
            header,
            hash,
            transactions: Vec::new(),
        });
    }

    pub fn height(&self) -> u64 {
        // Tinggi = index blok berikutnya (genesis = 0).
        self.blocks.len() as u64
    }

    pub fn tip_hash(&self) -> String {
        self.blocks
            .last()
            .map(|b| b.hash.clone())
            .unwrap_or_else(|| "0".repeat(64))
    }

    pub fn block_reward(&self, height: u64) -> u64 {
        let halvings = height / HALVING_INTERVAL;
        if halvings >= 64 {
            0
        } else {
            INITIAL_REWARD >> halvings
        }
    }

    pub fn current_difficulty(&self) -> u32 {
        let last = match self.blocks.last() {
            Some(b) => b,
            None => return self.initial_difficulty,
        };
        let height = self.blocks.len() as u64;

        // Tanpa retarget sebelum interval tercapai.
        if height < RETARGET_INTERVAL || height % RETARGET_INTERVAL != 0 {
            return last.header.difficulty;
        }

        // Bandingkan waktu aktual interval terakhir vs target.
        let past = &self.blocks[(height - RETARGET_INTERVAL) as usize];
        let elapsed = last.header.timestamp - past.header.timestamp;
        let expected = TARGET_BLOCK_SECS * RETARGET_INTERVAL as i64;

        let mut difficulty = last.header.difficulty;
        if elapsed < expected / 4 {
            // Terlalu cepat -> naikkan difficulty.
            difficulty = difficulty.saturating_add(1);
        } else if elapsed > expected * 4 {
            // Terlalu lambat -> turunkan difficulty.
            difficulty = difficulty.saturating_sub(1);
        }
        difficulty.clamp(MIN_DIFFICULTY_BITS, MAX_DIFFICULTY_BITS)
    }

    /// Bangun ulang chain dari data tersimpan (dipakai saat load dari SQLite).
    pub fn from_parts(
        blocks: Vec<Block>,
        utxos: Vec<(OutPoint, Utxo)>,
        mempool: Vec<Transaction>,
        initial_difficulty: u32,
    ) -> Self {
        Self {
            blocks,
            utxos: utxos.into_iter().collect(),
            mempool,
            initial_difficulty: initial_difficulty.clamp(MIN_DIFFICULTY_BITS, MAX_DIFFICULTY_BITS),
            store: None,
        }
    }

    /// Pasang store SQLite; bila database masih kosong, persist state sekarang.
    pub fn attach_store(&mut self, store: Store) {
        let fresh = store.load().map(|l| l.is_none()).unwrap_or(true);
        self.store = Some(store);
        if fresh {
            self.persist_full();
        }
    }

    // ------------------------------------------------------------------
    // Query state
    // ------------------------------------------------------------------

    /// Total saldo confirmed (belum termasuk mempool) milik satu address.
    pub fn balance(&self, address: &str) -> u64 {
        self.utxos
            .values()
            .filter(|u| u.address == address)
            .map(|u| u.value)
            .fold(0u64, |acc, v| acc.saturating_add(v))
    }

    /// UTXO milik address, diurutkan nilai terkecil dulu
    /// supaya coin selection deterministik.
    pub fn get_utxos_for_address(&self, address: &str) -> Vec<(OutPoint, Utxo)> {
        let mut list: Vec<(OutPoint, Utxo)> = self
            .utxos
            .iter()
            .filter(|(_, u)| u.address == address)
            .map(|(op, u)| (op.clone(), u.clone()))
            .collect();
        list.sort_by_key(|(_, u)| (u.value, u.height, u.coinbase));
        list
    }

    /// Total supply = seluruh UTXO yang belum dibelanjakan.
    pub fn total_supply(&self) -> u64 {
        self.utxos
            .values()
            .map(|u| u.value)
            .fold(0u64, |acc, v| acc.saturating_add(v))
    }

    pub fn info(&self) -> ChainInfo {
        ChainInfo {
            height: self.height(),
            tip_hash: self.tip_hash(),
            difficulty: self.current_difficulty(),
            mempool_size: self.mempool.len(),
            utxo_count: self.utxos.len(),
            total_supply: self.total_supply(),
        }
    }

    pub fn mempool_txids(&self) -> Vec<String> {
        self.mempool.iter().map(|tx| tx.txid()).collect()
    }

    /// Cari transaksi confirmed berdasarkan txid: (height, &Transaction).
    pub fn find_transaction(&self, txid: &str) -> Option<(u64, &Transaction)> {
        for (height, block) in self.blocks.iter().enumerate() {
            for tx in &block.transactions {
                if tx.txid() == txid {
                    return Some((height as u64, tx));
                }
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Mempool & konsensus
    // ------------------------------------------------------------------

    /// Masukkan transaksi ke mempool setelah validasi penuh.
    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<String, ChainError> {
        if tx.is_coinbase() {
            return Err(ChainError::Validation(
                "transaksi coinbase tidak boleh dikirim manual".into(),
            ));
        }

        let txid = tx.txid();
        if self.mempool.iter().any(|t| t.txid() == txid) {
            return Err(ChainError::Validation(format!(
                "transaksi {txid} sudah ada di mempool"
            )));
        }

        // Input yang sudah dikunci transaksi mempool lain (anti double-spend).
        let mut spent: HashSet<OutPoint> = HashSet::new();
        for mp in &self.mempool {
            for input in &mp.inputs {
                spent.insert(OutPoint::new(&input.prev_txid, input.prev_vout));
            }
        }

        validate_transaction(&tx, &self.utxos, &spent, self.height())?;

        // Persist ke SQLite (best-effort; in-memory tetap sumber kebenaran).
        if let Some(store) = self.store.as_ref() {
            if let Err(e) = store.insert_mempool_tx(&tx) {
                tracing::error!(error = %e, "gagal persist mempool ke SQLite");
            }
        }

        self.mempool.push(tx);
        Ok(txid)
    }

    /// Tambang blok baru: kumpulkan mempool valid, buat coinbase,
    /// cari nonce sampai PoW terpenuhi, lalu terapkan & persist.
    pub fn mine_block(&mut self, miner_address: &str) -> Result<Block, ChainError> {
        if !crypto::is_valid_address(miner_address) {
            return Err(ChainError::InvalidAddress(miner_address.to_string()));
        }

        let height = self.height();
        let difficulty = self.current_difficulty();

        // --- FEE MARKET ---
        // Urutkan mempool menurut fee-rate (fee per 1000 byte) menurun,
        // lalu ambil maksimal MAX_BLOCK_TXS. Inilah yang membuat chain
        // cepat & adil: pembayar lebih tinggi masuk blok lebih dulu,
        // dan blok dibatasi agar propagasi tetap sub-detik.
        let pending = std::mem::take(&mut self.mempool);
        let mut ranked: Vec<(u64, Transaction)> = pending
            .into_iter()
            .map(|tx| (crate::market::fee_rate(&self.utxos, &tx), tx))
            .collect();
        ranked.sort_by(|a, b| b.0.cmp(&a.0));

        let mut included: Vec<Transaction> = Vec::new();
        let mut spent: HashSet<OutPoint> = HashSet::new();
        let mut fees: u64 = 0;
        for (_, tx) in ranked {
            if included.len() >= crate::market::MAX_BLOCK_TXS {
                // Sisa tx dikembalikan ke mempool, tidak hilang.
                self.mempool.push(tx);
                continue;
            }
            match validate_transaction(&tx, &self.utxos, &spent, height) {
                Ok(fee) => {
                    for input in &tx.inputs {
                        spent.insert(OutPoint::new(&input.prev_txid, input.prev_vout));
                    }
                    fees = fees.saturating_add(fee);
                    included.push(tx);
                }
                Err(_) => continue,
            }
        }

        let reward = self.block_reward(height).saturating_add(fees);
        let coinbase = Transaction::coinbase(height, reward, miner_address);

        let mut transactions = vec![coinbase];
        transactions.extend(included);

        let txids: Vec<String> = transactions.iter().map(|t| t.txid()).collect();
        let mut header = BlockHeader {
            version: 1,
            prev_hash: self.tip_hash(),
            merkle_root: merkle_root(&txids),
            timestamp: now(),
            difficulty,
            nonce: 0,
        };

        // Loop proof-of-work.
        let mut hash = header.compute_hash();
        while !meets_difficulty(&hash, difficulty) {
            header.nonce = header.nonce.wrapping_add(1);
            if header.nonce % 500_000 == 0 {
                header.timestamp = now(); // cegah timestamp basi
            }
            hash = header.compute_hash();
        }

        let block = Block { header, hash, transactions };
        self.apply_block(&block);
        self.persist_block(height, &block);
        Ok(block)
    }

    /// Terapkan blok ke state: hapus UTXO dibelanjakan, tambah yang baru.
    fn apply_block(&mut self, block: &Block) {
        let height = self.blocks.len() as u64;

        for (index, tx) in block.transactions.iter().enumerate() {
            if index > 0 {
                // Hanya transaksi non-coinbase yang membelanjakan input.
                for input in &tx.inputs {
                    self.utxos
                        .remove(&OutPoint::new(&input.prev_txid, input.prev_vout));
                }
            }
            let txid = tx.txid();
            for (vout, out) in tx.outputs.iter().enumerate() {
                self.utxos.insert(
                    OutPoint::new(&txid, vout as u32),
                    Utxo {
                        value: out.value,
                        address: out.address.clone(),
                        coinbase: index == 0,
                        height,
                    },
                );
            }
        }

        self.blocks.push(block.clone());
    }

    /// Persist blok + sync UTXO & mempool ke SQLite (best-effort).
    fn persist_block(&mut self, height: u64, block: &Block) {
        if let Some(store) = self.store.as_mut() {
            if let Err(e) = store.persist_block(height, block, &self.utxos, &self.mempool) {
                tracing::error!(error = %e, "gagal persist blok {height} ke SQLite");
            }
        }
    }

    /// Persist seluruh state ke SQLite (best-effort).
    fn persist_full(&mut self) {
        if let Some(store) = self.store.as_mut() {
            if let Err(e) = store.persist_full(&self.blocks, &self.utxos, &self.mempool) {
                tracing::error!(error = %e, "gagal persist state penuh ke SQLite");
            }
        }
    }

    /// Validasi ulang seluruh chain dari genesis (seperti sync node penuh).
    pub fn verify_chain(&self) -> Result<(), ChainError> {
        let mut replay: HashMap<OutPoint, Utxo> = HashMap::new();

        for (index, block) in self.blocks.iter().enumerate() {
            let height = index as u64;

            // Hash blok harus cocok dengan header.
            if block.hash != block.header.compute_hash() {
                return Err(ChainError::Internal(format!(
                    "hash blok {height} tidak cocok dengan header"
                )));
            }

            if height == 0 {
                // Genesis: prev_hash harus 64 nol.
                if block.header.prev_hash != "0".repeat(64) {
                    return Err(ChainError::Internal(
                        "prev_hash genesis harus 64 nol".into(),
                    ));
                }
            } else {
                let prev = &self.blocks[index - 1];
                if block.header.prev_hash != prev.hash {
                    return Err(ChainError::Internal(format!(
                        "blok {height} tidak nyambung ke blok sebelumnya"
                    )));
                }
                // Genesis dibuat tanpa mining (konvensi Bitcoin);
                // PoW & merkle dicek untuk blok non-genesis.
                if !meets_difficulty(&block.hash, block.header.difficulty) {
                    return Err(ChainError::Internal(format!(
                        "PoW blok {height} tidak memenuhi difficulty"
                    )));
                }
                let txids: Vec<String> =
                    block.transactions.iter().map(|t| t.txid()).collect();
                if block.header.merkle_root != merkle_root(&txids) {
                    return Err(ChainError::Internal(format!(
                        "merkle root blok {height} tidak cocok"
                    )));
                }
            }

            // Replay transaksi.
            let mut fees: u64 = 0;
            for (tx_index, tx) in block.transactions.iter().enumerate() {
                if tx_index == 0 {
                    if !tx.is_coinbase() {
                        return Err(ChainError::Internal(format!(
                            "transaksi pertama blok {height} bukan coinbase"
                        )));
                    }
                } else {
                    let empty: HashSet<OutPoint> = HashSet::new();
                    fees = fees
                        .saturating_add(validate_transaction(tx, &replay, &empty, height)?);
                    for input in &tx.inputs {
                        replay.remove(&OutPoint::new(&input.prev_txid, input.prev_vout));
                    }
                }
                let txid = tx.txid();
                for (vout, out) in tx.outputs.iter().enumerate() {
                    replay.insert(
                        OutPoint::new(&txid, vout as u32),
                        Utxo {
                            value: out.value,
                            address: out.address.clone(),
                            coinbase: tx_index == 0,
                            height,
                        },
                    );
                }
            }

            // Reward coinbase = jadwal halving + total fee blok.
            if let Some(coinbase) = block.transactions.first() {
                let expected = self.block_reward(height).saturating_add(fees);
                let actual = coinbase
                    .total_output()
                    .map_err(|e| ChainError::Internal(e.to_string()))?;
                if actual != expected {
                    return Err(ChainError::Internal(format!(
                        "reward blok {height} salah: harapan {expected}, aktual {actual}"
                    )));
                }
            }
        }

        // UTXO hasil replay harus sama dengan state aktif.
        if replay.len() != self.utxos.len() {
            return Err(ChainError::Internal(
                "UTXO set tidak sinkron dengan isi chain".into(),
            ));
        }
        for (op, u) in &self.utxos {
            match replay.get(op) {
                Some(r) if r.value == u.value && r.address == u.address => {}
                _ => {
                    return Err(ChainError::Internal(format!(
                        "UTXO {}:{} tidak sinkron dengan replay",
                        op.txid, op.vout
                    )))
                }
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Wallet (delegasi ke store)
    // ------------------------------------------------------------------

    /// Simpan wallet ke SQLite (best-effort; gagal hanya di-log).
    pub fn save_wallet(&self, address: &str, secret_hex: &str, label: Option<&str>) {
        if let Some(store) = self.store.as_ref() {
            if let Err(e) = store.save_wallet(address, secret_hex, label) {
                tracing::error!(error = %e, "gagal menyimpan wallet {address}");
            }
        }
    }

    /// Daftar wallet tersimpan di SQLite.
    pub fn list_wallets(&self) -> Result<Vec<WalletRow>, ChainError> {
        match self.store.as_ref() {
            Some(store) => store.list_wallets().map_err(ChainError::Internal),
            None => Ok(Vec::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper pembuatan transaksi
// ---------------------------------------------------------------------------

/// Bangun transaksi transfer: coin selection otomatis + change + signature.
pub fn build_transfer(
    chain: &Chain,
    keypair: &KeyPair,
    to: &str,
    amount: u64,
    fee: u64,
) -> Result<Transaction, ChainError> {
    if !crypto::is_valid_address(to) {
        return Err(ChainError::InvalidAddress(to.to_string()));
    }
    if amount == 0 {
        return Err(ChainError::Validation("amount harus lebih dari 0".into()));
    }

    let from = keypair.address();
    let height = chain.height();
    let needed = amount
        .checked_add(fee)
        .ok_or_else(|| ChainError::Validation("amount + fee overflow".into()))?;

    // Coin selection: pakai UTXO termurah dulu, lewati coinbase belum matang.
    let mut selected: Vec<OutPoint> = Vec::new();
    let mut total: u64 = 0;
    for (op, u) in chain.get_utxos_for_address(&from) {
        if u.coinbase && height < u.height.saturating_add(COINBASE_MATURITY) {
            continue;
        }
        selected.push(op);
        total = total
            .checked_add(u.value)
            .ok_or_else(|| ChainError::Validation("overflow saat memilih UTXO".into()))?;
        if total >= needed {
            break;
        }
    }

    if total < needed {
        return Err(ChainError::Validation(format!(
            "saldo tidak cukup: butuh {needed} (termasuk fee), tersedia {total}"
        )));
    }

    let mut inputs: Vec<TxIn> = Vec::with_capacity(selected.len());
    for op in &selected {
        inputs.push(TxIn {
            prev_txid: op.txid.clone(),
            prev_vout: op.vout,
            public_key: String::new(), // diisi oleh sign_all
            signature: String::new(),
        });
    }

    let mut outputs = vec![TxOut {
        value: amount,
        address: to.to_string(),
    }];
    let change = total - needed;
    if change > 0 {
        outputs.push(TxOut {
            value: change,
            address: from.clone(),
        });
    }

    let mut tx = Transaction::new(inputs, outputs);
    tx.sign_all(keypair);
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_sane() {
        let chain = Chain::new(4);
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.blocks[0].transactions.len(), 0);
        assert_eq!(chain.tip_hash(), chain.blocks[0].hash);
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn mine_reward_and_maturity() {
        let mut chain = Chain::new(4);
        let miner = KeyPair::random();
        let other = KeyPair::random();

        let block = chain.mine_block(&miner.address()).unwrap();
        assert!(meets_difficulty(&block.hash, 4));
        assert_eq!(chain.height(), 2);
        assert_eq!(chain.balance(&miner.address()), INITIAL_REWARD);
        assert!(chain.verify_chain().is_ok());

        // Coinbase belum matang -> transfer harus gagal.
        let err = build_transfer(&chain, &miner, &other.address(), 1_000, 0).unwrap_err();
        assert!(err.to_string().contains("tidak cukup"));

        // Tambang sampai coinbase matang (COINBASE_MATURITY blok).
        while chain.height() <= COINBASE_MATURITY {
            chain.mine_block(&miner.address()).unwrap();
        }
        assert!(chain.verify_chain().is_ok());

        // Sekarang transfer bisa jalan.
        let tx = build_transfer(&chain, &miner, &other.address(), 1_000, 100).unwrap();
        let txid = chain.submit_transaction(tx).unwrap();
        assert_eq!(chain.mempool.len(), 1);

        chain.mine_block(&miner.address()).unwrap();
        assert_eq!(chain.mempool.len(), 0);
        assert_eq!(chain.balance(&other.address()), 1_000);
        assert!(chain.find_transaction(&txid).is_some());
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn double_spend_rejected() {
        let mut chain = Chain::new(4);
        let miner = KeyPair::random();
        let a = KeyPair::random();
        let b = KeyPair::random();

        while chain.height() <= COINBASE_MATURITY {
            chain.mine_block(&miner.address()).unwrap();
        }

        // Transfer ke A lalu tambang.
        let tx = build_transfer(&chain, &miner, &a.address(), 5_000_000_000, 0).unwrap();
        chain.submit_transaction(tx).unwrap();
        chain.mine_block(&miner.address()).unwrap();
        assert_eq!(chain.balance(&a.address()), 5_000_000_000);

        // A mencoba belanjakan lebih dari saldo -> gagal.
        let err = build_transfer(&chain, &a, &b.address(), 5_000_000_001, 0).unwrap_err();
        assert!(err.to_string().contains("tidak cukup"));

        // A belanjakan semuanya ke B -> sukses.
        let tx = build_transfer(&chain, &a, &b.address(), 5_000_000_000, 0).unwrap();
        chain.submit_transaction(tx).unwrap();
        chain.mine_block(&miner.address()).unwrap();
        assert_eq!(chain.balance(&b.address()), 5_000_000_000);
        assert_eq!(chain.balance(&a.address()), 0);
        assert!(chain.verify_chain().is_ok());
    }
}
