//! Struktur blok, merkle root, dan proof-of-work.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::transaction::Transaction;

pub const MAX_DIFFICULTY_BITS: u32 = 32;
pub const MIN_DIFFICULTY_BITS: u32 = 4;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_hash: String,
    pub merkle_root: String,
    pub timestamp: i64,
    /// Jumlah leading zero bit yang dibutuhkan pada hash blok.
    pub difficulty: u32,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub hash: String,
    pub transactions: Vec<Transaction>,
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl BlockHeader {
    fn serialize_for_hash(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(88);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(self.prev_hash.as_bytes());
        buf.extend_from_slice(self.merkle_root.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.difficulty.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    pub fn compute_hash(&self) -> String {
        hex::encode(crypto::sha256d(&self.serialize_for_hash()))
    }
}

/// Merkle root ala Bitcoin (duplikasi node terakhir bila ganjil).
pub fn merkle_root(txids: &[String]) -> String {
    if txids.is_empty() {
        return hex::encode(crypto::sha256d(&[]));
    }

    let mut level: Vec<[u8; 32]> = txids
        .iter()
        .map(|txid| {
            let mut arr = [0u8; 32];
            if let Ok(bytes) = hex::decode(txid) {
                if bytes.len() == 32 {
                    arr.copy_from_slice(&bytes);
                }
            }
            arr
        })
        .collect();

    while level.len() > 1 {
        if level.len() % 2 == 1 {
            if let Some(last) = level.last().copied() {
                level.push(last);
            }
        }
        level = level
            .chunks(2)
            .map(|pair| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                crypto::sha256d(&buf)
            })
            .collect();
    }

    hex::encode(level[0])
}

/// Hitung jumlah leading zero bit dari hash hex.
pub fn leading_zero_bits(hash_hex: &str) -> u32 {
    let bytes = match hex::decode(hash_hex) {
        Ok(b) => b,
        Err(_) => return 0,
    };

    let mut count = 0u32;
    for byte in bytes {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

pub fn meets_difficulty(hash_hex: &str, difficulty: u32) -> bool {
    leading_zero_bits(hash_hex) >= difficulty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zeros() {
        assert_eq!(leading_zero_bits(&"00".repeat(32)), 256);
        assert_eq!(leading_zero_bits(&format!("0f{}", "00".repeat(31))), 4);
    }

    #[test]
    fn single_tx_merkle_root_equals_txid_hash() {
        let txid = hex::encode(crypto::sha256d(b"a"));
        let root = merkle_root(std::slice::from_ref(&txid));
        assert_eq!(root, txid);
    }
}
