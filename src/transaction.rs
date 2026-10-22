//! Model transaksi UTXO + aturan validasi.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto;

/// Jumlah blok sebelum output coinbase boleh dibelanjakan.
pub const COINBASE_MATURITY: u64 = 100;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: String,
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: &str, vout: u32) -> Self {
        Self {
            txid: txid.to_string(),
            vout,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxIn {
    pub prev_txid: String,
    pub prev_vout: u32,
    /// Public key terkompresi (hex) milik pemilik UTXO.
    pub public_key: String,
    /// Signature ECDSA hex (64 byte).
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOut {
    pub value: u64,
    pub address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
}

/// UTXO yang tersimpan di state chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Utxo {
    pub value: u64,
    pub address: String,
    /// True bila berasal dari coinbase (terkena maturity).
    pub coinbase: bool,
    /// Tinggi blok saat UTXO dibuat.
    pub height: u64,
}

#[derive(Debug)]
pub enum TxError {
    EmptyInputs,
    EmptyOutputs,
    ZeroValueOutput,
    Overflow,
    DuplicateInput,
    MissingInput(String),
    AlreadySpent(String),
    ImmatureCoinbase(String),
    InvalidSignature(String),
    AddressMismatch(String),
    InsufficientInputs,
    InvalidAddress(String),
    CoinbaseMisuse,
}

impl std::fmt::Display for TxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxError::EmptyInputs => write!(f, "transaksi tanpa input"),
            TxError::EmptyOutputs => write!(f, "transaksi tanpa output"),
            TxError::ZeroValueOutput => write!(f, "output bernilai 0 tidak diizinkan"),
            TxError::Overflow => write!(f, "terjadi overflow nilai"),
            TxError::DuplicateInput => write!(f, "input duplikat dalam satu transaksi"),
            TxError::MissingInput(id) => write!(f, "UTXO tidak ditemukan: {id}"),
            TxError::AlreadySpent(id) => write!(f, "UTXO sudah dibelanjakan: {id}"),
            TxError::ImmatureCoinbase(id) => write!(f, "coinbase belum matang: {id}"),
            TxError::InvalidSignature(id) => write!(f, "signature tidak valid untuk input {id}"),
            TxError::AddressMismatch(id) => write!(f, "public key tidak cocok dengan address UTXO {id}"),
            TxError::InsufficientInputs => write!(f, "input<  output (fee negatif)"),
            TxError::InvalidAddress(a) => write!(f, "address tidak valid: {a}"),
            TxError::CoinbaseMisuse => write!(f, "transaksi coinbase tidak boleh dikirim manual"),
        }
    }
}

impl std::error::Error for TxError {}

impl Transaction {
    pub fn new(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Self {
        Self {
            version: 1,
            inputs,
            outputs,
        }
    }

    /// Coinbase: satu input dengan prev_txid = 64 nol, vout = u32::MAX.
    pub fn coinbase(height: u64, value: u64, address: &str) -> Self {
        Self {
            version: 1,
            inputs: vec![TxIn {
                prev_txid: "0".repeat(64),
                prev_vout: u32::MAX,
                public_key: String::new(),
                signature: format!("coinbase:{height}"),
            }],
            outputs: vec![TxOut {
                value,
                address: address.to_string(),
            }],
        }
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1
            && self.inputs[0].prev_txid == "0".repeat(64)
            && self.inputs[0].prev_vout == u32::MAX
    }

    /// Hash yang ditandatangani. Sengaja TIDAK memasukkan signature
    /// supaya tidak ada sirkularitas antara txid dan signature.
    pub fn sighash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ZOYCOIN_TX_V1");
        hasher.update(self.version.to_le_bytes());
        hasher.update((self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            hasher.update(input.prev_txid.as_bytes());
            hasher.update(input.prev_vout.to_le_bytes());
        }
        hasher.update((self.outputs.len() as u32).to_le_bytes());
        for output in &self.outputs {
            hasher.update(output.value.to_le_bytes());
            hasher.update(output.address.as_bytes());
        }
        crypto::sha256d(&hasher.finalize())
    }

    /// Transaction ID = hash seluruh transaksi (termasuk signature).
    pub fn txid(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"ZOYCOIN_TXID_V1");
        hasher.update(self.version.to_le_bytes());
        for input in &self.inputs {
            hasher.update(input.prev_txid.as_bytes());
            hasher.update(input.prev_vout.to_le_bytes());
            hasher.update(input.public_key.as_bytes());
            hasher.update(input.signature.as_bytes());
        }
        for output in &self.outputs {
            hasher.update(output.value.to_le_bytes());
            hasher.update(output.address.as_bytes());
        }
        hex::encode(crypto::sha256d(&hasher.finalize()))
    }

    pub fn total_output(&self) -> Result<u64, TxError> {
        let mut total: u64 = 0;
        for out in &self.outputs {
            total = total.checked_add(out.value).ok_or(TxError::Overflow)?;
        }
        Ok(total)
    }

    /// Tanda tangani semua input dengan satu keypair.
    pub fn sign_all(&mut self, keypair: &crypto::KeyPair) {
        let sighash = self.sighash();
        let public_key = keypair.public_key_hex();
        let signature = keypair.sign(&sighash);
        for input in self.inputs.iter_mut() {
            input.public_key = public_key.clone();
            input.signature = signature.clone();
        }
    }
}

/// Validasi lengkap transaksi non-coinbase terhadap UTXO set.
/// Mengembalikan fee (satuan terkecil) bila valid.
pub fn validate_transaction(
    tx: &Transaction,
    utxos: &HashMap<OutPoint, Utxo>,
    extra_spent: &HashSet<OutPoint>,
    current_height: u64,
) -> Result<u64, TxError> {
    if tx.is_coinbase() {
        return Err(TxError::CoinbaseMisuse);
    }
    if tx.inputs.is_empty() {
        return Err(TxError::EmptyInputs);
    }
    if tx.outputs.is_empty() {
        return Err(TxError::EmptyOutputs);
    }

    // Output: nilai & address.
    for out in &tx.outputs {
        if out.value == 0 {
            return Err(TxError::ZeroValueOutput);
        }
        if !crypto::is_valid_address(&out.address) {
            return Err(TxError::InvalidAddress(out.address.clone()));
        }
    }
    let total_output = tx.total_output()?;

    // Input: no duplikat.
    let mut seen: HashSet<OutPoint> = HashSet::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        let outpoint = OutPoint::new(&input.prev_txid, input.prev_vout);
        if !seen.insert(outpoint.clone()) {
            return Err(TxError::DuplicateInput);
        }
        if extra_spent.contains(&outpoint) {
            return Err(TxError::AlreadySpent(format!(
                "{}:{}",
                outpoint.txid, outpoint.vout
            )));
        }
    }

    let sighash = tx.sighash();
    let mut total_input: u64 = 0;

    for input in &tx.inputs {
        let outpoint = OutPoint::new(&input.prev_txid, input.prev_vout);
        let label = format!("{}:{}", outpoint.txid, outpoint.vout);

        let utxo = utxos.get(&outpoint).ok_or_else(|| TxError::MissingInput(label.clone()))?;

        // Coinbase maturity.
        if utxo.coinbase && current_height<  utxo.height.saturating_add(COINBASE_MATURITY) {
            return Err(TxError::ImmatureCoinbase(label));
        }

        // Public key harus menghasilkan address pemilik UTXO.
        // Decode eksplisit: `unwrap_or_default()` akan menghasilkan slice
        // kosong, dan address turunannya kebetulan selalu gagal cocok —
        // aman, tapi menyembunyikan input rusak sebagai "address salah".
        let pubkey_bytes = hex::decode(&input.public_key)
            .map_err(|_| TxError::InvalidSignature(label.clone()))?;
        let derived_address = crypto::address_from_pubkey_bytes(&pubkey_bytes);
        if derived_address != utxo.address {
            return Err(TxError::AddressMismatch(label));
        }

        if !crypto::verify_signature(&input.public_key, &sighash, &input.signature) {
            return Err(TxError::InvalidSignature(label));
        }

        total_input = total_input.checked_add(utxo.value).ok_or(TxError::Overflow)?;
    }

    if total_input<  total_output {
        return Err(TxError::InsufficientInputs);
    }

    Ok(total_input - total_output)
}
