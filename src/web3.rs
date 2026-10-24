//! Lapisan Web3: autentikasi berbasis tanda tangan (EIP-191 style),
//! challenge nonce sekali-pakai, dan registry sesi bearer.
//!
//! Alur login dApp:
//!   1. `POST /web3/challenge { address }` -> server menerbitkan nonce acak
//!      dengan TTL pendek (default 300 detik), disimpan di memori.
//!   2. Klien menandatangani pesan terstruktur dengan private key-nya.
//!   3. `POST /web3/verify { address, signature }` -> server memverifikasi
//!      ECDSA atas pesan kanonik, menghapus nonce (single-use), lalu
//!      menerbitkan sesi bearer dengan TTL.
//!
//! Keamanan yang dijaga di sini:
//! - Nonce sekali pakai: replay signature ditolak.
//! - TTL nonce & sesi: kredensial tidak hidup selamanya.
//! - Pesan kanonik domain-bound: signature untuk domain lain tidak valid.
//! - Perbandingan token constant-time.
//! - Batas jumlah nonce/sesi aktif: mencegah OOM dari pengirim challenge.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::crypto;

/// Masa berlaku challenge nonce.
pub const NONCE_TTL: Duration = Duration::from_secs(300);

/// Masa berlaku sesi setelah login berhasil.
pub const SESSION_TTL: Duration = Duration::from_secs(3600);

/// Batas jumlah nonce tertunda (anti-OOM).
pub const MAX_PENDING_NONCES: usize = 10_000;

/// Batas jumlah sesi aktif (anti-OOM).
pub const MAX_SESSIONS: usize = 10_000;

/// Domain yang diikat ke pesan. Signature dari domain lain ditolak.
pub const AUTH_DOMAIN: &str = "zoycoin";

/// Panjang nonce hex (32 byte = 64 karakter).
const NONCE_HEX_LEN: usize = 64;

/// Panjang token sesi hex (32 byte).
const SESSION_HEX_LEN: usize = 64;

#[derive(Debug)]
pub enum Web3Error {
    InvalidAddress,
    NoChallenge,
    Expired,
    BadSignature,
    Capacity,
}

impl std::fmt::Display for Web3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Web3Error::InvalidAddress => "address tidak valid",
            Web3Error::NoChallenge => "challenge tidak ditemukan atau sudah dipakai",
            Web3Error::Expired => "challenge kedaluwarsa",
            Web3Error::BadSignature => "tanda tangan tidak valid",
            Web3Error::Capacity => "kapasitas sesi penuh, coba lagi nanti",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Web3Error {}

#[derive(Debug, Clone)]
struct Nonce {
    value: String,
    issued: Instant,
}

#[derive(Debug, Clone)]
struct Session {
    address: String,
    issued: Instant,
}

/// Registry nonce + sesi. Dibungkus `Mutex` biasa (operasi O(1), tanpa await).
#[derive(Clone)]
pub struct Web3Auth {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    nonces: HashMap<String, Nonce>,
    sessions: HashMap<String, Session>,
}

/// Pesan kanonik yang ditandatangani klien.
///
/// Format deterministik dan berisi domain + nonce, sehingga signature tidak
/// bisa dipindah ke domain lain atau dipakai ulang di challenge berikutnya.
pub fn canonical_message(address: &str, nonce: &str) -> String {
    format!(
        "{AUTH_DOMAIN} authentication\naddress: {address}\nnonce: {nonce}"
    )
}

/// Nonce acak dari OS RNG.
fn random_hex(n_bytes: usize) -> String {
    use k256::elliptic_curve::rand_core::{OsRng, RngCore};
    let mut buf = vec![0u8; n_bytes];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl Web3Auth {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                nonces: HashMap::new(),
                sessions: HashMap::new(),
            })),
        }
    }

    /// Terbitkan challenge untuk address. Menghapus nonce lama milik address
    /// yang sama agar hanya challenge terakhir yang berlaku.
    pub fn issue_challenge(&self, address: &str) -> Result<(String, u64), Web3Error> {
        if !crypto::is_valid_address(address) {
            return Err(Web3Error::InvalidAddress);
        }

        let nonce = random_hex(32);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Sapu nonce kedaluwarsa (murah: hanya saat insert).
        inner
            .nonces
            .retain(|_, n| n.issued.elapsed() < NONCE_TTL);

        if inner.nonces.len() >= MAX_PENDING_NONCES {
            return Err(Web3Error::Capacity);
        }

        inner.nonces.insert(
            address.to_string(),
            Nonce {
                value: nonce.clone(),
                issued: Instant::now(),
            },
        );

        Ok((nonce, NONCE_TTL.as_secs()))
    }

    /// Verifikasi signature atas challenge yang tertunda, lalu terbitkan sesi.
    ///
    /// Nonce dihapus baik verifikasi berhasil maupun gagal (fail-closed):
    /// satu challenge hanya boleh dicoba sekali, sehingga penyerang tidak
    /// bisa brute-force signature terhadap nonce yang sama.
    pub fn verify_and_issue(
        &self,
        address: &str,
        signature_hex: &str,
        public_key_hex: &str,
    ) -> Result<(String, u64), Web3Error> {
        if !crypto::is_valid_address(address) {
            return Err(Web3Error::InvalidAddress);
        }

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        let entry = match inner.nonces.remove(address) {
            Some(n) => n,
            None => return Err(Web3Error::NoChallenge),
        };

        if entry.issued.elapsed() >= NONCE_TTL {
            return Err(Web3Error::Expired);
        }

        let message = canonical_message(address, &entry.value);
        if !crypto::verify_signature(public_key_hex, message.as_bytes(), signature_hex) {
            return Err(Web3Error::BadSignature);
        }

        // Address harus benar-benar milik public key yang menandatangani.
        if crypto::address_from_public_key(public_key_hex) != address {
            return Err(Web3Error::BadSignature);
        }

        inner
            .sessions
            .retain(|_, s| s.issued.elapsed() < SESSION_TTL);
        if inner.sessions.len() >= MAX_SESSIONS {
            return Err(Web3Error::Capacity);
        }

        let token = random_hex(32);
        inner.sessions.insert(
            token.clone(),
            Session {
                address: address.to_string(),
                issued: Instant::now(),
            },
        );

        Ok((token, SESSION_TTL.as_secs()))
    }

    /// Validasi token sesi; mengembalikan address pemilik bila masih hidup.
    pub fn session_address(&self, token: &str) -> Option<String> {
        if token.len() != SESSION_HEX_LEN || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Iterasi constant-time atas key: hindari early-return yang membocorkan
        // posisi karakter pertama yang cocok.
        let mut found: Option<&Session> = None;
        for (k, v) in inner.sessions.iter() {
            if constant_time_eq(k.as_bytes(), token.as_bytes()) {
                found = Some(v);
            }
        }
        found
            .filter(|s| s.issued.elapsed() < SESSION_TTL)
            .map(|s| s.address.clone())
    }

    /// Cabut sesi (logout).
    pub fn revoke(&self, token: &str) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.sessions.remove(token).is_some()
    }

    /// Jumlah nonce & sesi aktif (untuk observability).
    pub fn stats(&self) -> (usize, usize) {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (inner.nonces.len(), inner.sessions.len())
    }
}

impl Default for Web3Auth {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DTO
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ChallengeReq {
    pub address: String,
}

#[derive(Serialize)]
pub struct ChallengeResp {
    pub address: String,
    pub nonce: String,
    pub message: String,
    pub expires_in: u64,
}

#[derive(Deserialize)]
pub struct VerifyReq {
    pub address: String,
    pub signature: String,
    pub public_key: String,
}

#[derive(Serialize)]
pub struct VerifyResp {
    pub address: String,
    pub token: String,
    pub expires_in: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn challenge_is_single_use() {
        let auth = Web3Auth::new();
        let kp = KeyPair::random();
        let addr = kp.address();

        let (nonce, _) = auth.issue_challenge(&addr).unwrap();
        let msg = canonical_message(&addr, &nonce);
        let sig = kp.sign(msg.as_bytes());

        let (token, _) = auth
            .verify_and_issue(&addr, &sig, &kp.public_key_hex())
            .unwrap();
        assert_eq!(auth.session_address(&token).as_deref(), Some(addr.as_str()));

        // Replay dengan signature sama harus gagal: nonce sudah dihapus.
        let replay = auth.verify_and_issue(&addr, &sig, &kp.public_key_hex());
        assert!(matches!(replay, Err(Web3Error::NoChallenge)));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let auth = Web3Auth::new();
        let owner = KeyPair::random();
        let attacker = KeyPair::random();
        let addr = owner.address();

        let (nonce, _) = auth.issue_challenge(&addr).unwrap();
        let msg = canonical_message(&addr, &nonce);
        let sig = attacker.sign(msg.as_bytes());

        let res = auth.verify_and_issue(&addr, &sig, &attacker.public_key_hex());
        assert!(res.is_err());
    }

    #[test]
    fn revoke_kills_session() {
        let auth = Web3Auth::new();
        let kp = KeyPair::random();
        let addr = kp.address();
        let (nonce, _) = auth.issue_challenge(&addr).unwrap();
        let msg = canonical_message(&addr, &nonce);
        let sig = kp.sign(msg.as_bytes());
        let (token, _) = auth
            .verify_and_issue(&addr, &sig, &kp.public_key_hex())
            .unwrap();

        assert!(auth.revoke(&token));
        assert!(auth.session_address(&token).is_none());
    }

    #[test]
    fn message_is_domain_bound() {
        let m = canonical_message("abc", "def");
        assert!(m.contains(AUTH_DOMAIN));
        assert!(m.contains("abc"));
        assert!(m.contains("def"));
    }
}
