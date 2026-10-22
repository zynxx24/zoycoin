//! Primitif kriptografi: SHA-256d, Base58Check, keypair secp256k1, address.
//!
//! Catatan: `hash160` di sini = 20 byte pertama SHA-256 (bukan RIPEMD-160)
//! agar tidak menambah dependency. Format address tetap Base58Check.

use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::rand_core::OsRng;
use sha2::{Digest, Sha256};

/// Versi address (0x00 = mainnet-style).
pub const ADDRESS_VERSION: u8 = 0x00;
const CHECKSUM_LEN: usize = 4;
const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// SHA-256 dua kali (standar Bitcoin).
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// 20 byte pertama SHA-256 — pengganti RIPEMD-160 agar minim dependency.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let h = sha256(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h[..20]);
    out
}

// ---------------------------------------------------------------------------
// Base58
// ---------------------------------------------------------------------------

pub fn base58_encode(input: &[u8]) -> String {
    // Digit base58 disimpan little-endian.
    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 2);

    for &byte in input {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::new();
    // Leading zero byte -> karakter '1'.
    for &b in input {
        if b == 0 {
            out.push('1');
        } else {
            break;
        }
    }
    for &d in digits.iter().rev() {
        out.push(BASE58_ALPHABET[d as usize] as char);
    }
    out
}

pub fn base58_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return None;
    }

    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    for ch in s.bytes() {
        let value = BASE58_ALPHABET.iter().position(|&c| c == ch)? as u32;
        let mut carry = value;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    // Leading '1' -> leading zero byte.
    let leading_zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut out = vec![0u8; leading_zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

// ---------------------------------------------------------------------------
// Keypair & address
// ---------------------------------------------------------------------------

pub struct KeyPair {
    inner: SigningKey,
}

impl KeyPair {
    pub fn random() -> Self {
        Self {
            inner: SigningKey::random(&mut OsRng),
        }
    }

    pub fn from_secret_hex(secret: &str) -> Result<Self, String> {
        let bytes = hex::decode(secret.trim()).map_err(|e| format!("secret hex tidak valid: {e}"))?;
        let inner = SigningKey::from_slice(&bytes)
            .map_err(|_| "secret key harus 32 byte".to_string())?;
        Ok(Self { inner })
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.inner.to_bytes())
    }

    /// Public key terkompresi (33 byte).
    pub fn public_key(&self) -> Vec<u8> {
        self.inner
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    pub fn address(&self) -> String {
        address_from_pubkey_bytes(&self.public_key())
    }

    /// Tanda tangan deterministic-format (r‖s, 64 byte) dalam hex.
    pub fn sign(&self, message: &[u8]) -> String {
        let signature: Signature = self.inner.sign(message);
        hex::encode(signature.to_bytes())
    }
}

pub fn address_from_pubkey_bytes(pubkey: &[u8]) -> String {
    let payload_hash = hash160(pubkey);
    let mut payload = Vec::with_capacity(1 + 20 + CHECKSUM_LEN);
    payload.push(ADDRESS_VERSION);
    payload.extend_from_slice(&payload_hash);

    let checksum = sha256d(&payload);
    payload.extend_from_slice(&checksum[..CHECKSUM_LEN]);
    base58_encode(&payload)
}

/// Verifikasi signature ECDSA terhadap message.
pub fn verify_signature(public_key_hex: &str, message: &[u8], signature_hex: &str) -> bool {
    let pk_bytes = match hex::decode(public_key_hex) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let verifying_key = match VerifyingKey::from_sec1_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    verifying_key.verify(message, &signature).is_ok()
}

/// Validasi address: panjang, versi, dan checksum.
pub fn is_valid_address(address: &str) -> bool {
    let decoded = match base58_decode(address) {
        Some(v) => v,
        None => return false,
    };
    if decoded.len() != 1 + 20 + CHECKSUM_LEN {
        return false;
    }
    if decoded[0] != ADDRESS_VERSION {
        return false;
    }

    let (payload, checksum) = decoded.split_at(decoded.len() - CHECKSUM_LEN);
    let expected = sha256d(payload);
    checksum == &expected[..CHECKSUM_LEN]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_roundtrip() {
        let data = vec![0u8, 0, 1, 2, 3, 255, 254];
        let encoded = base58_encode(&data);
        assert_eq!(base58_decode(&encoded).unwrap(), data);
    }

    #[test]
    fn address_is_valid() {
        let kp = KeyPair::random();
        assert!(is_valid_address(&kp.address()));
    }

    #[test]
    fn sign_and_verify() {
        let kp = KeyPair::random();
        let msg = b"hello zoycoin";
        let sig = kp.sign(msg);
        assert!(verify_signature(&kp.public_key_hex(), msg, &sig));
        assert!(!verify_signature(&kp.public_key_hex(), b"tampered", &sig));
    }
}
