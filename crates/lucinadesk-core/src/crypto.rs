//! The NaCl primitives RustDesk uses (via sodiumoxide), with pure-Rust crates so they build for wasm:
//! - `sign` combined mode: signed message = 64-byte Ed25519 signature || message;
//! - `box_` (Curve25519-XSalsa20-Poly1305) with an all-zero nonce, to seal the session key;
//! - `secretbox` (XSalsa20-Poly1305) per message, nonce = little-endian counter starting at 1,
//!   one counter per direction (hbb_common `tcp::Encrypt`). Ciphertexts are tag || data, as NaCl.

use crypto_box::{aead::Aead, PublicKey, SalsaBox, SecretKey};
use crypto_secretbox::{KeyInit, XSalsa20Poly1305};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};

pub fn random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

/// Checks a sodium combined-mode signature and returns the signed message.
pub fn verify_signed(signed: &[u8], pk: &[u8; 32]) -> Result<Vec<u8>, String> {
    if signed.len() < 64 {
        return Err("signed message too short".into());
    }
    let vk = VerifyingKey::from_bytes(pk).map_err(|e| format!("bad public key: {e}"))?;
    let sig = Signature::from_bytes(signed[..64].try_into().unwrap());
    let msg = &signed[64..];
    vk.verify(msg, &sig).map_err(|_| "signature mismatch".to_string())?;
    Ok(msg.to_vec())
}

fn nonce(seq: u64) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..8].copy_from_slice(&seq.to_le_bytes());
    n
}

pub struct Encrypt {
    cipher: XSalsa20Poly1305,
    send_seq: u64,
    recv_seq: u64,
}

impl Encrypt {
    pub fn new(key: &[u8; 32]) -> Self {
        Encrypt { cipher: XSalsa20Poly1305::new(key.into()), send_seq: 0, recv_seq: 0 }
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        self.send_seq += 1;
        self.cipher.encrypt(&nonce(self.send_seq).into(), data).expect("secretbox encrypt")
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.recv_seq += 1;
        self.cipher.decrypt(&nonce(self.recv_seq).into(), data).map_err(|_| "decryption failed".to_string())
    }
}

/// Our ephemeral box public key, the session key sealed to `their_pk`, and the cipher for it.
pub fn create_symmetric_key(their_pk: [u8; 32]) -> (Vec<u8>, Vec<u8>, Encrypt) {
    let our_sk = SecretKey::generate(&mut OsRng);
    let our_pk = our_sk.public_key();
    let mut key = [0u8; 32];
    random(&mut key);
    let sealed = SalsaBox::new(&PublicKey::from(their_pk), &our_sk)
        .encrypt(&[0u8; 24].into(), key.as_slice())
        .expect("box seal");
    (our_pk.as_bytes().to_vec(), sealed, Encrypt::new(&key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_per_direction_and_start_at_one() {
        let key = [7u8; 32];
        let (mut a, mut b) = (Encrypt::new(&key), Encrypt::new(&key));
        let c1 = a.encrypt(b"one");
        let c2 = a.encrypt(b"two");
        assert_eq!(c1.len(), 3 + 16);
        assert_eq!(b.decrypt(&c1).unwrap(), b"one");
        assert_eq!(b.decrypt(&c2).unwrap(), b"two");
        // Nonce 1 is the first: a fresh cipher decrypting c2 (nonce 2) first must fail.
        assert!(Encrypt::new(&key).decrypt(&c2).is_err());
    }

    #[test]
    fn sealed_key_opens_with_the_peer_secret() {
        let host_sk = SecretKey::generate(&mut OsRng);
        let (ours, sealed, mut enc) = create_symmetric_key(*host_sk.public_key().as_bytes());
        let ours: [u8; 32] = ours.try_into().unwrap();
        let key = SalsaBox::new(&PublicKey::from(ours), &host_sk).decrypt(&[0u8; 24].into(), sealed.as_slice()).unwrap();
        let mut host = Encrypt::new(key.as_slice().try_into().unwrap());
        assert_eq!(host.decrypt(&enc.encrypt(b"hi")).unwrap(), b"hi");
    }

    #[test]
    fn combined_signature_round_trip() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let mut signed = sk.sign(b"payload").to_bytes().to_vec();
        signed.extend_from_slice(b"payload");
        let pk = sk.verifying_key().to_bytes();
        assert_eq!(verify_signed(&signed, &pk).unwrap(), b"payload");
        signed[70] ^= 1;
        assert!(verify_signed(&signed, &pk).is_err());
    }
}
