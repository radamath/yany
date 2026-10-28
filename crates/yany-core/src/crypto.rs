use crate::error::YanyError;
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::Sha256;

const INFO: &[u8] = b"yany-session-v1";

#[derive(Clone)]
pub struct SessionKeys {
    send: [u8; 32],
    recv: [u8; 32],
}

impl SessionKeys {
    pub fn derive(password: &str, nonce: &[u8; 32], host_is_sender: bool) -> Result<Self, YanyError> {
        crate::auth::validate_password(password)?;
        let mut ikm = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), nonce, &mut ikm)
            .map_err(|e| YanyError::Crypto(e.to_string()))?;
        let hk = Hkdf::<Sha256>::new(Some(nonce), &ikm);
        let mut okm = [0u8; 64];
        hk.expand(INFO, &mut okm)
            .map_err(|_| YanyError::Crypto("hkdf expand".into()))?;
        let mut host_to_view = [0u8; 32];
        let mut view_to_host = [0u8; 32];
        host_to_view.copy_from_slice(&okm[..32]);
        view_to_host.copy_from_slice(&okm[32..]);
        if host_is_sender {
            Ok(Self {
                send: host_to_view,
                recv: view_to_host,
            })
        } else {
            Ok(Self {
                send: view_to_host,
                recv: host_to_view,
            })
        }
    }

    pub fn seal(&self, seq: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, YanyError> {
        aead_seal(&self.send, seq, aad, plaintext)
    }

    pub fn open(&self, seq: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, YanyError> {
        aead_open(&self.recv, seq, aad, ciphertext)
    }

    pub fn seal_bincode<T: Serialize>(
        &self,
        seq: u64,
        aad: &[u8],
        val: &T,
    ) -> Result<Vec<u8>, YanyError> {
        let pt = bincode::serialize(val)?;
        self.seal(seq, aad, &pt)
    }

    pub fn open_bincode<T: DeserializeOwned>(
        &self,
        seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<T, YanyError> {
        let pt = self.open(seq, aad, ciphertext)?;
        Ok(bincode::deserialize(&pt)?)
    }

    pub fn auth_proof(password: &str, nonce: &[u8; 32]) -> Result<Vec<u8>, YanyError> {
        let keys = Self::derive(password, nonce, false)?;
        keys.seal(0, b"yany-auth", b"ok")
    }

    pub fn verify_auth_proof(&self, proof: &[u8]) -> Result<(), YanyError> {
        let pt = self.open(0, b"yany-auth", proof)?;
        if pt.as_slice() != b"ok" {
            return Err(YanyError::Auth);
        }
        Ok(())
    }
}

fn nonce_from_seq(seq: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_le_bytes());
    Nonce::from(n)
}

fn aead_seal(key: &[u8; 32], seq: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, YanyError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            &nonce_from_seq(seq),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| YanyError::Crypto("seal failed".into()))
}

fn aead_open(key: &[u8; 32], seq: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, YanyError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            &nonce_from_seq(seq),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| YanyError::Crypto("open failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_viewer_keys_match() {
        let nonce = [7u8; 32];
        let host = SessionKeys::derive("session-pass", &nonce, true).unwrap();
        let view = SessionKeys::derive("session-pass", &nonce, false).unwrap();
        let ct = host.seal(1, b"frame", b"hello").unwrap();
        let pt = view.open(1, b"frame", &ct).unwrap();
        assert_eq!(pt, b"hello");
        assert!(view.open(2, b"frame", &ct).is_err());
        assert!(view.open(1, b"other", &ct).is_err());
    }

    #[test]
    fn auth_proof_is_end_to_end() {
        let nonce = [3u8; 32];
        let host = SessionKeys::derive("session-pass", &nonce, true).unwrap();
        let proof = SessionKeys::auth_proof("session-pass", &nonce).unwrap();
        host.verify_auth_proof(&proof).unwrap();
        assert!(host.verify_auth_proof(b"nope").is_err());
        let wrong = SessionKeys::derive("wrong-passx", &nonce, true).unwrap();
        assert!(wrong.verify_auth_proof(&proof).is_err());
    }
}
