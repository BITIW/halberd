// src/crypto.rs
use anyhow::{anyhow, Result};
use blake3;
use base64::{engine::general_purpose, Engine as _};
use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher};
use rand::{rng, Rng};
use std::sync::OnceLock;

const SECRET_B64: &str = "/Rkx/U2y4bXvrALcO5JmlvWeba3kytwUkeLQ3twR1Jk=";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// Один раз декодируем SECRET_B64 → [u8; KEY_LEN]
fn secret_key() -> &'static [u8; KEY_LEN] {
    static KEY: OnceLock<[u8; KEY_LEN]> = OnceLock::new();
    KEY.get_or_init(|| {
        let decoded = general_purpose::STANDARD
            .decode(SECRET_B64)
            .expect("SECRET_B64 must be valid base64");
        decoded
            .as_slice()
            .try_into()
            .expect("SECRET_B64 must decode to exactly 32 bytes")
    })
}

/// Сгенерировать случайный 12-байтный nonce
fn gen_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rng().fill(&mut nonce);
    nonce
}

/// Шифруем ChaCha20: возвращает (ciphertext, nonce)
pub fn encrypt_chacha(plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let key = secret_key();
    let nonce = gen_nonce();
    // ChaCha20::new(&key.into(), &nonce.into())
    let mut cipher = ChaCha20::new(key.into(), (&nonce).into());
    let mut buf = plaintext.to_vec();
    cipher.apply_keystream(&mut buf);
    Ok((buf, nonce))
}

/// Дешифруем ChaCha20
pub fn decrypt_chacha(ciphertext: &[u8], nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let key = secret_key();
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    let mut buf = ciphertext.to_vec();
    cipher.apply_keystream(&mut buf);
    Ok(buf)
}

/// Подписываем данные BLAKE3
pub fn sign_blake3(data: &[u8]) -> Vec<u8> {
    let key = secret_key();
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(data);
    let mut out = [0u8; 36];
    hasher.finalize_xof().fill(&mut out);
    out.to_vec()
}

/// Верифицируем подпись
pub fn verify_blake3(data: &[u8], sig: &[u8]) -> bool {
    sign_blake3(data) == sig
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha_roundtrip() {
        let msg = b"Hello RAMP!";
        let (ct, nonce) = encrypt_chacha(msg).unwrap();
        let pt = decrypt_chacha(&ct, &nonce).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn test_blake3_roundtrip() {
        let m = b"foobar";
        let s = sign_blake3(m);
        assert!(verify_blake3(m, &s));
        let mut bad = s.clone();
        bad[0] ^= 1;
        assert!(!verify_blake3(m, &bad));
    }
}