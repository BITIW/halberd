// src/auth.rs

use base64::{engine::general_purpose, Engine as _};
use blake3;
use rand::{Rng};
use std::sync::OnceLock;
use time::{Duration, OffsetDateTime};

// —— Константы —————————————————————————————————————————————
const SECRET_B64: &str = "/Rkx/U2y4bXvrALcO5JmlvWeba3kytwUkeLQ3twR1Jk=";
const KEY_LEN: usize   = 32;

// —— Инициализация ключа BLAKE3 (декодирование из Base64) ——————————
fn secret_key() -> &'static [u8; KEY_LEN] {
    static KEY: OnceLock<[u8; KEY_LEN]> = OnceLock::new();
    KEY.get_or_init(|| {
        let bytes = general_purpose::STANDARD
            .decode(SECRET_B64)
            .expect("SECRET_B64 must be valid base64");
        bytes
            .try_into()
            .expect("SECRET_B64 must decode to 32 bytes")
    })
}

// —— Утилиты по времени и nonce ———————————————————————————————
fn now_ts() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn make_nonce() -> u64 {
    rand::rng().random()
}

// —— Формирование и подпись payload ————————————————————————————
fn make_payload(user_id: u64, expires: i64, nonce: u64) -> String {
    format!("{user_id}|{expires}|{nonce}")
}

fn sign_payload(payload: &str) -> String {
    let hash = blake3::keyed_hash(secret_key(), payload.as_bytes());
    general_purpose::STANDARD.encode(hash.as_bytes())
}

// —— Парсинг токена на части ————————————————————————————————
fn parse_token(token: &str) -> Option<(u64, i64, u64, &str)> {
    let mut parts = token.splitn(4, '|');
    let user_id = parts.next()?.parse().ok()?;
    let expires = parts.next()?.parse().ok()?;
    let nonce   = parts.next()?.parse().ok()?;
    let sig     = parts.next()?;
    Some((user_id, expires, nonce, sig))
}

// —— Публичный API ————————————————————————————————————————
/// Генерирует токен в формате `user_id|expires|nonce|signature`
pub fn generate_token(user_id: u64, ttl_minutes: i64) -> String {
    let expires = now_ts() + Duration::minutes(ttl_minutes).whole_minutes();
    let nonce   = make_nonce();
    let payload = make_payload(user_id, expires, nonce);
    let signature = sign_payload(&payload);
    format!("{payload}|{signature}")
}

/// Проверяет токен, возвращает `Some(user_id)` если валидный и не просрочен
pub fn verify_token(token: &str) -> Option<u64> {
    let (user_id, expires, nonce, sig) = parse_token(token)?;
    if now_ts() > expires {
        return None;
    }
    let payload = make_payload(user_id, expires, nonce);
    if sign_payload(&payload) == sig {
        Some(user_id)
    } else {
        None
    }
}