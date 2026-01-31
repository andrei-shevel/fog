use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rand::RngCore;
use anyhow::{bail, Result};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const PBKDF2_ITERATIONS: u32 = 200_000;

pub fn encrypt(password: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];

    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce_bytes);

    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        &salt,
        PBKDF2_ITERATIONS,
        &mut key_bytes,
    );

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("encryption failed due to internal error"))?;

    let mut output_data = Vec::new();

    output_data.extend_from_slice(&salt);
    output_data.extend_from_slice(&nonce_bytes);
    output_data.extend_from_slice(&ciphertext);

    Ok(output_data)
}

pub fn decrypt(password: &str, data: &[u8]) -> Result<Vec<u8>> {
    const MIN_LEN: usize = SALT_LEN + NONCE_LEN + 16; // 16 bytes for auth tag
    
    if data.len() < MIN_LEN {
        bail!("data is not encrypted or corrupted");
    }

    let salt = &data[..SALT_LEN];
    let nonce_bytes = &data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        &mut key_bytes,
    );

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!(
            "wrong password or corrupted data"
        ))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let password = "test_password";
        let plaintext = b"Hello, World!";

        let encrypted = encrypt(password, plaintext).unwrap();
        let decrypted = decrypt(password, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty_data() {
        let password = "test_password";
        let plaintext = b"";

        let encrypted = encrypt(password, plaintext).unwrap();
        let decrypted = decrypt(password, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_password_fails() {
        let plaintext = b"secret data";

        let encrypted = encrypt("correct_password", plaintext).unwrap();
        let result = decrypt("wrong_password", &encrypted);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("wrong password"));
    }

    #[test]
    fn decrypt_too_short_data_fails() {
        let short_data = vec![0u8; 10];
        let result = decrypt("password", &short_data);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not encrypted"));
    }

    #[test]
    fn decrypt_corrupted_data_fails() {
        let password = "test_password";
        let plaintext = b"Hello, World!";

        let mut encrypted = encrypt(password, plaintext).unwrap();
        // Corrupt the ciphertext
        if let Some(last) = encrypted.last_mut() {
            *last ^= 0xFF;
        }

        let result = decrypt(password, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn same_input_produces_different_output() {
        let password = "test_password";
        let plaintext = b"Hello, World!";

        let encrypted1 = encrypt(password, plaintext).unwrap();
        let encrypted2 = encrypt(password, plaintext).unwrap();

        // Due to random salt and nonce, outputs should differ
        assert_ne!(encrypted1, encrypted2);
    }
}
