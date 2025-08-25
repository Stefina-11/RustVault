use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rsa::{
    RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::{LineEnding}, // Only import LineEnding if needed
};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use anyhow::{Result, anyhow};

// AES Key size for AES256-GCM
const AES_KEY_SIZE: usize = 32; // 256 bits
const NONCE_SIZE: usize = 12; // 96 bits for GCM

pub struct CryptoUtils;

impl CryptoUtils {
    // Generates a new AES key
    pub fn generate_aes_key() -> Vec<u8> {
        let mut key = vec![0u8; AES_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        key
    }

    // Encrypts data using AES-GCM
    pub fn encrypt_data(data: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if key.len() != AES_KEY_SIZE {
            return Err(anyhow!("Invalid AES key size"));
        }
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;

        let mut nonce_bytes = vec![0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| anyhow!("Failed to encrypt data: {}", e))?;

        Ok((ciphertext, nonce_bytes))
    }

    // Decrypts data using AES-GCM
    pub fn decrypt_data(ciphertext: &[u8], key: &[u8], nonce_bytes: &[u8]) -> Result<Vec<u8>> {
        if key.len() != AES_KEY_SIZE {
            return Err(anyhow!("Invalid AES key size"));
        }
        if nonce_bytes.len() != NONCE_SIZE {
            return Err(anyhow!("Invalid Nonce size"));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Failed to decrypt data: {}", e))?;

        Ok(plaintext)
    }

    // Generates a new RSA key pair
    pub fn generate_rsa_key_pair() -> Result<(RsaPrivateKey, RsaPublicKey)> {
        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| anyhow!("Failed to generate RSA private key: {}", e))?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok((private_key, public_key))
    }

    // Encrypts an AES key using RSA public key
    pub fn encrypt_aes_key_with_rsa(aes_key: &[u8], public_key: &RsaPublicKey) -> Result<Vec<u8>> {
        let mut rng = OsRng;
        let encrypted_key = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, aes_key)
            .map_err(|e| anyhow!("Failed to encrypt AES key with RSA: {}", e))?;
        Ok(encrypted_key)
    }

    // Decrypts an AES key using RSA private key
    pub fn decrypt_aes_key_with_rsa(encrypted_aes_key: &[u8], private_key: &RsaPrivateKey) -> Result<Vec<u8>> {
        let decrypted_key = private_key.decrypt(Pkcs1v15Encrypt, encrypted_aes_key)
            .map_err(|e| anyhow!("Failed to decrypt AES key with RSA: {}", e))?;
        Ok(decrypted_key)
    }

    // Encode bytes to base64
    pub fn encode_base64(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }

    // Decode base64 to bytes
    pub fn decode_base64(data: &str) -> Result<Vec<u8>> {
        general_purpose::STANDARD.decode(data)
            .map_err(|e| anyhow!("Failed to decode base64: {}", e))
    }

    // Export RSA Public Key to PKCS8 PEM format
    pub fn export_public_key_to_pem(public_key: &RsaPublicKey) -> Result<String> {
        public_key.to_pkcs1_pem(LineEnding::LF)
            .map_err(|e| anyhow!("Failed to export public key to PEM: {}", e))
            .map(|pem| pem.to_string())
    }

    // Import RSA Public Key from PKCS1 PEM format
    pub fn import_public_key_from_pem(pem: &str) -> Result<RsaPublicKey> {
        RsaPublicKey::from_pkcs1_pem(pem)
            .map_err(|e| anyhow!("Failed to import public key from PEM: {}", e))
    }

    // Export RSA Private Key to PKCS8 PEM format
    pub fn export_private_key_to_pem(private_key: &RsaPrivateKey) -> Result<String> {
        private_key.to_pkcs1_pem(LineEnding::LF)
            .map_err(|e| anyhow!("Failed to export private key to PEM: {}", e))
            .map(|pem| pem.to_string())
    }

    // Import RSA Private Key from PKCS1 PEM format
    pub fn import_private_key_from_pem(pem: &str) -> Result<RsaPrivateKey> {
        RsaPrivateKey::from_pkcs1_pem(pem)
            .map_err(|e| anyhow!("Failed to import private key from PEM: {}", e))
    }
}
