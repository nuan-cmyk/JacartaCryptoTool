use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use std::error::Error;

const MAGIC_BYTES: &[u8; 8] = b"JACARTA1";

#[derive(Serialize, Deserialize)]
pub struct EncryptedFileHeader {
    pub magic: [u8; 8],
    pub nonce: [u8; 12],
}

pub fn encrypt_file_with_key(
    input_path: &Path,
    output_path: &Path,
    master_key: &[u8],
) -> Result<(), Box<dyn Error>> {
    if master_key.len() != 32 {
        return Err("Неверный размер мастер-ключа (требуется 32 байта)".into());
    }

    // Read input file
    let plaintext = fs::read(input_path)?;

    // Generate random Nonce per file
    let mut nonce_bytes = [0u8; 12];
    rand::fill(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    // Encrypt file content with AES-256-GCM using JaCarta master key
    let key = Key::<Aes256Gcm>::try_from(master_key).map_err(|_| "Invalid key size")?;
    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| format!("AES Encryption failed: {:?}", e))?;

    // Write header and ciphertext
    let header = EncryptedFileHeader {
        magic: *MAGIC_BYTES,
        nonce: nonce_bytes,
    };

    let mut out_data = bincode::serialize(&header)?;
    out_data.extend_from_slice(&ciphertext);

    fs::write(output_path, out_data)?;
    Ok(())
}

pub fn decrypt_file_with_key(
    input_path: &Path,
    output_path: &Path,
    master_key: &[u8],
) -> Result<(), Box<dyn Error>> {
    if master_key.len() != 32 {
        return Err("Неверный размер мастер-ключа (требуется 32 байта)".into());
    }

    // Read input file
    let input_data = fs::read(input_path)?;

    // Parse header
    let header: EncryptedFileHeader = 
        bincode::deserialize(&input_data)
        .map_err(|e| format!("Неверный формат файла: {:?}", e))?;
    
    let bytes_read = bincode::serialized_size(&header)? as usize;

    if header.magic != *MAGIC_BYTES {
        return Err("Файл не является зашифрованным архивом JaCarta.".into());
    }

    let ciphertext = &input_data[bytes_read..];

    let key = Key::<Aes256Gcm>::try_from(master_key).map_err(|_| "Invalid key size")?;
    let nonce = Nonce::try_from(header.nonce.as_slice()).map_err(|_| "Invalid nonce size")?;
    let cipher = Aes256Gcm::new(&key);

    // Decrypt file content
    let plaintext = cipher.decrypt(&nonce, ciphertext)
        .map_err(|e| format!("AES Decryption failed: {:?}", e))?;

    fs::write(output_path, plaintext)?;
    Ok(())
}

pub fn decrypt_file_to_memory(
    input_path: &Path,
    master_key: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    if master_key.len() != 32 {
        return Err("Неверный размер мастер-ключа (требуется 32 байта)".into());
    }

    let input_data = fs::read(input_path)?;
    let header: EncryptedFileHeader = bincode::deserialize(&input_data)
        .map_err(|e| format!("Неверный формат файла: {:?}", e))?;
    
    let bytes_read = bincode::serialized_size(&header)? as usize;
    if header.magic != *MAGIC_BYTES {
        return Err("Файл не является зашифрованным архивом JaCarta.".into());
    }

    let ciphertext = &input_data[bytes_read..];
    let key = Key::<Aes256Gcm>::try_from(master_key).map_err(|_| "Invalid key size")?;
    let nonce = Nonce::try_from(header.nonce.as_slice()).map_err(|_| "Invalid nonce size")?;
    let cipher = Aes256Gcm::new(&key);

    let plaintext = cipher.decrypt(&nonce, ciphertext)
        .map_err(|e| format!("AES Decryption failed: {:?}", e))?;

    Ok(plaintext)
}

