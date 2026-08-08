use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Serialize, Deserialize};
use std::fs;
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use std::error::Error;

const MAGIC_BYTES_V1: &[u8; 8] = b"JACARTA1";
const MAGIC_BYTES_V2: &[u8; 8] = b"JACARTA2";
const CHUNK_SIZE: usize = 65536; // 64 KB

#[derive(Serialize, Deserialize)]
pub struct EncryptedFileHeaderV1 {
    pub magic: [u8; 8],
    pub nonce: [u8; 12],
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedFileHeaderV2 {
    pub magic: [u8; 8],
    pub nonce_base: [u8; 12],
    pub file_size: u64,
}

// Helper to increment a 96-bit nonce by a counter
fn get_chunk_nonce(base: &[u8; 12], counter: u64) -> [u8; 12] {
    let mut nonce = *base;
    let counter_bytes = counter.to_be_bytes();
    // XOR the last 8 bytes of the nonce with the counter
    for i in 0..8 {
        nonce[4 + i] ^= counter_bytes[i];
    }
    nonce
}

pub fn encrypt_file_with_key(
    input_path: &Path,
    output_path: &Path,
    master_key: &[u8],
) -> Result<(), Box<dyn Error>> {
    if master_key.len() != 32 {
        return Err("Invalid master key size (32 bytes required)".into());
    }

    let file_size = fs::metadata(input_path)?.len();

    let mut nonce_base = [0u8; 12];
    rand::fill(&mut nonce_base);

    let key = Key::<Aes256Gcm>::try_from(master_key).map_err(|_| "Invalid key size")?;
    let cipher = Aes256Gcm::new(&key);

    let header = EncryptedFileHeaderV2 {
        magic: *MAGIC_BYTES_V2,
        nonce_base,
        file_size,
    };

    let mut out_file = fs::File::create(output_path)?;
    let header_bytes = bincode::serialize(&header)?;
    out_file.write_all(&header_bytes)?;

    let mut in_file = fs::File::open(input_path)?;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_index: u64 = 0;
    let mut total_read = 0;

    loop {
        let read_count = in_file.read(&mut buffer)?;
        if read_count == 0 {
            break;
        }

        let chunk_nonce_bytes = get_chunk_nonce(&nonce_base, chunk_index);
        let nonce = Nonce::from(chunk_nonce_bytes);

        let ciphertext = cipher.encrypt(&nonce, &buffer[..read_count])
            .map_err(|e| format!("AES Encryption failed: {:?}", e))?;

        out_file.write_all(&ciphertext)?;
        total_read += read_count as u64;
        chunk_index += 1;
    }

    if total_read != file_size {
        return Err("File size changed during encryption".into());
    }

    Ok(())
}

pub fn decrypt_file_with_key(
    input_path: &Path,
    output_path: &Path,
    master_key: &[u8],
) -> Result<(), Box<dyn Error>> {
    if master_key.len() != 32 {
        return Err("Invalid master key size (32 bytes required)".into());
    }

    let mut in_file = fs::File::open(input_path)?;
    
    let mut magic = [0u8; 8];
    in_file.read_exact(&mut magic)?;
    in_file.seek(SeekFrom::Start(0))?;

    if magic == *MAGIC_BYTES_V1 {
        // Fallback to V1 decryption for backward compatibility
        let input_data = fs::read(input_path)?;
        let header: EncryptedFileHeaderV1 = bincode::deserialize(&input_data)?;
        let bytes_read = bincode::serialized_size(&header)? as usize;
        let ciphertext = &input_data[bytes_read..];
        
        let key = Key::<Aes256Gcm>::try_from(master_key).map_err(|_| "Invalid key size")?;
        let nonce = Nonce::try_from(header.nonce.as_slice()).map_err(|_| "Invalid nonce size")?;
        let cipher = Aes256Gcm::new(&key);
        let plaintext = cipher.decrypt(&nonce, ciphertext)
            .map_err(|e| format!("AES Decryption failed: {:?}", e))?;
        fs::write(output_path, plaintext)?;
        return Ok(());
    } else if magic != *MAGIC_BYTES_V2 {
        return Err("File is not a JaCarta encrypted archive.".into());
    }

    let header: EncryptedFileHeaderV2 = bincode::deserialize_from(&mut in_file)
        .map_err(|e| format!("Invalid file format: {:?}", e))?;

    let key = Key::<Aes256Gcm>::try_from(master_key).map_err(|_| "Invalid key size")?;
    let cipher = Aes256Gcm::new(&key);

    let mut out_file = fs::File::create(output_path)?;
    let mut chunk_index: u64 = 0;
    let mut total_written = 0;

    let num_chunks = (header.file_size + CHUNK_SIZE as u64 - 1) / (CHUNK_SIZE as u64);
    if num_chunks == 0 {
        return Ok(());
    }

    for _ in 0..num_chunks {
        let expected_plaintext_size = if chunk_index == num_chunks - 1 {
            let rem = header.file_size % (CHUNK_SIZE as u64);
            if rem == 0 { CHUNK_SIZE as u64 } else { rem }
        } else {
            CHUNK_SIZE as u64
        };
        let expected_ciphertext_size = expected_plaintext_size as usize + 16;

        let mut chunk_data = vec![0u8; expected_ciphertext_size];
        in_file.read_exact(&mut chunk_data).map_err(|_| "Archive is truncated or corrupted")?;

        let chunk_nonce_bytes = get_chunk_nonce(&header.nonce_base, chunk_index);
        let nonce = Nonce::from(chunk_nonce_bytes);

        let plaintext = cipher.decrypt(&nonce, chunk_data.as_ref())
            .map_err(|e| format!("AES Decryption failed at chunk {}: {:?}", chunk_index, e))?;

        out_file.write_all(&plaintext)?;
        total_written += plaintext.len() as u64;
        chunk_index += 1;
    }

    if total_written != header.file_size {
        return Err("Decrypted file size mismatch".into());
    }

    Ok(())
}

pub fn decrypt_file_to_memory(
    input_path: &Path,
    master_key: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    if master_key.len() != 32 {
        return Err("Invalid master key size (32 bytes required)".into());
    }

    let mut in_file = fs::File::open(input_path)?;
    let mut magic = [0u8; 8];
    in_file.read_exact(&mut magic)?;
    in_file.seek(SeekFrom::Start(0))?;

    if magic == *MAGIC_BYTES_V1 {
        let input_data = fs::read(input_path)?;
        let header: EncryptedFileHeaderV1 = bincode::deserialize(&input_data)?;
        let bytes_read = bincode::serialized_size(&header)? as usize;
        let ciphertext = &input_data[bytes_read..];
        let key = Key::<Aes256Gcm>::try_from(master_key).map_err(|_| "Invalid key size")?;
        let nonce = Nonce::try_from(header.nonce.as_slice()).map_err(|_| "Invalid nonce size")?;
        let cipher = Aes256Gcm::new(&key);
        return cipher.decrypt(&nonce, ciphertext)
            .map_err(|e| format!("AES Decryption failed: {:?}", e).into());
    } else if magic != *MAGIC_BYTES_V2 {
        return Err("File is not a JaCarta encrypted archive.".into());
    }

    let header: EncryptedFileHeaderV2 = bincode::deserialize_from(&mut in_file)
        .map_err(|e| format!("Invalid file format: {:?}", e))?;

    let key = Key::<Aes256Gcm>::try_from(master_key).map_err(|_| "Invalid key size")?;
    let cipher = Aes256Gcm::new(&key);

    let mut result_buffer = Vec::with_capacity(header.file_size as usize);
    let mut chunk_index: u64 = 0;
    
    let num_chunks = (header.file_size + CHUNK_SIZE as u64 - 1) / (CHUNK_SIZE as u64);
    if num_chunks == 0 {
        return Ok(result_buffer);
    }

    for _ in 0..num_chunks {
        let expected_plaintext_size = if chunk_index == num_chunks - 1 {
            let rem = header.file_size % (CHUNK_SIZE as u64);
            if rem == 0 { CHUNK_SIZE as u64 } else { rem }
        } else {
            CHUNK_SIZE as u64
        };
        let expected_ciphertext_size = expected_plaintext_size as usize + 16;

        let mut chunk_data = vec![0u8; expected_ciphertext_size];
        in_file.read_exact(&mut chunk_data).map_err(|_| "Archive is truncated or corrupted")?;

        let chunk_nonce_bytes = get_chunk_nonce(&header.nonce_base, chunk_index);
        let nonce = Nonce::from(chunk_nonce_bytes);

        let plaintext = cipher.decrypt(&nonce, chunk_data.as_ref())
            .map_err(|e| format!("AES Decryption failed at chunk {}: {:?}", chunk_index, e))?;

        result_buffer.extend_from_slice(&plaintext);
        chunk_index += 1;
    }

    Ok(result_buffer)
}
