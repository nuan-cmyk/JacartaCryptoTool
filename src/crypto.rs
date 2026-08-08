use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use zeroize::{Zeroize, Zeroizing};
use serde::{Serialize, Deserialize};
use std::fs;
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use std::error::Error;

const MAGIC_BYTES_V1: &[u8; 8] = b"JACARTA1";
const MAGIC_BYTES_V2: &[u8; 8] = b"JACARTA2";
const MAGIC_BYTES_V3: &[u8; 8] = b"JACARTA3";
const CHUNK_SIZE: usize = 65536; // 64 KB

#[derive(Serialize, Deserialize)]
pub struct EncryptedFileHeaderV1 {
    pub magic: [u8; 8],
    pub nonce: [u8; 12],
}

// Header written after the magic bytes (without magic field itself)
#[derive(Serialize, Deserialize)]
pub struct EncryptedFileHeaderBody {
    pub nonce_base: [u8; 12],
    pub file_size: u64,
}

// Legacy struct for backward compat
#[derive(Serialize, Deserialize)]
pub struct EncryptedFileHeaderV2 {
    pub magic: [u8; 8],
    pub nonce_base: [u8; 12],
    pub file_size: u64,
}

fn get_chunk_nonce(base: &[u8; 12], counter: u64) -> [u8; 12] {
    let mut nonce = *base;
    let counter_bytes = counter.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= counter_bytes[i];
    }
    nonce
}

pub struct EncryptStream<W: Write + Seek> {
    writer: W,
    cipher: Aes256Gcm,
    nonce_base: [u8; 12],
    chunk_index: u64,
    buffer: Vec<u8>,
    pub total_written: u64,
}

impl<W: Write + Seek> EncryptStream<W> {
    pub fn new(mut writer: W, master_key: &[u8]) -> Result<Self, Box<dyn Error>> {
        let key = Key::<Aes256Gcm>::try_from(master_key).map_err(|_| "Invalid key size")?;
        let cipher = Aes256Gcm::new(&key);
        let mut nonce_base = [0u8; 12];
        rand::fill(&mut nonce_base);
        
        // Write magic bytes first, then header body separately
        let header_body = EncryptedFileHeaderBody {
            nonce_base,
            file_size: u64::MAX, // placeholder
        };
        writer.write_all(MAGIC_BYTES_V3)?;
        let header_bytes = bincode::serialize(&header_body)?;
        writer.write_all(&header_bytes)?;
        
        Ok(Self {
            writer,
            cipher,
            nonce_base,
            chunk_index: 0,
            buffer: Vec::with_capacity(CHUNK_SIZE),
            total_written: 0,
        })
    }
    
    pub fn finish(mut self) -> Result<(), Box<dyn Error>> {
        self.flush_buffer(true)?;
        self.writer.seek(SeekFrom::Start(0))?;
        // Write magic + header body
        let header_body = EncryptedFileHeaderBody {
            nonce_base: self.nonce_base,
            file_size: self.total_written,
        };
        self.writer.write_all(MAGIC_BYTES_V3)?;
        let header_bytes = bincode::serialize(&header_body)?;
        self.writer.write_all(&header_bytes)?;
        Ok(())
    }
    
    fn flush_buffer(&mut self, is_last: bool) -> std::io::Result<()> {
        if self.buffer.is_empty() && !is_last {
            return Ok(());
        }
        if self.chunk_index >= 0xFFFF_FFFF {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "AES-GCM chunk limit reached (max 256 TB per file) to prevent counter overflow",
            ));
        }
        let chunk_nonce_bytes = get_chunk_nonce(&self.nonce_base, self.chunk_index);
        let nonce = Nonce::from(chunk_nonce_bytes);
        
        let mut aad = Vec::new();
        aad.extend_from_slice(MAGIC_BYTES_V3);
        aad.extend_from_slice(&self.nonce_base);
        aad.push(if is_last { 1 } else { 0 }); // Authenticate the EOF flag
        let payload = Payload {
            msg: self.buffer.as_ref(),
            aad: &aad,
        };
        
        let ciphertext = self.cipher.encrypt(&nonce, payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("AES Error: {:?}", e)))?;
        
        self.writer.write_all(&ciphertext)?;
        self.total_written += self.buffer.len() as u64;
        self.buffer.zeroize();
        self.buffer.clear();
        self.chunk_index += 1;
        Ok(())
    }
}

impl<W: Write + Seek> Write for EncryptStream<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let space_left = CHUNK_SIZE - self.buffer.len();
            if space_left == 0 {
                self.flush_buffer(false)?;
                continue;
            }
            
            let to_write = std::cmp::min(space_left, buf.len() - written);
            self.buffer.extend_from_slice(&buf[written..written + to_write]);
            written += to_write;
        }
        Ok(written)
    }
    
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<W: Write + Seek> Drop for EncryptStream<W> {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

pub struct DecryptStream<R: Read> {
    reader: R,
    cipher: Aes256Gcm,
    nonce_base: [u8; 12],
    chunk_index: u64,
    file_size: u64,
    total_read: u64,
    buffer: Vec<u8>,
    buffer_pos: usize,
    is_v3: bool,
    is_last_chunk_reached: bool,
}

impl<R: Read> DecryptStream<R> {
    pub fn new(mut reader: R, master_key: &[u8]) -> Result<Self, Box<dyn Error>> {
        // Read magic separately first
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;
        
        if magic != *MAGIC_BYTES_V1 && magic != *MAGIC_BYTES_V2 && magic != *MAGIC_BYTES_V3 {
            return Err("File is not a JaCarta encrypted archive.".into());
        }
        
        let key = Key::<Aes256Gcm>::try_from(master_key).map_err(|_| "Invalid key size")?;
        let cipher = Aes256Gcm::new(&key);
        
        if magic == *MAGIC_BYTES_V1 {
            let mut nonce_bytes = [0u8; 12];
            reader.read_exact(&mut nonce_bytes)?;
            
            let mut ciphertext = Vec::new();
            reader.read_to_end(&mut ciphertext)?;
            
            let nonce = Nonce::from(nonce_bytes);
            let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())
                .map_err(|e| format!("AES V1 Decryption failed: {:?}", e))?;
                
            let size = plaintext.len() as u64;
            return Ok(Self {
                reader,
                cipher,
                nonce_base: [0u8; 12],
                chunk_index: 0,
                file_size: size,
                total_read: size,
                buffer: plaintext,
                buffer_pos: 0,
                is_v3: false,
                is_last_chunk_reached: true,
            });
        }

        let is_v3 = magic == *MAGIC_BYTES_V3;

        // Deserialize only the body (nonce_base + file_size), NOT the full header with magic
        let header_body: EncryptedFileHeaderBody = bincode::deserialize_from(&mut reader)
            .map_err(|e| format!("Invalid file format: {:?}", e))?;

        Ok(Self {
            reader,
            cipher,
            nonce_base: header_body.nonce_base,
            chunk_index: 0,
            file_size: header_body.file_size,
            total_read: 0,
            buffer: Vec::new(),
            buffer_pos: 0,
            is_v3,
            is_last_chunk_reached: false,
        })
    }
    
    fn read_next_chunk(&mut self) -> std::io::Result<()> {
        if !self.is_v3 && self.total_read >= self.file_size {
            return Ok(()); // Legacy EOF
        }
        if self.is_v3 && self.is_last_chunk_reached {
            return Ok(()); // V3 EOF
        }
        if self.chunk_index >= 0xFFFF_FFFF {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "AES-GCM chunk limit reached (max 256 TB per file) to prevent counter overflow",
            ));
        }
        
        if !self.is_v3 {
            // Legacy decryption logic (V2)
            let remaining = self.file_size - self.total_read;
            let expected_plaintext_size = std::cmp::min(remaining, CHUNK_SIZE as u64) as usize;
            let expected_ciphertext_size = expected_plaintext_size + 16;
            
            let mut chunk_data = vec![0u8; expected_ciphertext_size];
            self.reader.read_exact(&mut chunk_data)?;
            
            let chunk_nonce_bytes = get_chunk_nonce(&self.nonce_base, self.chunk_index);
            let nonce = Nonce::from(chunk_nonce_bytes);
            
            let mut plaintext = self.cipher.decrypt(&nonce, chunk_data.as_ref())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("AES Decryption failed: {:?}", e)))?;
                
            self.buffer = plaintext.clone();
            self.buffer_pos = 0;
            self.total_read += plaintext.len() as u64;
            self.chunk_index += 1;
            plaintext.zeroize();
            Ok(())
        } else {
            // V3 stream decryption logic with truncation protection
            let mut chunk_data = vec![0u8; CHUNK_SIZE + 16];
            let mut n = 0;
            while n < chunk_data.len() {
                match self.reader.read(&mut chunk_data[n..]) {
                    Ok(0) => break,
                    Ok(count) => n += count,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            if n == 0 {
                if self.is_last_chunk_reached {
                    return Ok(());
                } else {
                    return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Missing final chunk marker"));
                }
            }
            if n < 16 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Chunk is too small"));
            }
            chunk_data.truncate(n);

            let chunk_nonce_bytes = get_chunk_nonce(&self.nonce_base, self.chunk_index);
            let nonce = Nonce::from(chunk_nonce_bytes);

            // Determine if this must be the last chunk
            let must_be_last = n < CHUNK_SIZE + 16;
            let mut plaintext = None;
            
            if !must_be_last {
                // Try as intermediate chunk first (is_last = false)
                let mut aad = Vec::new();
                aad.extend_from_slice(MAGIC_BYTES_V3);
                aad.extend_from_slice(&self.nonce_base);
                aad.push(0); // is_last = false
                
                let payload = Payload {
                    msg: &chunk_data,
                    aad: &aad,
                };
                
                if let Ok(pt) = self.cipher.decrypt(&nonce, payload) {
                    plaintext = Some(pt);
                }
            }
            
            let plaintext = match plaintext {
                Some(pt) => pt,
                None => {
                    // Try as final chunk (is_last = true)
                    let mut aad = Vec::new();
                    aad.extend_from_slice(MAGIC_BYTES_V3);
                    aad.extend_from_slice(&self.nonce_base);
                    aad.push(1); // is_last = true
                    
                    let payload = Payload {
                        msg: &chunk_data,
                        aad: &aad,
                    };
                    
                    let pt = self.cipher.decrypt(&nonce, payload)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("AES Decryption failed or chunk was truncated: {:?}", e)))?;
                    
                    self.is_last_chunk_reached = true;
                    pt
                }
            };

            self.buffer = plaintext.clone();
            self.buffer_pos = 0;
            self.total_read += plaintext.len() as u64;
            self.chunk_index += 1;
            let mut pt = plaintext;
            pt.zeroize();
            Ok(())
        }
    }
}

impl<R: Read> Read for DecryptStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.buffer_pos >= self.buffer.len() {
            self.read_next_chunk()?;
            if self.buffer_pos >= self.buffer.len() {
                return Ok(0); // EOF
            }
        }
        
        let available = self.buffer.len() - self.buffer_pos;
        let to_read = std::cmp::min(available, buf.len());
        
        buf[..to_read].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_read]);
        self.buffer_pos += to_read;
        
        // Zeroize part of buffer that was read (optional but good practice)
        if self.buffer_pos >= self.buffer.len() {
            self.buffer.zeroize();
        }
        
        Ok(to_read)
    }
}

impl<R: Read> Drop for DecryptStream<R> {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}


// Wrapper for backward compatibility
pub fn encrypt_file_with_key(
    input_path: &Path,
    output_path: &Path,
    master_key: &[u8],
) -> Result<(), Box<dyn Error>> {
    let mut in_file = fs::File::open(input_path)?;
    let out_file = fs::File::create(output_path)?;
    let mut stream = EncryptStream::new(out_file, master_key)?;
    std::io::copy(&mut in_file, &mut stream)?;
    stream.finish()?;
    Ok(())
}

pub fn decrypt_file_with_key(
    input_path: &Path,
    output_path: &Path,
    master_key: &[u8],
) -> Result<(), Box<dyn Error>> {
    let in_file = fs::File::open(input_path)?;
    let mut out_file = fs::File::create(output_path)?;
    let mut stream = DecryptStream::new(in_file, master_key)?;
    std::io::copy(&mut stream, &mut out_file)?;
    Ok(())
}

pub fn decrypt_file_to_memory(
    input_path: &Path,
    master_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    let in_file = fs::File::open(input_path)?;
    let mut stream = DecryptStream::new(in_file, master_key)?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(Zeroizing::new(buf))
}
