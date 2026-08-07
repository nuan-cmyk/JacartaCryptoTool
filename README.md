# JacartaCryptoTool

JacartaCryptoTool is a secure, hardware-backed file encryption utility designed for use with JaCarta PKCS#11 hardware tokens. It provides a modern, fast, and secure graphical user interface for encrypting and decrypting files using AES-256-GCM, with cryptographic keys securely derived and managed within the hardware token.

## Features

* **Hardware-Backed Security:** Leverages JaCarta PKCS#11 tokens for Master Key generation and secure PIN authentication.
* **Strong Encryption:** Uses authenticated AES-256-GCM for all file encryption operations.
* **In-Memory Secure Preview:** Safely decrypt and preview files (text or hex dump) directly in RAM without ever writing decrypted data to the disk.
* **Modern GUI:** Built with Rust and `egui` for a responsive, lightweight, and professional dark-themed user interface.
* **Batch Processing:** Supports drag-and-drop for multiple files and recursive directory traversal for bulk encryption.
* **Asynchronous Operations:** Heavy cryptographic operations are processed in a background thread, preventing UI freezes and providing real-time progress updates.

## Requirements

* Windows OS (64-bit or 32-bit).
* A supported JaCarta hardware token connected via USB.
* Appropriate JaCarta PKCS#11 drivers (`jcPKCS11_2_Win64.dll` / `jcPKCS11_2_Win32.dll`) available in the system or bundled with the build.

## Installation and Build

This project is written in Rust. You will need `cargo` and `rustc` installed.

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/JacartaCryptoTool.git
   cd JacartaCryptoTool
   ```
2. Build the release version:
   ```bash
   cargo build --release
   ```
3. Run the executable located in `target/release/jacarta.exe`.

## Usage

1. Launch the application.
2. Drag and drop files or directories into the main window.
3. Enter your JaCarta User PIN.
4. Click "Encrypt" or "Decrypt". 
5. For in-memory reading of encrypted files without leaving a trace on the disk, use the "Preview in RAM" button.

## Architecture

The application strictly separates the UI thread (`egui`) from the cryptographic workload. Background processing is handled via standard Rust threads and `mpsc` channels to report progress back to the UI. Key derivation uses PBKDF2-HMAC-SHA256, and file data is processed using `aes-gcm`.

## License

This project is licensed under the MIT License.
