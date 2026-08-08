# JaCarta Crypto Tool

JaCarta Crypto Tool is a secure file and directory encryption utility that leverages JaCarta PKCS#11 hardware tokens for cryptographic key derivation and authentication. It features a zero-disk streaming architecture, robust memory zeroization, and active anti-analysis protections.

## Key Features

* **Hardware-Backed Key Derivation**: Integrates with JaCarta hardware tokens via PKCS#11 for secure PIN verification and master key derivation.
* **Stream AEAD Encryption**: Utilizes AES-256-GCM in streaming mode with 64 KB chunks.
* **Metadata Integrity Protection**: Uses Additional Authenticated Data (AAD) to bind the file headers (magic bytes and nonce base) to the authentication tag of each encrypted chunk, mitigating metadata tampering.
* **Zero-Disk Tar Streaming**: Packages directories and multiple files into a tar stream in memory and encrypts it on the fly. Plaintext files never touch physical storage during encryption or decryption.
* **Secure File Shredding**: Implements a multi-pass secure file wiper that overwrites original files with random data before deletion.
* **Anti-Screenshot Mitigation**: Restricts the application window from being captured by screen recorders, capture software, or OS-level screenshot API hooks (using `SetWindowDisplayAffinity`).
* **Anti-Debugging Shield**: Periodically queries the OS process environment block (`IsDebuggerPresent`) to instantly terminate execution if analysis tools are attached.
* **In-Memory Secure Preview**: Allows viewing the contents of encrypted files in a secure memory buffer without writing decrypted files to disk.

## Security Architecture

1. **Memory Security**: All sensitive cryptographic material, including the master key and user PIN, are wrapped in `zeroize` and `secrecy` wrappers to prevent memory leaks and dump exposure.
2. **Backward Compatibility**: Fully supports decryption of legacy archive versions (`JACARTA1` and `JACARTA2`) while writing new archives in the authenticated `JACARTA3` format.
3. **Threading Model**: Separation of UI thread (built with `egui` and `glow`) and the heavy cryptographic execution thread, synchronized using lock-free `mpsc` channels.

## Platform Compatibility

The application is configured to build and run on:
* **Windows** (x86_64, AArch64) - full feature set, including anti-debugging and anti-screenshot hooks.
* **Linux** (x86_64, AArch64) - encryption and archiving core.
* **macOS** (x86_64, AArch64) - encryption and archiving core.

*Note: Windows-specific security APIs (such as `windows-sys` and associated kernel hooks) are conditionally compiled and active only on Windows hosts.*

## Requirements

* Rust toolchain (2021 edition or later).
* A supported JaCarta USB hardware token and PKCS#11 drivers (`jcPKCS11_2_Win64.dll` / `jcPKCS11_2_Win32.dll` on Windows) configured in the system library path.

## Build and Run

To build the release binary locally:

```bash
cargo build --release
```

The compiled binary will be placed in the `target/release/` directory.

