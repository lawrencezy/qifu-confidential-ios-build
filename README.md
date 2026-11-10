# Confidential iOS build infrastructure

This repository contains generic CI code and AES-256-GCM authenticated ciphertext only. Application source, signing identities and diagnostic logs are not public. Execution is manual, on a standard hosted macOS runner. No App Store upload is performed. Encrypted results return on unique result branches without Actions artifact storage. The decryption key is an Actions Secret.
