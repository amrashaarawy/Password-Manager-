# Secure Password Manager

A command-line password manager written in C, built as a Computer Engineering Lab final project.

## Features
- Master-password authentication
- Encrypted local storage (XOR-based symmetric encryption)
- Linked-list credential database in RAM
- Secure password generation and strength analysis
- CSV import/export support

## Architecture
The system separates an encrypted disk layer (`master.bin`, `passwords.dat`) from a plaintext RAM layer for active use. On launch, the encrypted database is loaded and decrypted into a linked list of `PasswordNode` structs. All writes back to disk are re-encrypted before saving.

## How It Works
1. Enter master password to authenticate
2. Choose from: add entry, generate password, display credentials, import/export CSV, change master, or reset database
3. Any changes are immediately persisted to disk in encrypted form
