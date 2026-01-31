# fog

A command-line tool for encrypting and decrypting files using AES-256-GCM.

## Features

- AES-256-GCM authenticated encryption
- PBKDF2 key derivation with 200,000 iterations
- Secure password input (hidden from terminal)
- Memory zeroization of sensitive data
- Supports file input/output and Unix pipes

## Installation

```bash
cargo build --release
```

The binary will be at `target/release/fog`.

## Usage

### Encrypt a file (in-place)

```bash
fog -e secret.txt
```

### Decrypt a file (in-place)

```bash
fog -d secret.txt
```

### Encrypt with output redirection

```bash
fog -e secret.txt > encrypted.bin
```

### Using pipes

```bash
# Encrypt from stdin to file
cat secret.txt | fog -e > encrypted.bin

# Decrypt and print to terminal
cat encrypted.bin | fog -d

# Chain operations
echo "secret message" | fog -e | fog -d
```

## Testing

```bash
cargo test
```

## License

MIT
