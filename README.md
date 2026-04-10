# OpenSSL-Compatible AES Encryptor 🔐

A robust command-line tool written in Python for encrypting and decrypting data using **AES-128-bit in CBC mode**. This tool uses **PBKDF2** for secure key derivation with salting, ensuring high cryptographic standards.

The standout feature of this project is its **100% bidirectional compatibility with OpenSSL**. Data encrypted with this tool can be seamlessly decrypted using standard OpenSSL commands, and vice versa.

## 🚀 Technical Features
* **Algorithm:** AES (Advanced Encryption Standard) 128-bit.
* **Block Cipher Mode:** CBC (Cipher Block Chaining).
* **Key Derivation:** PBKDF2 (Password-Based Key Derivation Function 2) with salting.
* **I/O Handling:** Processes standard input (`stdin`) and standard output (`stdout`) securely without temporarily storing sensitive data on disk.

## 🛠️ Tech Stack
* **Language:** Python
* **Environment:** Linux/macOS Terminal
* **Core Concepts:** Cryptography, OpenSSL, CLI pipelines.

## ⚙️ Usage Examples

The script uses `-e` for encryption and `-d` for decryption.

**1. Encrypt a file using xaes.py:**
```bash
cat myfile.txt | ./xaes.py -e "my_password" > myfile.enc
```

**2. Decrypt a file using xaes.py:**
```bash
cat myfile.enc | ./xaes.py -d "my_password" > myfile.dec
```

### OpenSSL Bidirectional Compatibility

**Encrypt with OpenSSL, Decrypt with xaes.py:**
```bash
cat myfile.txt | openssl aes-128-cbc -pbkdf2 -k "my_password" > myfile.enc
cat myfile.enc | ./xaes.py -d "my_password" > myfile.dec
```

**Encrypt with xaes.py, Decrypt with OpenSSL:**
```bash
cat myfile.txt | ./xaes.py -e "my_password" > myfile.enc
cat myfile.enc | openssl aes-128-cbc -pbkdf2 -d -k "my_password" > myfile.dec
```
