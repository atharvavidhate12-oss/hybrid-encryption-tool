# Hybrid Encryption Tool (AES-GCM + RSA-OAEP)

Secure **Encrypt/Decrypt** tool using a hybrid cryptography scheme.

* **AES-256-GCM** — fast, authenticated symmetric encryption
* **RSA-OAEP (SHA-256)** — secure asymmetric key wrapping
* Built with the **`cryptography`** Python library
# 🔐 Overview

This project implements a hybrid encryption workflow:

1. Generate a random AES-256 key.
2. Encrypt file or message with AES-GCM (provides confidentiality + integrity).
3. Encrypt (wrap) the AES key using the recipient's RSA public key (RSA-OAEP with SHA-256).
4. Pack the encrypted AES key, nonce, and ciphertext into a single binary `.enc` file.

The tool exposes a simple CLI to `gen-keys`, `encrypt`, `decrypt`, `encrypt-msg`, and `decrypt-msg`.

## 📦 Repository structure

```
hybrid-encryption-tool/
├── hybrid_crypto.py      # Main CLI script
├── README.md             # This file
├── requirements.txt      # Python dependencies
└── .gitignore            # Ignore keys, enc files, caches
```

---

## ⚙️ Installation

```bash
git clone https://github.com/YOUR-USERNAME/hybrid-encryption-tool.git
cd hybrid-encryption-tool
python -m venv .venv
source .venv/bin/activate   # on Windows use: .venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt` should contain:

```
cryptography
```

---

## 🔧 Usage

### Generate RSA keypair

```bash
python hybrid_crypto.py gen-keys \
  --private private_key.pem \
  --public public_key.pem \
  --passphrase mypassword
```

* `--passphrase` is optional. When provided, the private key PEM is encrypted.

### Encrypt a file

```bash
python hybrid_crypto.py encrypt \
  --in secret.txt \
  --out secret.enc \
  --pub public_key.pem
```

### Decrypt a file

```bash
python hybrid_crypto.py decrypt \
  --in secret.enc \
  --out decrypted.txt \
  --priv private_key.pem \
  --passphrase mypassword
```

### Encrypt a short message (string)

```bash
python hybrid_crypto.py encrypt-msg \
  --msg "Hello World" \
  --out message.enc \
  --pub public_key.pem
```

### Decrypt a message and print to stdout

```bash
python hybrid_crypto.py decrypt-msg \
  --in message.enc \
  --priv private_key.pem \
  --passphrase mypassword \
  --out-stdout
```

---

## 🗂️ Encrypted file format

Binary layout produced by this tool:

```
[4 bytes: big-endian length N of RSA-encrypted AES key]
[N bytes: RSA-encrypted AES key (OAEP SHA-256)]
[12 bytes: AES-GCM nonce (IV)]
[remaining bytes: AES-GCM ciphertext (includes auth tag)]
```

This framing keeps reading deterministic and compact.

---

## 🔒 Security notes

* AES-GCM provides confidentiality **and** integrity. Never reuse nonce with same AES key.
* RSA-OAEP (SHA-256) is used for secure key wrapping (avoid raw RSA for large data).
* Default RSA key size in the script is 4096 bits; 2048 is acceptable for many use cases.
* Protect private keys: do not commit `.pem` files to the repository. Add them to `.gitignore`.
* Consider using hardware-backed key storage (HSM) or OS keystore for production secrets.
* This tool does not add sender authentication. For sender verification, sign the ciphertext with the sender's private key.

---

## 🧪 Quick test

1. Generate keys

```bash
python hybrid_crypto.py gen-keys --private pv.pem --public pb.pem --passphrase 1234
```

2. Create a test file

```bash
echo "hello secret" > test.txt
```

3. Encrypt & decrypt

```bash
python hybrid_crypto.py encrypt --in test.txt --out test.enc --pub pb.pem
python hybrid_crypto.py decrypt --in test.enc --out result.txt --priv pv.pem --passphrase 1234
```

Verify `result.txt` equals `test.txt`.

---

## 🚫 Important: .gitignore

```
__pycache__/
*.pem
*.enc
.env
```

---

## 📝 License

Choose a license for your repository (for example, MIT). Create `LICENSE` file with license text.

---

## ✨ Extensions (ideas)

* Add a magic header + version byte to the `.enc` files for forward compatibility.
* Include metadata (filename, timestamp) as AES-GCM AAD (authenticated associated data).
* Add streaming support for large files (chunked encryption with rekeying).
* Add signing for sender authentication (RSA or ECDSA).
* Add unit tests and CI workflow.

---

If you want, I can also:

* Create an MIT `LICENSE` file for you,
* Generate a sample `.gitignore` and `requirements.txt` files on the repo,
* Create a small demo script that automates generate->encrypt->decrypt roundtrip,
* Or commit everything to a GitHub repository (you'll need to provide the repo URL or grant access).
