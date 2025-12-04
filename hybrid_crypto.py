#!/usr/bin/env python3
"""
hybrid_crypto.py

Encrypt / Decrypt files and strings using AES-GCM (symmetric) + RSA-OAEP (asymmetric)
Requirements: cryptography

Usage examples:
  Generate RSA keys:
    python hybrid_crypto.py gen-keys --private private_key.pem --public public_key.pem --passphrase mypass

  Encrypt a file:
    python hybrid_crypto.py encrypt --in secret.txt --out secret.enc --pub public_key.pem

  Decrypt a file:
    python hybrid_crypto.py decrypt --in secret.enc --out secret.txt --priv private_key.pem --passphrase mypass

  Encrypt a string:
    python hybrid_crypto.py encrypt-msg --msg "hello" --out hello.enc --pub public_key.pem

  Decrypt a string:
    python hybrid_crypto.py decrypt-msg --in hello.enc --priv private_key.pem --out-stdout --passphrase mypass
"""

import argparse
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Constants
AES_KEY_SIZE = 32           # 256-bit AES key
AES_GCM_NONCE_SIZE = 12     # standard nonce size for AESGCM
RSA_KEY_SIZE = 4096         # RSA key size in bits (recommended >= 2048; 4096 for more security)
ENC_KEY_LEN_PREFIX = 4      # 4 bytes to store length (big-endian)


def generate_rsa_keys(private_path: str, public_path: str, passphrase: str | None = None, bits: int = RSA_KEY_SIZE):
    """
    Generate RSA private/public key pair and save to files.
    If passphrase provided, the private key is encrypted with it.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    # Private key serialization
    if passphrase:
        enc_algo = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        enc_algo = serialization.NoEncryption()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo
    )
    with open(private_path, "wb") as f:
        f.write(priv_bytes)
    # Public key serialization
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_path, "wb") as f:
        f.write(pub_bytes)
    print(f"Generated RSA keypair: private -> {private_path}, public -> {public_path}")


def load_public_key(path: str):
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_public_key(data, backend=default_backend())


def load_private_key(path: str, passphrase: str | None = None):
    with open(path, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=(passphrase.encode() if passphrase else None),
                                             backend=default_backend())


def wrap_aes_key(aes_key: bytes, public_key) -> bytes:
    """
    Encrypt (wrap) the AES key with RSA public key using OAEP (SHA-256).
    """
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def unwrap_aes_key(encrypted_key: bytes, private_key) -> bytes:
    """
    Decrypt (unwrap) AES key with RSA private key using OAEP (SHA-256).
    """
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key


def encrypt_bytes(plaintext: bytes, public_key_path: str) -> bytes:
    """
    Return a binary blob with: [len_encrypted_key(4)][encrypted_key][nonce(12)][ciphertext(with tag)]
    """
    public_key = load_public_key(public_key_path)
    aes_key = os.urandom(AES_KEY_SIZE)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(AES_GCM_NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)  # ciphertext includes tag

    enc_key = wrap_aes_key(aes_key, public_key)
    out = struct.pack(">I", len(enc_key)) + enc_key + nonce + ciphertext
    return out


def decrypt_bytes(blob: bytes, private_key_path: str, passphrase: str | None = None) -> bytes:
    """
    Parse blob and decrypt. Returns plaintext bytes.
    Expects: [4-byte len][enc_key][nonce(12)][ciphertext-with-tag]
    """
    if len(blob) < ENC_KEY_LEN_PREFIX + AES_GCM_NONCE_SIZE + 1:
        raise ValueError("Input too short or malformed")

    offset = 0
    (enc_key_len,) = struct.unpack(">I", blob[offset:offset + ENC_KEY_LEN_PREFIX])
    offset += ENC_KEY_LEN_PREFIX

    enc_key = blob[offset:offset + enc_key_len]
    offset += enc_key_len

    nonce = blob[offset:offset + AES_GCM_NONCE_SIZE]
    offset += AES_GCM_NONCE_SIZE

    ciphertext = blob[offset:]

    private_key = load_private_key(private_key_path, passphrase)
    aes_key = unwrap_aes_key(enc_key, private_key)
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext


# File helpers
def encrypt_file(in_path: str, out_path: str, public_key_path: str):
    with open(in_path, "rb") as f:
        data = f.read()
    encrypted_blob = encrypt_bytes(data, public_key_path)
    with open(out_path, "wb") as f:
        f.write(encrypted_blob)
    print(f"Encrypted {in_path} -> {out_path}")


def decrypt_file(in_path: str, out_path: str, private_key_path: str, passphrase: str | None = None):
    with open(in_path, "rb") as f:
        blob = f.read()
    plaintext = decrypt_bytes(blob, private_key_path, passphrase)
    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"Decrypted {in_path} -> {out_path}")


# CLI
def main():
    p = argparse.ArgumentParser(description="Hybrid RSA + AES encrypt/decrypt tool (AES-GCM + RSA-OAEP)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # gen-keys
    g = sub.add_parser("gen-keys", help="Generate RSA keypair")
    g.add_argument("--private", required=True, help="Private key output path (PEM)")
    g.add_argument("--public", required=True, help="Public key output path (PEM)")
    g.add_argument("--passphrase", required=False, help="Optional passphrase to encrypt private key")
    g.add_argument("--bits", type=int, default=RSA_KEY_SIZE, help="RSA key size in bits (2048, 3072, 4096...)")

    # encrypt file
    e = sub.add_parser("encrypt", help="Encrypt a file")
    e.add_argument("--in", dest="infile", required=True, help="Input file to encrypt")
    e.add_argument("--out", dest="outfile", required=True, help="Output encrypted file")
    e.add_argument("--pub", dest="pub", required=True, help="Recipient's public key (PEM)")

    # decrypt file
    d = sub.add_parser("decrypt", help="Decrypt a file")
    d.add_argument("--in", dest="infile", required=True, help="Input encrypted file")
    d.add_argument("--out", dest="outfile", required=True, help="Output decrypted file")
    d.add_argument("--priv", dest="priv", required=True, help="Private key (PEM)")
    d.add_argument("--passphrase", required=False, help="Passphrase if private key is encrypted")

    # encrypt message
    em = sub.add_parser("encrypt-msg", help="Encrypt a short message (string)")
    em.add_argument("--msg", required=True, help="Message to encrypt")
    em.add_argument("--out", dest="outfile", required=True, help="Output encrypted file")
    em.add_argument("--pub", dest="pub", required=True, help="Recipient's public key (PEM)")

    # decrypt message
    dm = sub.add_parser("decrypt-msg", help="Decrypt a message file and print to stdout or file")
    dm.add_argument("--in", dest="infile", required=True, help="Input encrypted file")
    dm.add_argument("--priv", dest="priv", required=True, help="Private key (PEM)")
    dm.add_argument("--passphrase", required=False, help="Passphrase if private key is encrypted")
    dm.add_argument("--out-stdout", action="store_true", help="Print message to stdout instead of writing to file")
    dm.add_argument("--out", dest="outfile", required=False, help="Optional output file")

    args = p.parse_args()

    if args.cmd == "gen-keys":
        generate_rsa_keys(args.private, args.public, args.passphrase, args.bits)
    elif args.cmd == "encrypt":
        encrypt_file(args.infile, args.outfile, args.pub)
    elif args.cmd == "decrypt":
        decrypt_file(args.infile, args.outfile, args.priv, args.passphrase)
    elif args.cmd == "encrypt-msg":
        blob = encrypt_bytes(args.msg.encode(), args.pub)
        with open(args.outfile, "wb") as f:
            f.write(blob)
        print(f"Encrypted message -> {args.outfile}")
    elif args.cmd == "decrypt-msg":
        with open(args.infile, "rb") as f:
            blob = f.read()
        plaintext = decrypt_bytes(blob, args.priv, args.passphrase)
        if args.out_stdout:
            print(plaintext.decode(errors="replace"))
        elif args.outfile:
            with open(args.outfile, "wb") as f:
                f.write(plaintext)
            print(f"Wrote decrypted message to {args.outfile}")
        else:
            print(plaintext.decode(errors="replace"))


if __name__ == "__main__":
    main()
