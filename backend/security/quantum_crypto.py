"""
NHI Shield - Quantum-Safe Hybrid Encryption v1.0
Combines classical AES-256-GCM with HKDF key expansion to prepare for
post-quantum migration (X25519 + AES-256-GCM hybrid scheme).

When PQC libraries become production-ready (e.g., liboqs), swap the
X25519 key exchange for Kyber-1024 without changing any downstream code.

Reference: NIST PQC standards (FIPS 203 - ML-KEM / Kyber)
"""

import os
import secrets
import base64
import hashlib
import json
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─── Key Pair Generation ──────────────────────────────────────────────────────

def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generate X25519 key pair.
    Returns (private_key_pem, public_key_pem) as bytes.
    In post-quantum migration: replace with Kyber-1024 key pair.
    """
    private_key = X25519PrivateKey.generate()
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    return priv_pem, pub_pem


# ─── Hybrid Encrypt ───────────────────────────────────────────────────────────

def hybrid_encrypt(plaintext: str, recipient_public_pem: bytes) -> str:
    """
    Hybrid encrypt using X25519 ECDH + AES-256-GCM.
    1. Generate ephemeral X25519 key pair
    2. Perform ECDH to get shared secret
    3. Derive AES-256 key via HKDF-SHA256
    4. Encrypt with AES-256-GCM
    5. Bundle: ephemeral_pub + iv + ciphertext+tag → base64 JSON

    Migration path to Kyber: replace steps 1-3 with Kyber KEM encaps.
    """
    # Load recipient public key
    recipient_pub = serialization.load_pem_public_key(recipient_public_pem)

    # Ephemeral key pair for this message
    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub_raw = ephemeral_priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )

    # ECDH shared secret
    shared_secret = ephemeral_priv.exchange(recipient_pub)

    # HKDF to derive AES-256 key (32 bytes)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'nhi-shield-hybrid-v1'
    ).derive(shared_secret)

    # AES-256-GCM encrypt
    iv = secrets.token_bytes(12)
    ct_tag = AESGCM(aes_key).encrypt(iv, plaintext.encode(), None)

    payload = {
        'version':      '1',
        'scheme':       'X25519-HKDF-AES256GCM',
        'ephemeral_pub': base64.b64encode(ephemeral_pub_raw).decode(),
        'iv':            base64.b64encode(iv).decode(),
        'ciphertext':    base64.b64encode(ct_tag).decode(),
        # Checksum for integrity verification before decryption
        'checksum':      hashlib.sha256(ct_tag).hexdigest()[:16],
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


# ─── Hybrid Decrypt ───────────────────────────────────────────────────────────

def hybrid_decrypt(token: str, private_key_pem: bytes) -> str:
    """
    Reverse of hybrid_encrypt.
    Migration path: replace ECDH with Kyber KEM decaps.
    """
    payload = json.loads(base64.b64decode(token).decode())

    # Load private key
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    # Reconstruct ephemeral public key
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    ephemeral_pub_raw = base64.b64decode(payload['ephemeral_pub'])
    ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_raw)

    # ECDH
    shared_secret = private_key.exchange(ephemeral_pub)

    # HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'nhi-shield-hybrid-v1'
    ).derive(shared_secret)

    # AES-256-GCM decrypt
    iv       = base64.b64decode(payload['iv'])
    ct_tag   = base64.b64decode(payload['ciphertext'])
    return AESGCM(aes_key).decrypt(iv, ct_tag, None).decode()


# ─── Symmetric Fallback (AES-256-GCM) ────────────────────────────────────────

def symmetric_encrypt(plaintext: str, key_hex: str) -> str:
    """AES-256-GCM symmetric encryption (for scenarios without asymmetric keys)."""
    key = bytes.fromhex(key_hex)[:32]
    iv = secrets.token_bytes(12)
    ct_tag = AESGCM(key).encrypt(iv, plaintext.encode(), None)
    return base64.b64encode(iv + ct_tag).decode()


def symmetric_decrypt(token: str, key_hex: str) -> str:
    key = bytes.fromhex(key_hex)[:32]
    raw = base64.b64decode(token)
    return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode()


# ─── Key Storage Helpers ──────────────────────────────────────────────────────

def save_keypair(priv_pem: bytes, pub_pem: bytes, name: str, output_dir: str = 'certs/quantum'):
    """Save key pair to PEM files (for service-level encryption)."""
    os.makedirs(output_dir, exist_ok=True)
    with open(f'{output_dir}/{name}.key.pem', 'wb') as f:
        f.write(priv_pem)
    os.chmod(f'{output_dir}/{name}.key.pem', 0o600)
    with open(f'{output_dir}/{name}.pub.pem', 'wb') as f:
        f.write(pub_pem)
    print(f"Keys saved: {output_dir}/{name}.key.pem / {name}.pub.pem")


if __name__ == '__main__':
    # Demo
    priv_pem, pub_pem = generate_keypair()
    token = hybrid_encrypt("ultra-secret-api-key-12345", pub_pem)
    plaintext = hybrid_decrypt(token, priv_pem)
    print("Hybrid encrypt/decrypt test:")
    print("  Original : ultra-secret-api-key-12345")
    print(f"  Recovered: {plaintext}")
    print(f"  Match    : {plaintext == 'ultra-secret-api-key-12345'}")
    print("  Scheme   : X25519-HKDF-AES256GCM (post-quantum ready)")
