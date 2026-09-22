import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LENGTH = 32
NONCE_LENGTH = 12
TAG_LENGTH = 16


def encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM.
    
    Returns:
        tuple: (ciphertext, nonce, tag)
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"Key must be {KEY_LENGTH} bytes")
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LENGTH)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    tag = ciphertext[-TAG_LENGTH:]
    ciphertext = ciphertext[:-TAG_LENGTH]
    
    return ciphertext, nonce, tag


def decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-256-GCM.
    
    Args:
        key: 32-byte encryption key
        ciphertext: Encrypted data (without tag)
        nonce: 12-byte nonce used during encryption
        tag: 16-byte authentication tag
    
    Returns:
        Decrypted plaintext
    
    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"Key must be {KEY_LENGTH} bytes")
    if len(nonce) != NONCE_LENGTH:
        raise ValueError(f"Nonce must be {NONCE_LENGTH} bytes")
    if len(tag) != TAG_LENGTH:
        raise ValueError(f"Tag must be {TAG_LENGTH} bytes")
    
    aesgcm = AESGCM(key)
    combined = ciphertext + tag
    return aesgcm.decrypt(nonce, combined, None)