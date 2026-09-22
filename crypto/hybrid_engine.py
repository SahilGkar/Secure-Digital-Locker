import os
from crypto.aes_engine import encrypt as aes_encrypt, decrypt as aes_decrypt
from crypto.rsa_engine import encrypt_aes_key, decrypt_aes_key

def encrypt_document(plaintext: bytes, rsa_public_key) -> dict:
    """
    Encrypts a document using Hybrid Encryption (AES-256-GCM + RSA-OAEP).
    
    1. Generates a random 32-byte (256-bit) AES key.
    2. Encrypts the document with AES-GCM.
    3. Encrypts the AES key with RSA-OAEP.
    
    Returns a dictionary containing the encrypted components.
    """
    # 1. Generate a random AES-256 key
    aes_key = os.urandom(32)
    
    # 2. Encrypt the document using AES-256-GCM
    # This also generates a random 12-byte nonce
    ciphertext, nonce, auth_tag = aes_encrypt(aes_key, plaintext)
    
    # 3. Encrypt the AES key using RSA-OAEP
    encrypted_aes_key = encrypt_aes_key(aes_key, rsa_public_key)
    
    return {
        'encrypted_file': ciphertext,
        'encrypted_aes_key': encrypted_aes_key,
        'nonce': nonce,
        'auth_tag': auth_tag
    }

def decrypt_document(encrypted_file: bytes, encrypted_aes_key: bytes, nonce: bytes, auth_tag: bytes, rsa_private_key) -> bytes:
    """
    Decrypts a document encrypted with Hybrid Encryption.
    
    1. Decrypts the AES key using RSA-OAEP.
    2. Decrypts the document using AES-256-GCM (which verifies the authentication tag).
    """
    # 1. Decrypt the AES key using RSA-OAEP
    aes_key = decrypt_aes_key(encrypted_aes_key, rsa_private_key)
    
    # 2. Decrypt the document using AES-256-GCM
    # If the file, nonce, or tag has been tampered with, this will raise cryptography.exceptions.InvalidTag
    plaintext = aes_decrypt(aes_key, encrypted_file, nonce, auth_tag)
    
    return plaintext
