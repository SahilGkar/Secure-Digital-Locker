import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.aes_engine import encrypt, decrypt
from cryptography.exceptions import InvalidTag

class TestAESEngine:
    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(32)
        plaintext = b"Test document content"
        
        ciphertext, nonce, tag = encrypt(key, plaintext)
        decrypted = decrypt(key, ciphertext, nonce, tag)
        
        assert decrypted == plaintext
        
    def test_tampered_ciphertext_fails(self):
        key = os.urandom(32)
        plaintext = b"Test document content"
        
        ciphertext, nonce, tag = encrypt(key, plaintext)
        
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 0x01
        
        with pytest.raises(InvalidTag):
            decrypt(key, bytes(tampered_ciphertext), nonce, tag)
            
    def test_tampered_tag_fails(self):
        key = os.urandom(32)
        plaintext = b"Test document content"
        
        ciphertext, nonce, tag = encrypt(key, plaintext)
        
        tampered_tag = bytearray(tag)
        tampered_tag[0] ^= 0x01
        
        with pytest.raises(InvalidTag):
            decrypt(key, ciphertext, nonce, bytes(tampered_tag))
