import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import rsa
from crypto.rsa_engine import encrypt_aes_key, decrypt_aes_key

class TestRSAEngine:
    def test_encrypt_decrypt_aes_key(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        aes_key = os.urandom(32)
        
        encrypted_key = encrypt_aes_key(aes_key, public_key)
        decrypted_key = decrypt_aes_key(encrypted_key, private_key)
        
        assert decrypted_key == aes_key
        assert len(encrypted_key) == 256 # 2048-bit RSA produces 256-byte ciphertext
