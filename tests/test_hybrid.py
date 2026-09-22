import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import rsa
from crypto.hybrid_engine import encrypt_document, decrypt_document
from cryptography.exceptions import InvalidTag

class TestHybridEngine:
    def test_encrypt_decrypt_document(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        plaintext = b"This is a confidential document."
        
        enc_data = encrypt_document(plaintext, public_key)
        
        assert 'encrypted_file' in enc_data
        assert 'encrypted_aes_key' in enc_data
        assert 'nonce' in enc_data
        assert 'auth_tag' in enc_data
        
        decrypted = decrypt_document(
            enc_data['encrypted_file'],
            enc_data['encrypted_aes_key'],
            enc_data['nonce'],
            enc_data['auth_tag'],
            private_key
        )
        
        assert decrypted == plaintext
        
    def test_tampered_document_fails(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        plaintext = b"This is a confidential document."
        enc_data = encrypt_document(plaintext, public_key)
        
        tampered_ct = bytearray(enc_data['encrypted_file'])
        tampered_ct[0] ^= 0x01
        
        with pytest.raises(InvalidTag):
            decrypt_document(
                bytes(tampered_ct),
                enc_data['encrypted_aes_key'],
                enc_data['nonce'],
                enc_data['auth_tag'],
                private_key
            )
