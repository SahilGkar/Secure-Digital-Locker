import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from config import Config

def get_rsa_key_paths():
    """Return paths to the public and private key files."""
    keys_dir = Config.RSA_KEY_DIR
    private_key_path = os.path.join(keys_dir, 'private_key.pem')
    public_key_path = os.path.join(keys_dir, 'public_key.pem')
    return private_key_path, public_key_path


def initialize_keys():
    """Generate RSA key pair if it doesn't exist."""
    keys_dir = Config.RSA_KEY_DIR
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir, exist_ok=True)
        
    private_key_path, public_key_path = get_rsa_key_paths()
    
    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        # Generate new RSA-2048 key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Save private key
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        # Save public key
        with open(public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))


def load_private_key():
    """Load the RSA private key from disk."""
    private_key_path, _ = get_rsa_key_paths()
    with open(private_key_path, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


def load_public_key():
    """Load the RSA public key from disk."""
    _, public_key_path = get_rsa_key_paths()
    with open(public_key_path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())


def encrypt_aes_key(aes_key: bytes, public_key) -> bytes:
    """
    Encrypt the AES-256 document key using RSA-OAEP.
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


def decrypt_aes_key(encrypted_aes_key: bytes, private_key) -> bytes:
    """
    Decrypt the AES-256 document key using RSA-OAEP.
    """
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key
