"""
Comprehensive cryptographic verification tests.

Verifies that the application's encryption/decryption pipeline produces
real cryptographic outputs and that all security properties hold.
"""
import pytest
import os
import sys
import tempfile
import io

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from auth.models import db, User
from documents.models import Document
from werkzeug.security import generate_password_hash
from crypto.rsa_engine import initialize_keys, load_private_key, load_public_key, decrypt_aes_key
from crypto.aes_engine import decrypt as aes_decrypt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidTag


SAMPLE_PLAINTEXT = b'This is a confidential test document with enough content to verify encryption.'


@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp()
    keys_dir = tempfile.mkdtemp()
    storage_dir = tempfile.mkdtemp()

    app = create_app()
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['RSA_KEY_DIR'] = keys_dir
    app.config['DEMO_MODE'] = True

    # Override STORAGE_PATH for test isolation
    import documents.routes as dr
    original_storage = dr.STORAGE_PATH
    dr.STORAGE_PATH = storage_dir

    with app.app_context():
        db.create_all()
        initialize_keys()
        yield app
        db.drop_all()

    dr.STORAGE_PATH = original_storage
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def logged_in_client(client, app):
    """A client that is already logged in with a test user."""
    with app.app_context():
        password_hash = generate_password_hash("testpassword")
        pin_hash = generate_password_hash("123456")
        user = User(username="testuser", password_hash=password_hash, pin_hash=pin_hash)
        db.session.add(user)
        db.session.commit()

    client.post('/login', data={
        'username': 'testuser',
        'password': 'testpassword'
    })
    return client


@pytest.fixture
def uploaded_doc(logged_in_client, app):
    """Upload a test document and return the Document object."""
    data = {
        'file': (io.BytesIO(SAMPLE_PLAINTEXT), 'test_document.txt'),
        'document_type': 'Test Document'
    }
    logged_in_client.post('/upload', data=data, content_type='multipart/form-data')

    with app.app_context():
        doc = Document.query.filter_by(original_filename='test_document.txt').first()
        return doc


# ════════════════════════════════════════════════════════════════
# TEST 1: Upload produces ciphertext different from plaintext
# ════════════════════════════════════════════════════════════════

class TestCryptographicVerification:

    def test_upload_produces_different_ciphertext(self, uploaded_doc, app):
        """Upload file, read .enc from disk, assert ≠ plaintext."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)
            assert os.path.exists(doc.storage_path), "Encrypted file must exist on disk"

            with open(doc.storage_path, 'rb') as f:
                ciphertext = f.read()

            assert ciphertext != SAMPLE_PLAINTEXT, \
                "Ciphertext on disk must differ from original plaintext"
            assert len(ciphertext) > 0, "Ciphertext must not be empty"

    # ════════════════════════════════════════════════════════════════
    # TEST 2: Stored file contains encrypted ciphertext
    # ════════════════════════════════════════════════════════════════

    def test_stored_file_is_encrypted(self, uploaded_doc, app):
        """Read stored .enc blob, assert it doesn't contain plaintext."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)

            with open(doc.storage_path, 'rb') as f:
                stored_data = f.read()

            # The plaintext should not appear anywhere in the ciphertext
            assert SAMPLE_PLAINTEXT not in stored_data, \
                "Stored file must not contain plaintext content"

    # ════════════════════════════════════════════════════════════════
    # TEST 3: AES key is not stored plaintext
    # ════════════════════════════════════════════════════════════════

    def test_aes_key_not_stored_plaintext(self, uploaded_doc, app):
        """Verify DB encrypted_aes_key ≠ raw AES key (it's RSA-encrypted)."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)
            encrypted_key = doc.encrypted_aes_key

            # The encrypted AES key should be much larger than 32 bytes
            # (RSA-2048 produces 256-byte output, RSA-4096 produces 512-byte output)
            assert len(encrypted_key) > 32, \
                "Encrypted AES key should be larger than a raw 32-byte AES key"

            # Decrypt to get the real AES key and verify it's different from the encrypted form
            private_key = load_private_key()
            real_aes_key = decrypt_aes_key(encrypted_key, private_key)
            assert len(real_aes_key) == 32, "Decrypted AES key must be 32 bytes (256-bit)"
            assert real_aes_key != encrypted_key[:32], \
                "Encrypted AES key must not contain the raw AES key"

    # ════════════════════════════════════════════════════════════════
    # TEST 4: RSA encrypted AES key is present
    # ════════════════════════════════════════════════════════════════

    def test_rsa_encrypted_aes_key_present(self, uploaded_doc, app):
        """Check encrypted_aes_key is not None and has correct length for the RSA key size."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)
            assert doc.encrypted_aes_key is not None, \
                "Encrypted AES key must be present"

            # Derive expected length from actual RSA key
            pub_key = load_public_key()
            expected_len = pub_key.key_size // 8  # bits to bytes
            assert len(doc.encrypted_aes_key) == expected_len, \
                f"Encrypted AES key length must match RSA key size: expected {expected_len} bytes"

    # ════════════════════════════════════════════════════════════════
    # TEST 5: Nonce is present and 12 bytes
    # ════════════════════════════════════════════════════════════════

    def test_nonce_present_and_12_bytes(self, uploaded_doc, app):
        """Check document.nonce is 12 bytes."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)
            assert doc.nonce is not None, "Nonce must be present"
            assert len(doc.nonce) == 12, f"Nonce must be 12 bytes, got {len(doc.nonce)}"

    # ════════════════════════════════════════════════════════════════
    # TEST 6: Authentication tag is present and 16 bytes
    # ════════════════════════════════════════════════════════════════

    def test_auth_tag_present_and_16_bytes(self, uploaded_doc, app):
        """Check document.auth_tag is 16 bytes."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)
            assert doc.auth_tag is not None, "Authentication tag must be present"
            assert len(doc.auth_tag) == 16, f"Auth tag must be 16 bytes, got {len(doc.auth_tag)}"

    # ════════════════════════════════════════════════════════════════
    # TEST 7: Correct RSA private key recovers the AES key
    # ════════════════════════════════════════════════════════════════

    def test_correct_rsa_key_recovers_aes_key(self, uploaded_doc, app):
        """Use app's RSA private key to decrypt encrypted_aes_key, then decrypt ciphertext."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)
            private_key = load_private_key()

            # Recover the AES key
            aes_key = decrypt_aes_key(doc.encrypted_aes_key, private_key)
            assert len(aes_key) == 32, "Recovered AES key must be 32 bytes"

            # Use it to decrypt the document
            with open(doc.storage_path, 'rb') as f:
                ciphertext = f.read()

            plaintext = aes_decrypt(aes_key, ciphertext, doc.nonce, doc.auth_tag)
            assert plaintext == SAMPLE_PLAINTEXT, "Recovered plaintext must match original"

    # ════════════════════════════════════════════════════════════════
    # TEST 8: Correct AES key decrypts the document
    # ════════════════════════════════════════════════════════════════

    def test_correct_aes_key_decrypts_document(self, uploaded_doc, app):
        """Full roundtrip: upload → read encrypted → decrypt → matches original."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)
            private_key = load_private_key()

            with open(doc.storage_path, 'rb') as f:
                ciphertext = f.read()

            from crypto.hybrid_engine import decrypt_document
            plaintext = decrypt_document(
                ciphertext,
                doc.encrypted_aes_key,
                doc.nonce,
                doc.auth_tag,
                private_key
            )
            assert plaintext == SAMPLE_PLAINTEXT, \
                "Full hybrid decryption must recover original plaintext"

    # ════════════════════════════════════════════════════════════════
    # TEST 9: Wrong RSA private key fails
    # ════════════════════════════════════════════════════════════════

    def test_wrong_rsa_key_fails(self, uploaded_doc, app):
        """Generate different RSA key, attempt decrypt_aes_key → raises error."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)

            # Generate a completely different RSA key pair
            wrong_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            with pytest.raises(Exception):
                decrypt_aes_key(doc.encrypted_aes_key, wrong_private_key)

    # ════════════════════════════════════════════════════════════════
    # TEST 10: Modified ciphertext fails GCM authentication
    # ════════════════════════════════════════════════════════════════

    def test_modified_ciphertext_fails_gcm(self, uploaded_doc, app):
        """Flip byte in .enc file → GCM auth fails."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)
            private_key = load_private_key()

            with open(doc.storage_path, 'rb') as f:
                ciphertext = bytearray(f.read())

            # Tamper with ciphertext
            ciphertext[0] ^= 0x01

            from crypto.hybrid_engine import decrypt_document
            with pytest.raises(InvalidTag):
                decrypt_document(
                    bytes(ciphertext),
                    doc.encrypted_aes_key,
                    doc.nonce,
                    doc.auth_tag,
                    private_key
                )

    # ════════════════════════════════════════════════════════════════
    # TEST 11: Modified authentication tag fails
    # ════════════════════════════════════════════════════════════════

    def test_modified_auth_tag_fails(self, uploaded_doc, app):
        """Modify auth_tag → GCM auth fails."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)
            private_key = load_private_key()

            with open(doc.storage_path, 'rb') as f:
                ciphertext = f.read()

            tampered_tag = bytearray(doc.auth_tag)
            tampered_tag[0] ^= 0x01

            from crypto.hybrid_engine import decrypt_document
            with pytest.raises(InvalidTag):
                decrypt_document(
                    ciphertext,
                    doc.encrypted_aes_key,
                    doc.nonce,
                    bytes(tampered_tag),
                    private_key
                )

    # ════════════════════════════════════════════════════════════════
    # TEST 12: Correct PIN required before decryption
    # ════════════════════════════════════════════════════════════════

    def test_correct_pin_required(self, logged_in_client, uploaded_doc, app):
        """POST to /access with correct PIN → 200; shows decryption success page."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)

            response = logged_in_client.post(f'/access/{doc.id}', data={
                'action': 'download',
                'pin': '123456'
            })
            assert response.status_code == 200
            assert b'DOCUMENT DECRYPTED' in response.data
            assert b'PIN verified' in response.data
            assert b'RSA-OAEP decrypted' in response.data
            assert b'AES-256-GCM decrypted' in response.data
            assert b'GCM authentication tag verified' in response.data

    # ════════════════════════════════════════════════════════════════
    # TEST 13: Incorrect PIN prevents decryption
    # ════════════════════════════════════════════════════════════════

    def test_incorrect_pin_prevents_decryption(self, logged_in_client, uploaded_doc, app):
        """POST to /access with wrong PIN → error flash."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)

            response = logged_in_client.post(f'/access/{doc.id}', data={
                'action': 'download',
                'pin': '999999'
            })
            assert response.status_code == 200
            assert b'Incorrect Locker PIN' in response.data

    # ════════════════════════════════════════════════════════════════
    # TEST 14: View returns inline response
    # ════════════════════════════════════════════════════════════════

    def test_view_returns_inline(self, logged_in_client, uploaded_doc, app):
        """Access with action=view → inline content-disposition."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)

            # First, get the serve token via PIN submission
            response = logged_in_client.post(f'/access/{doc.id}', data={
                'action': 'view',
                'pin': '123456'
            })
            assert response.status_code == 200

            # Extract the serve token from the response
            html = response.data.decode()
            import re
            token_match = re.search(r'token=([a-f0-9\-]+)', html)
            assert token_match, "Serve token must be present in decryption success page"
            token = token_match.group(1)

            # Use the token to serve the file
            response = logged_in_client.get(f'/serve/{doc.id}?token={token}')
            assert response.status_code == 200
            assert response.data == SAMPLE_PLAINTEXT

            # For view, content-disposition should NOT be 'attachment'
            cd = response.headers.get('Content-Disposition', '')
            assert 'attachment' not in cd, "View should return inline, not attachment"

    # ════════════════════════════════════════════════════════════════
    # TEST 15: Download returns attachment response
    # ════════════════════════════════════════════════════════════════

    def test_download_returns_attachment(self, logged_in_client, uploaded_doc, app):
        """Access with action=download → attachment content-disposition."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)

            # Get the serve token
            response = logged_in_client.post(f'/access/{doc.id}', data={
                'action': 'download',
                'pin': '123456'
            })
            assert response.status_code == 200

            html = response.data.decode()
            import re
            token_match = re.search(r'token=([a-f0-9\-]+)', html)
            assert token_match, "Serve token must be present in decryption success page"
            token = token_match.group(1)

            response = logged_in_client.get(f'/serve/{doc.id}?token={token}')
            assert response.status_code == 200
            assert response.data == SAMPLE_PLAINTEXT

            cd = response.headers.get('Content-Disposition', '')
            assert 'attachment' in cd, "Download should return attachment disposition"
