"""
Tests for the new security-related routes:
- GET /security/<id>              (Security Details page)
- GET /security/<id>/ciphertext   (Hex preview API)
- POST /security/<id>/tamper-demo (Tamper detection API)
- GET /serve/<id>                 (One-time serve endpoint)
"""
import pytest
import os
import sys
import tempfile
import io
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from auth.models import db, User
from documents.models import Document
from werkzeug.security import generate_password_hash
from crypto.rsa_engine import initialize_keys


SAMPLE_PLAINTEXT = b'Security route test content - confidential data.'


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
    app.config['SERVE_TOKEN_EXPIRY'] = 30

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
    data = {
        'file': (io.BytesIO(SAMPLE_PLAINTEXT), 'security_test.txt'),
        'document_type': 'Security Test'
    }
    logged_in_client.post('/upload', data=data, content_type='multipart/form-data')

    with app.app_context():
        doc = Document.query.filter_by(original_filename='security_test.txt').first()
        return doc


class TestSecurityDetailsRoute:
    def test_security_details_returns_200(self, logged_in_client, uploaded_doc, app):
        """GET /security/<id> returns 200 with real metadata."""
        with app.app_context():
            response = logged_in_client.get(f'/security/{uploaded_doc.id}')
            assert response.status_code == 200
            html = response.data.decode()

            # Verify real metadata is present
            assert 'AES-256-GCM' in html
            assert 'RSA-OAEP' in html
            assert 'security_test.txt' in html
            assert '12 bytes' in html  # nonce
            assert '16 bytes' in html  # auth tag
            assert '.enc' in html  # storage filename

    def test_security_details_unauthorized(self, client, app):
        """GET /security/<id> without login redirects."""
        response = client.get('/security/1')
        assert response.status_code == 302

    def test_security_details_wrong_user(self, logged_in_client, uploaded_doc, app):
        """Another user cannot access security details."""
        with app.app_context():
            password_hash = generate_password_hash("otherpass")
            pin_hash = generate_password_hash("654321")
            user2 = User(username="otheruser", password_hash=password_hash, pin_hash=pin_hash)
            db.session.add(user2)
            db.session.commit()

        # Login as different user
        logged_in_client.get('/logout')
        logged_in_client.post('/login', data={
            'username': 'otheruser',
            'password': 'otherpass'
        })

        with app.app_context():
            response = logged_in_client.get(f'/security/{uploaded_doc.id}', follow_redirects=True)
            assert b'Access denied' in response.data


class TestCiphertextPreviewRoute:
    def test_ciphertext_preview_returns_valid_hex(self, logged_in_client, uploaded_doc, app):
        """GET /security/<id>/ciphertext returns valid hex JSON."""
        with app.app_context():
            response = logged_in_client.get(f'/security/{uploaded_doc.id}/ciphertext')
            assert response.status_code == 200

            data = json.loads(response.data)
            assert 'hex' in data
            assert 'total_bytes' in data
            assert 'preview_bytes' in data

            # Verify hex string is valid
            hex_str = data['hex']
            hex_bytes = hex_str.split(' ')
            assert len(hex_bytes) > 0

            # Verify each element is a valid hex pair
            for hb in hex_bytes:
                assert len(hb) == 2
                int(hb, 16)  # Must not raise ValueError

            assert data['total_bytes'] > 0
            assert data['preview_bytes'] > 0
            assert data['preview_bytes'] <= 128

    def test_ciphertext_preview_matches_actual_file(self, logged_in_client, uploaded_doc, app):
        """The hex preview must match the actual bytes of the .enc file."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)

            # Read actual file bytes
            with open(doc.storage_path, 'rb') as f:
                actual_bytes = f.read(128)

            # Get preview from API
            response = logged_in_client.get(f'/security/{doc.id}/ciphertext')
            data = json.loads(response.data)

            # Reconstruct bytes from hex
            hex_bytes_list = data['hex'].split(' ')
            preview_bytes = bytes(int(h, 16) for h in hex_bytes_list)

            assert preview_bytes == actual_bytes, \
                "Hex preview must exactly match the actual bytes on disk"

    def test_ciphertext_preview_not_plaintext(self, logged_in_client, uploaded_doc, app):
        """Preview hex must NOT decode to the original plaintext."""
        with app.app_context():
            response = logged_in_client.get(f'/security/{uploaded_doc.id}/ciphertext')
            data = json.loads(response.data)

            hex_bytes_list = data['hex'].split(' ')
            preview_bytes = bytes(int(h, 16) for h in hex_bytes_list)

            assert SAMPLE_PLAINTEXT[:len(preview_bytes)] != preview_bytes, \
                "Ciphertext preview must not match plaintext"


class TestTamperDemoRoute:
    def test_tamper_demo_returns_result(self, logged_in_client, uploaded_doc, app):
        """POST /security/<id>/tamper-demo returns tamper detection result."""
        with app.app_context():
            response = logged_in_client.post(f'/security/{uploaded_doc.id}/tamper-demo')
            assert response.status_code == 200

            data = json.loads(response.data)
            assert 'original' in data
            assert 'tampered' in data
            assert 'explanation' in data

            # Original ciphertext should authenticate
            assert data['original']['authenticated'] is True
            assert data['original']['error'] is None

            # Tampered ciphertext should fail authentication
            assert data['tampered']['authenticated'] is False
            assert data['tampered']['error'] is not None
            assert 'modified' in data['tampered']['error'].lower() or 'failed' in data['tampered']['error'].lower()

    def test_tamper_demo_disabled_when_not_demo_mode(self, logged_in_client, uploaded_doc, app):
        """Tamper demo returns 403 when DEMO_MODE is False."""
        with app.app_context():
            app.config['DEMO_MODE'] = False
            response = logged_in_client.post(f'/security/{uploaded_doc.id}/tamper-demo')
            assert response.status_code == 403
            app.config['DEMO_MODE'] = True  # restore

    def test_tamper_demo_does_not_corrupt_file(self, logged_in_client, uploaded_doc, app):
        """After running tamper demo, the actual .enc file is unchanged."""
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)

            # Read original file bytes
            with open(doc.storage_path, 'rb') as f:
                original_bytes = f.read()

            # Run tamper demo
            logged_in_client.post(f'/security/{doc.id}/tamper-demo')

            # Verify file is unchanged
            with open(doc.storage_path, 'rb') as f:
                after_bytes = f.read()

            assert original_bytes == after_bytes, \
                "Tamper demo must NOT modify the actual encrypted file on disk"


class TestServeRoute:
    def test_serve_without_token_fails(self, logged_in_client, uploaded_doc, app):
        """GET /serve/<id> without token redirects with error."""
        with app.app_context():
            response = logged_in_client.get(f'/serve/{uploaded_doc.id}', follow_redirects=True)
            assert b'token missing' in response.data.lower() or b'please re-enter' in response.data.lower()

    def test_serve_with_wrong_token_fails(self, logged_in_client, uploaded_doc, app):
        """GET /serve/<id> with wrong token redirects with error."""
        with app.app_context():
            response = logged_in_client.get(
                f'/serve/{uploaded_doc.id}?token=wrong-token-value',
                follow_redirects=True
            )
            assert b'Invalid access token' in response.data or b'token missing' in response.data.lower()

    def test_serve_token_is_one_time_use(self, logged_in_client, uploaded_doc, app):
        """Serve token can only be used once."""
        import re
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)

            # Get token
            response = logged_in_client.post(f'/access/{doc.id}', data={
                'action': 'download',
                'pin': '123456'
            })
            html = response.data.decode()
            token_match = re.search(r'token=([a-f0-9\-]+)', html)
            assert token_match
            token = token_match.group(1)

            # First use should succeed
            response = logged_in_client.get(f'/serve/{doc.id}?token={token}')
            assert response.status_code == 200

            # Second use should fail (token already consumed)
            response = logged_in_client.get(
                f'/serve/{doc.id}?token={token}',
                follow_redirects=True
            )
            assert b'token missing' in response.data.lower() or b'already used' in response.data.lower()

    def test_serve_token_expires(self, logged_in_client, uploaded_doc, app):
        """Serve token expires after SERVE_TOKEN_EXPIRY seconds."""
        import re
        with app.app_context():
            doc = Document.query.get(uploaded_doc.id)

            # Set very short expiry for testing
            app.config['SERVE_TOKEN_EXPIRY'] = 0  # Immediate expiry

            response = logged_in_client.post(f'/access/{doc.id}', data={
                'action': 'download',
                'pin': '123456'
            })
            html = response.data.decode()
            token_match = re.search(r'token=([a-f0-9\-]+)', html)
            assert token_match
            token = token_match.group(1)

            # Token should be expired
            time.sleep(0.1)
            response = logged_in_client.get(
                f'/serve/{doc.id}?token={token}',
                follow_redirects=True
            )
            assert b'expired' in response.data.lower()

            app.config['SERVE_TOKEN_EXPIRY'] = 30  # restore


class TestEncryptionCompletePanel:
    def test_upload_shows_encryption_complete(self, logged_in_client, app):
        """After upload, dashboard shows encryption complete panel with real metadata."""
        data = {
            'file': (io.BytesIO(b'Encryption complete test content'), 'enc_test.txt'),
            'document_type': 'Test Type'
        }
        response = logged_in_client.post(
            '/upload', data=data, content_type='multipart/form-data',
            follow_redirects=True
        )
        html = response.data.decode()

        assert 'ENCRYPTION COMPLETE' in html
        assert 'Random 256-bit AES key generated' in html
        assert 'AES-256-GCM encryption completed' in html
        assert 'GCM nonce generated' in html
        assert 'GCM authentication tag generated' in html
        assert 'AES key protected using RSA-OAEP' in html
        assert '.enc' in html  # storage filename

    def test_encryption_complete_not_shown_on_refresh(self, logged_in_client, app):
        """Encryption complete panel only appears once (session pop)."""
        data = {
            'file': (io.BytesIO(b'One time test content'), 'onetime.txt'),
        }
        logged_in_client.post('/upload', data=data, content_type='multipart/form-data')

        # First visit shows the panel
        response = logged_in_client.get('/')
        html = response.data.decode()
        assert 'ENCRYPTION COMPLETE' in html

        # Second visit should not show it
        response = logged_in_client.get('/')
        html = response.data.decode()
        assert 'ENCRYPTION COMPLETE' not in html
