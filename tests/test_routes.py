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
from crypto.rsa_engine import initialize_keys

@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp()
    keys_dir = tempfile.mkdtemp()
    
    app = create_app()
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['RSA_KEY_DIR'] = keys_dir
    
    with app.app_context():
        db.create_all()
        initialize_keys()
        yield app
        db.drop_all()
    
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def user(app):
    with app.app_context():
        password_hash = generate_password_hash("testpassword")
        pin_hash = generate_password_hash("123456")
        user = User(username="testuser", password_hash=password_hash, pin_hash=pin_hash)
        db.session.add(user)
        db.session.commit()
        return user.id

class TestAuthRoutes:
    def test_register_get(self, client):
        response = client.get('/register')
        assert response.status_code == 200
        assert b'Register' in response.data
    
    def test_register_post_success(self, client):
        response = client.post('/register', data={
            'username': 'newuser',
            'password': 'password123',
            'pin': '123456',
            'confirm_pin': '123456'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'Registration successful' in response.data
    
    def test_login_post_success(self, client, user):
        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'testpassword'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'Logged in successfully' in response.data
        
class TestDocumentRoutes:
    def test_upload_and_download(self, client, user):
        client.post('/login', data={
            'username': 'testuser',
            'password': 'testpassword'
        })
        
        data = {
            'file': (io.BytesIO(b'Test document content'), 'test.txt')
        }
        response = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
        assert b'File uploaded and encrypted successfully' in response.data
        
        with client.application.app_context():
            doc = Document.query.filter_by(original_filename='test.txt').first()
            assert doc is not None
            
            # First get the PIN prompt page
            response = client.get(f'/access/{doc.id}?action=download')
            assert response.status_code == 200
            
            # Then submit PIN to verify decryption
            response = client.post(f'/access/{doc.id}', data={
                'action': 'download',
                'pin': '123456'
            })
            assert response.status_code == 200
            html = response.data.decode()
            import re
            token_match = re.search(r'token=([a-f0-9\-]+)', html)
            assert token_match, "Serve token must be present"
            token = token_match.group(1)

            # Serve document using one-time token
            serve_resp = client.get(f'/serve/{doc.id}?token={token}')
            assert serve_resp.status_code == 200
            assert serve_resp.data == b'Test document content'
            
    def test_tampered_download_fails(self, client, user):
        client.post('/login', data={
            'username': 'testuser',
            'password': 'testpassword'
        })
        
        data = {
            'file': (io.BytesIO(b'Test document content'), 'test.txt')
        }
        client.post('/upload', data=data, content_type='multipart/form-data')
        
        with client.application.app_context():
            doc = Document.query.filter_by(original_filename='test.txt').first()
            
            # Tamper with encrypted file on disk
            with open(doc.storage_path, 'r+b') as f:
                content = bytearray(f.read())
                content[0] ^= 0x01
                f.seek(0)
                f.write(content)
                
            # First get the PIN prompt page
            response = client.get(f'/access/{doc.id}?action=download')
            assert response.status_code == 200
            
            # Then submit PIN to download (should fail due to tampering)
            response = client.post(f'/access/{doc.id}', data={
                'action': 'download',
                'pin': '123456'
            }, follow_redirects=True)
            assert response.status_code == 200
            assert b'Decryption failed' in response.data
