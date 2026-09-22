"""
Comprehensive tests for the Three-Tab Architecture, Simplified Security Details,
and the interactive Cryptography Lab.
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
import documents.routes as dr


SAMPLE_CONTENT = b"Confidential Medical Form: Patient diagnosis and treatment plan."


@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp()
    keys_dir = tempfile.mkdtemp()
    storage_dir = tempfile.mkdtemp()

    app = create_app()
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test-secret-key-12345'
    app.config['RSA_KEY_DIR'] = keys_dir
    app.config['DEMO_MODE'] = True

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
def user_and_doc(client, app):
    with app.app_context():
        password_hash = generate_password_hash("password123")
        pin_hash = generate_password_hash("123456")
        user = User(username="alice", password_hash=password_hash, pin_hash=pin_hash)
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    client.post('/login', data={'username': 'alice', 'password': 'password123'})

    data = {
        'file': (io.BytesIO(SAMPLE_CONTENT), 'medical_form.pdf'),
        'document_type': 'Medical Form'
    }
    client.post('/upload', data=data, content_type='multipart/form-data')

    with app.app_context():
        doc = Document.query.filter_by(original_filename='medical_form.pdf').first()
        doc_id = doc.id
        storage_path = doc.storage_path

    return {'user_id': user_id, 'doc_id': doc_id, 'storage_path': storage_path}


class TestThreeTabNavigation:
    def test_dashboard_navigation_tabs(self, client, user_and_doc):
        resp = client.get('/')
        assert resp.status_code == 200
        html = resp.data.decode()
        assert 'Dashboard' in html
        assert 'How It Works' in html
        assert 'Cryptography Lab' in html
        assert 'Logout' in html

    def test_how_it_works_page(self, client, user_and_doc):
        resp = client.get('/how-it-works')
        assert resp.status_code == 200
        html = resp.data.decode()
        assert 'Hybrid Encryption' in html
        assert 'AES-256-GCM' in html
        assert 'RSA-OAEP' in html
        assert 'ORIGINAL DOCUMENT' in html
        assert 'ENCRYPTED DOCUMENT' in html
        # Syllabus-aligned simplified explanation:
        assert 'RSA-OAEP is used to securely protect the random AES-256 document key' in html
        # Must not contain advanced proof jargon:
        assert 'chosen-ciphertext' not in html.lower()
        assert 'padding oracle' not in html.lower()

    def test_cryptography_lab_page(self, client, user_and_doc):
        resp = client.get('/cryptography-lab')
        assert resp.status_code == 200
        html = resp.data.decode()
        assert 'Cryptography Laboratory' in html
        assert 'medical_form.pdf' in html
        assert 'Locker PIN' in html
        assert 'EXPERIMENT 1' in html
        assert 'EXPERIMENT 2' in html


class TestSimplifiedSecurityDetails:
    def test_security_details_simplified_content(self, client, user_and_doc):
        doc_id = user_and_doc['doc_id']
        resp = client.get(f'/security/{doc_id}')
        assert resp.status_code == 200
        html = resp.data.decode()

        # Document Information
        assert 'medical_form.pdf' in html
        assert 'Medical Form' in html
        assert 'Encrypted' in html

        # Encryption Metadata
        assert 'AES-256-GCM' in html
        assert '256-bit' in html
        assert '12 bytes' in html
        assert '16 bytes' in html
        assert 'RSA-OAEP' in html
        assert '.enc' in html

        # REMOVED sections:
        assert 'Ciphertext Exposure Demonstration' not in html
        assert 'View Encrypted File Data' not in html
        assert 'Tamper Detection Demonstration' not in html
        assert 'What an attacker has' not in html


class TestCryptographyLabExperiments:
    def test_lab_init_wrong_pin(self, client, user_and_doc):
        doc_id = user_and_doc['doc_id']
        resp = client.post('/cryptography-lab/init', json={
            'doc_id': doc_id,
            'pin': '999999'
        })
        assert resp.status_code == 401
        data = resp.get_json()
        assert 'Incorrect Locker PIN' in data['error']

    def test_lab_init_other_user_doc_forbidden(self, client, app, user_and_doc):
        with app.app_context():
            u2 = User(
                username="bob",
                password_hash=generate_password_hash("bobpass"),
                pin_hash=generate_password_hash("112233")
            )
            db.session.add(u2)
            db.session.commit()

        client.get('/logout')
        client.post('/login', data={'username': 'bob', 'password': 'bobpass'})

        # Bob attempts to access Alice's doc
        resp = client.post('/cryptography-lab/init', json={
            'doc_id': user_and_doc['doc_id'],
            'pin': '112233'
        })
        assert resp.status_code == 403

    def test_lab_init_success(self, client, user_and_doc):
        doc_id = user_and_doc['doc_id']
        resp = client.post('/cryptography-lab/init', json={
            'doc_id': doc_id,
            'pin': '123456'
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert 'lab_token' in data
        assert len(data['lab_token']) == 64  # 32-byte hex token

    def test_experiment_1_normal_mode(self, client, user_and_doc):
        doc_id = user_and_doc['doc_id']
        init_resp = client.post('/cryptography-lab/init', json={'doc_id': doc_id, 'pin': '123456'})
        token = init_resp.get_json()['lab_token']

        # Run Normal Mode
        resp = client.post('/cryptography-lab/run-normal', json={'lab_token': token})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data['matches'] is True
        assert 'CRYPTOGRAPHIC ROUND TRIP SUCCESSFUL' in data['status']
        assert len(data['steps']) == 7

    def test_experiment_1_step_by_step_sequential(self, client, user_and_doc):
        doc_id = user_and_doc['doc_id']
        init_resp = client.post('/cryptography-lab/init', json={'doc_id': doc_id, 'pin': '123456'})
        token = init_resp.get_json()['lab_token']

        # Step 1
        s1 = client.post('/cryptography-lab/step', json={'lab_token': token, 'step': 1}).get_json()
        assert s1['success'] is True
        assert s1['step'] == 1

        # Step 2
        s2 = client.post('/cryptography-lab/step', json={'lab_token': token, 'step': 2}).get_json()
        assert s2['success'] is True
        assert s2['key_size'] == '256-bit'

        # Step 3
        s3 = client.post('/cryptography-lab/step', json={'lab_token': token, 'step': 3}).get_json()
        assert s3['success'] is True
        assert s3['ciphertext_size'] > 0

        # Step 4
        s4 = client.post('/cryptography-lab/step', json={'lab_token': token, 'step': 4}).get_json()
        assert s4['success'] is True
        assert '12 bytes' in s4['nonce_size']
        assert '16 bytes' in s4['tag_size']

        # Step 5
        s5 = client.post('/cryptography-lab/step', json={'lab_token': token, 'step': 5}).get_json()
        assert s5['success'] is True
        assert 'RSA' in s5['title']

        # Step 6
        s6 = client.post('/cryptography-lab/step', json={'lab_token': token, 'step': 6}).get_json()
        assert s6['success'] is True
        assert 'Key recovered' in s6['status']

        # Step 7
        s7 = client.post('/cryptography-lab/step', json={'lab_token': token, 'step': 7}).get_json()
        assert s7['success'] is True
        assert s7['verified'] is True
        assert s7['matches'] is True
        assert 'CRYPTOGRAPHIC ROUND TRIP SUCCESSFUL' in s7['status']

    def test_experiment_2_tamper_detection_and_restore(self, client, user_and_doc):
        doc_id = user_and_doc['doc_id']
        init_resp = client.post('/cryptography-lab/init', json={'doc_id': doc_id, 'pin': '123456'})
        token = init_resp.get_json()['lab_token']

        # Record original disk file content
        with open(user_and_doc['storage_path'], 'rb') as f:
            disk_content_before = f.read()

        # Initialize tamper lab
        t_init = client.post('/cryptography-lab/init-tamper', json={'lab_token': token}).get_json()
        assert t_init['success'] is True
        assert len(t_init['rows']) > 0

        # Initial decryption should succeed
        dec1 = client.post('/cryptography-lab/test-decryption', json={'lab_token': token}).get_json()
        assert dec1['authenticated'] is True
        assert 'successful' in dec1['message'].lower()

        # Tamper: modify byte at offset 0 to 'FF'
        first_row = t_init['rows'][0]
        orig_hex = first_row['hex_bytes'][0]
        new_hex = '00' if orig_hex != '00' else 'FF'

        mod_resp = client.post('/cryptography-lab/modify-byte', json={
            'lab_token': token,
            'offset': 0,
            'new_val': new_hex
        }).get_json()
        assert mod_resp['success'] is True
        assert mod_resp['is_modified'] is True

        # Decryption of tampered ciphertext MUST fail GCM authentication
        dec_tampered = client.post('/cryptography-lab/test-decryption', json={'lab_token': token}).get_json()
        assert dec_tampered['authenticated'] is False
        assert 'failed' in dec_tampered['message'].lower()

        # Restore the original byte
        rest_resp = client.post('/cryptography-lab/restore-byte', json={
            'lab_token': token,
            'offset': 0
        }).get_json()
        assert rest_resp['success'] is True
        assert rest_resp['is_modified'] is False

        # Decryption of restored ciphertext MUST succeed again!
        dec_restored = client.post('/cryptography-lab/test-decryption', json={'lab_token': token}).get_json()
        assert dec_restored['authenticated'] is True
        assert 'successful' in dec_restored['message'].lower()

        # CRITICAL VERIFICATION: Stored document on disk must be completely untouched!
        with open(user_and_doc['storage_path'], 'rb') as f:
            disk_content_after = f.read()
        assert disk_content_before == disk_content_after, "Stored encrypted file on disk was modified!"

    def test_tamper_byte_invalid_hex_rejected(self, client, user_and_doc):
        doc_id = user_and_doc['doc_id']
        init_resp = client.post('/cryptography-lab/init', json={'doc_id': doc_id, 'pin': '123456'})
        token = init_resp.get_json()['lab_token']
        client.post('/cryptography-lab/init-tamper', json={'lab_token': token})

        # Invalid 3-letter hex
        resp = client.post('/cryptography-lab/modify-byte', json={
            'lab_token': token,
            'offset': 0,
            'new_val': 'XYZ'
        })
        assert resp.status_code == 400

        # Invalid single char
        resp2 = client.post('/cryptography-lab/modify-byte', json={
            'lab_token': token,
            'offset': 0,
            'new_val': 'F'
        })
        assert resp2.status_code == 400

    def test_lab_reset_deletes_session(self, client, user_and_doc):
        doc_id = user_and_doc['doc_id']
        init_resp = client.post('/cryptography-lab/init', json={'doc_id': doc_id, 'pin': '123456'})
        token = init_resp.get_json()['lab_token']

        # Reset lab
        reset_resp = client.post('/cryptography-lab/reset', json={'lab_token': token})
        assert reset_resp.status_code == 200

        # Subsequent calls with that token should fail
        step_resp = client.post('/cryptography-lab/step', json={'lab_token': token, 'step': 1})
        assert step_resp.status_code == 401
