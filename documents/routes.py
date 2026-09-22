import os
import io
import uuid
import time
import secrets
import re
import threading
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, session, send_file, abort, jsonify, current_app
)
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from auth.models import db, User
from documents.models import Document
from crypto.hybrid_engine import encrypt_document, decrypt_document
from crypto.aes_engine import encrypt as aes_encrypt, decrypt as aes_decrypt
from crypto.rsa_engine import load_public_key, load_private_key, encrypt_aes_key, decrypt_aes_key
from cryptography.exceptions import InvalidTag
from config import Config

STORAGE_PATH = Config.STORAGE_PATH

documents_bp = Blueprint('documents', __name__)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


def _get_rsa_key_size_bits():
    """Determine the RSA key size from the actual public key on disk."""
    try:
        pub = load_public_key()
        return pub.key_size
    except Exception:
        return None


def _get_document_or_abort(doc_id, user_id):
    """Fetch a document with ownership verification. Returns (document, error_redirect)."""
    document = Document.query.filter_by(id=doc_id).first()
    if not document:
        flash('Encrypted document not found.', 'error')
        return None, redirect(url_for('documents.dashboard'))
    if document.owner_id != user_id:
        flash('Access denied: You are not authorized to access this document.', 'error')
        return None, redirect(url_for('documents.dashboard'))
    return document, None


# ────────────────────────────────────────────────────────────────────
# DASHBOARD & MAIN TABS
# ────────────────────────────────────────────────────────────────────

@documents_bp.route('/')
@login_required
def dashboard():
    user_id = session['user_id']
    search_query = request.args.get('search', '').strip()
    
    query = Document.query.filter_by(owner_id=user_id)
    if search_query:
        # Case-insensitive partial search
        query = query.filter(Document.document_type.ilike(f'%{search_query}%'))
        
    documents = query.order_by(Document.uploaded_at.desc()).all()

    # Pop one-time encryption-complete data (set during upload)
    last_encryption = session.pop('last_encryption', None)

    return render_template(
        'dashboard.html',
        documents=documents,
        search_query=search_query,
        last_encryption=last_encryption,
        active_tab='dashboard',
    )


@documents_bp.route('/how-it-works')
@login_required
def how_it_works():
    rsa_key_size = _get_rsa_key_size_bits()
    return render_template(
        'how_it_works.html',
        active_tab='how_it_works',
        rsa_key_size=rsa_key_size
    )


@documents_bp.route('/cryptography-lab')
@login_required
def cryptography_lab():
    user_id = session['user_id']
    selected_doc_id = request.args.get('doc_id', type=int)
    documents = Document.query.filter_by(owner_id=user_id).order_by(Document.uploaded_at.desc()).all()

    selected_doc = None
    if selected_doc_id:
        selected_doc = Document.query.filter_by(id=selected_doc_id, owner_id=user_id).first()
    elif documents:
        selected_doc = documents[0]

    rsa_key_size = _get_rsa_key_size_bits()

    return render_template(
        'cryptography_lab.html',
        active_tab='cryptography_lab',
        documents=documents,
        selected_doc=selected_doc,
        rsa_key_size=rsa_key_size
    )


# ────────────────────────────────────────────────────────────────────
# UPLOAD  (modified: captures real encryption metadata)
# ────────────────────────────────────────────────────────────────────

@documents_bp.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('documents.dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('documents.dashboard'))
        
    document_type = request.form.get('document_type', '').strip()
    
    filename = secure_filename(file.filename)
    file_data = file.read()
    
    if not file_data:
        flash('Empty file not allowed', 'error')
        return redirect(url_for('documents.dashboard'))
    
    user_id = session['user_id']
    
    try:
        # Load the locker's RSA public key
        public_key = load_public_key()
        
        # Encrypt document using Hybrid Encryption (AES-GCM + RSA-OAEP)
        enc_data = encrypt_document(file_data, public_key)
        
    except Exception as e:
        flash('Encryption failed during upload.', 'error')
        return redirect(url_for('documents.dashboard'))
    
    file_id = str(uuid.uuid4())
    storage_filename = f"{file_id}.enc"
    storage_filepath = os.path.join(STORAGE_PATH, storage_filename)
    
    os.makedirs(STORAGE_PATH, exist_ok=True)
    
    with open(storage_filepath, 'wb') as f:
        f.write(enc_data['encrypted_file'])
    
    document = Document(
        owner_id=user_id,
        original_filename=filename,
        document_type=document_type if document_type else None,
        storage_path=storage_filepath,
        encrypted_aes_key=enc_data['encrypted_aes_key'],
        nonce=enc_data['nonce'],
        auth_tag=enc_data['auth_tag'],
        file_size=len(file_data)
    )
    
    db.session.add(document)
    db.session.commit()
    
    # Store real encryption metadata for the "Encryption Complete" panel
    rsa_key_size = _get_rsa_key_size_bits()
    session['last_encryption'] = {
        'filename': filename,
        'document_type': document_type if document_type else 'Not specified',
        'original_size': len(file_data),
        'ciphertext_size': len(enc_data['encrypted_file']),
        'nonce_len': len(enc_data['nonce']),
        'tag_len': len(enc_data['auth_tag']),
        'encrypted_key_len': len(enc_data['encrypted_aes_key']),
        'storage_filename': storage_filename,
        'rsa_key_size': rsa_key_size,
    }
    
    flash('File uploaded and encrypted successfully', 'success')
    return redirect(url_for('documents.dashboard'))


# ────────────────────────────────────────────────────────────────────
# ACCESS  (modified: two-step flow — verify then show status page)
# ────────────────────────────────────────────────────────────────────

@documents_bp.route('/access/<int:doc_id>', methods=['GET', 'POST'])
@login_required
def access(doc_id):
    user_id = session['user_id']
    document, err = _get_document_or_abort(doc_id, user_id)
    if err:
        return err
        
    # Action validation
    if request.method == 'POST':
        action = request.form.get('action')
    else:
        action = request.args.get('action')
        
    if action not in ['view', 'download']:
        flash('Invalid action requested.', 'error')
        return redirect(url_for('documents.dashboard'))
        
    if request.method == 'GET':
        return render_template('pin_prompt.html', document=document, action=action)
        
    # Handle POST (PIN submission)
    pin = request.form.get('pin', '')
    if not pin:
        flash('PIN is required.', 'error')
        return render_template('pin_prompt.html', document=document, action=action)
        
    # PIN Validation
    user = User.query.get(user_id)
    if not check_password_hash(user.pin_hash, pin):
        flash('Incorrect Locker PIN.', 'error')
        return render_template('pin_prompt.html', document=document, action=action)
    
    # PIN is correct — perform first decryption to verify crypto pipeline
    decryption_steps = []
    decryption_steps.append({'step': 'Locker PIN verified', 'ok': True})

    try:
        if not os.path.exists(document.storage_path):
            flash('Encrypted document not found on disk.', 'error')
            return redirect(url_for('documents.dashboard'))
            
        with open(document.storage_path, 'rb') as f:
            encrypted_file = f.read()
        
        # Load the locker's RSA private key
        private_key = load_private_key()
        
        # Decrypt document using Hybrid Decryption (RSA-OAEP + AES-GCM)
        # This is the FIRST real decryption — used to verify the crypto pipeline
        plaintext = decrypt_document(
            encrypted_file, 
            document.encrypted_aes_key, 
            document.nonce, 
            document.auth_tag, 
            private_key
        )
        
        decryption_steps.append({'step': 'RSA-OAEP decrypted the protected AES key', 'ok': True})
        decryption_steps.append({'step': 'AES-256-GCM decrypted the document', 'ok': True})
        decryption_steps.append({'step': 'GCM authentication tag verified', 'ok': True})
        decryption_steps.append({'step': 'Document successfully recovered', 'ok': True})

        # Plaintext is intentionally discarded here — NOT cached.
        # The /serve route will perform the second decryption.
        del plaintext
        
    except InvalidTag:
        decryption_steps.append({'step': 'RSA-OAEP decrypted the protected AES key', 'ok': True})
        decryption_steps.append({'step': 'AES-256-GCM decryption failed', 'ok': False})
        decryption_steps.append({'step': 'GCM authentication tag verification FAILED', 'ok': False})
        decryption_steps.append({
            'step': 'Decryption failed: the encrypted document may have been modified or corrupted.',
            'ok': False
        })
        return render_template(
            'decryption_success.html',
            document=document,
            action=action,
            steps=decryption_steps,
            success=False,
            serve_token=None,
        )
    except ValueError:
        decryption_steps.append({'step': 'RSA-OAEP key recovery FAILED', 'ok': False})
        decryption_steps.append({
            'step': 'Unable to recover the document encryption key.',
            'ok': False
        })
        return render_template(
            'decryption_success.html',
            document=document,
            action=action,
            steps=decryption_steps,
            success=False,
            serve_token=None,
        )
    except Exception as e:
        decryption_steps.append({
            'step': 'An error occurred during decryption.',
            'ok': False
        })
        return render_template(
            'decryption_success.html',
            document=document,
            action=action,
            steps=decryption_steps,
            success=False,
            serve_token=None,
        )

    # Create a short-lived, one-time-use serve token
    token = str(uuid.uuid4())
    session[f'serve_token_{doc_id}'] = {
        'token': token,
        'action': action,
        'created_at': time.time(),
    }

    return render_template(
        'decryption_success.html',
        document=document,
        action=action,
        steps=decryption_steps,
        success=True,
        serve_token=token,
    )


# ────────────────────────────────────────────────────────────────────
# SERVE  (new: second decryption, one-time-use token)
# ────────────────────────────────────────────────────────────────────

@documents_bp.route('/serve/<int:doc_id>')
@login_required
def serve(doc_id):
    user_id = session['user_id']
    document, err = _get_document_or_abort(doc_id, user_id)
    if err:
        return err

    # Validate the one-time serve token
    token_key = f'serve_token_{doc_id}'
    token_data = session.pop(token_key, None)  # One-time use: pop immediately

    if not token_data:
        flash('Access token missing or already used. Please re-enter your PIN.', 'error')
        return redirect(url_for('documents.dashboard'))

    provided_token = request.args.get('token', '')
    if provided_token != token_data.get('token'):
        flash('Invalid access token. Please re-enter your PIN.', 'error')
        return redirect(url_for('documents.dashboard'))

    # Check token expiry
    token_expiry = current_app.config.get('SERVE_TOKEN_EXPIRY', 30)
    if time.time() - token_data.get('created_at', 0) > token_expiry:
        flash('Access token has expired. Please re-enter your PIN.', 'error')
        return redirect(url_for('documents.dashboard'))

    action = token_data.get('action', 'download')

    # Second decryption — this one actually serves the file
    try:
        if not os.path.exists(document.storage_path):
            flash('Encrypted document not found on disk.', 'error')
            return redirect(url_for('documents.dashboard'))

        with open(document.storage_path, 'rb') as f:
            encrypted_file = f.read()

        private_key = load_private_key()

        plaintext = decrypt_document(
            encrypted_file,
            document.encrypted_aes_key,
            document.nonce,
            document.auth_tag,
            private_key
        )

        import mimetypes
        mimetype, _ = mimetypes.guess_type(document.original_filename)
        if not mimetype:
            mimetype = 'application/octet-stream'

        as_attachment = (action == 'download')

        return send_file(
            io.BytesIO(plaintext),
            as_attachment=as_attachment,
            download_name=document.original_filename,
            mimetype=mimetype
        )

    except InvalidTag:
        flash('Decryption failed: the document may have been modified or corrupted.', 'error')
        return redirect(url_for('documents.dashboard'))
    except ValueError:
        flash('Unable to recover the document encryption key.', 'error')
        return redirect(url_for('documents.dashboard'))
    except Exception as e:
        flash('An error occurred during decryption.', 'error')
        return redirect(url_for('documents.dashboard'))


# ────────────────────────────────────────────────────────────────────
# SECURITY DETAILS PAGE
# ────────────────────────────────────────────────────────────────────

@documents_bp.route('/security/<int:doc_id>')
@login_required
def security_details(doc_id):
    user_id = session['user_id']
    document, err = _get_document_or_abort(doc_id, user_id)
    if err:
        return err

    # Derive all metadata from actual stored data
    enc_file_exists = os.path.exists(document.storage_path)
    enc_file_size = os.path.getsize(document.storage_path) if enc_file_exists else 0
    storage_filename = os.path.basename(document.storage_path)

    nonce_len = len(document.nonce) if document.nonce else 0
    tag_len = len(document.auth_tag) if document.auth_tag else 0
    encrypted_key_len = len(document.encrypted_aes_key) if document.encrypted_aes_key else 0

    rsa_key_size = _get_rsa_key_size_bits()

    demo_mode = current_app.config.get('DEMO_MODE', False)

    return render_template(
        'security_details.html',
        document=document,
        enc_file_exists=enc_file_exists,
        enc_file_size=enc_file_size,
        storage_filename=storage_filename,
        nonce_len=nonce_len,
        tag_len=tag_len,
        encrypted_key_len=encrypted_key_len,
        rsa_key_size=rsa_key_size,
        demo_mode=demo_mode,
        active_tab='dashboard',
    )


# ────────────────────────────────────────────────────────────────────
# CIPHERTEXT PREVIEW API  (AJAX)
# ────────────────────────────────────────────────────────────────────

@documents_bp.route('/security/<int:doc_id>/ciphertext')
@login_required
def ciphertext_preview(doc_id):
    user_id = session['user_id']
    document, err = _get_document_or_abort(doc_id, user_id)
    if err:
        return jsonify({'error': 'Access denied'}), 403

    if not os.path.exists(document.storage_path):
        return jsonify({'error': 'Encrypted file not found on disk'}), 404

    preview_bytes = 128
    total_bytes = os.path.getsize(document.storage_path)

    with open(document.storage_path, 'rb') as f:
        raw = f.read(preview_bytes)

    hex_str = ' '.join(f'{b:02X}' for b in raw)

    return jsonify({
        'hex': hex_str,
        'total_bytes': total_bytes,
        'preview_bytes': len(raw),
    })


# ────────────────────────────────────────────────────────────────────
# TAMPER DETECTION DEMO  (AJAX, dev-only, in-memory only)
# ────────────────────────────────────────────────────────────────────

@documents_bp.route('/security/<int:doc_id>/tamper-demo', methods=['POST'])
@login_required
def tamper_demo(doc_id):
    if not current_app.config.get('DEMO_MODE', False):
        return jsonify({'error': 'Tamper demo is disabled'}), 403

    user_id = session['user_id']
    document, err = _get_document_or_abort(doc_id, user_id)
    if err:
        return jsonify({'error': 'Access denied'}), 403

    if not os.path.exists(document.storage_path):
        return jsonify({'error': 'Encrypted file not found on disk'}), 404

    with open(document.storage_path, 'rb') as f:
        original_ciphertext = f.read()

    private_key = load_private_key()

    # --- Step 1: Verify original ciphertext authenticates correctly ---
    original_ok = False
    original_error = None
    try:
        decrypt_document(
            original_ciphertext,
            document.encrypted_aes_key,
            document.nonce,
            document.auth_tag,
            private_key
        )
        original_ok = True
    except InvalidTag:
        original_error = 'GCM authentication failed on original ciphertext'
    except Exception as e:
        original_error = f'Decryption error: {str(e)}'

    # --- Step 2: Tamper with an IN-MEMORY COPY — flip one byte ---
    tampered_ciphertext = bytearray(original_ciphertext)
    if len(tampered_ciphertext) > 0:
        tampered_ciphertext[0] ^= 0x01
    tampered_ciphertext = bytes(tampered_ciphertext)

    tampered_ok = False
    tampered_error = None
    try:
        decrypt_document(
            tampered_ciphertext,
            document.encrypted_aes_key,
            document.nonce,
            document.auth_tag,
            private_key
        )
        tampered_ok = True
    except InvalidTag:
        tampered_error = 'GCM authentication failed: the encrypted document has been modified or corrupted.'
    except Exception as e:
        tampered_error = f'Decryption error: {str(e)}'

    return jsonify({
        'original': {
            'authenticated': original_ok,
            'error': original_error,
        },
        'tampered': {
            'authenticated': tampered_ok,
            'error': tampered_error,
        },
        'explanation': (
            'One byte of the encrypted ciphertext was modified in memory. '
            'AES-256-GCM detected the modification and rejected the tampered data. '
            'The actual stored document was NOT modified.'
        ),
    })


# ────────────────────────────────────────────────────────────────────
# CRYPTOGRAPHY LAB IN-MEMORY STORE & APIS
# ────────────────────────────────────────────────────────────────────

LAB_STORE = {}
LAB_STORE_LOCK = threading.Lock()
LAB_SESSION_TTL_SECONDS = 900  # 15 minutes auto-expiry


def _cleanup_expired_lab_sessions():
    """Remove expired lab sessions older than 15 minutes."""
    now = time.time()
    with LAB_STORE_LOCK:
        expired = [k for k, v in LAB_STORE.items() if now - v.get('last_activity', 0) > LAB_SESSION_TTL_SECONDS]
        for k in expired:
            del LAB_STORE[k]


def _get_lab_session(token, user_id):
    """Fetch active lab session belonging to current user or None."""
    _cleanup_expired_lab_sessions()
    if not token:
        return None
    with LAB_STORE_LOCK:
        data = LAB_STORE.get(token)
        if not data:
            return None
        if data.get('user_id') != user_id:
            return None
        data['last_activity'] = time.time()
        return data


def _format_hex_dump(data_bytes, max_bytes=128):
    """Format bytes into offset + hex rows for lab display."""
    preview = data_bytes[:max_bytes]
    rows = []
    for i in range(0, len(preview), 8):
        chunk = preview[i:i+8]
        offset_str = f"{i:08X}"
        hex_bytes = [f"{b:02X}" for b in chunk]
        rows.append({
            'offset': offset_str,
            'offset_int': i,
            'hex_bytes': hex_bytes,
        })
    return rows


@documents_bp.route('/cryptography-lab/init', methods=['POST'])
@login_required
def lab_init():
    user_id = session['user_id']
    req_data = request.get_json(silent=True) or request.form
    doc_id = req_data.get('doc_id')
    pin = req_data.get('pin', '')

    if not doc_id:
        return jsonify({'error': 'Document ID is required'}), 400

    try:
        doc_id = int(doc_id)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid document ID'}), 400

    document, err = _get_document_or_abort(doc_id, user_id)
    if err:
        return jsonify({'error': 'Access denied or document not found'}), 403

    if not pin:
        return jsonify({'error': 'Locker PIN is required'}), 400

    user = User.query.get(user_id)
    if not check_password_hash(user.pin_hash, pin):
        return jsonify({'error': 'Incorrect Locker PIN'}), 401

    if not os.path.exists(document.storage_path):
        return jsonify({'error': 'Encrypted document not found on disk'}), 404

    # Read encrypted document from disk
    with open(document.storage_path, 'rb') as f:
        encrypted_file = f.read()

    # Recover AES key and decrypt document strictly in memory
    try:
        private_key = load_private_key()
        aes_key = decrypt_aes_key(document.encrypted_aes_key, private_key)
        plaintext = aes_decrypt(aes_key, encrypted_file, document.nonce, document.auth_tag)
    except Exception as e:
        return jsonify({'error': 'Decryption of selected document failed'}), 500

    # Cryptographically random token
    lab_token = secrets.token_hex(32)

    with LAB_STORE_LOCK:
        LAB_STORE[lab_token] = {
            'user_id': user_id,
            'doc_id': document.id,
            'filename': document.original_filename,
            'document_type': document.document_type or 'General Document',
            'original_size': len(plaintext),
            'plaintext': plaintext,  # temporary in-memory copy ONLY
            # Step-by-step state
            'step2_key': None,
            'step3_ciphertext': None,
            'step4_nonce': None,
            'step4_tag': None,
            'step5_enc_key': None,
            'step6_recovered_key': None,
            # Tamper experiment state
            'tamper_key': None,
            'tamper_original_ciphertext': None,
            'tamper_current_ciphertext': None,
            'tamper_nonce': None,
            'tamper_tag': None,
            'modified_bytes': {},
            'created_at': time.time(),
            'last_activity': time.time(),
        }

    return jsonify({
        'success': True,
        'lab_token': lab_token,
        'document': {
            'id': document.id,
            'filename': document.original_filename,
            'type': document.document_type or 'General Document',
            'size': len(plaintext),
            'status': 'Encrypted'
        }
    })


@documents_bp.route('/cryptography-lab/step', methods=['POST'])
@login_required
def lab_step():
    user_id = session['user_id']
    req_data = request.get_json(silent=True) or request.form
    token = req_data.get('lab_token')
    step = req_data.get('step')

    try:
        step = int(step)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid step number'}), 400

    lab_data = _get_lab_session(token, user_id)
    if not lab_data:
        return jsonify({'error': 'Lab session expired or invalid. Please re-authenticate.'}), 401

    plaintext = lab_data['plaintext']

    try:
        if step == 1:
            # Step 1: Prepare temporary plaintext copy
            return jsonify({
                'success': True,
                'step': 1,
                'title': 'Original Document Prepared',
                'description': 'Temporary laboratory copy prepared in memory.',
                'filename': lab_data['filename'],
                'size': len(plaintext),
                'details': f'{lab_data["filename"]} ({len(plaintext)} bytes) loaded securely in memory.',
                'status': 'Temporary laboratory copy prepared'
            })

        elif step == 2:
            # Step 2: Generate a NEW random 256-bit AES key
            new_key = os.urandom(32)
            lab_data['step2_key'] = new_key
            return jsonify({
                'success': True,
                'step': 2,
                'title': 'Generate Random AES-256 Key',
                'description': 'A new random 256-bit AES key has been generated.',
                'key_size': '256-bit',
                'status': 'Generated',
                'details': '✓ A new cryptographically random 256-bit AES key has been generated in memory.'
            })

        elif step == 3:
            # Step 3: AES-256-GCM Encryption
            if not lab_data.get('step2_key'):
                lab_data['step2_key'] = os.urandom(32)

            ciphertext, nonce, tag = aes_encrypt(lab_data['step2_key'], plaintext)
            lab_data['step3_ciphertext'] = ciphertext
            lab_data['step4_nonce'] = nonce
            lab_data['step4_tag'] = tag

            return jsonify({
                'success': True,
                'step': 3,
                'title': 'AES-256-GCM Encryption',
                'description': 'Temporary plaintext encrypted with AES-256-GCM.',
                'ciphertext_size': len(ciphertext),
                'status': 'Encryption completed',
                'details': f'✓ In-memory encryption complete ({len(ciphertext)} bytes of ciphertext produced).'
            })

        elif step == 4:
            # Step 4: GCM Parameters
            if not lab_data.get('step4_nonce') or not lab_data.get('step4_tag'):
                return jsonify({'error': 'Step 3 must be executed first'}), 400

            nonce_len = len(lab_data['step4_nonce'])
            tag_len = len(lab_data['step4_tag'])

            return jsonify({
                'success': True,
                'step': 4,
                'title': 'GCM Parameters',
                'description': 'GCM Nonce and Authentication Tag generated.',
                'nonce_size': f'{nonce_len} bytes',
                'tag_size': f'{tag_len} bytes',
                'status': 'Generated',
                'details': f'✓ Nonce: {nonce_len} bytes (unique IV), Authentication Tag: {tag_len} bytes (integrity/authenticity check).'
            })

        elif step == 5:
            # Step 5: RSA-OAEP Key Protection
            if not lab_data.get('step2_key'):
                return jsonify({'error': 'AES key missing from previous step'}), 400

            public_key = load_public_key()
            encrypted_aes_key = encrypt_aes_key(lab_data['step2_key'], public_key)
            lab_data['step5_enc_key'] = encrypted_aes_key

            return jsonify({
                'success': True,
                'step': 5,
                'title': 'RSA-OAEP Key Protection',
                'description': 'AES-256 laboratory key protected with RSA-OAEP.',
                'rsa_key_size': f'{public_key.key_size}-bit',
                'encrypted_key_size': f'{len(encrypted_aes_key)} bytes',
                'status': 'Key protection completed',
                'details': f'✓ AES-256 key protected using RSA-OAEP with {public_key.key_size}-bit public key.'
            })

        elif step == 6:
            # Step 6: Decryption Key Recovery
            if not lab_data.get('step5_enc_key'):
                return jsonify({'error': 'Encrypted key missing from Step 5'}), 400

            private_key = load_private_key()
            recovered_key = decrypt_aes_key(lab_data['step5_enc_key'], private_key)
            lab_data['step6_recovered_key'] = recovered_key

            return jsonify({
                'success': True,
                'step': 6,
                'title': 'Decryption Key Recovery',
                'description': 'RSA-OAEP recovers the AES key using the private key.',
                'status': 'Key recovered',
                'details': '✓ RSA-OAEP private-key operation successfully recovered the AES-256 document key.'
            })

        elif step == 7:
            # Step 7: AES-256-GCM Decryption & Authentication Verification
            if not lab_data.get('step6_recovered_key') or not lab_data.get('step3_ciphertext'):
                return jsonify({'error': 'Previous steps required before Step 7'}), 400

            recovered_plaintext = aes_decrypt(
                lab_data['step6_recovered_key'],
                lab_data['step3_ciphertext'],
                lab_data['step4_nonce'],
                lab_data['step4_tag']
            )

            matches = (recovered_plaintext == plaintext)

            return jsonify({
                'success': True,
                'step': 7,
                'title': 'Authentication Verification',
                'description': 'GCM authentication successful and plaintext recovered.',
                'matches': matches,
                'verified': True,
                'status': 'CRYPTOGRAPHIC ROUND TRIP SUCCESSFUL',
                'details': '✓ GCM authentication successful\n✓ Plaintext recovered\n✓ Recovered data matches original temporary data'
            })

        else:
            return jsonify({'error': 'Step must be between 1 and 7'}), 400

    except Exception as e:
        return jsonify({'error': f'Cryptographic operation failed: {str(e)}'}), 500


@documents_bp.route('/cryptography-lab/run-normal', methods=['POST'])
@login_required
def lab_run_normal():
    user_id = session['user_id']
    req_data = request.get_json(silent=True) or request.form
    token = req_data.get('lab_token')

    lab_data = _get_lab_session(token, user_id)
    if not lab_data:
        return jsonify({'error': 'Lab session expired or invalid. Please re-authenticate.'}), 401

    plaintext = lab_data['plaintext']
    public_key = load_public_key()
    private_key = load_private_key()

    try:
        # Step 1: Prep
        # Step 2: New AES key
        lab_aes_key = os.urandom(32)
        # Step 3: Encrypt with AES-GCM
        ciphertext, nonce, tag = aes_encrypt(lab_aes_key, plaintext)
        # Step 4: Params (nonce, tag)
        # Step 5: Protect AES key with RSA-OAEP
        encrypted_aes_key = encrypt_aes_key(lab_aes_key, public_key)
        # Step 6: Recover AES key with RSA private key
        recovered_key = decrypt_aes_key(encrypted_aes_key, private_key)
        # Step 7: Decrypt with AES-GCM & verify
        recovered_plaintext = aes_decrypt(recovered_key, ciphertext, nonce, tag)
        matches = (recovered_plaintext == plaintext)

        steps = [
            {'step': 1, 'text': 'Temporary laboratory copy prepared', 'ok': True},
            {'step': 2, 'text': 'New random 256-bit AES key generated', 'ok': True},
            {'step': 3, 'text': f'AES-256-GCM encryption complete ({len(ciphertext)} bytes)', 'ok': True},
            {'step': 4, 'text': f'GCM Nonce ({len(nonce)} bytes) & Tag ({len(tag)} bytes) generated', 'ok': True},
            {'step': 5, 'text': f'AES key protected using RSA-OAEP ({public_key.key_size}-bit RSA)', 'ok': True},
            {'step': 6, 'text': 'AES key recovered using RSA-OAEP private key', 'ok': True},
            {'step': 7, 'text': 'AES-256-GCM decryption & authentication tag verified', 'ok': True},
        ]

        return jsonify({
            'success': True,
            'steps': steps,
            'matches': matches,
            'round_trip_success': True,
            'status': '🔐 CRYPTOGRAPHIC ROUND TRIP SUCCESSFUL',
            'summary': {
                'key_size': '256-bit',
                'nonce_size': f'{len(nonce)} bytes',
                'tag_size': f'{len(tag)} bytes',
                'rsa_key_size': f'{public_key.key_size}-bit',
                'ciphertext_size': f'{len(ciphertext)} bytes'
            }
        })
    except Exception as e:
        return jsonify({'error': f'Round trip failed: {str(e)}'}), 500


@documents_bp.route('/cryptography-lab/init-tamper', methods=['POST'])
@login_required
def lab_init_tamper():
    user_id = session['user_id']
    req_data = request.get_json(silent=True) or request.form
    token = req_data.get('lab_token')

    lab_data = _get_lab_session(token, user_id)
    if not lab_data:
        return jsonify({'error': 'Lab session expired or invalid. Please re-authenticate.'}), 401

    plaintext = lab_data['plaintext']

    # Generate a new random AES-256 key and encrypt the temporary plaintext
    tamper_key = os.urandom(32)
    ciphertext, nonce, tag = aes_encrypt(tamper_key, plaintext)

    lab_data['tamper_key'] = tamper_key
    lab_data['tamper_original_ciphertext'] = bytes(ciphertext)
    lab_data['tamper_current_ciphertext'] = bytearray(ciphertext)
    lab_data['tamper_nonce'] = nonce
    lab_data['tamper_tag'] = tag
    lab_data['modified_bytes'] = {}

    rows = _format_hex_dump(ciphertext, max_bytes=128)

    return jsonify({
        'success': True,
        'rows': rows,
        'total_bytes': len(ciphertext),
        'preview_bytes': min(len(ciphertext), 128),
        'modified_bytes': {}
    })


@documents_bp.route('/cryptography-lab/modify-byte', methods=['POST'])
@login_required
def lab_modify_byte():
    user_id = session['user_id']
    req_data = request.get_json(silent=True) or request.form
    token = req_data.get('lab_token')
    offset = req_data.get('offset')
    new_val = req_data.get('new_val', '').strip()

    lab_data = _get_lab_session(token, user_id)
    if not lab_data:
        return jsonify({'error': 'Lab session expired or invalid. Please re-authenticate.'}), 401

    if lab_data.get('tamper_current_ciphertext') is None:
        return jsonify({'error': 'Tamper lab not initialized'}), 400

    try:
        offset = int(offset)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid byte offset'}), 400

    ciphertext_len = len(lab_data['tamper_current_ciphertext'])
    if offset < 0 or offset >= ciphertext_len:
        return jsonify({'error': f'Offset {offset} is out of bounds (0 to {ciphertext_len - 1})'}), 400

    if not re.match(r'^[0-9A-Fa-f]{2}$', new_val):
        return jsonify({'error': 'Input must be exactly two hexadecimal characters (e.g. 00, 7A, FF)'}), 400

    new_val = new_val.upper()
    byte_val = int(new_val, 16)

    orig_byte = lab_data['tamper_original_ciphertext'][offset]
    orig_hex = f"{orig_byte:02X}"

    lab_data['tamper_current_ciphertext'][offset] = byte_val

    if new_val == orig_hex:
        lab_data['modified_bytes'].pop(str(offset), None)
    else:
        lab_data['modified_bytes'][str(offset)] = {
            'offset': offset,
            'original': orig_hex,
            'current': new_val
        }

    rows = _format_hex_dump(bytes(lab_data['tamper_current_ciphertext']), max_bytes=128)

    return jsonify({
        'success': True,
        'offset': offset,
        'original_val': orig_hex,
        'new_val': new_val,
        'rows': rows,
        'modified_bytes': lab_data['modified_bytes'],
        'is_modified': len(lab_data['modified_bytes']) > 0
    })


@documents_bp.route('/cryptography-lab/restore-byte', methods=['POST'])
@login_required
def lab_restore_byte():
    user_id = session['user_id']
    req_data = request.get_json(silent=True) or request.form
    token = req_data.get('lab_token')
    offset = req_data.get('offset')

    lab_data = _get_lab_session(token, user_id)
    if not lab_data:
        return jsonify({'error': 'Lab session expired or invalid. Please re-authenticate.'}), 401

    if lab_data.get('tamper_current_ciphertext') is None:
        return jsonify({'error': 'Tamper lab not initialized'}), 400

    if offset is not None and str(offset) != '':
        try:
            offset = int(offset)
            orig_byte = lab_data['tamper_original_ciphertext'][offset]
            lab_data['tamper_current_ciphertext'][offset] = orig_byte
            lab_data['modified_bytes'].pop(str(offset), None)
        except (ValueError, IndexError):
            return jsonify({'error': 'Invalid offset'}), 400
    else:
        # Restore all modified bytes
        lab_data['tamper_current_ciphertext'] = bytearray(lab_data['tamper_original_ciphertext'])
        lab_data['modified_bytes'] = {}

    rows = _format_hex_dump(bytes(lab_data['tamper_current_ciphertext']), max_bytes=128)

    return jsonify({
        'success': True,
        'rows': rows,
        'modified_bytes': lab_data['modified_bytes'],
        'is_modified': len(lab_data['modified_bytes']) > 0
    })


@documents_bp.route('/cryptography-lab/test-decryption', methods=['POST'])
@login_required
def lab_test_decryption():
    user_id = session['user_id']
    req_data = request.get_json(silent=True) or request.form
    token = req_data.get('lab_token')

    lab_data = _get_lab_session(token, user_id)
    if not lab_data:
        return jsonify({'error': 'Lab session expired or invalid. Please re-authenticate.'}), 401

    if lab_data.get('tamper_current_ciphertext') is None:
        return jsonify({'error': 'Tamper lab not initialized'}), 400

    is_modified = len(lab_data['modified_bytes']) > 0

    try:
        recovered = aes_decrypt(
            lab_data['tamper_key'],
            bytes(lab_data['tamper_current_ciphertext']),
            lab_data['tamper_nonce'],
            lab_data['tamper_tag']
        )
        return jsonify({
            'success': True,
            'authenticated': True,
            'is_modified': is_modified,
            'message': '✓ Authentication successful: document recovered.'
        })
    except InvalidTag:
        return jsonify({
            'success': True,
            'authenticated': False,
            'is_modified': True,
            'message': '✗ Authentication failed: the encrypted data was modified or corrupted.'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'authenticated': False,
            'message': f'Decryption error: {str(e)}'
        }), 500


@documents_bp.route('/cryptography-lab/reset', methods=['POST'])
@login_required
def lab_reset():
    user_id = session['user_id']
    req_data = request.get_json(silent=True) or request.form
    token = req_data.get('lab_token')

    if token:
        with LAB_STORE_LOCK:
            data = LAB_STORE.get(token)
            if data and data.get('user_id') == user_id:
                del LAB_STORE[token]

    return jsonify({'success': True})



# ────────────────────────────────────────────────────────────────────
# DELETE  (unchanged)
# ────────────────────────────────────────────────────────────────────

@documents_bp.route('/delete/<int:doc_id>', methods=['POST'])
@login_required
def delete(doc_id):
    user_id = session['user_id']
    document = Document.query.filter_by(id=doc_id).first()
    
    if not document:
        flash('Encrypted document not found.', 'error')
        return redirect(url_for('documents.dashboard'))
        
    if document.owner_id != user_id:
        flash('Access denied: You are not authorized to delete this document.', 'error')
        return redirect(url_for('documents.dashboard'))
    
    try:
        if os.path.exists(document.storage_path):
            os.remove(document.storage_path)
    except OSError:
        pass
    
    db.session.delete(document)
    db.session.commit()
    
    flash('File deleted successfully', 'success')
    return redirect(url_for('documents.dashboard'))