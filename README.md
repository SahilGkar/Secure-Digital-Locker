# Secure Digital Locker

A secure web-based digital locker that allows users to store documents using AES-256-GCM encryption with RSA-OAEP protected document keys, while providing an interactive Cryptography Lab for demonstrating encryption, decryption, and tamper detection.

Developed as a second-year BSc Artificial Intelligence Cryptography project demonstrating applied symmetric and asymmetric cryptosystems.

---

## Features

- **User Authentication**: Secure user registration and login with password hashing.
- **6-Digit Locker PIN**: Secondary application-level access control gate for sensitive document access.
- **Secure Document Upload**: Upload documents of any file type with immediate cryptographic protection.
- **AES-256-GCM Document Encryption**: Authenticated Encryption with Associated Data (AEAD) delivering confidentiality and data integrity.
- **RSA-OAEP Key Protection**: Asymmetric wrapping of symmetric document keys using RSA-2048 with OAEP padding.
- **Per-Document Encryption Keys**: Every uploaded file receives a unique, cryptographically random 256-bit AES key.
- **Document Type Classification**: Categorize stored files (e.g., Medical Form, ID Card, Certificate).
- **Search by Document Type**: Partial, case-insensitive search with a one-click Clear filter.
- **PIN-Protected Document Viewing**: Verify PIN and cryptographic integrity before viewing documents inline in the browser.
- **PIN-Protected Document Downloading**: Secure download workflow with one-time, short-lived authorization tokens.
- **Two-Step Verification Flow**: Decryption integrity is validated prior to serving file bytes, ensuring corrupted data is never delivered.
- **Secure Document Deletion**: Permanently removes ciphertext from disk and deletes associated database metadata.
- **Simplified Security Details**: View document-specific encryption metadata (algorithms, key sizes, nonce, auth tag, storage file) without exposing secret credentials.
- **Educational "How It Works" Tab**: Dedicated architecture guide with visual diagrams explaining hybrid encryption concepts.
- **Interactive "Cryptography Lab" Tab**: Educational experimental environment operating on temporary in-memory copies:
  - **Normal Mode**: Executes the entire cryptographic round-trip in real time with live status feedback.
  - **Step-by-Step Demo Mode**: Sequentially triggers and inspects each of the 7 cryptographic stages.
  - **Interactive AES-GCM Tamper Detection**: Real-time hexadecimal ciphertext viewer, custom byte modification, actual GCM authentication failure demonstration, and byte restoration.
- **Strict In-Memory Lab Isolation**: Laboratory experiments never overwrite or modify actual stored `.enc` files on disk.
- **Scroll Position Restoration**: Dashboard reloads (upload, delete, search) seamlessly restore previous vertical scroll positions.
- **Strict User Isolation**: Users can only view, download, delete, or experiment on documents they personally own.

---

## Cryptographic Architecture

The application implements a **Hybrid Encryption** architecture, combining the high performance of symmetric encryption for bulk file data with the secure key management of asymmetric encryption.

```
Upload Flow:
                ORIGINAL DOCUMENT
                        │
                        ▼
                Random AES-256 Key
                        │
                        ▼
                   AES-256-GCM
                        │
             ┌──────────┼──────────┐
             │          │          │
             ▼          ▼          ▼
        Ciphertext    Nonce    Auth Tag
             │
             ▼
      ENCRYPTED DOCUMENT (.enc on disk)


                AES-256 KEY
                     │
                     ▼
                 RSA-OAEP
                     │
                     ▼
            ENCRYPTED AES KEY (stored in database)
```

```
Decryption Flow:
            ENCRYPTED AES KEY
                     │
                     ▼
                  RSA-OAEP
            (using RSA Private Key)
                     │
                     ▼
                AES-256 KEY
                     │
                     ▼
            ENCRYPTED DOCUMENT + Nonce + Auth Tag
                     │
                     ▼
                AES-256-GCM
                     │
           ┌─────────┴─────────┐
           ▼                   ▼
   Verify Auth Tag      Original Document
      (GMAC check)            │
           │                  ▼
  ✓ Untampered: Accept   SERVED TO USER
  ✗ Modified: Reject
```

### Document Encryption (Symmetric)

- **Cipher**: Advanced Encryption Standard (AES) operating in Galois/Counter Mode (GCM).
- **Key Size**: 256-bit (32 bytes), generated independently for every document using `os.urandom(32)`.
- **Nonce (IV)**: 12-byte (96-bit) cryptographically random nonce generated per encryption. Nonces are never reused with the same key.
- **Authentication Tag**: 16-byte (128-bit) GMAC tag computed over the ciphertext and nonce. AES-GCM verifies that the ciphertext has not been modified or corrupted.
- **Why Symmetric for Documents?** AES is computationally efficient, hardware-accelerated, and scales seamlessly to arbitrarily large files without size restrictions or ciphertext bloat.

### Key Protection (Asymmetric)

- **Cipher**: RSA with Optimal Asymmetric Encryption Padding (RSA-OAEP).
- **Key Pair**: 2048-bit RSA key pair generated and managed by the locker runtime (`instance/keys/`).
- **Public Key**: Encrypts the random AES-256 document key during upload.
- **Private Key**: Decrypts the encrypted AES key during authorized retrieval.
- **Why Asymmetric for Keys?** RSA solves the key storage problem. The symmetric AES key is never saved in plaintext on disk or in the database; it is protected by the locker's public key and can only be recovered using the private key.
- *Note:* RSA-OAEP is used exclusively to wrap the 256-bit AES key. RSA does NOT encrypt the document content itself.

---

## Locker PIN Security Model

The 6-digit Locker PIN is an **application-level access-control credential** used to authenticate sensitive actions (viewing, downloading, and initializing Cryptography Lab sessions).

- **Storage**: Stored as a salted, irreversible password hash (`pin_hash` generated using Werkzeug's secure hashing).
- **Role**: Validates user authorization prior to initiating decryption routines.
- **Important Distinction**: The PIN is **not** an AES encryption key, an RSA key, or a key derivation input. It acts as an authorization factor, preventing unauthorized access if a browser session is left unattended.

---

## Application Workflow

```text
User Registration
       ↓ (Username, Password, 6-digit Locker PIN)
User Login
       ↓
Dashboard
       ↓
Upload Document
       ↓
Generate fresh random AES-256 key
       ↓
AES-256-GCM encrypts document (produces ciphertext, 12-byte nonce, 16-byte auth tag)
       ↓
RSA-OAEP encrypts AES key with RSA public key
       ↓
Ciphertext saved to storage/blobs/<uuid>.enc; metadata saved to database
       ↓
View / Download Requested
       ↓
6-Digit Locker PIN Submitted & Verified
       ↓
RSA private key recovers AES key via RSA-OAEP
       ↓
AES-256-GCM decrypts ciphertext and verifies 16-byte authentication tag
       ↓
Integrity verified → Document served to user in-memory (plaintext never written to disk)
```

---

## Three-Tab Architecture

The application is structured into three clean, focused sections:

### 1. Dashboard (`/`)
The operational hub for day-to-day document management:
- Upload documents with document type tagging.
- Search and filter by document type with a one-click Clear button.
- Document inventory table displaying original filename, type, size, upload date, and crypto badges.
- Action buttons: **🔐 Security Details**, **View**, **Download**, and **Delete**.
- Preserves scroll position across uploads, searches, and deletions.

### 2. How It Works (`/how-it-works`)
A dedicated educational resource detailing the complete cryptographic architecture:
- Explanation of hybrid encryption principles and why symmetric and asymmetric ciphers are paired.
- Deep dives into AES-256-GCM, random key lifecycles, nonces, and authentication tags.
- RSA-OAEP key wrapping explanation aligned with academic syllabi.
- Visual ASCII pipeline diagrams of upload encryption and retrieval decryption flows.
- Detailed explanation of GMAC tag calculation and mathematical tamper detection.

### 3. Cryptography Lab (`/cryptography-lab`)
An interactive laboratory environment demonstrating live cryptographic operations on temporary in-memory copies:
- **Document Selector**: Choose any of your uploaded documents for experimentation.
- **PIN Gate**: Enter your 6-digit Locker PIN to decrypt a temporary copy into server memory.
- **Zero Disk Mutation Guarantee**: Stored `.enc` files on disk are never altered or overwritten.

#### Experiment 1: Encryption & Decryption Demonstration
- **Normal Mode**: Runs the complete 7-stage cryptographic pipeline in real time, displaying confirmation badges for key generation, GCM encryption, parameter derivation, RSA-OAEP protection, private key recovery, GCM decryption, and 100% plaintext verification.
- **Step-by-Step Demo Mode**: Pauses between actual backend operations. Each click of **Next Step →** triggers the corresponding real cryptographic operation:
  1. *Step 1 / 7*: Prepare temporary laboratory copy in memory.
  2. *Step 2 / 7*: Generate a new random 256-bit AES key (key bytes remain hidden).
  3. *Step 3 / 7*: Perform AES-256-GCM encryption.
  4. *Step 4 / 7*: Inspect 12-byte nonce and 16-byte authentication tag parameters.
  5. *Step 5 / 7*: Protect the AES key using RSA-OAEP.
  6. *Step 6 / 7*: Recover the AES key using the RSA private key.
  7. *Step 7 / 7*: Decrypt with AES-256-GCM, verify GMAC tag, and confirm round-trip success.

#### Experiment 2: Interactive AES-GCM Tamper Detection
- **Live Hexadecimal Viewer**: Displays actual ciphertext bytes from the temporary laboratory encryption with byte offsets (e.g., `00000000  7A 91 C4 ...`).
- **Interactive Byte Inspector**: Click on any byte in the grid to view its offset, original hex value, and current hex value.
- **Byte Modification**: Enter any two-digit hexadecimal value (e.g., `FF`, `00`, `7B`) and click **Modify Byte** to alter that specific byte in server memory.
- **Test Decryption**:
  - *If tampered*: AES-256-GCM decryption throws an `InvalidTag` exception. The interface displays: `✗ Authentication failed: the encrypted data was modified or corrupted.`
  - *If untampered / restored*: AES-256-GCM decryption succeeds and verifies the tag: `✓ Authentication successful: document recovered.`
- **Restore Original Byte**: Click **Restore Original** to revert modified bytes back to their initial values and confirm that authentication succeeds once again.

---

## Security Details View (`/security/<doc_id>`)

Simplified to present strictly essential document information and cryptographic metadata without exposing confidential material:

| Document Information | Encryption Metadata |
| :--- | :--- |
| **Filename** (e.g., `medical_form.pdf`) | **Encryption**: AES-256-GCM |
| **Document Type** (e.g., `Medical Form`) | **AES Key Size**: 256-bit |
| **Original Size** (e.g., `552.2 KB`) | **GCM Nonce**: 12 bytes |
| **Uploaded** (Timestamp) | **Authentication Tag**: 16 bytes |
| **Status**: Encrypted | **Key Protection**: RSA-OAEP |
| | **RSA Key Size**: Actual configured key size (e.g., 2048-bit) |
| | **Encrypted AES Key Size**: Stored key length (e.g., 256 bytes) |
| | **Storage**: Encrypted ciphertext (`<uuid>.enc`) |

*Security Guarantee:* The actual AES key, RSA private key, user password, Locker PIN, and plaintext content are never displayed in Security Details or exposed via client APIs.

---

## Project Structure

```text
secure_digital_locker/
│
├── app.py                         # Application factory, blueprint registration, key init
├── config.py                      # Central configuration (paths, DB URI, token expiry)
├── requirements.txt               # Production and test dependencies
├── README.md                      # Comprehensive project documentation
├── .gitignore                     # Git rules ignoring instance, keys, blobs, and cache
│
├── auth/                          # Authentication & PIN subsystem
│   ├── __init__.py                # Auth module initializer
│   ├── models.py                  # User SQLAlchemy model (password_hash, pin_hash)
│   └── routes.py                  # Register, login, and logout endpoints
│
├── crypto/                        # Core cryptographic engines
│   ├── __init__.py                # Crypto module initializer
│   ├── aes_engine.py              # AES-256-GCM encryption and decryption functions
│   ├── rsa_engine.py              # RSA key pair generation, loading, and OAEP wrapping
│   └── hybrid_engine.py           # Hybrid pipeline orchestrating AES-GCM + RSA-OAEP
│
├── documents/                     # Document management & Cryptography Lab subsystem
│   ├── __init__.py                # Documents module initializer
│   ├── models.py                  # Document SQLAlchemy model (metadata, nonce, auth_tag)
│   └── routes.py                  # Dashboard, upload, view, serve, security, and lab APIs
│
├── static/                        # Static client-side assets
│   ├── css/
│   │   └── style.css              # Custom responsive stylesheet and component styling
│   └── js/
│       ├── crypto_lab.js          # Cryptography Lab interactive frontend controller
│       └── scroll_restore.js      # Client-side scroll restoration for dashboard actions
│
├── storage/                       # Encrypted file storage (ciphertexts ignored by git)
│   └── blobs/
│       └── .gitkeep               # Preserves storage directory structure
│
├── templates/                     # Jinja2 HTML5 presentation templates
│   ├── base.html                  # Base layout with three-tab top navigation
│   ├── dashboard.html             # Document management dashboard
│   ├── how_it_works.html          # Educational architecture guide with diagrams
│   ├── cryptography_lab.html      # Interactive Cryptography Lab interface
│   ├── security_details.html      # Simplified document security metadata page
│   ├── decryption_success.html    # Decryption verification and serve token gate
│   ├── encryption_complete.html   # Upload notification showing encryption parameters
│   ├── pin_prompt.html            # 6-digit Locker PIN entry modal
│   ├── login.html                 # User authentication form
│   └── register.html              # User registration form with PIN setup
│
└── tests/                         # Automated test suite (53 passing tests)
    ├── __init__.py                # Test package initializer
    ├── test_aes_engine.py         # AES-256-GCM unit tests (encryption, tag, tamper)
    ├── test_rsa_engine.py         # RSA-OAEP unit tests (key wrapping and recovery)
    ├── test_hybrid.py             # Hybrid engine integration tests
    ├── test_routes.py             # User auth and document lifecycle tests
    ├── test_security_routes.py    # Security metadata, preview, and token tests
    ├── test_security_verification.py # 15 comprehensive cryptographic pipeline tests
    └── test_cryptography_lab.py   # Navigation, lab PIN, Exp 1, Exp 2, and isolation tests
```

---

## Installation & Setup

### 1. Prerequisites

- Python 3.10, 3.11, or 3.12+
- `pip` (Python package manager)
- Git

### 2. Clone the Repository

```bash
git clone https://github.com/your-username/secure-digital-locker.git
cd secure-digital-locker
```

### 3. Create and Activate a Virtual Environment

On Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

On macOS / Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the Application

```bash
python app.py
```

The application will start on `http://127.0.0.1:5000`.

*First-run behavior:* On first launch, the application automatically initializes the SQLite database (`instance/locker.db`) and generates a fresh 2048-bit RSA key pair (`instance/keys/private_key.pem` and `public_key.pem`).

---

## Running the Automated Test Suite

The test suite contains **53 comprehensive automated tests** covering cryptography, access control, route security, and laboratory experiments.

Run all tests:
```bash
python -m pytest -v
```

Run tests with code coverage:
```bash
python -m pytest --cov=. -v
```

Run specific test modules:
```bash
# Cryptography Lab and Navigation tests
python -m pytest tests/test_cryptography_lab.py -v

# Cryptographic pipeline verification tests
python -m pytest tests/test_security_verification.py -v

# Core AES and RSA unit tests
python -m pytest tests/test_aes_engine.py tests/test_rsa_engine.py tests/test_hybrid.py -v
```

---

## Security Considerations & Academic Scope

- **Educational Purpose**: This project was developed as an educational cryptography demonstration illustrating the practical integration of AES-GCM and RSA-OAEP.
- **Key Storage**: The locker's RSA private key is stored in the local `instance/keys/` directory and is excluded from version control via `.gitignore`. In a commercial production environment, master asymmetric keys would typically reside in a Hardware Security Module (HSM) or cloud KMS.
- **In-Memory Safety**: Decrypted document bytes are kept strictly in transient server memory and are never written to disk.
- **Transport Security**: In production deployments, TLS/HTTPS must terminate before or at the Flask application to protect session cookies, credentials, and plaintext payloads in transit.

---

## License

This project is open-source and available under the [MIT License](LICENSE).
