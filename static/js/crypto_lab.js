/**
 * crypto_lab.js — Interactive Cryptography Laboratory
 * 
 * Manages:
 * - Locker PIN verification and in-memory laboratory session initialization
 * - Experiment 1: Real cryptographic round-trip (Normal Mode & Step-by-Step Mode)
 * - Experiment 2: Interactive AES-GCM Tamper Detection (byte modification, real GCM test, restore)
 */

document.addEventListener('DOMContentLoaded', () => {
    let labToken = null;
    let currentDocId = null;
    let currentStep = 1;
    let selectedOffset = null;
    let hexRows = [];
    let modifiedBytes = {};

    const selectedDocInfo = document.getElementById('selected-doc-info');
    if (selectedDocInfo) {
        currentDocId = selectedDocInfo.getAttribute('data-doc-id');
    }

    const pinInput = document.getElementById('lab-pin-input');
    const btnInitLab = document.getElementById('btn-init-lab');
    const pinErrorMsg = document.getElementById('pin-error-msg');
    const labAuthContainer = document.getElementById('lab-auth-container');
    const labActiveSessionIndicator = document.getElementById('lab-active-session-indicator');
    const experimentsContainer = document.getElementById('experiments-container');
    const btnResetLab = document.getElementById('btn-reset-lab');

    // Mode toggles
    const modeNormalBtn = document.getElementById('mode-normal-btn');
    const modeStepBtn = document.getElementById('mode-step-btn');
    const viewNormalMode = document.getElementById('view-normal-mode');
    const viewStepMode = document.getElementById('view-step-mode');

    // Experiment 1 elements
    const btnRunNormal = document.getElementById('btn-run-normal');
    const normalResults = document.getElementById('normal-results');
    const normalStepsList = document.getElementById('normal-steps-list');
    const normalFinalStatus = document.getElementById('normal-final-status');

    const stepCounter = document.getElementById('step-counter');
    const stepTitle = document.getElementById('step-title');
    const stepContentArea = document.getElementById('step-content-area');
    const btnNextStep = document.getElementById('btn-next-step');
    const btnRestartStep = document.getElementById('btn-restart-step');

    // Experiment 2 elements
    const hexTbody = document.getElementById('hex-tbody');
    const dispOffset = document.getElementById('disp-offset');
    const dispOrigVal = document.getElementById('disp-orig-val');
    const dispCurrVal = document.getElementById('disp-curr-val');
    const newByteInput = document.getElementById('new-byte-input');
    const btnModifyByte = document.getElementById('btn-modify-byte');
    const byteInputError = document.getElementById('byte-input-error');
    const btnTestDecrypt = document.getElementById('btn-test-decrypt');
    const btnRestoreByte = document.getElementById('btn-restore-byte');
    const decryptionTestResult = document.getElementById('decryption-test-result');
    const decryptionStatusIcon = document.getElementById('decryption-status-icon');
    const decryptionStatusText = document.getElementById('decryption-status-text');

    // ────────────────────────────────────────────────────────────────
    // 1. PIN AUTHENTICATION & LAB SESSION INITIALIZATION
    // ────────────────────────────────────────────────────────────────
    if (btnInitLab) {
        btnInitLab.addEventListener('click', async () => {
            const pin = pinInput.value.trim();
            if (!pin || pin.length !== 6) {
                showPinError('Please enter your 6-digit Locker PIN.');
                return;
            }

            hidePinError();
            btnInitLab.disabled = true;
            btnInitLab.textContent = 'Verifying PIN & Initializing...';

            try {
                const resp = await fetch('/cryptography-lab/init', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ doc_id: currentDocId, pin: pin })
                });

                const data = await resp.json();

                if (!resp.ok || !data.success) {
                    showPinError(data.error || 'Authentication failed. Please check your PIN.');
                    btnInitLab.disabled = false;
                    btnInitLab.textContent = 'Start Experiment';
                    return;
                }

                // Success! Store token
                labToken = data.labToken || data.lab_token;

                // Update UI to active session
                labAuthContainer.style.display = 'none';
                labActiveSessionIndicator.style.display = 'flex';
                experimentsContainer.style.display = 'block';

                // Initialize Step 1
                currentStep = 1;
                loadStep(1);

                // Initialize Tamper Experiment
                await initTamperLab();

            } catch (err) {
                showPinError('An error occurred during lab initialization.');
                btnInitLab.disabled = false;
                btnInitLab.textContent = 'Start Experiment';
            }
        });

        // Allow Enter key on PIN input
        pinInput.addEventListener('keyup', (e) => {
            if (e.key === 'Enter') {
                btnInitLab.click();
            }
        });
    }

    function showPinError(msg) {
        if (pinErrorMsg) {
            pinErrorMsg.textContent = msg;
            pinErrorMsg.style.display = 'block';
        }
    }

    function hidePinError() {
        if (pinErrorMsg) {
            pinErrorMsg.style.display = 'none';
        }
    }

    // Reset Lab Session
    if (btnResetLab) {
        btnResetLab.addEventListener('click', async () => {
            if (labToken) {
                try {
                    await fetch('/cryptography-lab/reset', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ lab_token: labToken })
                    });
                } catch (e) {}
            }

            labToken = null;
            pinInput.value = '';
            labAuthContainer.style.display = 'block';
            labActiveSessionIndicator.style.display = 'none';
            experimentsContainer.style.display = 'none';
            btnInitLab.disabled = false;
            btnInitLab.textContent = 'Start Experiment';
            hidePinError();
        });
    }

    // ────────────────────────────────────────────────────────────────
    // 2. MODE TOGGLING
    // ────────────────────────────────────────────────────────────────
    if (modeNormalBtn && modeStepBtn) {
        modeNormalBtn.addEventListener('click', () => {
            modeNormalBtn.classList.add('active');
            modeStepBtn.classList.remove('active');
            viewNormalMode.style.display = 'block';
            viewStepMode.style.display = 'none';
        });

        modeStepBtn.addEventListener('click', () => {
            modeStepBtn.classList.add('active');
            modeNormalBtn.classList.remove('active');
            viewStepMode.style.display = 'block';
            viewNormalMode.style.display = 'none';
        });
    }

    // ────────────────────────────────────────────────────────────────
    // 3. EXPERIMENT 1 — NORMAL MODE
    // ────────────────────────────────────────────────────────────────
    if (btnRunNormal) {
        btnRunNormal.addEventListener('click', async () => {
            if (!labToken) return;

            btnRunNormal.disabled = true;
            btnRunNormal.textContent = '⏳ Executing Cryptographic Pipeline...';
            normalResults.style.display = 'block';
            normalStepsList.innerHTML = '<li>🔐 Running in-memory encryption &amp; decryption pipeline...</li>';
            normalFinalStatus.style.display = 'none';

            try {
                const resp = await fetch('/cryptography-lab/run-normal', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ lab_token: labToken })
                });

                const data = await resp.json();

                if (!resp.ok || !data.success) {
                    normalStepsList.innerHTML = `<li class="step-fail">✗ Error: ${data.error || 'Execution failed'}</li>`;
                    btnRunNormal.disabled = false;
                    btnRunNormal.textContent = '▶ Run Cryptographic Round-Trip';
                    return;
                }

                // Render execution steps
                normalStepsList.innerHTML = '';
                const icons = ['📄', '🔑', '🔒', '🛡️', '🔏', '🔓', '✅'];

                data.steps.forEach((st, idx) => {
                    const li = document.createElement('li');
                    li.className = 'step-item';
                    li.innerHTML = `
                        <span class="step-num">${idx + 1}</span>
                        <span class="step-icon">${icons[idx] || '✓'}</span>
                        <span class="step-text">${st.text}</span>
                        <span class="step-ok">✓ Completed</span>
                    `;
                    normalStepsList.appendChild(li);
                });

                // Final status callout
                normalFinalStatus.className = 'final-status-callout status-success';
                normalFinalStatus.innerHTML = `
                    <div class="status-title">${data.status}</div>
                    <div class="status-sub">Plaintext was recovered in memory and matches the original data with 100% cryptographic integrity.</div>
                    <div class="status-summary-tags">
                        <span>AES Key: ${data.summary.key_size}</span>
                        <span>Nonce: ${data.summary.nonce_size}</span>
                        <span>Auth Tag: ${data.summary.tag_size}</span>
                        <span>Key Protection: RSA-OAEP (${data.summary.rsa_key_size})</span>
                    </div>
                `;
                normalFinalStatus.style.display = 'block';

            } catch (err) {
                normalStepsList.innerHTML = '<li class="step-fail">✗ Network error executing round-trip.</li>';
            } finally {
                btnRunNormal.disabled = false;
                btnRunNormal.textContent = '▶ Run Cryptographic Round-Trip';
            }
        });
    }

    // ────────────────────────────────────────────────────────────────
    // 4. EXPERIMENT 1 — STEP-BY-STEP MODE
    // ────────────────────────────────────────────────────────────────
    async function loadStep(stepNum) {
        if (!labToken) return;

        btnNextStep.disabled = true;
        btnNextStep.textContent = '⏳ Executing Stage...';

        try {
            const resp = await fetch('/cryptography-lab/step', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ lab_token: labToken, step: stepNum })
            });

            const data = await resp.json();

            if (!resp.ok || !data.success) {
                stepContentArea.innerHTML = `<div class="alert alert-danger">✗ Error: ${data.error}</div>`;
                btnNextStep.disabled = false;
                btnNextStep.textContent = 'Next Step →';
                return;
            }

            // Update Header
            stepCounter.textContent = `STEP ${stepNum} / 7`;
            stepTitle.textContent = data.title;

            // Render content according to step
            renderStepContent(stepNum, data);

            // Controls
            if (stepNum < 7) {
                btnNextStep.style.display = 'inline-block';
                btnRestartStep.style.display = 'none';
                btnNextStep.textContent = 'Next Step →';
            } else {
                btnNextStep.style.display = 'none';
                btnRestartStep.style.display = 'inline-block';
            }

        } catch (err) {
            stepContentArea.innerHTML = `<div class="alert alert-danger">✗ Network error loading step ${stepNum}.</div>`;
        } finally {
            btnNextStep.disabled = false;
        }
    }

    function renderStepContent(stepNum, data) {
        let html = '';
        if (stepNum === 1) {
            html = `
                <div class="step-detail-box">
                    <h5>Original Document</h5>
                    <div class="step-meta-row"><span>Filename:</span> <strong>${data.filename}</strong></div>
                    <div class="step-meta-row"><span>Original Size:</span> <strong>${(data.size / 1024).toFixed(1)} KB (${data.size} bytes)</strong></div>
                    <div class="step-status-tag ok">✓ Temporary laboratory copy prepared in memory</div>
                    <p class="step-expl">A temporary in-memory copy of the document has been prepared for the experiment. The real stored <code>.enc</code> file remains untouched on disk.</p>
                </div>
            `;
        } else if (stepNum === 2) {
            html = `
                <div class="step-detail-box">
                    <h5>Generate Random AES-256 Key</h5>
                    <div class="step-meta-row"><span>Algorithm:</span> <strong>AES (Advanced Encryption Standard)</strong></div>
                    <div class="step-meta-row"><span>Key Size:</span> <strong>${data.key_size} (32 bytes)</strong></div>
                    <div class="step-meta-row"><span>Status:</span> <strong class="text-success">${data.status}</strong></div>
                    <div class="step-status-tag ok">✓ A new random 256-bit AES key has been generated</div>
                    <p class="step-expl"><strong>Security Note:</strong> The actual key bytes are kept confidential in server memory and are never displayed.</p>
                </div>
            `;
        } else if (stepNum === 3) {
            html = `
                <div class="step-detail-box">
                    <h5>AES-256-GCM Encryption</h5>
                    <div class="pipeline-ascii">
Temporary Plaintext  ───►  AES-256-GCM  ───►  Ciphertext (${data.ciphertext_size} bytes)
                    </div>
                    <div class="step-meta-row"><span>Ciphertext Size:</span> <strong>${data.ciphertext_size} bytes</strong></div>
                    <div class="step-status-tag ok">✓ Encryption completed</div>
                    <p class="step-expl">The temporary plaintext was encrypted using AES-256 in Galois/Counter Mode. Confidentiality is now assured.</p>
                </div>
            `;
        } else if (stepNum === 4) {
            html = `
                <div class="step-detail-box">
                    <h5>GCM Parameters</h5>
                    <div class="step-meta-row"><span>Nonce (IV):</span> <strong>${data.nonce_size}</strong> (unique number used once)</div>
                    <div class="step-meta-row"><span>Authentication Tag:</span> <strong>${data.tag_size}</strong> (cryptographic checksum)</div>
                    <div class="step-status-tag ok">✓ Nonce and Authentication Tag generated</div>
                    <p class="step-expl">The 16-byte authentication tag provides cryptographic authenticity and integrity verification. If any byte of ciphertext is altered, tag verification will fail.</p>
                </div>
            `;
        } else if (stepNum === 5) {
            html = `
                <div class="step-detail-box">
                    <h5>RSA-OAEP Key Protection</h5>
                    <div class="pipeline-ascii">
AES-256 Lab Key  ───►  RSA-OAEP (Public Key)  ───►  Encrypted AES Key (${data.encrypted_key_size})
                    </div>
                    <div class="step-meta-row"><span>Asymmetric Scheme:</span> <strong>RSA-OAEP</strong></div>
                    <div class="step-meta-row"><span>RSA Key Size:</span> <strong>${data.rsa_key_size}</strong></div>
                    <div class="step-meta-row"><span>Encrypted Key Size:</span> <strong>${data.encrypted_key_size}</strong></div>
                    <div class="step-status-tag ok">✓ Key protection completed</div>
                    <p class="step-expl">RSA-OAEP is used to securely protect the random AES-256 document key. The RSA public key is used for protection, and the corresponding private key is required to recover the AES key.</p>
                </div>
            `;
        } else if (stepNum === 6) {
            html = `
                <div class="step-detail-box">
                    <h5>Decryption Key Recovery</h5>
                    <div class="pipeline-ascii">
Encrypted AES Key  ───►  RSA-OAEP (Private Key)  ───►  Recovered AES Key
                    </div>
                    <div class="step-meta-row"><span>Key Recovery:</span> <strong class="text-success">Successful</strong></div>
                    <div class="step-status-tag ok">✓ AES key recovered from RSA-OAEP ciphertext</div>
                    <p class="step-expl">The RSA private key was used to decrypt the protected AES key. With the symmetric key recovered, document decryption can proceed.</p>
                </div>
            `;
        } else if (stepNum === 7) {
            html = `
                <div class="step-detail-box">
                    <h5>Authentication Verification &amp; Document Recovery</h5>
                    <div class="pipeline-ascii">
Ciphertext + Nonce + Tag + AES Key  ───►  AES-256-GCM  ───►  Recovered Document
                    </div>
                    <div class="step-status-tag ok">✓ GCM authentication successful</div>
                    <div class="step-status-tag ok">✓ Plaintext recovered</div>
                    <div class="step-status-tag ok">✓ Recovered data matches original temporary data</div>
                    <div class="final-status-callout status-success" style="margin-top: 15px;">
                        <div class="status-title">STATUS: 🔐 CRYPTOGRAPHIC ROUND TRIP SUCCESSFUL</div>
                        <div class="status-sub">All 7 cryptographic stages executed successfully in memory with full integrity verification.</div>
                    </div>
                </div>
            `;
        }

        stepContentArea.innerHTML = html;
    }

    if (btnNextStep) {
        btnNextStep.addEventListener('click', () => {
            if (currentStep < 7) {
                currentStep++;
                loadStep(currentStep);
            }
        });
    }

    if (btnRestartStep) {
        btnRestartStep.addEventListener('click', () => {
            currentStep = 1;
            loadStep(1);
        });
    }

    // ────────────────────────────────────────────────────────────────
    // 5. EXPERIMENT 2 — INTERACTIVE TAMPER DETECTION
    // ────────────────────────────────────────────────────────────────
    async function initTamperLab() {
        if (!labToken) return;

        try {
            const resp = await fetch('/cryptography-lab/init-tamper', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ lab_token: labToken })
            });

            const data = await resp.json();
            if (!resp.ok || !data.success) return;

            hexRows = data.rows || [];
            modifiedBytes = data.modified_bytes || {};
            selectedOffset = null;

            renderHexTable();
            clearByteInspector();
            hideDecryptionResult();

        } catch (e) {
            console.error('Failed to init tamper lab:', e);
        }
    }

    function renderHexTable() {
        if (!hexTbody) return;
        hexTbody.innerHTML = '';

        hexRows.forEach((row) => {
            const tr = document.createElement('tr');

            // Offset column
            const tdOffset = document.createElement('td');
            tdOffset.className = 'offset-col';
            tdOffset.textContent = row.offset;
            tr.appendChild(tdOffset);

            // Byte cells (8 bytes per row)
            row.hex_bytes.forEach((byteHex, byteIdx) => {
                const byteOffset = row.offset_int + byteIdx;
                const tdByte = document.createElement('td');
                tdByte.className = 'byte-cell';
                tdByte.textContent = byteHex;
                tdByte.setAttribute('data-offset', byteOffset);

                // Check if modified
                if (modifiedBytes[byteOffset.toString()]) {
                    tdByte.classList.add('byte-tampered');
                    tdByte.title = `Modified (Original: ${modifiedBytes[byteOffset.toString()].original})`;
                }

                // Check if selected
                if (selectedOffset === byteOffset) {
                    tdByte.classList.add('byte-selected');
                }

                // Click to select byte
                tdByte.addEventListener('click', () => {
                    selectByte(byteOffset, byteHex);
                });

                tr.appendChild(tdByte);
            });

            hexTbody.appendChild(tr);
        });
    }

    function selectByte(offset, currentHex) {
        selectedOffset = offset;
        const modInfo = modifiedBytes[offset.toString()];
        const origHex = modInfo ? modInfo.original : currentHex;

        dispOffset.textContent = formatOffset(offset);
        dispOrigVal.textContent = origHex;
        dispCurrVal.textContent = currentHex;
        newByteInput.value = currentHex;
        btnModifyByte.disabled = false;
        hideByteError();

        // Highlight in table
        document.querySelectorAll('.byte-cell').forEach(el => el.classList.remove('byte-selected'));
        const cell = document.querySelector(`.byte-cell[data-offset="${offset}"]`);
        if (cell) cell.classList.add('byte-selected');
    }

    function formatOffset(offset) {
        return offset.toString(16).padStart(8, '0').toUpperCase();
    }

    function clearByteInspector() {
        selectedOffset = null;
        dispOffset.textContent = '—';
        dispOrigVal.textContent = '—';
        dispCurrVal.textContent = '—';
        newByteInput.value = '';
        btnModifyByte.disabled = true;
        hideByteError();
    }

    function showByteError(msg) {
        if (byteInputError) {
            byteInputError.textContent = msg;
            byteInputError.style.display = 'block';
        }
    }

    function hideByteError() {
        if (byteInputError) {
            byteInputError.style.display = 'none';
        }
    }

    function hideDecryptionResult() {
        if (decryptionTestResult) {
            decryptionTestResult.style.display = 'none';
        }
    }

    // Modify Byte
    if (btnModifyByte) {
        btnModifyByte.addEventListener('click', async () => {
            if (!labToken || selectedOffset === null) return;

            const newVal = newByteInput.value.trim().toUpperCase();
            if (!/^[0-9A-F]{2}$/.test(newVal)) {
                showByteError('Value must be exactly two hexadecimal characters (00–FF).');
                return;
            }

            hideByteError();
            btnModifyByte.disabled = true;

            try {
                const resp = await fetch('/cryptography-lab/modify-byte', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        lab_token: labToken,
                        offset: selectedOffset,
                        new_val: newVal
                    })
                });

                const data = await resp.json();
                if (!resp.ok || !data.success) {
                    showByteError(data.error || 'Failed to modify byte');
                    btnModifyByte.disabled = false;
                    return;
                }

                hexRows = data.rows || [];
                modifiedBytes = data.modified_bytes || {};

                renderHexTable();
                selectByte(selectedOffset, newVal);
                hideDecryptionResult();

            } catch (err) {
                showByteError('Network error modifying byte');
            } finally {
                btnModifyByte.disabled = false;
            }
        });
    }

    // Restore Original Byte
    if (btnRestoreByte) {
        btnRestoreByte.addEventListener('click', async () => {
            if (!labToken) return;

            btnRestoreByte.disabled = true;

            try {
                const resp = await fetch('/cryptography-lab/restore-byte', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        lab_token: labToken,
                        offset: selectedOffset !== null ? selectedOffset : ''
                    })
                });

                const data = await resp.json();
                if (!resp.ok || !data.success) return;

                hexRows = data.rows || [];
                modifiedBytes = data.modified_bytes || {};

                renderHexTable();

                if (selectedOffset !== null) {
                    const cell = document.querySelector(`.byte-cell[data-offset="${selectedOffset}"]`);
                    const restoredVal = cell ? cell.textContent : '—';
                    selectByte(selectedOffset, restoredVal);
                }

                hideDecryptionResult();

            } catch (err) {
                console.error('Restore error:', err);
            } finally {
                btnRestoreByte.disabled = false;
            }
        });
    }

    // Test Decryption
    if (btnTestDecrypt) {
        btnTestDecrypt.addEventListener('click', async () => {
            if (!labToken) return;

            btnTestDecrypt.disabled = true;
            btnTestDecrypt.textContent = '⏳ Verifying AES-GCM Authentication...';

            try {
                const resp = await fetch('/cryptography-lab/test-decryption', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ lab_token: labToken })
                });

                const data = await resp.json();

                decryptionTestResult.style.display = 'block';

                if (data.authenticated) {
                    // Success!
                    decryptionTestResult.className = 'decryption-result-box result-success';
                    decryptionStatusIcon.innerHTML = '🛡️ ✓';
                    decryptionStatusText.innerHTML = `
                        <strong>Authentication Successful</strong>
                        <p>${data.message}</p>
                        <div class="result-details">
                            AES-256-GCM evaluated the 16-byte authentication tag over the ciphertext and nonce. The tag matched exactly. Data integrity and authenticity confirmed.
                        </div>
                    `;
                } else {
                    // Tamper detected!
                    decryptionTestResult.className = 'decryption-result-box result-failed';
                    decryptionStatusIcon.innerHTML = '⚠️ ✗';
                    decryptionStatusText.innerHTML = `
                        <strong>Authentication Failed</strong>
                        <p>${data.message}</p>
                        <div class="result-details">
                            AES-256-GCM detected unauthorized modification! The computed authentication tag did not match the original tag. Decryption was immediately aborted and the tampered document was rejected.
                        </div>
                    `;
                }

            } catch (err) {
                decryptionTestResult.style.display = 'block';
                decryptionTestResult.className = 'decryption-result-box result-failed';
                decryptionStatusIcon.innerHTML = '✗';
                decryptionStatusText.innerHTML = `<strong>Error:</strong> Failed to test decryption.`;
            } finally {
                btnTestDecrypt.disabled = false;
                btnTestDecrypt.textContent = '🔍 Test Decryption';
            }
        });
    }
});
