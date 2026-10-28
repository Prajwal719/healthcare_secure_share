# Secure Healthcare File-Sharing Protocol

**Course:** Cryptography and Network Security  
**Team:** 4 students  
**Topic:** Design and Implementation of a Secure Healthcare File-Sharing Protocol Using AES-256-GCM, RSA-OAEP Key Exchange, RSA-PSS Digital Signatures, and Nonce-Based Replay Protection over Mutual TLS

---

## Security Properties Demonstrated

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM per-file encryption; RSA-OAEP key wrapping |
| Integrity | GCM authentication tag; RSA-PSS signature |
| Authentication | Mutual TLS; scrypt password hashing; HMAC session tokens |
| Non-repudiation | RSA-PSS signature stored with every file |
| Secure key management | Per-file AES keys; PKCS#8-encrypted RSA keys on disk |
| Replay protection | Timestamp window + UUID message ID + monotonic counter |
| Access control | Role-based (doctor/nurse/patient/admin); per-file wrapped keys |
| Emergency recovery | Institutional Key Escrow break-glass procedure with audit alerts |
| Audit & tamper evidence | Hash-chained audit log with external signed anchor checkpoints |
| Interactive testing | Web UI Security Observatory & 9-attack simulation lab |

---

## Project Structure

```
healthcare_secure_share/
  certs/                  Generated TLS certificates (gitignored)
  keys/                   Generated application RSA keys (gitignored)
  common/
    config.py             All security parameters in one place
    crypto_utils.py       AES-GCM, RSA-OAEP, RSA-PSS, scrypt helpers
    protocol.py           Length-prefixed JSON message framing
    replay_guard.py       Three-layer replay protection
  server/
    server.py             Threaded mutual-TLS server
    auth.py               Login, lockout, HMAC tokens, RBAC
    storage.py            SQLite: users, files, wrapped_keys, audit
    audit_log.py          Hash-chained audit log
  client/
    client.py             CLI client
    keystore.py           Application RSA key management
  scripts/
    generate_certs.py     Local PKI (CA + server + client certs)
    generate_user_keys.py Application RSA key pairs & key escrow
    benchmark.py          Crypto performance benchmarking suite
  attacks/
    attacker.py           Attack simulator (9 attacks) & programmatic API
  webapp/
    app.py                Flask frontend & Security Observatory endpoints
    templates/
      observatory.html    Interactive Attack & Defense Lab dashboard
      break_glass.html    Emergency clinical break-glass recovery modal
  tests/
    test_crypto.py        Crypto primitive tests
    test_replay.py        Replay guard + protocol tests
    test_auth.py          Auth + RBAC tests
    test_integration.py   End-to-end server tests
  docs/
    THREAT_MODEL.md       STRIDE threat model
    ALGORITHM_JUSTIFICATION.md  Why each algorithm was chosen
    COMPLIANCE_MAPPING.md HIPAA Security Rule & GDPR Art. 32 cross-reference
    LIMITATIONS.md        Honest limitations & resolved mitigations
  run_demo.py             Interactive all-in-one launcher and test runner
  README.md
  requirements.txt
  pytest.ini
```

---

## Prerequisites

- Python 3.10+
- pip

---

## Setup

### 1. Install dependencies

```bash
cd healthcare_secure_share
pip install -r requirements.txt
```

### 2. Generate TLS certificates

```bash
python scripts/generate_certs.py \
  --clients doctor nurse patient admin \
  --ca-password capass123 \
  --server-password srvpass123 \
  --client-password clipass123
```

This creates `certs/ca.crt`, `certs/server.crt`, `certs/server.key`, and one cert+key per client role.

### 3. Generate application RSA keys

```bash
python scripts/generate_user_keys.py --username doctor  --password DoctorPass1!
python scripts/generate_user_keys.py --username nurse   --password NursePass1!
python scripts/generate_user_keys.py --username patient --password PatientPass1!
python scripts/generate_user_keys.py --username admin   --password AdminPass1!
```

This creates `keys/<username>_app_private.pem` and `keys/<username>_app_public.pem`.

---

## Running the Server

```bash
# Set the server TLS key password (must match --server-password above)
set SERVER_KEY_PASSWORD=srvpass123        # Windows
export SERVER_KEY_PASSWORD=srvpass123     # Linux/macOS

python -m server.server
# Output: [Server] Listening on 127.0.0.1:9443 (mutual TLS)
```

---

## Using the CLI Client

Set the client TLS key password first:

```bash
set CLIENT_KEY_PASSWORD=clipass123        # Windows
export CLIENT_KEY_PASSWORD=clipass123     # Linux/macOS
```

### Register users

```bash
python -m client.client register --username doctor  --password DoctorPass1! --role doctor
python -m client.client register --username nurse   --password NursePass1!  --role nurse
python -m client.client register --username patient --password PatientPass1! --role patient
python -m client.client register --username admin   --password AdminPass1!  --role admin
```

### Upload a file (doctor)

```bash
echo "Patient: Alice. BP: 120/80. Rx: Ibuprofen 400mg" > patient_record.txt
python -m client.client upload --username doctor --password DoctorPass1! --file patient_record.txt
# Output: [OK] Uploaded 'patient_record.txt' -> file_id=<uuid>
```

### List files

```bash
python -m client.client list --username doctor --password DoctorPass1!
```

### Download and decrypt

```bash
python -m client.client download --username doctor --password DoctorPass1! --file-id <uuid> --output decrypted.txt
cat decrypted.txt
```

### Share with nurse

```bash
python -m client.client share --username doctor --password DoctorPass1! --file-id <uuid> --recipient nurse
```

### Revoke access

```bash
python -m client.client revoke --username doctor --password DoctorPass1! --file-id <uuid> --target nurse
```

### View audit log (admin only)

```bash
python -m client.client audit --username admin --password AdminPass1!
```

### Verify audit log integrity (admin only)

```bash
python -m client.client verify-log --username admin --password AdminPass1!
# Output: [OK] Audit log chain is VALID — no tampering detected.
```

---

## Running Tests

```bash
cd healthcare_secure_share

# Unit tests (no server required)
pytest tests/test_crypto.py tests/test_replay.py tests/test_auth.py -v

# Integration tests (require certs/ to exist; server started automatically in-process)
pytest tests/test_integration.py -v

# All tests
pytest -v
```

Expected output: all tests pass (green).

---

## Running the Attack Simulator

```bash
# Start the server in one terminal first (for server-dependent attacks)
python -m server.server

# In another terminal:
python -m attacks.attacker
```

Expected output for each attack:
```
[PASS] Bit-flip detected by GCM authentication tag
[PASS] Forged signature rejected by RSA-PSS verification
[PASS] 7a: Forged token rejected — Token signature invalid.
[PASS] Tampered audit log detected
[PASS] Replay rejected by server
[PASS] Account locked after 5 attempts
[PASS] MITM rejected: TLS certificate verification failed
[PASS] TLS downgrade rejected by server
[PASS] Nurse upload rejected by RBAC
```

---

## Cryptographic Design Summary

### Per-file encryption
- Random 256-bit AES key per file (`os.urandom(32)`)
- AES-256-GCM with fresh 96-bit nonce (`os.urandom(12)`)
- Metadata `{sender_id, filename, timestamp}` bound as GCM AAD

### Key wrapping
- AES key wrapped with recipient's RSA-3072 public key via RSA-OAEP (SHA-256, MGF1-SHA-256)
- One wrapped key row per (file, recipient) — sharing = new row, never re-encrypt

### Signatures
- Sender signs `ciphertext ‖ nonce ‖ AAD` with RSA-PSS (SHA-256, MAX_LENGTH salt)
- Server verifies on upload; client verifies on download

### Replay protection
- Timestamp: ±30 second window
- UUID message ID: bounded LRU cache (10,000 entries)
- Monotonic counter: per-session strictly increasing

### Transport
- TLS 1.2+ mutual TLS; `ssl.CERT_REQUIRED`; CA-signed client certificates

### Passwords
- scrypt (N=2^17, r=8, p=1) with 256-bit random salt; constant-time comparison

### Session tokens
- HMAC-SHA256 signed; 15-minute expiry; in-memory key (invalidated on restart)

---

## Role Permissions

| Action | doctor | nurse | patient | admin |
|---|---|---|---|---|
| upload | ✓ | ✗ | ✗ | ✗ |
| download | ✓ | ✓ | own files | ✓ |
| list | ✓ | ✓ | ✓ | ✓ |
| share | ✓ | ✗ | ✗ | ✗ |
| revoke | ✓ | ✗ | ✗ | ✗ |
| break_glass | ✓ | ✗ | ✗ | ✗ |
| list_users | ✗ | ✗ | ✗ | ✓ |
| audit_log | ✗ | ✗ | ✗ | ✓ |
| manage_users | ✗ | ✗ | ✗ | ✓ |

---

## Further Reading

- `docs/THREAT_MODEL.md` — STRIDE threat analysis
- `docs/ALGORITHM_JUSTIFICATION.md` — Why each algorithm was chosen
- `docs/LIMITATIONS.md` — Known limitations and production mitigations
