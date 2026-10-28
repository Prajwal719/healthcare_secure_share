# Healthcare Regulatory & Security Standards Compliance Matrix

**Protocol:** Secure Healthcare File-Sharing Protocol  
**Standards Covered:** HIPAA Security Rule (45 CFR Part 160 & Part 164 Subparts A & C), EU GDPR (Articles 25 & 32), and NIST SP 800-52 / SP 800-57.

---

## 1. HIPAA Security Rule — Technical Safeguards (45 CFR § 164.312)

The HIPAA Security Rule defines standards that covered entities and business associates must implement to protect electronic Protected Health Information (ePHI).

| HIPAA Section | Requirement | Project Implementation Mechanism | Compliance Status |
|---|---|---|---|
| **§ 164.312(a)(1)**<br>Access Control | Unique User Identification | Per-user unique `user_id` (UUIDv4), role assignment (`doctor`, `nurse`, `patient`, `admin`), and separate PKCS#8 encrypted RSA private keys. | **COMPLIANT** |
| **§ 164.312(a)(2)(i)**<br>Emergency Access Procedure | "Break-Glass" Procedure | **Institutional Key Escrow:** Attending doctors can initiate break-glass recovery. The server unwraps the escrow-wrapped key and re-encrypts it for the attending physician with mandatory reason recording and real-time security alerts. | **COMPLIANT** |
| **§ 164.312(a)(2)(iii)**<br>Automatic Logoff | Terminate session after inactivity | Session tokens expire after 1 hour (3600s); client-side session poll prompts and redirects after expiration. | **COMPLIANT** |
| **§ 164.312(a)(2)(iv)**<br>Encryption & Decryption | Mechanism to encrypt & decrypt ePHI | **AES-256-GCM** per-file encryption with fresh random 96-bit nonces. Keys wrapped via **RSA-OAEP 3072** with SHA-256 and MGF1. Server never stores or sees plaintext. | **COMPLIANT** |
| **§ 164.312(b)**<br>Audit Controls | Record and examine activity in ePHI systems | **Hash-Chained Audit Log:** Every login, upload, download, share, revoke, and break-glass event is stored in a linear SHA-256 hash chain with external signed anchor checkpoints (`audit_checkpoints.json`). | **COMPLIANT** |
| **§ 164.312(c)(1)**<br>Integrity | Protect ePHI from improper alteration or destruction | **GCM 128-bit authentication tag** guarantees ciphertext integrity. **RSA-PSS 3072** digital signatures bound to file content, nonce, and sender metadata guarantee non-repudiation. | **COMPLIANT** |
| **§ 164.312(d)**<br>Person / Entity Authentication | Verify that person seeking access is the one claimed | Dual-layer authentication: **Mutual TLS (mTLS)** for network-layer device/client certificate verification; **scrypt** (N=2^17) memory-hard password hashing + HMAC-SHA256 session tokens. | **COMPLIANT** |
| **§ 164.312(e)(1)**<br>Transmission Security | Protect ePHI transmitted over network | TLS 1.2 minimum version (TLS 1.3 preferred) with forward-secret cipher suites. Ephemeral Diffie-Hellman key exchange over wire. | **COMPLIANT** |

---

## 2. EU General Data Protection Regulation (GDPR)

| GDPR Article | Principle | Implementation Mechanism |
|---|---|---|
| **Article 25**<br>Data Protection by Design & Default | Privacy by design; minimal data exposure | **Zero-Knowledge Architecture:** Data is encrypted client-side prior to network transmission. Server acts as an untrusted ciphertext storage and access relay. |
| **Article 32(1)(a)**<br>Pseudonymisation & Encryption | Pseudonymisation and encryption of personal data | Files are identified exclusively by UUIDv4; content is encrypted using AES-256-GCM. Metadata does not reveal medical diagnostic content. |
| **Article 32(1)(b)**<br>Confidentiality & Integrity | Ongoing confidentiality, integrity, availability, and resilience | Combination of AEAD (AES-GCM), PKI digital signatures (RSA-PSS), account lockout defense against brute force, and multi-threaded request processing. |
| **Article 32(1)(d)**<br>Regular Testing & Evaluation | Process for regularly testing security effectiveness | **Security Observatory / Attack Simulator:** Integrated 9-point automated adversarial test suite validating replay defense, bit-flip detection, rogue certificates, and audit integrity. |

---

## 3. NIST Guidelines & Algorithmic Justification

| Standard | Guidance | Our Implementation |
|---|---|---|
| **NIST SP 800-38D** | Recommendation for GCM Mode | 96-bit random nonce generated with OS CSPRNG (`os.urandom(12)`); 128-bit tag; never reuse `(key, nonce)` tuple. |
| **NIST SP 800-131A Rev 2** | Cryptographic Key Lengths | 3072-bit RSA keys providing ~128-bit security level, matching AES-256 and acceptable beyond 2030. |
| **NIST SP 800-52 Rev 2** | TLS Configuration | Minimum TLS 1.2; mutual client certificate authentication; weak cipher suites (SSLv3, TLS 1.0, 1.1) unconditionally refused. |
| **NIST SP 800-63B** | Digital Identity Guidelines | Scrypt memory-hard key derivation ($N=2^{17}, r=8, p=1$); rate-limiting with 5-attempt account lockout. |
| **NIST SP 800-57 Part 1** | Key Management & Key Escrow | Institutional Key Escrow for life-critical healthcare break-glass access under strict audit control. |

