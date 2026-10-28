# Limitations

This document honestly describes the known limitations of the Secure Healthcare File-Sharing Protocol. These are important for the technical report and for understanding the gap between this course project and a production system.

---

## 1. Keys Stored on Disk (No HSM)

**Limitation:** Application RSA private keys are stored as PKCS#8-encrypted PEM files on the local filesystem. TLS private keys are also on disk.

**Risk:** An attacker with read access to the filesystem can obtain the encrypted key files. If they also know (or can brute-force) the passphrase, they can decrypt the private key and:
- Decrypt any file for which they have the wrapped AES key.
- Forge signatures as that user.

**Production mitigation:** Use a Hardware Security Module (HSM) or a managed key service (AWS KMS, Azure Key Vault, HashiCorp Vault). Private key operations happen inside the HSM; the key material never leaves the hardware boundary.

---

## 2. No Recall of Downloaded Copies

**Limitation:** When a user downloads and decrypts a file, the plaintext exists on their local machine. Revoking access (deleting the wrapped key from the server) prevents future downloads but cannot recall copies already downloaded.

**Risk:** A revoked user who previously downloaded a file retains access to the plaintext indefinitely.

**Production mitigation:** Digital Rights Management (DRM) systems, short-lived decryption keys that must be refreshed from the server, or client-side enforcement with remote attestation (e.g., TPM-backed). All of these add significant complexity and are outside the scope of this project.

---

## 3. Single Key Pair for Sign and Encrypt

**Limitation:** Each user has one RSA key pair used for both RSA-OAEP (key wrapping) and RSA-PSS (signing). RFC 4270 and NIST SP 800-57 recommend separate keys for these operations.

**Risk:** Some attacks (e.g., Bleichenbacher) apply specifically to encryption keys. Using the same key for signing could theoretically allow an attacker to use a signing oracle as a decryption oracle (or vice versa), though no practical attack is known for RSA-OAEP + RSA-PSS with the same key.

**Production mitigation:** Generate separate key pairs for encryption and signing per user.

---

## 4. No Key Rotation

**Limitation:** There is no mechanism to rotate application RSA keys. If a key is compromised, the user must re-register with a new key, and all files must be re-shared with the new key.

**Risk:** A long-lived compromised key can be used to decrypt all past files (no forward secrecy for stored files).

**Production mitigation:** Implement key rotation with re-wrapping of all affected file keys. This is a complex operation requiring careful coordination.

---

## 5. SQLite Concurrency Limitations

**Limitation:** SQLite uses a single write lock. Under high concurrent write load (many simultaneous uploads), writes are serialised, reducing throughput.

**Risk:** Not a security risk, but a scalability limitation. For a single-server localhost demo, this is acceptable.

**Production mitigation:** Use PostgreSQL or MySQL with proper connection pooling.

---

## 6. No Rate Limiting

**Limitation:** The server does not implement per-IP rate limiting beyond account lockout. An attacker can send an unlimited number of requests.

**Risk:** Denial-of-service via request flooding. The `MAX_MESSAGE_SIZE_BYTES` cap prevents memory exhaustion from individual large messages, but not from many small messages.

**Production mitigation:** Implement per-IP rate limiting (e.g., token bucket algorithm) at the application or network layer (nginx, AWS WAF).

---

## 7. Break-Glass Key Access (Implemented via Key Escrow)

**Status: Addressed via Institutional Key Escrow Service.**

**Original Limitation:** Previously, the break-glass mechanism returned the uploader's wrapped key, preventing an emergency accessor from decrypting unless they possessed the uploader's private key.

**Implemented Solution:** The protocol now features **Institutional Key Escrow**:
1. During upload, the per-file AES-256 key is wrapped for the uploader and the institutional Escrow public key.
2. When an attending doctor invokes break-glass with clinical justification, the server unwraps the escrow copy using the Escrow Private Key and re-wraps the AES key for the requesting doctor's public key.
3. The doctor can immediately decrypt with their own private key.
4. The event is permanently logged with an `ACTION_BREAK_GLASS` high-severity audit record.

---

## 8. Python Memory Safety

**Limitation:** Python does not provide guaranteed memory zeroing. When a private key or AES key is loaded into a Python object and then dereferenced, the memory may remain accessible until the garbage collector reclaims it.

**Risk:** A memory dump of a running client process could expose decrypted private keys or AES keys.

**Production mitigation:** Use a native extension (ctypes, cffi) to explicitly zero sensitive memory buffers after use. The `cryptography` library uses OpenSSL's `OPENSSL_cleanse()` internally for some operations, but Python object memory is not guaranteed to be zeroed.

---

## 9. No Post-Quantum Cryptography

**Limitation:** RSA-3072 and AES-256 are not post-quantum secure. A sufficiently powerful quantum computer running Shor's algorithm could break RSA-3072 in polynomial time.

**Risk:** "Harvest now, decrypt later" attacks: an adversary records encrypted traffic today and decrypts it once a quantum computer is available. Healthcare data may need to remain confidential for 30+ years.

**Production mitigation:** Migrate to NIST PQC standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA) once library support matures. AES-256 is considered quantum-resistant (Grover's algorithm halves the effective key length to 128 bits, which remains secure).

---

## 10. Audit Log Recomputation Attack (Addressed via External Signed Checkpoints)

**Status: Addressed via External Signed Anchor Checkpointing.**

**Original Limitation:** The SQLite hash-chained audit log could theoretically be recomputed by an attacker with write access to the database by rewriting subsequent entry hashes.

**Implemented Solution:** The protocol now features **External Signed Checkpoints** (`server/audit_checkpoints.json`):
1. Administrators can anchor the tip of the hash chain by calculating an anchor digest and signing/saving the checkpoint file outside of the SQLite database.
2. During chain verification (`verify_audit_log(check_external_anchor=True)`), the system validates both internal pointer consistency and compares the recomputed state against the external signed anchor tip.
3. If a rogue database administrator modifies a historical record and recalculates the database hashes, verification immediately flags the mismatch against the external anchor.

---

## 11. No Certificate Revocation

**Limitation:** There is no CRL (Certificate Revocation List) or OCSP (Online Certificate Status Protocol) endpoint. A compromised TLS client certificate cannot be revoked without regenerating the entire PKI.

**Production mitigation:** Implement a CRL or OCSP responder. For a localhost demo, regenerating the CA and all certificates is acceptable.

---

## 12. Localhost Only

**Limitation:** The system is designed for localhost operation. The server certificate's SAN includes only `localhost` and `127.0.0.1`. Deploying to a real network requires regenerating certificates with the correct hostname/IP.

**This is intentional** per the project specification ("Must run entirely on localhost with no paid services or external servers").
