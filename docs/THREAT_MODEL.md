# Threat Model — Secure Healthcare File-Sharing Protocol

## Methodology: STRIDE

STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) is a structured threat-modelling framework developed by Microsoft. Each row below identifies one threat, the attacker's assumed capability, the defence implemented, and the residual risk after the defence is applied.

---

## System Assets

| Asset | Sensitivity |
|---|---|
| Patient file plaintext | Critical — PHI (Protected Health Information) |
| AES-256 per-file keys | Critical — loss = loss of confidentiality |
| RSA private keys (application) | Critical — loss = loss of non-repudiation |
| RSA private keys (TLS) | High — loss = MITM possible |
| Session tokens | Medium — short-lived (15 min), role-scoped |
| Audit log | High — tamper = loss of accountability |
| Password hashes | High — scrypt-hardened but still a target |

---

## STRIDE Threat Table

| # | Category | Threat | Attacker Capability | Defence | Residual Risk |
|---|---|---|---|---|---|
| T1 | **Spoofing** | Attacker impersonates a legitimate user at login | Network access; stolen password | scrypt password hashing (N=2^17); account lockout after 5 failures; mutual TLS requires CA-signed client cert | If attacker steals both password AND TLS client cert private key, impersonation succeeds. Mitigated by optional TOTP 2FA. |
| T2 | **Spoofing** | Attacker presents a forged TLS client certificate | Ability to generate self-signed certs | Mutual TLS with `ssl.CERT_REQUIRED`; only certs signed by our CA are accepted | If the CA private key is compromised, attacker can issue valid certs. CA key is encrypted on disk; no online CA. |
| T3 | **Spoofing** | Attacker forges an RSA-PSS file signature | Access to any RSA key pair | Server verifies signature against the uploader's registered public key; RSA-PSS with SHA-256 is unforgeable without the private key | If the uploader's private key is stolen, the attacker can forge signatures for that user. |
| T4 | **Tampering** | Attacker flips bits in stored ciphertext | Write access to the database | AES-256-GCM authentication tag covers the ciphertext; any modification raises `InvalidTag` on decryption | None — GCM provides 128-bit authentication. |
| T5 | **Tampering** | Attacker modifies the AAD (metadata) after upload | Write access to the database | AAD is bound into the GCM tag; modified AAD causes tag failure | None — GCM covers AAD. |
| T6 | **Tampering** | Attacker modifies the audit log | Write access to the SQLite database | Hash-chained audit log; `verify_audit_log()` detects any modification | An attacker with DB write access can recompute the entire chain. Mitigation: anchor chain tip to an external append-only log (not implemented — documented limitation). |
| T7 | **Repudiation** | Uploader denies having uploaded a file | Ability to lie | RSA-PSS signature over (ciphertext ‖ nonce ‖ AAD) stored with the file; server verifies on upload; recipient verifies on download | If the uploader's private key is compromised before the upload, a third party could have signed. Key generation timestamp in audit log provides partial evidence. |
| T8 | **Information Disclosure** | Attacker reads the database file | Read access to the server filesystem | Server stores only AES-256-GCM ciphertext; AES keys are RSA-OAEP wrapped per recipient; plaintext is never stored | Attacker who also steals a user's RSA private key can decrypt that user's files. |
| T9 | **Information Disclosure** | Attacker intercepts network traffic (passive eavesdrop) | Network tap on the LAN | All traffic is TLS 1.2+ encrypted; TLS 1.3 provides forward secrecy via ephemeral key exchange | None for traffic in transit. Stored data risk covered by T8. |
| T10 | **Information Disclosure** | Attacker performs a MITM attack | Control of network path | Mutual TLS with certificate pinning to our CA; client verifies server cert against `ca.crt` | If the CA key is compromised, MITM is possible. |
| T11 | **Information Disclosure** | Attacker replays a captured download response | Passive network capture | TLS provides replay protection at the transport layer; application-layer replay guard on requests | None — TLS sequence numbers prevent replay of captured TLS records. |
| T12 | **Information Disclosure** | Timing side-channel on password verification | Ability to measure response times | `hmac.compare_digest()` for constant-time comparison; scrypt always runs even for unknown usernames | Scrypt timing varies slightly with CPU load; not a practical attack on a LAN. |
| T13 | **Denial of Service** | Attacker sends oversized messages to exhaust memory | Network access | `MAX_MESSAGE_SIZE_BYTES` (64 MiB) enforced before buffer allocation; size check on the 4-byte length prefix | A sustained flood of max-size messages could exhaust bandwidth. No rate limiting implemented (documented limitation). |
| T14 | **Denial of Service** | Attacker triggers account lockout for legitimate users | Knowledge of valid usernames | Lockout is per-account with a 5-minute cooldown; admin can unlock via `manage_user` | An attacker who knows valid usernames can lock them out. Username enumeration is mitigated by constant-time login (T12). |
| T15 | **Denial of Service** | Attacker fills the replay cache | Ability to send many requests | Replay cache is bounded at 10,000 entries (LRU eviction); timestamp window limits effective cache lifetime | Eviction of old entries is safe because the timestamp check independently rejects stale messages. |
| T16 | **Elevation of Privilege** | Nurse attempts to upload a file | Valid nurse session token | RBAC allowlist checked server-side on every request; `check_permission()` raises before any action is taken | None — RBAC is enforced server-side, not client-side. |
| T17 | **Elevation of Privilege** | Attacker forges a session token to claim admin role | Ability to craft arbitrary strings | HMAC-SHA256 token signed with a server-side secret key (in-memory only); MAC verified before payload is parsed | If the server process memory is dumped, the HMAC key is exposed. Mitigated by short token lifetime (15 min). |
| T18 | **Elevation of Privilege** | Attacker replays a captured session token | Passive network capture | TLS encrypts tokens in transit; token expiry (15 min) limits the replay window; replay guard on msg_id | A token captured within its 15-minute window could be replayed if TLS is broken (covered by T10). |
| T19 | **Elevation of Privilege** | Patient accesses another patient's files | Valid patient session token | Server-side check: patient role can only download files where they are the uploader OR have an explicit wrapped key | A doctor who shares a file with a patient grants that patient access — this is intentional. |

---

## Trust Boundaries

```
[Client Process]  ──TLS 1.2+──  [Server Process]  ──SQLite──  [Database File]
     │                                  │
  App RSA keys                    In-memory HMAC key
  (disk, encrypted)               (lost on restart)
```

- The TLS boundary protects against network-level attackers.
- The application-layer crypto (AES-GCM, RSA-OAEP, RSA-PSS) protects against a compromised server that can read the database.
- The HMAC token boundary protects against session hijacking within a TLS session.

---

## Out-of-Scope Threats

- **Physical access** to the server machine (OS-level compromise).
- **Supply-chain attacks** on the `cryptography` library.
- **Quantum computing** (RSA-3072 and AES-256 are not post-quantum; documented in LIMITATIONS.md).
- **Side-channel attacks** on the CPU (cache-timing, power analysis).
