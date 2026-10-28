"""
benchmark.py — Cryptographic Performance Benchmarking Suite for
Healthcare Secure Share Protocol.

Measures:
  1. AES-256-GCM throughput across representative medical data sizes (64KB, 1MB, 10MB).
  2. RSA-3072 OAEP key wrapping/unwrapping operations/sec and latency.
  3. RSA-3072 PSS signature generation/verification operations/sec and latency.
  4. Scrypt CPU/memory-hard key derivation vs. PBKDF2 trade-off analysis.
  5. ReplayGuard in-memory deduplication and sliding window check latency.

Usage:
  cd healthcare_secure_share
  python scripts/benchmark.py
"""

import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from common.crypto_utils import (
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    generate_rsa_keypair,
    rsa_oaep_wrap,
    rsa_oaep_unwrap,
    rsa_pss_sign,
    rsa_pss_verify,
    scrypt_hash_password,
    verify_password_scrypt,
    pbkdf2_hash_password,
    verify_password_pbkdf2,
    sha256_digest,
)
from common.replay_guard import ReplayGuard


def format_table(headers: list[str], rows: list[list[str]]) -> str:
    """Format an aligned Markdown table."""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    def make_line(items: list[str]) -> str:
        return "| " + " | ".join(f"{items[i]:<{col_widths[i]}}" for i in range(len(items))) + " |"

    sep = "| " + " | ".join("-" * col_widths[i] for i in range(len(headers))) + " |"
    table_lines = [make_line(headers), sep]
    for row in rows:
        table_lines.append(make_line(row))
    return "\n".join(table_lines)


def benchmark_symmetric() -> str:
    print("--> Benchmarking AES-256-GCM AEAD...")
    sizes = [
        ("64 KB (Lab Result / Prescription)", 64 * 1024, 100),
        ("1 MB (EHR Record / Scan)", 1024 * 1024, 30),
        ("10 MB (High-Res DICOM Image)", 10 * 1024 * 1024, 5),
    ]
    rows = []
    aad = b'{"record_type":"DICOM_EHR","timestamp":1700000000}'

    for label, size_bytes, iters in sizes:
        data = os.urandom(size_bytes)
        # Encrypt benchmark
        t0 = time.perf_counter()
        for _ in range(iters):
            enc, key = aes_gcm_encrypt(data, aad)
        enc_time = (time.perf_counter() - t0) / iters

        # Decrypt benchmark
        t0 = time.perf_counter()
        for _ in range(iters):
            _ = aes_gcm_decrypt(enc, key)
        dec_time = (time.perf_counter() - t0) / iters

        mb = size_bytes / (1024 * 1024)
        enc_throughput = mb / enc_time
        dec_throughput = mb / dec_time

        rows.append([
            label,
            f"{enc_time*1000:.2f} ms",
            f"{enc_throughput:.1f} MB/s",
            f"{dec_time*1000:.2f} ms",
            f"{dec_throughput:.1f} MB/s",
        ])

    return format_table(
        ["Payload Profile", "Enc Latency", "Enc Throughput", "Dec Latency", "Dec Throughput"],
        rows
    )


def benchmark_asymmetric() -> str:
    print("--> Benchmarking RSA-3072 Key Operations (OAEP & PSS)...")
    priv, pub = generate_rsa_keypair()
    aes_key = os.urandom(32)
    sample_data = os.urandom(1024)

    # OAEP Wrap
    iters = 30
    t0 = time.perf_counter()
    for _ in range(iters):
        wrapped = rsa_oaep_wrap(aes_key, pub)
    wrap_latency = (time.perf_counter() - t0) / iters

    # OAEP Unwrap
    t0 = time.perf_counter()
    for _ in range(iters):
        _ = rsa_oaep_unwrap(wrapped, priv)
    unwrap_latency = (time.perf_counter() - t0) / iters

    # PSS Sign
    t0 = time.perf_counter()
    for _ in range(iters):
        sig = rsa_pss_sign(sample_data, priv)
    sign_latency = (time.perf_counter() - t0) / iters

    # PSS Verify
    t0 = time.perf_counter()
    for _ in range(iters):
        _ = rsa_pss_verify(sample_data, sig, pub)
    verify_latency = (time.perf_counter() - t0) / iters

    rows = [
        ["RSA-3072 OAEP Wrap (Encrypt Key)", f"{wrap_latency*1000:.2f} ms", f"{1.0/wrap_latency:.1f} ops/s"],
        ["RSA-3072 OAEP Unwrap (Decrypt Key)", f"{unwrap_latency*1000:.2f} ms", f"{1.0/unwrap_latency:.1f} ops/s"],
        ["RSA-3072 PSS Sign (Digital Signature)", f"{sign_latency*1000:.2f} ms", f"{1.0/sign_latency:.1f} ops/s"],
        ["RSA-3072 PSS Verify (Verification)", f"{verify_latency*1000:.2f} ms", f"{1.0/verify_latency:.1f} ops/s"],
    ]

    return format_table(["Operation", "Avg Latency", "Throughput"], rows)


def benchmark_kdf() -> str:
    print("--> Benchmarking Password KDF & Hashing...")
    password = "HealthcareHospitalPass2026!"
    rows = []

    # Scrypt with varying N
    scrypt_configs = [
        ("scrypt (N=2^14, r=8, p=1) - Low RAM", 2**14, 8, 1),
        ("scrypt (N=2^15, r=8, p=1) - Medium", 2**15, 8, 1),
        ("scrypt (N=2^16, r=8, p=1) - Standard", 2**16, 8, 1),
        ("scrypt (N=2^17, r=8, p=1) - OWASP 2023", 2**17, 8, 1),
    ]

    for label, n, r, p in scrypt_configs:
        t0 = time.perf_counter()
        ph = scrypt_hash_password(password, n=n, r=r, p=p)
        dur = time.perf_counter() - t0
        mem_mb = (128 * r * n) / (1024 * 1024)
        rows.append([label, f"{mem_mb:.1f} MB", f"{dur*1000:.1f} ms"])

    # PBKDF2 comparison
    t0 = time.perf_counter()
    pb = pbkdf2_hash_password(password, iterations=600_000)
    pb_dur = time.perf_counter() - t0
    rows.append(["PBKDF2-HMAC-SHA256 (600,000 iter)", "< 1 MB (CPU-only)", f"{pb_dur*1000:.1f} ms"])

    return format_table(["KDF Algorithm & Work Factor", "RAM Footprint", "Derivation Latency"], rows)


def benchmark_replay_guard() -> str:
    print("--> Benchmarking ReplayGuard in-memory check throughput...")
    import uuid
    guard = ReplayGuard(window_seconds=60)
    session_id = "session_bench_001"
    now = time.time()
    n_ops = 5000

    t0 = time.perf_counter()
    for i in range(1, n_ops + 1):
        guard.check_and_record(str(uuid.uuid4()), now, i, session_id)
    total_time = time.perf_counter() - t0

    latency_us = (total_time / n_ops) * 1_000_000
    ops_sec = n_ops / total_time

    rows = [
        ["ReplayGuard Monotonic & Nonce Verification", f"{latency_us:.2f} µs", f"{ops_sec:,.0f} checks/s"],
    ]
    return format_table(["Component", "Check Latency", "Throughput"], rows)


def main():
    print("=" * 70)
    print("  Healthcare Secure Share — Cryptographic Benchmark Suite")
    print("=" * 70)
    print()

    sym_table = benchmark_symmetric()
    print("\n### 1. Symmetric Encryption Performance (AES-256-GCM)\n")
    print(sym_table)
    print()

    asym_table = benchmark_asymmetric()
    print("\n### 2. Asymmetric Cryptography Performance (RSA-3072)\n")
    print(asym_table)
    print()

    kdf_table = benchmark_kdf()
    print("\n### 3. Password Key Derivation Function (KDF) Trade-offs\n")
    print(kdf_table)
    print()

    replay_table = benchmark_replay_guard()
    print("\n### 4. Protocol Defense Overhead (ReplayGuard)\n")
    print(replay_table)
    print()

    print("=" * 70)
    print("Benchmark complete. Output tables are ready for technical reports.")
    print("=" * 70)


if __name__ == "__main__":
    main()

