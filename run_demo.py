"""
run_demo.py — Interactive All-in-One Launcher for Healthcare Secure Share.

Provides single-command environment verification, test data seeding,
and orchestration for Server, Webapp, Benchmarks, and Attack simulations.

Run:
    python run_demo.py
"""

import os
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

CERTS_DIR = PROJECT_ROOT / "certs"
KEYS_DIR = PROJECT_ROOT / "keys"


def print_banner():
    print(r"""
========================================================================
  🏥  HEALTHCARE SECURE SHARE — PROTOCOL SUITE & LAB LAUNCHER
========================================================================
  * AES-256-GCM Authenticated Encryption with Associated Data (AEAD)
  * RSA-OAEP 3072 Key Wrapping & Institutional Key Escrow
  * RSA-PSS 3072 Digital Signatures for Non-Repudiation
  * Mutual TLS (mTLS) with Strict TLSv1.2+ Handshake
  * Scrypt Memory-Hard KDF + Monotonic Replay Protection
  * Hash-Chained Audit Log with External Signed Anchor Checkpoints
========================================================================
    """)


def check_prerequisites():
    print("[*] Checking environment prerequisites...")
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    has_certs = (CERTS_DIR / "ca.crt").exists() and (CERTS_DIR / "server.crt").exists()
    if not has_certs:
        print("[!] TLS Certificates not found in certs/. Generating now...")
        cmd = [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "generate_certs.py"),
            "--clients", "doctor", "nurse", "patient", "admin",
            "--ca-password", "capass123",
            "--server-password", "srvpass123",
            "--client-password", "clipass123",
        ]
        subprocess.run(cmd, check=True)
    else:
        print("  [✓] TLS Certificates: Verified.")

    users = [
        ("doctor", "DoctorPass1!"),
        ("nurse", "NursePass1!"),
        ("patient", "PatientPass1!"),
        ("admin", "AdminPass1!"),
        ("escrow", "EscrowPass1!"),
    ]
    for u, p in users:
        priv = KEYS_DIR / f"{u}_app_private.pem"
        pub = KEYS_DIR / f"{u}_app_public.pem"
        if not priv.exists() or not pub.exists():
            print(f"[!] Generating RSA-3072 application keys for '{u}'...")
            cmd = [
                sys.executable,
                str(PROJECT_ROOT / "scripts" / "generate_user_keys.py"),
                "--username", u,
                "--password", p,
            ]
            subprocess.run(cmd, check=True)
    print("  [✓] Application RSA-3072 Key Pairs: Verified.")


def seed_sample_patient_records():
    print("[*] Seeding realistic sample healthcare records...")
    samples_dir = PROJECT_ROOT / "sample_records"
    samples_dir.mkdir(exist_ok=True)

    cardiology = samples_dir / "Cardiology_Stress_Test_Report.txt"
    if not cardiology.exists():
        cardiology.write_text(
            "PATIENT: John Doe (DOB: 1984-05-12)\n"
            "RECORD ID: MED-883921-CAR\n"
            "PROCEDURE: Nuclear Stress Test / Echocardiogram\n"
            "FINDINGS: Normal left ventricular systolic function. Ejection Fraction: 62%.\n"
            "ALLERGIES: Penicillin (Anaphylaxis), Contrast Dye (Mild Rash)\n"
            "PHYSICIAN: Dr. S. Smith, MD (Cardiology)\n",
            encoding="utf-8"
        )

    radiology = samples_dir / "Chest_CT_Radiology_Diagnostic.txt"
    if not radiology.exists():
        radiology.write_text(
            "PATIENT: Jane Roe (DOB: 1991-11-23)\n"
            "RECORD ID: RAD-449102-CT\n"
            "SCAN TYPE: High-Resolution Computed Tomography (HRCT) - Thorax\n"
            "IMPRESSION: No pulmonary embolism. Clear lung parenchyma bilaterally.\n"
            "PHYSICIAN: Dr. E. Davis, MD (Radiology)\n",
            encoding="utf-8"
        )
    print(f"  [✓] Sample records generated in {samples_dir.relative_to(PROJECT_ROOT)}/")


def show_menu():
    print("""
Select an action to launch:
  [1] Start Mutual-TLS Backend Server
  [2] Start Web Interface (http://127.0.0.1:5000)
  [3] Run 9-Point Attack & Defense Simulator (CLI)
  [4] Run Cryptographic Performance Benchmarking Suite
  [5] Seed Sample Patient Medical Records
  [6] Open Documentation & Compliance Matrix
  [Q] Exit
    """)


def main():
    print_banner()
    try:
        check_prerequisites()
    except Exception as e:
        print(f"[!] Error preparing environment: {e}")

    env = os.environ.copy()
    env["SERVER_KEY_PASSWORD"] = "srvpass123"
    env["CLIENT_KEY_PASSWORD"] = "clipass123"

    while True:
        show_menu()
        choice = input("Enter choice (1-6 or Q): ").strip().upper()
        if choice == "1":
            print("\n[+] Starting Mutual-TLS Backend Server on 127.0.0.1:9443...")
            print("Press Ctrl+C to stop.\n")
            try:
                subprocess.run([sys.executable, "-m", "server.server"], env=env)
            except KeyboardInterrupt:
                pass
        elif choice == "2":
            print("\n[+] Starting Web Application on http://127.0.0.1:5000...")
            print("Press Ctrl+C to stop.\n")
            try:
                subprocess.run([sys.executable, "-m", "webapp.app"], env=env)
            except KeyboardInterrupt:
                pass
        elif choice == "3":
            print("\n[+] Executing Attack Simulator...")
            subprocess.run([sys.executable, "-m", "attacks.attacker"], env=env)
        elif choice == "4":
            print("\n[+] Executing Cryptographic Benchmarking Suite...")
            subprocess.run([sys.executable, str(PROJECT_ROOT / "scripts" / "benchmark.py")], env=env)
        elif choice == "5":
            seed_sample_patient_records()
        elif choice == "6":
            print("\n--- Documentation Quick Links ---")
            print("  * Architecture & Justification : docs/ALGORITHM_JUSTIFICATION.md")
            print("  * Threat Model & STRIDE       : docs/THREAT_MODEL.md")
            print("  * HIPAA / GDPR Compliance     : docs/COMPLIANCE_MAPPING.md")
            print("  * Limitations & Future Work   : docs/LIMITATIONS.md")
        elif choice in ("Q", "QUIT", "EXIT"):
            print("\nExiting. Stay secure!")
            break


if __name__ == "__main__":
    main()

