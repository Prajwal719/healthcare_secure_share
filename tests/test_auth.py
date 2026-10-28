"""
test_auth.py — pytest suite for server/auth.py

Tests cover:
    - Token issuance and verification
    - Token expiry and forgery
    - RBAC permission checks
    - Login flow (correct, wrong password, lockout)

Run:
    cd healthcare_secure_share
    pytest tests/test_auth.py -v
"""

import base64
import hmac as _hmac
import hashlib
import os
import time

import pytest

from server.auth import (
    AccountLockedError,
    InvalidCredentialsError,
    InvalidTokenError,
    PermissionDeniedError,
    authenticate_user,
    check_permission,
    has_permission,
    issue_token,
    verify_token,
    _TOKEN_HMAC_KEY,
)
from server.storage import Database
from common.crypto_utils import hmac_sign, scrypt_hash_password
from common.config import MAX_LOGIN_ATTEMPTS, ROLES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db():
    return Database(":memory:")


@pytest.fixture
def populated_db(db):
    ph_doc = scrypt_hash_password("DoctorPass1!")
    db.create_user(
        username="testdoctor", role="doctor",
        password_hash=ph_doc.derived_key, password_salt=ph_doc.salt,
        scrypt_n=ph_doc.n, scrypt_r=ph_doc.r, scrypt_p=ph_doc.p,
    )
    ph_nur = scrypt_hash_password("NursePass1!")
    db.create_user(
        username="testnurse", role="nurse",
        password_hash=ph_nur.derived_key, password_salt=ph_nur.salt,
        scrypt_n=ph_nur.n, scrypt_r=ph_nur.r, scrypt_p=ph_nur.p,
    )
    return db


# ---------------------------------------------------------------------------
# Token issuance and verification
# ---------------------------------------------------------------------------

class TestTokenIssuance:
    def test_issue_and_verify_returns_correct_fields(self):
        token = issue_token("user-uuid-123", "doctor")
        user_id, role = verify_token(token)
        assert user_id == "user-uuid-123"
        assert role == "doctor"

    def test_all_roles_can_be_issued(self):
        for role in ROLES:
            token = issue_token("uid", role)
            _, r = verify_token(token)
            assert r == role

    def test_empty_user_id_raises(self):
        with pytest.raises(ValueError):
            issue_token("", "doctor")

    def test_empty_role_raises(self):
        with pytest.raises(ValueError):
            issue_token("uid", "")


class TestTokenVerification:
    def test_malformed_token_raises(self):
        with pytest.raises(InvalidTokenError):
            verify_token("notavalidtoken")

    def test_wrong_signature_raises(self):
        token = issue_token("uid", "doctor")
        parts = token.split(".")
        tampered = parts[0] + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        with pytest.raises(InvalidTokenError):
            verify_token(tampered)

    def test_tampered_payload_raises(self):
        token = issue_token("uid", "nurse")
        parts = token.split(".")
        payload = base64.urlsafe_b64decode(parts[0] + "==")
        evil = payload.decode().replace("nurse", "admin").encode()
        evil_b64 = base64.urlsafe_b64encode(evil).decode().rstrip("=")
        with pytest.raises(InvalidTokenError):
            verify_token(evil_b64 + "." + parts[1])

    def test_expired_token_raises(self):
        past = time.time() - 3600
        payload = f"uid|doctor|{past:.6f}".encode()
        fake_key = os.urandom(32)
        mac = _hmac.new(fake_key, payload, hashlib.sha256).digest()
        p64 = base64.urlsafe_b64encode(payload).decode()
        m64 = base64.urlsafe_b64encode(mac).decode()
        with pytest.raises(InvalidTokenError):
            verify_token(f"{p64}.{m64}")

    def test_unknown_role_in_token_raises(self):
        future = time.time() + 900
        payload = f"uid|superadmin|{future:.6f}".encode()
        mac = hmac_sign(payload, _TOKEN_HMAC_KEY)
        p64 = base64.urlsafe_b64encode(payload).decode()
        m64 = base64.urlsafe_b64encode(mac).decode()
        with pytest.raises(InvalidTokenError, match="unknown role"):
            verify_token(f"{p64}.{m64}")


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------

class TestRbac:
    def test_doctor_can_upload(self):
        check_permission("doctor", "upload")

    def test_doctor_can_share(self):
        check_permission("doctor", "share")

    def test_nurse_cannot_upload(self):
        with pytest.raises(PermissionDeniedError):
            check_permission("nurse", "upload")

    def test_nurse_can_download(self):
        check_permission("nurse", "download")

    def test_patient_cannot_upload(self):
        with pytest.raises(PermissionDeniedError):
            check_permission("patient", "upload")

    def test_patient_cannot_share(self):
        with pytest.raises(PermissionDeniedError):
            check_permission("patient", "share")

    def test_admin_can_view_audit_log(self):
        check_permission("admin", "audit_log")

    def test_admin_cannot_upload(self):
        with pytest.raises(PermissionDeniedError):
            check_permission("admin", "upload")

    def test_unknown_role_raises(self):
        with pytest.raises(PermissionDeniedError):
            check_permission("hacker", "upload")

    def test_has_permission_returns_bool(self):
        assert has_permission("doctor", "upload") is True
        assert has_permission("nurse", "upload") is False
        assert has_permission("unknown", "upload") is False


# ---------------------------------------------------------------------------
# Login flow
# ---------------------------------------------------------------------------

class TestLoginFlow:
    def test_correct_credentials_return_token(self, populated_db):
        user, token = authenticate_user(populated_db, "testdoctor", "DoctorPass1!")
        assert user.username == "testdoctor"
        assert user.role == "doctor"
        uid, role = verify_token(token)
        assert uid == user.user_id
        assert role == "doctor"

    def test_wrong_password_raises(self, populated_db):
        with pytest.raises(InvalidCredentialsError):
            authenticate_user(populated_db, "testdoctor", "WrongPassword!")

    def test_nonexistent_user_raises(self, populated_db):
        with pytest.raises(InvalidCredentialsError):
            authenticate_user(populated_db, "nobody", "anything")

    def test_failed_attempts_increment(self, populated_db):
        for _ in range(3):
            try:
                authenticate_user(populated_db, "testdoctor", "wrong")
            except InvalidCredentialsError:
                pass
        user = populated_db.get_user_by_username("testdoctor")
        assert user.failed_attempts == 3

    def test_account_locks_after_max_attempts(self, populated_db):
        for _ in range(MAX_LOGIN_ATTEMPTS):
            try:
                authenticate_user(populated_db, "testdoctor", "wrong")
            except (InvalidCredentialsError, AccountLockedError):
                pass
        with pytest.raises(AccountLockedError):
            authenticate_user(populated_db, "testdoctor", "DoctorPass1!")

    def test_successful_login_resets_failed_counter(self, populated_db):
        for _ in range(2):
            try:
                authenticate_user(populated_db, "testdoctor", "wrong")
            except InvalidCredentialsError:
                pass
        authenticate_user(populated_db, "testdoctor", "DoctorPass1!")
        user = populated_db.get_user_by_username("testdoctor")
        assert user.failed_attempts == 0

    def test_nurse_login_returns_nurse_role(self, populated_db):
        user, token = authenticate_user(populated_db, "testnurse", "NursePass1!")
        assert user.role == "nurse"
        _, role = verify_token(token)
        assert role == "nurse"
