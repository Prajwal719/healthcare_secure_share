"""
test_crypto.py — pytest suite for common/crypto_utils.py

Tests are named after the behaviour they verify, not the function they call,
so that a failing test name immediately tells you WHAT broke.

Run:
    cd healthcare_secure_share
    pytest tests/test_crypto.py -v
"""

import os

import pytest
from cryptography.exceptions import InvalidTag

from common.crypto_utils import (
    EncryptedFile,
    PasswordHash,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    generate_rsa_keypair,
    hmac_sign,
    hmac_verify,
    load_private_key,
    load_public_key,
    pbkdf2_hash_password,
    pbkdf2_verify_password,
    rsa_oaep_unwrap,
    rsa_oaep_wrap,
    rsa_pss_sign,
    rsa_pss_verify,
    scrypt_hash_password,
    scrypt_verify_password,
    serialize_private_key,
    serialize_public_key,
    sha256_digest,
)

# ---------------------------------------------------------------------------
# Fixtures (module-scoped to avoid generating keys for every test)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rsa_keypair_alice():
    """Alice's RSA key pair, generated once per test session."""
    return generate_rsa_keypair()


@pytest.fixture(scope="module")
def rsa_keypair_bob():
    """Bob's RSA key pair — a different party."""
    return generate_rsa_keypair()


# ---------------------------------------------------------------------------
# AES-256-GCM
# ---------------------------------------------------------------------------


class TestAesGcmEncrypt:
    """Encryption primitive tests."""

    def test_encrypt_returns_encrypted_file_and_key(self):
        plaintext = b"Patient record: Alice, DOB 1990-01-01"
        aad = b'{"file_id":"f1","sender_id":"doc1","ts":1234567890}'
        enc, key = aes_gcm_encrypt(plaintext, aad)
        assert isinstance(enc, EncryptedFile)
        assert isinstance(key, bytes)
        assert len(key) == 32  # 256-bit AES key

    def test_ciphertext_differs_from_plaintext(self):
        plaintext = b"secret data"
        enc, _ = aes_gcm_encrypt(plaintext, b"aad")
        assert enc.ciphertext != plaintext

    def test_nonce_is_96_bits(self):
        _, _ = aes_gcm_encrypt(b"data", b"aad")
        enc, _ = aes_gcm_encrypt(b"data", b"aad")
        assert len(enc.nonce) == 12

    def test_each_call_produces_unique_nonce(self):
        """Nonce reuse with the same key would be catastrophic — verify randomness."""
        nonces = {aes_gcm_encrypt(b"data", b"aad")[0].nonce for _ in range(100)}
        # All 100 nonces must be distinct
        assert len(nonces) == 100

    def test_each_call_produces_unique_key(self):
        """A new key must be generated per file, never reused."""
        keys = {aes_gcm_encrypt(b"data", b"aad")[1] for _ in range(50)}
        assert len(keys) == 50

    def test_empty_plaintext_raises(self):
        with pytest.raises(ValueError, match="empty"):
            aes_gcm_encrypt(b"", b"aad")


class TestAesGcmDecrypt:
    """Decryption and authentication tests."""

    def test_decrypt_recovers_original_plaintext(self):
        plaintext = b"Confidential: prescribe 500mg ibuprofen"
        aad = b"meta"
        enc, key = aes_gcm_encrypt(plaintext, aad)
        recovered = aes_gcm_decrypt(enc, key)
        assert recovered == plaintext

    def test_wrong_key_raises_invalid_tag(self):
        enc, _ = aes_gcm_encrypt(b"data", b"aad")
        wrong_key = os.urandom(32)
        with pytest.raises(InvalidTag):
            aes_gcm_decrypt(enc, wrong_key)

    def test_tampered_ciphertext_raises_invalid_tag(self):
        """Flipping a single bit in the ciphertext must cause authentication failure."""
        plaintext = b"Integrity is sacred"
        enc, key = aes_gcm_encrypt(plaintext, b"aad")
        # Flip the first byte of the ciphertext
        tampered = bytes([enc.ciphertext[0] ^ 0xFF]) + enc.ciphertext[1:]
        tampered_enc = EncryptedFile(ciphertext=tampered, nonce=enc.nonce, aad=enc.aad)
        with pytest.raises(InvalidTag):
            aes_gcm_decrypt(tampered_enc, key)

    def test_tampered_aad_raises_invalid_tag(self):
        """Modifying metadata (AAD) after encryption must break the tag."""
        enc, key = aes_gcm_encrypt(b"data", b'{"file_id":"original"}')
        modified_enc = EncryptedFile(
            ciphertext=enc.ciphertext,
            nonce=enc.nonce,
            aad=b'{"file_id":"modified"}',   # attacker changes the file_id
        )
        with pytest.raises(InvalidTag):
            aes_gcm_decrypt(modified_enc, key)

    def test_tampered_nonce_raises_invalid_tag(self):
        enc, key = aes_gcm_encrypt(b"data", b"aad")
        bad_nonce = bytes([enc.nonce[0] ^ 0x01]) + enc.nonce[1:]
        bad_enc = EncryptedFile(ciphertext=enc.ciphertext, nonce=bad_nonce, aad=enc.aad)
        with pytest.raises(InvalidTag):
            aes_gcm_decrypt(bad_enc, key)

    def test_wrong_key_length_raises_value_error(self):
        enc, _ = aes_gcm_encrypt(b"data", b"aad")
        with pytest.raises(ValueError, match="AES key must be"):
            aes_gcm_decrypt(enc, b"tooshort")


# ---------------------------------------------------------------------------
# RSA Key Generation and Serialisation
# ---------------------------------------------------------------------------


class TestRsaKeyGeneration:
    def test_private_key_modulus_size(self, rsa_keypair_alice):
        priv, _ = rsa_keypair_alice
        assert priv.key_size == 3072

    def test_public_key_extracted_correctly(self, rsa_keypair_alice):
        priv, pub = rsa_keypair_alice
        assert pub.key_size == 3072

    def test_two_keypairs_are_different(self, rsa_keypair_alice, rsa_keypair_bob):
        _, pub_a = rsa_keypair_alice
        _, pub_b = rsa_keypair_bob
        pem_a = serialize_public_key(pub_a)
        pem_b = serialize_public_key(pub_b)
        assert pem_a != pem_b


class TestRsaKeySerialization:
    def test_private_key_round_trip(self, rsa_keypair_alice):
        priv, _ = rsa_keypair_alice
        password = b"hunter2_correct_horse_battery_staple"
        pem = serialize_private_key(priv, password)
        assert b"ENCRYPTED" in pem or b"PRIVATE KEY" in pem
        recovered = load_private_key(pem, password)
        # Verify same public key after round-trip
        assert recovered.public_key().public_bytes(
            __import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
            __import__("cryptography").hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
        ) == serialize_public_key(priv.public_key())

    def test_wrong_password_raises(self, rsa_keypair_alice):
        priv, _ = rsa_keypair_alice
        pem = serialize_private_key(priv, b"correct_password")
        with pytest.raises(Exception):
            load_private_key(pem, b"wrong_password")

    def test_empty_password_raises(self, rsa_keypair_alice):
        priv, _ = rsa_keypair_alice
        with pytest.raises(ValueError, match="empty password"):
            serialize_private_key(priv, b"")

    def test_public_key_round_trip(self, rsa_keypair_alice):
        _, pub = rsa_keypair_alice
        pem = serialize_public_key(pub)
        recovered = load_public_key(pem)
        assert serialize_public_key(recovered) == pem


# ---------------------------------------------------------------------------
# RSA-OAEP Key Wrapping
# ---------------------------------------------------------------------------


class TestRsaOaepWrap:
    def test_wrap_produces_correct_output_length(self, rsa_keypair_alice):
        priv, pub = rsa_keypair_alice
        aes_key = os.urandom(32)
        wrapped = rsa_oaep_wrap(aes_key, pub)
        # For 3072-bit RSA: modulus = 384 bytes
        assert len(wrapped) == 384

    def test_unwrap_recovers_original_key(self, rsa_keypair_alice):
        priv, pub = rsa_keypair_alice
        aes_key = os.urandom(32)
        wrapped = rsa_oaep_wrap(aes_key, pub)
        recovered = rsa_oaep_unwrap(wrapped, priv)
        assert recovered == aes_key

    def test_wrong_private_key_fails_unwrap(self, rsa_keypair_alice, rsa_keypair_bob):
        _, pub_alice = rsa_keypair_alice
        priv_bob, _ = rsa_keypair_bob
        aes_key = os.urandom(32)
        wrapped_for_alice = rsa_oaep_wrap(aes_key, pub_alice)
        # Bob's key must NOT be able to unwrap Alice's ciphertext
        with pytest.raises(Exception):
            rsa_oaep_unwrap(wrapped_for_alice, priv_bob)

    def test_same_key_produces_different_ciphertexts(self, rsa_keypair_alice):
        """OAEP is randomised — two wrappings of the same AES key differ."""
        _, pub = rsa_keypair_alice
        aes_key = os.urandom(32)
        c1 = rsa_oaep_wrap(aes_key, pub)
        c2 = rsa_oaep_wrap(aes_key, pub)
        assert c1 != c2

    def test_wrong_key_length_raises(self, rsa_keypair_alice):
        _, pub = rsa_keypair_alice
        with pytest.raises(ValueError, match="AES key must be"):
            rsa_oaep_wrap(b"tooshort", pub)


# ---------------------------------------------------------------------------
# RSA-PSS Signatures
# ---------------------------------------------------------------------------


class TestRsaPssSignatures:
    def test_valid_signature_verifies(self, rsa_keypair_alice):
        priv, pub = rsa_keypair_alice
        message = b"ciphertext_bytes || nonce || metadata"
        sig = rsa_pss_sign(message, priv)
        assert rsa_pss_verify(message, sig, pub) is True

    def test_modified_message_fails_verification(self, rsa_keypair_alice):
        """Bit-flip in signed data must be detected."""
        priv, pub = rsa_keypair_alice
        message = b"original message content"
        sig = rsa_pss_sign(message, priv)
        tampered = b"0riginal message content"  # first char changed
        assert rsa_pss_verify(tampered, sig, pub) is False

    def test_wrong_public_key_fails_verification(self, rsa_keypair_alice, rsa_keypair_bob):
        """Signature made with Alice's key must not verify with Bob's public key."""
        priv_alice, _ = rsa_keypair_alice
        _, pub_bob = rsa_keypair_bob
        message = b"alice signs this"
        sig = rsa_pss_sign(message, priv_alice)
        assert rsa_pss_verify(message, sig, pub_bob) is False

    def test_forged_signature_fails_verification(self, rsa_keypair_alice):
        _, pub = rsa_keypair_alice
        message = b"legitimate message"
        forged_sig = os.urandom(384)   # random 384-byte blob
        assert rsa_pss_verify(message, forged_sig, pub) is False

    def test_pss_signature_is_randomised(self, rsa_keypair_alice):
        """PSS with MAX_LENGTH salt must produce different signatures each time."""
        priv, _ = rsa_keypair_alice
        message = b"same message"
        sigs = {rsa_pss_sign(message, priv) for _ in range(10)}
        assert len(sigs) == 10

    def test_empty_message_raises(self, rsa_keypair_alice):
        priv, _ = rsa_keypair_alice
        with pytest.raises(ValueError, match="empty"):
            rsa_pss_sign(b"", priv)


# ---------------------------------------------------------------------------
# Password Hashing — scrypt
# ---------------------------------------------------------------------------


class TestScryptPasswordHashing:
    def test_correct_password_verifies(self):
        ph = scrypt_hash_password("P@ssw0rd!Ultra$ecure")
        assert scrypt_verify_password("P@ssw0rd!Ultra$ecure", ph) is True

    def test_wrong_password_fails(self):
        ph = scrypt_hash_password("correct_password")
        assert scrypt_verify_password("wrong_password", ph) is False

    def test_empty_password_raises(self):
        with pytest.raises(ValueError, match="empty"):
            scrypt_hash_password("")

    def test_salt_is_unique_per_call(self):
        """Two hashes of the same password must have different salts."""
        ph1 = scrypt_hash_password("password")
        ph2 = scrypt_hash_password("password")
        assert ph1.salt != ph2.salt

    def test_derived_key_different_with_different_salts(self):
        """Same password + different salt → different derived key (rainbow-table prevention)."""
        ph1 = scrypt_hash_password("password")
        ph2 = scrypt_hash_password("password")
        assert ph1.derived_key != ph2.derived_key

    def test_derived_key_length(self):
        ph = scrypt_hash_password("mypassword")
        assert len(ph.derived_key) == 32  # 256 bits


class TestPbkdf2PasswordHashing:
    def test_correct_password_verifies(self):
        dk, salt = pbkdf2_hash_password("SecurePass123!")
        assert pbkdf2_verify_password("SecurePass123!", dk, salt) is True

    def test_wrong_password_fails(self):
        dk, salt = pbkdf2_hash_password("correct")
        assert pbkdf2_verify_password("wrong", dk, salt) is False

    def test_empty_password_raises(self):
        with pytest.raises(ValueError, match="empty"):
            pbkdf2_hash_password("")


# ---------------------------------------------------------------------------
# HMAC-SHA256
# ---------------------------------------------------------------------------


class TestHmac:
    def test_valid_mac_verifies(self):
        key = os.urandom(32)
        data = b"user_id=42&role=doctor&expiry=9999999999"
        mac = hmac_sign(data, key)
        assert hmac_verify(data, mac, key) is True

    def test_modified_data_fails(self):
        key = os.urandom(32)
        data = b"legitimate token payload"
        mac = hmac_sign(data, key)
        assert hmac_verify(b"modified token payload", mac, key) is False

    def test_wrong_key_fails(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        data = b"payload"
        mac = hmac_sign(data, key1)
        assert hmac_verify(data, mac, key2) is False

    def test_mac_is_32_bytes(self):
        mac = hmac_sign(b"data", os.urandom(32))
        assert len(mac) == 32


# ---------------------------------------------------------------------------
# SHA-256 audit helper
# ---------------------------------------------------------------------------


class TestSha256Digest:
    def test_known_hash(self):
        # SHA-256("") == well-known constant
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert sha256_digest(b"") == expected

    def test_different_inputs_produce_different_digests(self):
        assert sha256_digest(b"a") != sha256_digest(b"b")

    def test_returns_64_hex_chars(self):
        digest = sha256_digest(b"healthcare data")
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)
