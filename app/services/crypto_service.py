import os
import base64
import hashlib
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from app.core.config import MASTER_KEK


@dataclass
class EncryptedEnvelope:
    ciphertext: bytes
    wrapped_dek_b64: str
    dek_nonce_b64: str
    file_nonce_b64: str
    plaintext_sha256: str
    ciphertext_sha256: str


class CryptoService:
    """
    Implements Envelope Encryption using AES-256-GCM (Authenticated Encryption with Associated Data).
    1. Generates a unique 256-bit Data Encryption Key (DEK) per document.
    2. Encrypts document plaintext using AES-256-GCM with the DEK + random 96-bit nonce.
    3. Wraps (encrypts) the DEK using the Master Key Encryption Key (KEK).
    4. Computes SHA-256 digests of both plaintext and ciphertext for dual-layer integrity verification.
    """

    @staticmethod
    def compute_sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def encrypt_document(cls, plaintext: bytes, associated_data: bytes = b"") -> EncryptedEnvelope:
        # 1. Compute plaintext digest before encryption
        plaintext_hash = cls.compute_sha256(plaintext)

        # 2. Generate a fresh 256-bit (32-byte) Data Encryption Key (DEK) for this document only
        dek = AESGCM.generate_key(bit_length=256)
        file_nonce = os.urandom(12)  # 96-bit standard GCM nonce

        # 3. Encrypt document contents with AES-256-GCM (provides confidentiality + integrity auth tag)
        aes_file = AESGCM(dek)
        ciphertext = aes_file.encrypt(file_nonce, plaintext, associated_data)
        ciphertext_hash = cls.compute_sha256(ciphertext)

        # 4. Wrap the DEK using the Master KEK so the DEK is never stored in plaintext
        dek_nonce = os.urandom(12)
        aes_kek = AESGCM(MASTER_KEK)
        wrapped_dek = aes_kek.encrypt(dek_nonce, dek, None)

        return EncryptedEnvelope(
            ciphertext=ciphertext,
            wrapped_dek_b64=base64.b64encode(wrapped_dek).decode("utf-8"),
            dek_nonce_b64=base64.b64encode(dek_nonce).decode("utf-8"),
            file_nonce_b64=base64.b64encode(file_nonce).decode("utf-8"),
            plaintext_sha256=plaintext_hash,
            ciphertext_sha256=ciphertext_hash,
        )

    @classmethod
    def decrypt_document(
        cls,
        ciphertext: bytes,
        wrapped_dek_b64: str,
        dek_nonce_b64: str,
        file_nonce_b64: str,
        expected_plaintext_sha256: str,
        expected_ciphertext_sha256: str,
        associated_data: bytes = b"",
    ) -> bytes:
        # 1. Verify ciphertext hash on disk before attempting decryption
        actual_ciphertext_hash = cls.compute_sha256(ciphertext)
        if actual_ciphertext_hash != expected_ciphertext_sha256:
            raise ValueError("INTEGRITY_ALERT: Vault ciphertext SHA-256 mismatch! File was altered on disk.")

        # 2. Unwrap the DEK using the Master KEK
        wrapped_dek = base64.b64decode(wrapped_dek_b64)
        dek_nonce = base64.b64decode(dek_nonce_b64)
        file_nonce = base64.b64decode(file_nonce_b64)

        aes_kek = AESGCM(MASTER_KEK)
        dek = aes_kek.decrypt(dek_nonce, wrapped_dek, None)

        # 3. Decrypt and verify GCM authentication tag
        aes_file = AESGCM(dek)
        try:
            plaintext = aes_file.decrypt(file_nonce, ciphertext, associated_data)
        except InvalidTag as exc:
            raise ValueError("INTEGRITY_ALERT: AES-GCM authentication tag verification failed!") from exc

        # 4. Verify decrypted plaintext matches original SHA-256 digest
        if cls.compute_sha256(plaintext) != expected_plaintext_sha256:
            raise ValueError("INTEGRITY_ALERT: Decrypted plaintext SHA-256 mismatch!")

        return plaintext