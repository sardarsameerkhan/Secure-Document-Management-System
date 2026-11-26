import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from app.core.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    # System-level role: 'user' or 'admin'
    # Note: 'admin' can audit system logs and manage users, but does NOT get automatic read access to user documents!
    role = Column(String(20), nullable=False, default="user")
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    owned_documents = relationship("Document", back_populates="owner", cascade="all, delete-orphan")
    permissions = relationship("DocumentPermission", back_populates="user", cascade="all, delete-orphan")


class Document(Base):
    __tablename__ = "documents"

    # UUIDv4 prevents predictable sequential enumeration (IDOR mitigation layer 1)
    id = Column(String(36), primary_key=True, default=generate_uuid)
    owner_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    original_filename = Column(String(255), nullable=False)
    content_type = Column(String(100), nullable=False, default="application/octet-stream")
    file_size = Column(Integer, nullable=False)

    # Storage separation: random opaque filename inside storage/vault/
    vault_filename = Column(String(255), unique=True, nullable=False)

    # Envelope Encryption metadata (AES-256-GCM)
    wrapped_dek = Column(Text, nullable=False)        # Document Encryption Key encrypted with Master KEK
    dek_nonce = Column(String(64), nullable=False)    # Nonce used to wrap the DEK
    file_nonce = Column(String(64), nullable=False)   # Nonce used to encrypt the file contents

    # Cryptographic integrity verification (SHA-256 of original plaintext)
    plaintext_sha256 = Column(String(64), nullable=False)
    ciphertext_sha256 = Column(String(64), nullable=False)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    owner = relationship("User", back_populates="owned_documents")
    permissions = relationship("DocumentPermission", back_populates="document", cascade="all, delete-orphan")


class DocumentPermission(Base):
    """
    Discretionary Access Control (DAC) table mapping users to specific documents
    with granular roles ('viewer' or 'editor'). Owners are tracked on Document.owner_id.
    """
    __tablename__ = "document_permissions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    document_id = Column(String(36), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    permission = Column(String(20), nullable=False)  # 'viewer' or 'editor'
    granted_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    granted_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("document_id", "user_id", name="uq_doc_user_permission"),
    )

    document = relationship("Document", back_populates="permissions")
    user = relationship("User", foreign_keys=[user_id], back_populates="permissions")


class AuditLog(Base):
    """
    Tamper-evident append-only audit trail.
    Each record links cryptographically to the previous record via prev_hash + entry_hmac.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(String(40), nullable=False)
    actor_id = Column(String(36), nullable=True)
    actor_username = Column(String(64), nullable=False, default="anonymous")
    action = Column(String(64), nullable=False)       # e.g., LOGIN_SUCCESS, DOC_UPLOAD, ACCESS_DENIED
    resource_id = Column(String(36), nullable=True)   # Document ID or Target User ID
    status = Column(String(20), nullable=False)       # 'SUCCESS', 'DENIED', 'ALERT'
    details = Column(Text, nullable=False)            # Non-sensitive context (never passwords/keys/content)

    # Cryptographic hash-chain fields for tamper detection
    prev_hash = Column(String(64), nullable=False)
    entry_hmac = Column(String(64), nullable=False)