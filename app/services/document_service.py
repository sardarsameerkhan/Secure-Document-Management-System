import uuid
from typing import Tuple, List
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.core.config import STORAGE_DIR
from app.models.entities import User, Document, DocumentPermission
from app.services.crypto_service import CryptoService
from app.services.audit_service import AuditService


class DocumentService:
    """
    Enforces server-side Discretionary Access Control (DAC) and manages encrypted vault storage.
    Notice: System administrators are NOT automatically granted read access to user documents
    (Principle of Least Privilege & Separation of Duties).
    """

    @staticmethod
    def get_effective_role(db: Session, doc: Document, user: User) -> str:
        """
        Returns 'owner', 'editor', 'viewer', or 'none'.
        """
        if doc.owner_id == user.id:
            return "owner"

        perm = (
            db.query(DocumentPermission)
            .filter(
                DocumentPermission.document_id == doc.id,
                DocumentPermission.user_id == user.id,
            )
            .first()
        )
        if perm:
            return perm.permission  # 'editor' or 'viewer'

        return "none"

    @classmethod
    def get_document_with_auth(
        cls,
        db: Session,
        doc_id: str,
        user: User,
        required_levels: Tuple[str, ...],
        action_name: str,
    ) -> Tuple[Document, str]:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            AuditService.log_event(
                db=db,
                action=action_name,
                status="DENIED",
                details=f"Attempted access to non-existent document ID '{doc_id}'.",
                actor_id=user.id,
                actor_username=user.username,
                resource_id=doc_id,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found or access denied.",
            )

        role = cls.get_effective_role(db, doc, user)
        if role not in required_levels:
            AuditService.log_event(
                db=db,
                action=action_name,
                status="DENIED",
                details=f"Unauthorized '{action_name}' attempt (effective role='{role}', required={required_levels}).",
                actor_id=user.id,
                actor_username=user.username,
                resource_id=doc.id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: insufficient permissions for this document.",
            )

        return doc, role

    @classmethod
    def upload_document(
        cls,
        db: Session,
        owner: User,
        filename: str,
        content_type: str,
        plaintext_bytes: bytes,
    ) -> Document:
        if not plaintext_bytes:
            raise HTTPException(status_code=400, detail="Cannot upload an empty file.")

        doc_id = str(uuid.uuid4())
        vault_filename = f"{uuid.uuid4().hex}.enc"

        # Bind ciphertext to doc_id using GCM Associated Authenticated Data (AAD)
        envelope = CryptoService.encrypt_document(
            plaintext=plaintext_bytes,
            associated_data=doc_id.encode("utf-8"),
        )

        vault_path = STORAGE_DIR / vault_filename
        vault_path.write_bytes(envelope.ciphertext)

        doc = Document(
            id=doc_id,
            owner_id=owner.id,
            original_filename=filename,
            content_type=content_type or "application/octet-stream",
            file_size=len(plaintext_bytes),
            vault_filename=vault_filename,
            wrapped_dek=envelope.wrapped_dek_b64,
            dek_nonce=envelope.dek_nonce_b64,
            file_nonce=envelope.file_nonce_b64,
            plaintext_sha256=envelope.plaintext_sha256,
            ciphertext_sha256=envelope.ciphertext_sha256,
        )
        db.add(doc)
        db.commit()
        db.refresh(doc)

        AuditService.log_event(
            db=db,
            action="DOC_UPLOAD",
            status="SUCCESS",
            details=f"Uploaded and encrypted '{filename}' ({len(plaintext_bytes)} bytes) into vault.",
            actor_id=owner.id,
            actor_username=owner.username,
            resource_id=doc.id,
        )
        return doc

    @classmethod
    def retrieve_document(cls, db: Session, doc_id: str, user: User) -> Tuple[Document, bytes]:
        doc, role = cls.get_document_with_auth(
            db=db,
            doc_id=doc_id,
            user=user,
            required_levels=("owner", "editor", "viewer"),
            action_name="DOC_READ",
        )

        vault_path = STORAGE_DIR / doc.vault_filename
        if not vault_path.exists():
            AuditService.log_event(
                db=db,
                action="DOC_INTEGRITY_ERROR",
                status="ALERT",
                details=f"Encrypted vault blob missing for document '{doc.original_filename}'.",
                actor_id=user.id,
                actor_username=user.username,
                resource_id=doc.id,
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Integrity Alert: Encrypted file is missing from vault storage.",
            )

        ciphertext = vault_path.read_bytes()
        try:
            plaintext = CryptoService.decrypt_document(
                ciphertext=ciphertext,
                wrapped_dek_b64=doc.wrapped_dek,
                dek_nonce_b64=doc.dek_nonce,
                file_nonce_b64=doc.file_nonce,
                expected_plaintext_sha256=doc.plaintext_sha256,
                expected_ciphertext_sha256=doc.ciphertext_sha256,
                associated_data=doc.id.encode("utf-8"),
            )
        except ValueError as err:
            AuditService.log_event(
                db=db,
                action="DOC_TAMPER_DETECTED",
                status="ALERT",
                details=str(err),
                actor_id=user.id,
                actor_username=user.username,
                resource_id=doc.id,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Security Integrity Alert: {err}",
            )

        AuditService.log_event(
            db=db,
            action="DOC_READ",
            status="SUCCESS",
            details=f"Decrypted and retrieved '{doc.original_filename}' as '{role}'.",
            actor_id=user.id,
            actor_username=user.username,
            resource_id=doc.id,
        )
        return doc, plaintext

    @classmethod
    def update_document_content(
        cls,
        db: Session,
        doc_id: str,
        user: User,
        new_plaintext: bytes,
    ) -> Document:
        doc, role = cls.get_document_with_auth(
            db=db,
            doc_id=doc_id,
            user=user,
            required_levels=("owner", "editor"),
            action_name="DOC_UPDATE",
        )

        # Re-encrypt with a fresh DEK and fresh nonces (key rotation on modification)
        envelope = CryptoService.encrypt_document(
            plaintext=new_plaintext,
            associated_data=doc.id.encode("utf-8"),
        )
        vault_path = STORAGE_DIR / doc.vault_filename
        vault_path.write_bytes(envelope.ciphertext)

        doc.file_size = len(new_plaintext)
        doc.wrapped_dek = envelope.wrapped_dek_b64
        doc.dek_nonce = envelope.dek_nonce_b64
        doc.file_nonce = envelope.file_nonce_b64
        doc.plaintext_sha256 = envelope.plaintext_sha256
        doc.ciphertext_sha256 = envelope.ciphertext_sha256

        db.commit()
        db.refresh(doc)

        AuditService.log_event(
            db=db,
            action="DOC_UPDATE",
            status="SUCCESS",
            details=f"Updated and re-encrypted '{doc.original_filename}' ({len(new_plaintext)} bytes) as '{role}'.",
            actor_id=user.id,
            actor_username=user.username,
            resource_id=doc.id,
        )
        return doc

    @classmethod
    def share_document(
        cls,
        db: Session,
        doc_id: str,
        owner: User,
        target_username: str,
        permission: str,
    ) -> DocumentPermission:
        if permission not in ("viewer", "editor"):
            raise HTTPException(status_code=400, detail="Permission must be 'viewer' or 'editor'.")

        doc, _ = cls.get_document_with_auth(
            db=db,
            doc_id=doc_id,
            user=owner,
            required_levels=("owner",),
            action_name="DOC_SHARE",
        )

        target_user = db.query(User).filter(User.username == target_username).first()
        if not target_user:
            raise HTTPException(status_code=404, detail=f"Target user '{target_username}' not found.")
        if target_user.id == owner.id:
            raise HTTPException(status_code=400, detail="You already own this document.")

        existing = (
            db.query(DocumentPermission)
            .filter(
                DocumentPermission.document_id == doc.id,
                DocumentPermission.user_id == target_user.id,
            )
            .first()
        )
        if existing:
            existing.permission = permission
            existing.granted_by = owner.id
            perm_record = existing
        else:
            perm_record = DocumentPermission(
                document_id=doc.id,
                user_id=target_user.id,
                permission=permission,
                granted_by=owner.id,
            )
            db.add(perm_record)

        db.commit()
        db.refresh(perm_record)

        AuditService.log_event(
            db=db,
            action="DOC_SHARE",
            status="SUCCESS",
            details=f"Granted '{permission}' access on '{doc.original_filename}' to '{target_user.username}'.",
            actor_id=owner.id,
            actor_username=owner.username,
            resource_id=doc.id,
        )
        return perm_record

    @classmethod
    def revoke_permission(
        cls,
        db: Session,
        doc_id: str,
        owner: User,
        target_username: str,
    ) -> None:
        doc, _ = cls.get_document_with_auth(
            db=db,
            doc_id=doc_id,
            user=owner,
            required_levels=("owner",),
            action_name="DOC_REVOKE",
        )

        target_user = db.query(User).filter(User.username == target_username).first()
        if not target_user:
            raise HTTPException(status_code=404, detail="Target user not found.")

        perm = (
            db.query(DocumentPermission)
            .filter(
                DocumentPermission.document_id == doc.id,
                DocumentPermission.user_id == target_user.id,
            )
            .first()
        )
        if not perm:
            raise HTTPException(status_code=404, detail="No active share permission found for this user.")

        db.delete(perm)
        db.commit()

        AuditService.log_event(
            db=db,
            action="DOC_REVOKE",
            status="SUCCESS",
            details=f"Revoked access on '{doc.original_filename}' from '{target_user.username}'.",
            actor_id=owner.id,
            actor_username=owner.username,
            resource_id=doc.id,
        )

    @classmethod
    def delete_document(cls, db: Session, doc_id: str, owner: User) -> None:
        doc, _ = cls.get_document_with_auth(
            db=db,
            doc_id=doc_id,
            user=owner,
            required_levels=("owner",),
            action_name="DOC_DELETE",
        )

        vault_path = STORAGE_DIR / doc.vault_filename
        if vault_path.exists():
            vault_path.unlink()

        filename = doc.original_filename
        db.delete(doc)
        db.commit()

        AuditService.log_event(
            db=db,
            action="DOC_DELETE",
            status="SUCCESS",
            details=f"Deleted document '{filename}' and purged encrypted vault file.",
            actor_id=owner.id,
            actor_username=owner.username,
            resource_id=doc_id,
        )

    @staticmethod
    def list_accessible_documents(db: Session, user: User) -> List[dict]:
        owned = db.query(Document).filter(Document.owner_id == user.id).all()
        shared_perms = (
            db.query(DocumentPermission)
            .filter(DocumentPermission.user_id == user.id)
            .all()
        )

        results = []
        for d in owned:
            shares = [
                {"username": p.user.username, "permission": p.permission}
                for p in d.permissions
            ]
            results.append({
                "id": d.id,
                "filename": d.original_filename,
                "content_type": d.content_type,
                "file_size": d.file_size,
                "role": "owner",
                "owner": user.username,
                "plaintext_sha256": d.plaintext_sha256,
                "updated_at": d.updated_at.isoformat(),
                "shared_with": shares,
            })

        for p in shared_perms:
            d = p.document
            results.append({
                "id": d.id,
                "filename": d.original_filename,
                "content_type": d.content_type,
                "file_size": d.file_size,
                "role": p.permission,
                "owner": d.owner.username,
                "plaintext_sha256": d.plaintext_sha256,
                "updated_at": d.updated_at.isoformat(),
                "shared_with": [],
            })

        return results