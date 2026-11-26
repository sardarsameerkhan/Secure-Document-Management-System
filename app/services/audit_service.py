import hmac
import hashlib
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from app.models.entities import AuditLog
from app.core.config import AUDIT_HMAC_KEY

GENESIS_HASH = "0" * 64


class AuditService:
    """
    Append-only, hash-chained audit logging service.
    Each log row includes an HMAC-SHA256 over (prev_hash + timestamp + actor + action + resource + status + details).
    Any direct SQL modification or row deletion breaks the cryptographic chain.
    """

    @staticmethod
    def _compute_entry_hmac(
        prev_hash: str,
        timestamp: str,
        actor_id: Optional[str],
        actor_username: str,
        action: str,
        resource_id: Optional[str],
        status: str,
        details: str,
    ) -> str:
        payload = "|".join([
            prev_hash,
            timestamp,
            actor_id or "NONE",
            actor_username,
            action,
            resource_id or "NONE",
            status,
            details,
        ]).encode("utf-8")
        return hmac.new(AUDIT_HMAC_KEY, payload, hashlib.sha256).hexdigest()

    @classmethod
    def log_event(
        cls,
        db: Session,
        action: str,
        status: str,
        details: str,
        actor_id: Optional[str] = None,
        actor_username: str = "anonymous",
        resource_id: Optional[str] = None,
    ) -> AuditLog:
        last_entry = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        prev_hash = last_entry.entry_hmac if last_entry else GENESIS_HASH
        timestamp = datetime.now(timezone.utc).isoformat()

        entry_hmac = cls._compute_entry_hmac(
            prev_hash=prev_hash,
            timestamp=timestamp,
            actor_id=actor_id,
            actor_username=actor_username,
            action=action,
            resource_id=resource_id,
            status=status,
            details=details,
        )

        entry = AuditLog(
            timestamp=timestamp,
            actor_id=actor_id,
            actor_username=actor_username,
            action=action,
            resource_id=resource_id,
            status=status,
            details=details,
            prev_hash=prev_hash,
            entry_hmac=entry_hmac,
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry

    @classmethod
    def verify_chain(cls, db: Session) -> dict:
        """
        Walks the entire audit log table from ID 1 to N and verifies:
        1. Continuity: entry.prev_hash == previous_entry.entry_hmac (detects deleted rows)
        2. Authenticity: recomputed HMAC == entry.entry_hmac (detects altered fields)
        """
        logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
        expected_prev_hash = GENESIS_HASH

        for entry in logs:
            if entry.prev_hash != expected_prev_hash:
                return {
                    "valid": False,
                    "total_records": len(logs),
                    "corrupted_at_id": entry.id,
                    "reason": f"Chain break at record #{entry.id}: previous record was deleted or reordered.",
                }

            recomputed = cls._compute_entry_hmac(
                prev_hash=entry.prev_hash,
                timestamp=entry.timestamp,
                actor_id=entry.actor_id,
                actor_username=entry.actor_username,
                action=entry.action,
                resource_id=entry.resource_id,
                status=entry.status,
                details=entry.details,
            )
            if not hmac.compare_digest(recomputed, entry.entry_hmac):
                return {
                    "valid": False,
                    "total_records": len(logs),
                    "corrupted_at_id": entry.id,
                    "reason": f"HMAC mismatch at record #{entry.id}: record contents were altered.",
                }

            expected_prev_hash = entry.entry_hmac

        return {
            "valid": True,
            "total_records": len(logs),
            "corrupted_at_id": None,
            "reason": "All audit records verified intact.",
        }