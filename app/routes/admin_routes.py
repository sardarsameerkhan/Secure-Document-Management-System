from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.entities import User, AuditLog
from app.services.auth_service import require_admin
from app.services.audit_service import AuditService

router = APIRouter(prefix="/api/admin", tags=["Admin & Auditing"])


@router.get("/audit-logs")
def get_audit_logs(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(200).all()
    verification = AuditService.verify_chain(db)
    return {
        "chain_verification": verification,
        "logs": [
            {
                "id": log.id,
                "timestamp": log.timestamp,
                "actor_username": log.actor_username,
                "action": log.action,
                "resource_id": log.resource_id,
                "status": log.status,
                "details": log.details,
                "prev_hash": log.prev_hash[:12] + "...",
                "entry_hmac": log.entry_hmac[:12] + "...",
            }
            for log in logs
        ],
    }


@router.get("/verify-audit-chain")
def verify_audit_chain(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return AuditService.verify_chain(db)