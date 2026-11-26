from urllib.parse import quote
from fastapi import APIRouter, Depends, UploadFile, File, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.entities import User
from app.services.auth_service import get_current_user
from app.services.document_service import DocumentService

router = APIRouter(prefix="/api/documents", tags=["Documents"])


class ShareRequest(BaseModel):
    username: str
    permission: str  # 'viewer' or 'editor'


class RevokeRequest(BaseModel):
    username: str


@router.get("")
def list_documents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return {"documents": DocumentService.list_accessible_documents(db, current_user)}


@router.post("/upload")
async def upload_document(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    content = await file.read()
    doc = DocumentService.upload_document(
        db=db,
        owner=current_user,
        filename=file.filename or "untitled.bin",
        content_type=file.content_type or "application/octet-stream",
        plaintext_bytes=content,
    )
    return {
        "id": doc.id,
        "filename": doc.original_filename,
        "file_size": doc.file_size,
        "plaintext_sha256": doc.plaintext_sha256,
    }


@router.get("/{doc_id}/download")
def download_document(
    doc_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doc, plaintext = DocumentService.retrieve_document(db, doc_id, current_user)
    safe_filename = quote(doc.original_filename)
    return Response(
        content=plaintext,
        media_type=doc.content_type,
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{safe_filename}",
            "X-Document-SHA256": doc.plaintext_sha256,
            "Cache-Control": "no-store, no-cache, must-revalidate",
        },
    )


@router.put("/{doc_id}/update")
async def update_document(
    doc_id: str,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    content = await file.read()
    doc = DocumentService.update_document_content(
        db=db,
        doc_id=doc_id,
        user=current_user,
        new_plaintext=content,
    )
    return {
        "id": doc.id,
        "filename": doc.original_filename,
        "file_size": doc.file_size,
        "plaintext_sha256": doc.plaintext_sha256,
    }


@router.post("/{doc_id}/share")
def share_document(
    doc_id: str,
    payload: ShareRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    perm = DocumentService.share_document(
        db=db,
        doc_id=doc_id,
        owner=current_user,
        target_username=payload.username.strip(),
        permission=payload.permission,
    )
    return {"message": f"Shared with {payload.username} as {perm.permission}."}


@router.post("/{doc_id}/revoke")
def revoke_document(
    doc_id: str,
    payload: RevokeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    DocumentService.revoke_permission(
        db=db,
        doc_id=doc_id,
        owner=current_user,
        target_username=payload.username.strip(),
    )
    return {"message": f"Revoked access from {payload.username}."}


@router.delete("/{doc_id}")
def delete_document(
    doc_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    DocumentService.delete_document(db=db, doc_id=doc_id, owner=current_user)
    return {"message": "Document permanently deleted."}