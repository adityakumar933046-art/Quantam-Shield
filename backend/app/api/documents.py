import os
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.config import UPLOADS_ORIGINAL, UPLOADS_SIGNED
from app.models import User, SignedDocument, DigitalSignature, AuditLog, VerificationActivity
from app.schemas import DocumentUploadResponse, DocumentResponse, SignatureDetailsResponse
from app.api.auth import get_current_user
from app.core.signer import compute_sha256, sign_pdf_document, sign_text_content, sign_json_content
from app.core.id_generator import generate_signature_id

router = APIRouter(prefix="/documents", tags=["Document Digital Signing"])

MAX_FILE_SIZE = 25 * 1024 * 1024 # 25 MB

def require_signature_user(current_user: User = Depends(get_current_user)):
    if current_user.role not in ["DIGITAL_SIGNATURE_USER", "SUPER_ADMIN"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. Only Digital Signature Users can access this resource."
        )
    return current_user

@router.post("/upload", response_model=DocumentUploadResponse)
async def upload_document(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_signature_user)
):
    # 1. Validate File Extension
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file format. Only PDF (.pdf) documents are supported."
        )

    # 2. Validate MIME Type
    if file.content_type and file.content_type != "application/pdf":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MIME type. Must be application/pdf."
        )

    # 3. Read Header & Validate File Content & Size
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File exceeds maximum allowed size of {MAX_FILE_SIZE // (1024*1024)}MB."
        )

    if not content.startswith(b"%PDF-"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File is not a valid PDF document (missing PDF header signature)."
        )

    # 4. Save Original PDF safely to uploads/original/
    file_id = str(uuid.uuid4())[:8]
    safe_basename = Path(file.filename).name.replace(" ", "_")
    saved_filename = f"{current_user.user_id}_{file_id}_{safe_basename}"
    saved_filepath = UPLOADS_ORIGINAL / saved_filename

    with open(saved_filepath, "wb") as f:
        f.write(content)

    # 5. Compute SHA-256 Hash
    doc_hash = compute_sha256(saved_filepath)

    # 6. Store Database Metadata
    doc = SignedDocument(
        user_id=current_user.user_id,
        original_filename=file.filename,
        original_file_path=str(saved_filepath),
        document_hash=doc_hash,
        file_size=len(content),
        status="UPLOADED"
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    # 7. Audit Logging
    audit1 = AuditLog(
        user_id=current_user.user_id,
        user_email=current_user.email,
        action="DOCUMENT_UPLOAD",
        details=f"Uploaded PDF document: {file.filename} ({len(content)} bytes)"
    )
    audit2 = AuditLog(
        user_id=current_user.user_id,
        user_email=current_user.email,
        action="HASH_GENERATED",
        details=f"Generated SHA-256 hash for document #{doc.document_id}: {doc_hash}"
    )
    db.add_all([audit1, audit2])
    db.commit()

    return doc

@router.post("/{document_id}/sign", response_model=DocumentResponse)
def generate_digital_signature(
    document_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_signature_user)
):
    # 1. Fetch & Verify Ownership
    doc = db.query(SignedDocument).filter(SignedDocument.document_id == document_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    
    if doc.user_id != current_user.user_id and current_user.role != "SUPER_ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. You do not own this document.")

    orig_path = Path(doc.original_file_path)
    if not orig_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Original PDF file is missing from storage.")

    # 2. Output Signed Path in uploads/signed/
    file_id = str(uuid.uuid4())[:8]
    signed_filename = f"signed_{doc.original_filename}"
    saved_signed_filename = f"{current_user.user_id}_{file_id}_{signed_filename}"
    signed_filepath = UPLOADS_SIGNED / saved_signed_filename

    # 3. Perform Cryptographic Signing
    try:
        if doc.content_type == "TEXT" or orig_path.suffix.lower() in [".txt", ".text"]:
            text_data = orig_path.read_text(encoding="utf-8")
            sig_meta = sign_text_content(text_data, doc.original_filename)
            with open(signed_filepath, "w", encoding="utf-8") as f:
                f.write(sig_meta["signed_message_json"])
            doc.signature_value = sig_meta.get("signature_value")
            doc.canonical_hash = sig_meta.get("canonical_hash")
            doc.raw_text_content = text_data
        elif doc.content_type == "JSON" or orig_path.suffix.lower() == ".json":
            json_text = orig_path.read_text(encoding="utf-8")
            sig_meta = sign_json_content(json_text, doc.original_filename)
            with open(signed_filepath, "w", encoding="utf-8") as f:
                f.write(sig_meta["signed_message_json"])
            doc.signature_value = sig_meta.get("signature_value")
            doc.canonical_hash = sig_meta.get("canonical_hash")
            doc.raw_text_content = json_text
        else:
            sig_meta = sign_pdf_document(orig_path, signed_filepath)
    except Exception as e:
        audit_fail = AuditLog(
            user_id=current_user.user_id,
            user_email=current_user.email,
            action="SIGNING_FAILED",
            details=f"Cryptographic signature failed for document #{doc.document_id}: {str(e)}"
        )
        db.add(audit_fail)
        db.commit()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Signing operation failed: {str(e)}")

    # 4. Update Document & Create DigitalSignature Record
    doc.signed_filename = signed_filename
    doc.signed_file_path = str(signed_filepath)
    doc.status = "SIGNED"
    if not doc.signature_id:
        doc.signature_id = generate_signature_id()
    doc.signed_at = sig_meta.get("signing_timestamp", datetime.now(timezone.utc))
    doc.public_key_fingerprint = sig_meta.get("certificate_fingerprint")

    # Delete previous signature if re-signing
    if doc.signature:
        db.delete(doc.signature)
        db.commit()

    digital_sig = DigitalSignature(
        document_id=doc.document_id,
        signature_algorithm=sig_meta["signature_algorithm"],
        hash_algorithm=sig_meta["hash_algorithm"],
        certificate_subject=sig_meta["certificate_subject"],
        certificate_issuer=sig_meta["certificate_issuer"],
        certificate_serial_number=sig_meta["certificate_serial_number"],
        certificate_fingerprint=sig_meta["certificate_fingerprint"],
        signature_fingerprint=sig_meta["signature_fingerprint"],
        signing_timestamp=sig_meta["signing_timestamp"],
        verification_status="VALID"
    )
    db.add(digital_sig)

    # Log VerificationActivity (action=SIGN)
    v_act = VerificationActivity(
        user_id=current_user.user_id,
        document_hash=doc.document_hash,
        signature_fingerprint=sig_meta.get("signature_fingerprint"),
        action="SIGN",
        result="SUCCESS",
        source_identifier=f"user_{current_user.user_id}"
    )
    db.add(v_act)
    db.commit()
    db.refresh(doc)

    # 5. Audit Trail Logging
    audit1 = AuditLog(
        user_id=current_user.user_id,
        user_email=current_user.email,
        action="SIGNATURE_GENERATED",
        details=f"Generated RSA-2048 cryptographic signature for document #{doc.document_id}"
    )
    audit2 = AuditLog(
        user_id=current_user.user_id,
        user_email=current_user.email,
        action="SIGNED_DOCUMENT_CREATED",
        details=f"Created signed output PDF: {signed_filename}"
    )
    db.add_all([audit1, audit2])
    db.commit()

    return doc

@router.get("/my-documents", response_model=List[DocumentResponse])
def get_my_documents(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_signature_user)
):
    docs = db.query(SignedDocument).filter(SignedDocument.user_id == current_user.user_id).order_by(SignedDocument.created_at.desc()).all()
    return docs

@router.get("/{document_id}", response_model=DocumentResponse)
def get_document_by_id(
    document_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    doc = db.query(SignedDocument).filter(SignedDocument.document_id == document_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    
    if doc.user_id != current_user.user_id and current_user.role != "SUPER_ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. Ownership verification failed.")
    
    return doc

@router.get("/{document_id}/download")
def download_signed_pdf(
    document_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    doc = db.query(SignedDocument).filter(SignedDocument.document_id == document_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    # Strict Ownership Authorization
    if doc.user_id != current_user.user_id and current_user.role != "SUPER_ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. Ownership verification failed.")

    target_path = Path(doc.signed_file_path) if doc.signed_file_path else Path(doc.original_file_path)
    if not target_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File content missing on server.")

    # Audit Logging
    audit = AuditLog(
        user_id=current_user.user_id,
        user_email=current_user.email,
        action="SIGNED_DOCUMENT_DOWNLOADED",
        details=f"Downloaded file for document #{doc.document_id} ({doc.signed_filename or doc.original_filename})"
    )
    db.add(audit)
    db.commit()

    return FileResponse(
        path=str(target_path),
        filename=doc.signed_filename or doc.original_filename,
        media_type="application/pdf"
    )

    return doc.signature

from app.core.format_processors import detect_content_format, ContentType
from app.core.signer import sign_text_content, sign_json_content, sign_structured_message
from app.schemas import TextSignRequest, JsonSignRequest, StructuredMessageSignRequest, MultiFormatSignResponse

@router.post("/upload-multiformat", response_model=DocumentUploadResponse)
async def upload_multiformat_document(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_signature_user)
):
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File exceeds maximum allowed size of {MAX_FILE_SIZE // (1024*1024)}MB."
        )

    # Detect Content Format
    fmt = detect_content_format(content, file.filename or "")

    file_id = str(uuid.uuid4())[:8]
    safe_basename = Path(file.filename or "content.txt").name.replace(" ", "_")
    saved_filename = f"{current_user.user_id}_{file_id}_{safe_basename}"
    saved_filepath = UPLOADS_ORIGINAL / saved_filename

    with open(saved_filepath, "wb") as f:
        f.write(content)

    import hashlib
    doc_hash = hashlib.sha256(content).hexdigest()

    raw_text = None
    if fmt in [ContentType.TEXT, ContentType.JSON, ContentType.RAW_TEXT, ContentType.STRUCTURED_MESSAGE]:
        try:
            raw_text = content.decode('utf-8')
        except Exception:
            pass

    doc = SignedDocument(
        user_id=current_user.user_id,
        original_filename=file.filename or "content.txt",
        original_file_path=str(saved_filepath),
        document_hash=doc_hash,
        content_type=fmt,
        raw_text_content=raw_text,
        file_size=len(content),
        status="UPLOADED"
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    db.add_all([
        AuditLog(user_id=current_user.user_id, user_email=current_user.email, action="DOCUMENT_UPLOAD", details=f"Uploaded {fmt} document: {file.filename}"),
        AuditLog(user_id=current_user.user_id, user_email=current_user.email, action="HASH_GENERATED", details=f"Generated SHA-256 hash: {doc_hash}")
    ])
    db.commit()

    return doc

@router.post("/sign-text", response_model=MultiFormatSignResponse)
def sign_raw_text(
    req: TextSignRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_signature_user)
):
    res = sign_text_content(req.text_content, req.filename or "signed_message.txt")

    file_id = str(uuid.uuid4())[:8]
    saved_filename = f"{current_user.user_id}_{file_id}_{req.filename}"
    saved_filepath = UPLOADS_SIGNED / saved_filename

    with open(saved_filepath, "w", encoding="utf-8") as f:
        f.write(res["signed_message_json"])

    doc = SignedDocument(
        user_id=current_user.user_id,
        original_filename=req.filename or "signed_message.txt",
        original_file_path=str(saved_filepath),
        signed_filename=saved_filename,
        signed_file_path=str(saved_filepath),
        document_hash=res["original_hash"],
        content_type=ContentType.TEXT,
        raw_text_content=req.text_content,
        canonical_hash=res["canonical_hash"],
        signature_type="RSA-SHA256",
        signature_value=res["signature_value"],
        file_size=res["file_size"],
        status="SIGNED"
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    sig = DigitalSignature(
        document_id=doc.document_id,
        signature_algorithm="RSA-SHA256",
        hash_algorithm="SHA-256",
        certificate_subject=res["certificate_subject"],
        certificate_issuer=res["certificate_issuer"],
        certificate_serial_number=res["certificate_serial_number"],
        certificate_fingerprint=res["certificate_fingerprint"],
        signature_fingerprint=res["signature_fingerprint"],
        verification_status="VALID"
    )
    db.add(sig)
    db.commit()

    return {
        "document_id": doc.document_id,
        "content_type": res["content_type"],
        "original_filename": doc.original_filename,
        "content_hash": res["original_hash"],
        "canonical_hash": res["canonical_hash"],
        "signature_algorithm": res["signature_algorithm"],
        "signature_value": res["signature_value"],
        "signed_message_json": res["signed_message_json"],
        "public_key_fingerprint": res["certificate_fingerprint"],
        "signing_timestamp": res["signing_timestamp"],
        "status": "SIGNED"
    }

@router.post("/sign-json", response_model=MultiFormatSignResponse)
def sign_json_data(
    req: JsonSignRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_signature_user)
):
    res = sign_json_content(req.json_content, req.filename or "signed_data.json", req.canonicalize)

    file_id = str(uuid.uuid4())[:8]
    saved_filename = f"{current_user.user_id}_{file_id}_{req.filename}"
    saved_filepath = UPLOADS_SIGNED / saved_filename

    with open(saved_filepath, "w", encoding="utf-8") as f:
        f.write(res["signed_message_json"])

    doc = SignedDocument(
        user_id=current_user.user_id,
        original_filename=req.filename or "signed_data.json",
        original_file_path=str(saved_filepath),
        signed_filename=saved_filename,
        signed_file_path=str(saved_filepath),
        document_hash=res["original_hash"],
        content_type=ContentType.JSON,
        raw_text_content=res["raw_text_content"],
        canonical_hash=res["canonical_hash"],
        signature_type="RSA-SHA256",
        signature_value=res["signature_value"],
        file_size=res["file_size"],
        status="SIGNED"
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    sig = DigitalSignature(
        document_id=doc.document_id,
        signature_algorithm="RSA-SHA256",
        hash_algorithm="SHA-256",
        certificate_subject=res["certificate_subject"],
        certificate_issuer=res["certificate_issuer"],
        certificate_serial_number=res["certificate_serial_number"],
        certificate_fingerprint=res["certificate_fingerprint"],
        signature_fingerprint=res["signature_fingerprint"],
        verification_status="VALID"
    )
    db.add(sig)
    db.commit()

    return {
        "document_id": doc.document_id,
        "content_type": res["content_type"],
        "original_filename": doc.original_filename,
        "content_hash": res["original_hash"],
        "canonical_hash": res["canonical_hash"],
        "signature_algorithm": res["signature_algorithm"],
        "signature_value": res["signature_value"],
        "signed_message_json": res["signed_message_json"],
        "public_key_fingerprint": res["certificate_fingerprint"],
        "signing_timestamp": res["signing_timestamp"],
        "status": "SIGNED"
    }

@router.post("/sign-structured-message", response_model=MultiFormatSignResponse)
def sign_bitcoin_style_message(
    req: StructuredMessageSignRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_signature_user)
):
    res = sign_structured_message(
        sender=req.sender,
        receiver=req.receiver,
        message=req.message,
        amount_data=req.amount_data or "",
        nonce=req.nonce or ""
    )

    file_id = str(uuid.uuid4())[:8]
    saved_filename = f"{current_user.user_id}_{file_id}_msg_{res['nonce']}.json"
    saved_filepath = UPLOADS_SIGNED / saved_filename

    with open(saved_filepath, "w", encoding="utf-8") as f:
        f.write(res["signed_message_json"])

    doc = SignedDocument(
        user_id=current_user.user_id,
        original_filename=res["original_filename"],
        original_file_path=str(saved_filepath),
        signed_filename=saved_filename,
        signed_file_path=str(saved_filepath),
        document_hash=res["original_hash"],
        content_type=ContentType.BITCOIN_MESSAGE,
        raw_text_content=res["signed_message_json"],
        canonical_hash=res["canonical_hash"],
        signature_type="RSA-SHA256",
        signature_value=res["signature_value"],
        nonce=res["nonce"],
        file_size=res["file_size"],
        status="SIGNED"
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)

    sig = DigitalSignature(
        document_id=doc.document_id,
        signature_algorithm="RSA-SHA256",
        hash_algorithm="SHA-256",
        certificate_subject=res["certificate_subject"],
        certificate_issuer=res["certificate_issuer"],
        certificate_serial_number=res["certificate_serial_number"],
        certificate_fingerprint=res["certificate_fingerprint"],
        signature_fingerprint=res["signature_fingerprint"],
        verification_status="VALID"
    )
    db.add(sig)
    db.commit()

    return {
        "document_id": doc.document_id,
        "content_type": res["content_type"],
        "original_filename": doc.original_filename,
        "content_hash": res["original_hash"],
        "canonical_hash": res["canonical_hash"],
        "signature_algorithm": res["signature_algorithm"],
        "signature_value": res["signature_value"],
        "signed_message_json": res["signed_message_json"],
        "public_key_fingerprint": res["certificate_fingerprint"],
        "signing_timestamp": res["signing_timestamp"],
        "status": "SIGNED"
    }
