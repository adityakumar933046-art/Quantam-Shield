from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.core.db import get_db
from app.core.security import get_password_hash
from app.models import User, AuditLog
from app.schemas import UserResponse, UserCreate, UserStatusUpdate
from app.api.auth import get_current_user

router = APIRouter(prefix="/users", tags=["Users Management"])

def require_super_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "SUPER_ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. Super Admin role required.")
    return current_user

@router.get("/", response_model=List[UserResponse])
def get_all_users(db: Session = Depends(get_db), admin: User = Depends(require_super_admin)):
    return db.query(User).all()

@router.post("/", response_model=UserResponse)
def create_user(user_in: UserCreate, db: Session = Depends(get_db), admin: User = Depends(require_super_admin)):
    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    new_user = User(
        full_name=user_in.full_name,
        email=user_in.email,
        password_hash=get_password_hash(user_in.password),
        role=user_in.role,
        status=user_in.status
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    audit = AuditLog(
        user_id=admin.user_id,
        user_email=admin.email,
        action="USER_CREATED",
        details=f"Created user {new_user.email} with role {new_user.role}"
    )
    db.add(audit)
    db.commit()

    return new_user

@router.patch("/{user_id}/status", response_model=UserResponse)
def update_user_status(user_id: int, status_in: UserStatusUpdate, db: Session = Depends(get_db), admin: User = Depends(require_super_admin)):
    target_user = db.query(User).filter(User.user_id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    target_user.status = status_in.status
    db.commit()
    db.refresh(target_user)

    audit = AuditLog(
        user_id=admin.user_id,
        user_email=admin.email,
        action="USER_STATUS_UPDATED",
        details=f"Updated user {target_user.email} status to {target_user.status}"
    )
    db.add(audit)
    db.commit()

    return target_user
