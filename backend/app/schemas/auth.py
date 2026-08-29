from pydantic import BaseModel, field_validator
from datetime import datetime
from uuid import UUID
from typing import Optional
from app.models.user import UserRole

class UserBase(BaseModel):
    email: str
    role: UserRole
    org_id: Optional[str] = None

    @field_validator("org_id", mode="before")
    @classmethod
    def convert_org_id_to_str(cls, v):
        return str(v) if v is not None else None

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: UUID
    created_at: datetime
    is_active: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[UserRole] = None

class LoginRequest(BaseModel):
    email: str
    password: str
