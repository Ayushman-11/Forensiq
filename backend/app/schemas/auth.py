"""
Pydantic request/response schemas for authentication and user management endpoints.
"""

from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)

    @field_validator("password")
    @classmethod
    def _bcrypt_byte_limit(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 72:
            raise ValueError("password must be at most 72 bytes")
        return value


class RefreshRequest(BaseModel):
    refresh_token: Optional[str] = None


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    mfa_required: bool = False
    mfa_token: Optional[str] = None


class MfaSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str


class MfaVerifyRequest(BaseModel):
    token: str = Field(..., min_length=6, max_length=6)


class MfaChallengeRequest(BaseModel):
    mfa_token: str
    code: str = Field(..., min_length=6, max_length=6)


class WsTicketResponse(BaseModel):
    ticket: str
    expires_in: int = 60


class UserOut(BaseModel):
    id: str
    email: EmailStr
    role: str
    is_active: bool
    mfa_enabled: bool = False
    created_at: Optional[str] = None


class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="analyst")


class UpdateUserStatusRequest(BaseModel):
    is_active: bool


class ResetPasswordRequest(BaseModel):
    password: str = Field(..., min_length=8, max_length=128)
