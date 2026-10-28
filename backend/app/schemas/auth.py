"""
Pydantic request/response schemas for authentication and user management endpoints.
"""

from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator
import re
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field, field_validator

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")


def normalize_email(value: str) -> str:
    """Lowercase and sanity-check a login email.

    Deliberately not EmailStr: that rejects special-use domains such as corp.local, .internal
    and .test, which are normal for Active Directory accounts. A login identifier only needs
    to be a stable user@domain string, so this is the one validator for login and bootstrap.
    """
    email = value.strip().lower()
    if len(email) > 254 or not _EMAIL_RE.match(email):
        raise ValueError("email must look like user@domain")
    return email


LoginEmail = Annotated[str, AfterValidator(normalize_email)]


class LoginRequest(BaseModel):
    email: LoginEmail
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
    email: str
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
