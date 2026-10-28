"""
Pydantic request/response schemas for authentication endpoints.
"""

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
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    is_active: bool
