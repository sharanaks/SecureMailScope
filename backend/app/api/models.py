from pydantic import BaseModel, EmailStr, Field

from typing import Optional, Any


class RegisterRequest(BaseModel):

    email: EmailStr

    password: str = Field(min_length=8)


class LoginRequest(BaseModel):

    email: EmailStr

    password: str


class TokenResponse(BaseModel):

    access_token: str

    token_type: str = "bearer"

    email: str


class ScanRequest(BaseModel):

    domain: str

    dkim_selector: Optional[str] = None


class VerifyReportRequest(BaseModel):

    report: Optional[dict[str, Any]] = None