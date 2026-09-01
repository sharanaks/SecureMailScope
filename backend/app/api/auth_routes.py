from fastapi import APIRouter, HTTPException, Depends, Header
from app.database.db import get_cursor
from app.services import auth
from app.api.models import RegisterRequest, LoginRequest, TokenResponse

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse)
def register(payload: RegisterRequest):
    with get_cursor() as cur:
        cur.execute("SELECT id FROM users WHERE email = ?", (payload.email,))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail="An account with this email already exists.")

    password_hash = auth.hash_password(payload.password)
    with get_cursor(commit=True) as cur:
        cur.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (payload.email, password_hash),
        )
        user_id = cur.lastrowid

    token = auth.create_access_token(user_id, payload.email)
    return TokenResponse(access_token=token, email=payload.email)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    with get_cursor() as cur:
        cur.execute("SELECT id, password_hash FROM users WHERE email = ?", (payload.email,))
        row = cur.fetchone()

    if not row or not auth.verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = auth.create_access_token(row["id"], payload.email)
    return TokenResponse(access_token=token, email=payload.email)


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    """
    Dependency for protected routes. For hackathon simplicity, this
    validates the JWT but does not hard-block every endpoint — scanning
    is allowed for demo purposes even without a logged-in user (see
    scan_routes.py), while report/account-linked actions do require it
    where used.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
    token = authorization.removeprefix("Bearer ").strip()
    payload = auth.decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    return payload


def get_optional_user(authorization: str | None = Header(default=None)) -> dict | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.removeprefix("Bearer ").strip()
    return auth.decode_access_token(token)
