"""Role-based authentication for the review console (SPEC §6, §9.6).

Self-contained and dependency-light: PBKDF2 password hashing (stdlib), stateless HMAC-signed bearer
tokens (stdlib), SQLite-backed user store. Four roles with a strict order:

    viewer < analyst < soc_manager < admin

* viewer      - read-only.
* analyst     - investigate + review (approve/override/annotate).
* soc_manager - analyst + configure automation, see team analytics.
* admin       - everything + user management.

Endpoints: ``/api/auth/{signup,login,me,logout}`` and ``/api/auth/users`` (admin). A few demo users
are seeded on first run so the UI is usable immediately.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from aegis.api.store import Store
from aegis.db.models import User

router = APIRouter(prefix="/api/auth")
_store = Store()

ROLES = ["viewer", "analyst", "soc_manager", "admin"]
_ROLE_RANK = {r: i for i, r in enumerate(ROLES)}
TOKEN_TTL = timedelta(days=7)

PERMISSIONS: dict[str, list[str]] = {
    "viewer": ["read"],
    "analyst": ["read", "investigate", "review"],
    "soc_manager": ["read", "investigate", "review", "automation", "team"],
    "admin": ["read", "investigate", "review", "automation", "team", "users", "settings"],
}
_AVATARS = ["#0A84FF", "#30D158", "#FF9F0A", "#FF375F", "#BF5AF2", "#64D2FF", "#FFD60A"]


def _secret() -> bytes:
    env = os.environ.get("AEGIS_AUTH_SECRET")
    if env:
        return env.encode()
    p = Path(os.environ.get("AEGIS_DATA_ROOT", "data")) / ".auth_secret"
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text(secrets.token_hex(32), encoding="utf-8")
    return p.read_text(encoding="utf-8").encode()


# ------------------------------------------------------------------ password hashing
def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return base64.b64encode(salt + dk).decode()


def verify_password(pw: str, stored: str) -> bool:
    try:
        raw = base64.b64decode(stored)
    except (ValueError, TypeError):
        return False
    salt, dk = raw[:16], raw[16:]
    return hmac.compare_digest(dk, hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000))


# ------------------------------------------------------------------ tokens
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(user_id: str, role: str) -> str:
    payload = {"sub": user_id, "role": role, "exp": (datetime.now(tz=UTC) + TOKEN_TTL).timestamp()}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def read_token(token: str) -> dict[str, Any] | None:
    try:
        body, sig = token.split(".", 1)
    except ValueError:
        return None
    expected = _b64(hmac.new(_secret(), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload: dict[str, Any] = json.loads(_unb64(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if payload.get("exp", 0) < datetime.now(tz=UTC).timestamp():
        return None
    return payload


# ------------------------------------------------------------------ dependencies
def current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    payload = read_token(authorization.split(" ", 1)[1])
    if payload is None:
        raise HTTPException(401, "invalid or expired token")
    with _store.session() as s:
        u = s.get(User, payload["sub"])
        if u is None or not u.active:
            raise HTTPException(401, "user not found")
        return _public(u)


def require_role(minimum: str):  # type: ignore[no-untyped-def]
    def dep(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
        if _ROLE_RANK.get(user["role"], 0) < _ROLE_RANK[minimum]:
            raise HTTPException(403, f"requires {minimum} role or higher")
        return user

    return dep


def _public(u: User) -> dict[str, Any]:
    return {
        "id": u.id,
        "email": u.email,
        "name": u.name,
        "role": u.role,
        "team": u.team,
        "avatar_color": u.avatar_color,
        "permissions": PERMISSIONS.get(u.role, ["read"]),
        "created_at": u.created_at.isoformat(),
        "last_login": u.last_login.isoformat() if u.last_login else None,
    }


# ------------------------------------------------------------------ schemas
class SignupIn(BaseModel):
    email: str
    name: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=6, max_length=128)
    role: str = "analyst"

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("invalid email")
        return v


class LoginIn(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return v.strip().lower()


class RoleUpdate(BaseModel):
    role: str


# ------------------------------------------------------------------ endpoints
@router.post("/signup")
def signup(body: SignupIn) -> dict[str, Any]:
    role = body.role if body.role in ROLES and body.role != "admin" else "analyst"
    with _store.session() as s:
        if s.scalar(select(User).where(User.email == body.email.lower())):
            raise HTTPException(409, "email already registered")
        n_users = s.scalar(select(User).limit(1))
        effective_role = "admin" if n_users is None else role  # first user is admin
        u = User(
            id=f"u-{uuid.uuid4().hex[:12]}",
            email=body.email.lower(),
            name=body.name,
            password_hash=hash_password(body.password),
            role=effective_role,
            avatar_color=_AVATARS[hash(body.email) % len(_AVATARS)],
            created_at=datetime.now(tz=UTC),
        )
        s.add(u)
        s.commit()
        return {"token": make_token(u.id, u.role), "user": _public(u)}


@router.post("/login")
def login(body: LoginIn) -> dict[str, Any]:
    with _store.session() as s:
        u = s.scalar(select(User).where(User.email == body.email.lower()))
        if u is None or not verify_password(body.password, u.password_hash):
            raise HTTPException(401, "invalid email or password")
        if not u.active:
            raise HTTPException(403, "account disabled")
        u.last_login = datetime.now(tz=UTC)
        s.commit()
        return {"token": make_token(u.id, u.role), "user": _public(u)}


@router.get("/me")
def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return user


@router.post("/logout")
def logout(user: dict[str, Any] = Depends(current_user)) -> dict[str, str]:
    return {"status": "ok"}  # stateless tokens: client discards it


@router.get("/users")
def list_users(user: dict[str, Any] = Depends(require_role("admin"))) -> list[dict[str, Any]]:
    with _store.session() as s:
        return [_public(u) for u in s.scalars(select(User).order_by(User.created_at)).all()]


@router.patch("/users/{user_id}/role")
def set_role(
    user_id: str, body: RoleUpdate, user: dict[str, Any] = Depends(require_role("admin"))
) -> dict[str, Any]:
    if body.role not in ROLES:
        raise HTTPException(400, "invalid role")
    with _store.session() as s:
        u = s.get(User, user_id)
        if u is None:
            raise HTTPException(404, "user not found")
        u.role = body.role
        s.commit()
        return _public(u)


def seed_demo_users() -> None:
    """Seed demo accounts so the console is usable immediately (idempotent)."""
    demo = [
        ("admin@aegis.local", "Ava Chen", "admin", "SOC Leadership"),
        ("manager@aegis.local", "Marcus Reed", "soc_manager", "Blue Team"),
        ("analyst@aegis.local", "Priya Nair", "analyst", "Tier-2"),
        ("viewer@aegis.local", "Sam Ortega", "viewer", "Audit"),
    ]
    with _store.session() as s:
        for i, (email, name, role, team) in enumerate(demo):
            if s.scalar(select(User).where(User.email == email)):
                continue
            s.add(
                User(
                    id=f"u-demo-{i}",
                    email=email,
                    name=name,
                    password_hash=hash_password("aegis1234"),
                    role=role,
                    team=team,
                    avatar_color=_AVATARS[i % len(_AVATARS)],
                    created_at=datetime.now(tz=UTC),
                )
            )
        s.commit()
