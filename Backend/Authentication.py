"""Local password plus TOTP authentication for the GearEye dashboard."""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import struct
import threading
import time
from pathlib import Path

from fastapi import HTTPException, Request, Response
from pydantic import BaseModel, Field


APP_DATA_DIR = Path(
    os.environ.get(
        "GEAREYE_DATA_DIR",
        Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share")) / "GearEye",
    )
)
STATE_FILE = Path(
    os.environ.get("GEAREYE_AUTH_FILE", APP_DATA_DIR / "auth_state.json")
)
COOKIE_NAME = "geareye_session"
SESSION_TTL = 8 * 60 * 60
IDLE_TTL = 5 * 60
CHALLENGE_TTL = 5 * 60
_lock = threading.RLock()
_attempts = {}


def _read_state():
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2), encoding="utf-8")
    temporary.replace(STATE_FILE)


def _password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return {
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(digest).decode("ascii"),
    }


def _password_matches(password, record):
    try:
        salt = base64.b64decode(record["salt"])
        expected = base64.b64decode(record["hash"])
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (KeyError, ValueError, TypeError):
        return False


def _totp(secret, timestamp=None):
    timestamp = int(time.time() if timestamp is None else timestamp)
    key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    counter = struct.pack(">Q", timestamp // 30)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def _matching_totp_counter(secret, code):
    code = "".join(char for char in code if char.isdigit())
    if len(code) != 6:
        return None
    current = int(time.time()) // 30
    for counter in (current - 1, current, current + 1):
        if hmac.compare_digest(_totp(secret, counter * 30), code):
            return counter
    return None


def _ensure_state():
    """Prepare a one-time bootstrap key until the first account is enrolled."""
    with _lock:
        state = _read_state()
        if state.get("user"):
            return
        bootstrap_key = secrets.token_urlsafe(24)
        state["bootstrap_hash"] = _password_hash(bootstrap_key)
        state.setdefault("signing_key", secrets.token_bytes(32).hex())
        _write_state(state)
        print("\nGearEye first-time setup key (use it once in the dashboard):")
        print(f"{bootstrap_key}\n")


_ensure_state()


class SetupRequest(BaseModel):
    setup_key: str = Field(min_length=1, max_length=200)
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=200)


class CodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class VerifyRequest(CodeRequest):
    challenge: str = Field(min_length=20, max_length=500)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=200)


def status(request: Request):
    with _lock:
        state = _read_state()
        user = state.get("user")
        claims = _read_token(request.cookies.get(COOKIE_NAME, ""), state, "session")
        authenticated = _valid_session(claims, user, state)
        return {
            "configured": bool(user),
            "authenticated": authenticated,
            "username": user["username"] if authenticated else None,
        }


def _require_loopback(request: Request):
    try:
        if request.client and ipaddress.ip_address(request.client.host).is_loopback:
            return
    except ValueError:
        pass
    raise HTTPException(status_code=403, detail="La configuración inicial solo se permite desde este equipo.")


def setup_account(payload: SetupRequest, request: Request):
    _require_loopback(request)
    _rate_limit(request)
    username = payload.username.strip()
    if len(username) < 3:
        raise HTTPException(status_code=422, detail="El usuario debe tener al menos 3 caracteres no vacíos.")
    if payload.password.isspace():
        raise HTTPException(status_code=422, detail="La contraseña no puede contener solo espacios.")
    with _lock:
        state = _read_state()
        if state.get("user"):
            raise HTTPException(status_code=409, detail="La cuenta GearEye ya está configurada.")
        if not _password_matches(payload.setup_key, state.get("bootstrap_hash", {})):
            raise HTTPException(status_code=401, detail="La clave inicial no es válida. Usa la última clave de la terminal.")
        if len(payload.password) < 12:
            raise HTTPException(status_code=422, detail="La contraseña debe tener al menos 12 caracteres.")

        secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
        account = {
            "username": username,
            "password": _password_hash(payload.password),
            "totp_secret": secret,
        }
        state["pending_user"] = account
        state.setdefault("signing_key", secrets.token_bytes(32).hex())
        _write_state(state)
        issuer = "GearEye"
        label = f"{issuer}:{account['username']}"
        uri = f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
        return {"secret": secret, "otpauth_uri": uri, "issuer": issuer}


def _sign_token(payload, signing_key):
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=")
    signature = hmac.new(bytes.fromhex(signing_key), body, hashlib.sha256).digest()
    return body.decode() + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


def _read_token(token, state, purpose):
    try:
        body, supplied = token.split(".", 1)
        expected = hmac.new(bytes.fromhex(state["signing_key"]), body.encode(), hashlib.sha256).digest()
        signature = base64.urlsafe_b64decode(supplied + "=" * (-len(supplied) % 4))
        if not hmac.compare_digest(expected, signature):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if payload.get("purpose") != purpose or payload.get("exp", 0) < time.time():
            return None
        return payload
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def _set_session(response, username, state, request):
    now = int(time.time())
    token = _sign_token(
        {
            "sub": username,
            "iat": now,
            "exp": now + SESSION_TTL,
            "last_activity": now,
            "sid": secrets.token_urlsafe(24),
            "purpose": "session",
            "ver": state.get("session_version", 0),
        },
        state["signing_key"],
    )
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=IDLE_TTL,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="strict",
        path="/",
    )


def confirm_setup(payload: CodeRequest, response: Response, request: Request):
    _require_loopback(request)
    _rate_limit(request)
    with _lock:
        state = _read_state()
        pending = state.get("pending_user")
        if not pending:
            raise HTTPException(status_code=409, detail="Inicia primero la configuración de la cuenta.")
        counter = _matching_totp_counter(pending["totp_secret"], payload.code)
        if counter is None:
            raise HTTPException(status_code=401, detail="Código incorrecto o vencido. Revisa la hora de tu autenticador.")
        state["user"] = pending
        state["last_totp_counter"] = counter
        state.pop("pending_user", None)
        state.pop("bootstrap_hash", None)
        _write_state(state)
        _set_session(response, pending["username"], state, request)
        return {"ok": True, "username": pending["username"]}


def _rate_limit(request):
    now = time.time()
    address = request.client.host if request.client else "unknown"
    recent = [attempt for attempt in _attempts.get(address, []) if now - attempt < 60]
    if len(recent) >= 8:
        raise HTTPException(status_code=429, detail="Demasiados intentos. Espera un minuto y vuelve a probar.")
    recent.append(now)
    _attempts[address] = recent


def begin_login(payload: LoginRequest, request: Request):
    _rate_limit(request)
    state = _read_state()
    user = state.get("user")
    if not user or not hmac.compare_digest(payload.username.strip(), user["username"]) or not _password_matches(payload.password, user["password"]):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos.")
    now = int(time.time())
    challenge = _sign_token({"sub": user["username"], "jti": secrets.token_urlsafe(16), "iat": now, "exp": now + CHALLENGE_TTL, "purpose": "challenge"}, state["signing_key"])
    return {"challenge": challenge, "expires_in": CHALLENGE_TTL}


def verify_login(payload: VerifyRequest, response: Response, request: Request):
    _rate_limit(request)
    with _lock:
        state = _read_state()
        claims = _read_token(payload.challenge, state, "challenge")
        user = state.get("user")
        if not claims or not user or claims.get("sub") != user.get("username"):
            raise HTTPException(status_code=401, detail="El desafío venció. Inicia sesión otra vez.")

        challenge_id = claims.get("jti")
        used_challenges = state.setdefault("used_challenges", [])
        if not challenge_id or challenge_id in used_challenges:
            raise HTTPException(status_code=401, detail="Este desafío ya fue utilizado. Inicia sesión otra vez.")

        counter = _matching_totp_counter(user["totp_secret"], payload.code)
        if counter is None:
            raise HTTPException(status_code=401, detail="Código incorrecto o vencido.")
        if counter <= state.get("last_totp_counter", -1):
            raise HTTPException(status_code=401, detail="Ese código ya fue utilizado. Espera el siguiente código.")

        state["last_totp_counter"] = counter
        used_challenges.append(challenge_id)
        state["used_challenges"] = used_challenges[-1000:]
        _write_state(state)
        _set_session(response, user["username"], state, request)
        return {"ok": True, "username": user["username"]}


def _valid_session(claims, user, state):
    if (not claims or not user or claims.get("sub") != user.get("username")
            or claims.get("ver", 0) != state.get("session_version", 0)):
        return False
    last_activity = claims.get("last_activity", claims.get("iat", 0))
    if not isinstance(last_activity, (int, float)) or time.time() - last_activity >= IDLE_TTL:
        return False
    revoked = state.get("revoked_sessions", [])
    return claims.get("sid") not in {entry.get("sid") for entry in revoked if isinstance(entry, dict)}


def require_user(request: Request, response: Response):
    state = _read_state()
    claims = _read_token(request.cookies.get(COOKIE_NAME, ""), state, "session")
    user = state.get("user")
    if not _valid_session(claims, user, state):
        raise HTTPException(status_code=401, detail="Inicia sesi\u00f3n para acceder a GearEye.")
    now = int(time.time())
    refreshed = {**claims, "last_activity": now}
    if request.headers.get("x-geareye-background") != "true":
        response.set_cookie(COOKIE_NAME, _sign_token(refreshed, state["signing_key"]),
            max_age=max(1, min(IDLE_TTL, int(claims["exp"] - now))), httponly=True,
            secure=request.url.scheme == "https", samesite="strict", path="/")
    return user["username"]


def logout(response: Response, request: Request):
    with _lock:
        state = _read_state()
        claims = _read_token(request.cookies.get(COOKIE_NAME, ""), state, "session")
        if claims and claims.get("sid"):
            now = int(time.time())
            revoked = [entry for entry in state.get("revoked_sessions", []) if isinstance(entry, dict) and entry.get("exp", 0) > now]
            revoked.append({"sid": claims["sid"], "exp": claims.get("exp", now)})
            state["revoked_sessions"] = revoked[-1000:]
        _write_state(state)
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, samesite="strict")
    return {"ok": True}
