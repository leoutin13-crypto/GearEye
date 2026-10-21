"""Local password plus TOTP authentication for the GearEye dashboard."""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import smtplib
import ssl
import struct
import threading
import time
from pathlib import Path
from email.message import EmailMessage
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, Response
from pydantic import BaseModel, Field
from Backend.Services.TenantContext import active_company_id


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
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        legacy = state.get("user")
        if legacy:
            legacy.setdefault("name", legacy.get("username", "Administrador"))
            legacy.setdefault("email", "")
            legacy.setdefault("company_name", "GearEye")
            legacy.setdefault("company_id", "default")
            legacy.setdefault("role", "platform_admin")
            state.setdefault("users", {}).setdefault(legacy["username"], legacy)
            state.setdefault("companies", [{"id": "default", "name": legacy["company_name"], "status": "active", "created_at": int(time.time())}])
        return state
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
    email: str = Field(min_length=3, max_length=254)
    company: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=12, max_length=200)


class CodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class VerifyRequest(CodeRequest):
    challenge: str = Field(min_length=20, max_length=500)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=200)


class CompanyRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    admin_name: str = Field(min_length=2, max_length=120)
    admin_email: str = Field(min_length=5, max_length=254)


class InviteRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=5, max_length=254)
    company_id: str = Field(min_length=1, max_length=80)
    role: str = Field(pattern="^(company_admin|viewer)$")


class AcceptInviteRequest(BaseModel):
    token: str = Field(min_length=32, max_length=120)
    password: str = Field(min_length=12, max_length=200)


def accept_invite(payload, request):
    _rate_limit(request)
    token_hash = hashlib.sha256(payload.token.encode()).hexdigest()
    with _lock:
        state = _read_state()
        invitation = state.get("invitations", {}).get(token_hash)
        if not invitation or invitation.get("expires_at", 0) < time.time():
            raise HTTPException(status_code=410, detail="La invitación venció o ya fue utilizada.")
        username = invitation["email"]
        secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
        user = {**invitation, "username": username, "password": _password_hash(payload.password), "totp_secret": secret, "name": invitation["name"]}
        state.setdefault("pending_users", {})[token_hash] = user
        _write_state(state)
        label = f"GearEye:{username}"
        uri = f"otpauth://totp/{label}?secret={secret}&issuer=GearEye&algorithm=SHA1&digits=6&period=30"
        return {"secret": secret, "otpauth_uri": uri}


def confirm_invite(token, payload, response, request):
    _rate_limit(request)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with _lock:
        state = _read_state()
        user = state.get("pending_users", {}).get(token_hash)
        invitation = state.get("invitations", {}).get(token_hash)
        if not user or not invitation or invitation.get("expires_at", 0) < time.time():
            raise HTTPException(status_code=410, detail="La invitación venció. Solicita una nueva.")
        counter = _matching_totp_counter(user["totp_secret"], payload.code)
        if counter is None:
            raise HTTPException(status_code=401, detail="Código incorrecto o vencido.")
        user.pop("expires_at", None)
        state.setdefault("users", {})[user["username"]] = user
        state.setdefault("last_totp_counters", {})[user["username"]] = counter
        state["pending_users"].pop(token_hash, None)
        state["invitations"].pop(token_hash, None)
        _write_state(state)
        _set_session(response, user["username"], state, request)
        return {"ok": True, "username": user["username"]}


def admin_overview(actor):
    state = _read_state()
    if actor.get("role") not in {"platform_admin", "company_admin"}:
        raise HTTPException(status_code=403, detail="Tu cuenta no tiene permisos de administración.")
    companies = state.get("companies", [])
    users = list(state.get("users", {}).values())
    if actor.get("role") == "company_admin":
        companies = [c for c in companies if c.get("id") == actor.get("company_id")]
        users = [u for u in users if u.get("company_id") == actor.get("company_id")]
    counts = {c.get("id"): sum(u.get("company_id") == c.get("id") for u in users) for c in companies}
    return {
        "companies": [{"id": c.get("id"), "name": c.get("name"), "status": c.get("status", "active"),
                       "created_at": c.get("created_at"), "last_agent_report": c.get("last_agent_report"),
                       "user_count": counts.get(c.get("id"), 0)} for c in companies],
        "users": [{"name": u.get("name", u.get("username", "")), "email": u.get("email", ""),
                   "company_id": u.get("company_id"),
                   "company_name": next((c["name"] for c in companies if c.get("id") == u.get("company_id")), ""),
                   "role": u.get("role"), "role_label": {"platform_admin": "Administrador general", "company_admin": "Administrador de empresa", "viewer": "Consulta"}.get(u.get("role"), "Invitado"),
                   "disabled": bool(u.get("disabled"))} for u in users],
    }


def create_company(actor, payload):
    if actor.get("role") != "platform_admin":
        raise HTTPException(status_code=403, detail="Solo el administrador general puede crear empresas.")
    name = payload.name.strip()
    admin_name = payload.admin_name.strip()
    admin_email = payload.admin_email.strip().lower()
    if len(name) < 2 or len(admin_name) < 2 or admin_email.count("@") != 1 or "." not in admin_email.rsplit("@", 1)[-1]:
        raise HTTPException(status_code=422, detail="Escribe un nombre de empresa, nombre y correo validos para el administrador.")
    smtp_host = os.environ.get("GEAREYE_SMTP_HOST", "").strip()
    smtp_from = os.environ.get("GEAREYE_SMTP_FROM", "").strip()
    if not smtp_host or not smtp_from:
        raise HTTPException(status_code=503, detail="Configura el correo SMTP de GearEye antes de crear empresas.")
    host = os.environ.get("GEAREYE_PUBLIC_URL", "").strip().rstrip("/")
    parsed_host = urlsplit(host)
    try:
        is_ip_address = bool(parsed_host.hostname and ipaddress.ip_address(parsed_host.hostname))
    except ValueError:
        is_ip_address = False
    if (parsed_host.scheme != "https" or not parsed_host.hostname or is_ip_address
            or parsed_host.hostname == "localhost" or parsed_host.path not in {"", "/"}
            or parsed_host.query or parsed_host.fragment or parsed_host.username or parsed_host.password):
        raise HTTPException(status_code=503, detail="Configura GEAREYE_PUBLIC_URL con un dominio HTTPS antes de enviar invitaciones.")

    company_id = secrets.token_urlsafe(12)
    agent_token = secrets.token_urlsafe(40)
    invite_token = secrets.token_urlsafe(32)
    invite_hash = hashlib.sha256(invite_token.encode()).hexdigest()
    company = {"id": company_id, "name": name, "status": "waiting_agent", "created_at": int(time.time()), "agent_token_hash": hashlib.sha256(agent_token.encode()).hexdigest()}
    invitation = {"name": admin_name, "email": admin_email, "company_id": company_id,
                  "company_name": name, "role": "company_admin", "expires_at": int(time.time()) + 48 * 60 * 60}
    with _lock:
        state = _read_state()
        companies = state.setdefault("companies", [])
        if any(item.get("name", "").casefold() == name.casefold() for item in companies):
            raise HTTPException(status_code=409, detail="Ya existe una empresa con ese nombre.")
        users = state.setdefault("users", {})
        pending = state.get("invitations", {}).values()
        if any(key.casefold() == admin_email for key in users) or any(user.get("email", "").casefold() == admin_email for user in users.values()) or any(item.get("email", "").casefold() == admin_email for item in pending):
            raise HTTPException(status_code=409, detail="Ese correo ya tiene una cuenta o invitaciÃ³n pendiente.")
        companies.append(company)
        state.setdefault("invitations", {})[invite_hash] = invitation
        _write_state(state)

    invitation_url = f"{host}/app/?invite={invite_token}"
    agent_config = f"$env:GEAREYE_SERVER_URL='{host}'\n$env:GEAREYE_AGENT_TOKEN='{agent_token}'\npython -m Backend.agent"
    message = EmailMessage()
    message["Subject"] = f"Bienvenido a GearEye - {name}"
    message["From"] = smtp_from
    message["To"] = admin_email
    message.set_content(
        f"Hola {admin_name},\n\n"
        f"Te hemos invitado como administrador de {name} en GearEye.\n\n"
        f"1. Activa tu cuenta y configura tu autenticador (el enlace vence en 48 horas):\n{invitation_url}\n\n"
        "2. Copia el proyecto GearEye en un equipo Windows conectado a la red de tu empresa.\n"
        "3. Instala sus dependencias con: pip install -r requirements.txt\n"
        "4. Abre PowerShell en la carpeta del proyecto y ejecuta:\n\n"
        f"{agent_config}\n\n"
        "El token del agente es privado. No lo compartas ni lo publiques.\n"
    )
    try:
        port = int(os.environ.get("GEAREYE_SMTP_PORT", "587"))
        username = os.environ.get("GEAREYE_SMTP_USER", "")
        password = os.environ.get("GEAREYE_SMTP_PASSWORD", "")
        if port == 465:
            with smtplib.SMTP_SSL(smtp_host, port, timeout=15, context=ssl.create_default_context()) as server:
                if username:
                    server.login(username, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(smtp_host, port, timeout=15) as server:
                server.ehlo()
                if os.environ.get("GEAREYE_SMTP_STARTTLS", "true").lower() == "true":
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                if username:
                    server.login(username, password)
                server.send_message(message)
    except (OSError, smtplib.SMTPException, ValueError) as error:
        with _lock:
            state = _read_state()
            state["companies"] = [item for item in state.get("companies", []) if item.get("id") != company_id]
            state.get("invitations", {}).pop(invite_hash, None)
            _write_state(state)
        raise HTTPException(status_code=502, detail="No se pudo enviar el correo de bienvenida. Revisa la configuracion SMTP.") from error
    return {"id": company_id, "name": name, "status": company["status"], "email": admin_email}

def company_for_agent_token(token):
    if not token:
        return None
    supplied_hash = hashlib.sha256(token.encode()).hexdigest()
    state = _read_state()
    with _lock:
        state = _read_state()
        for company in state.get("companies", []):
            stored_hash = company.get("agent_token_hash", "")
            if stored_hash and hmac.compare_digest(supplied_hash, stored_hash):
                company["last_agent_report"] = int(time.time())
                company["status"] = "active"
                _write_state(state)
                return {"id": company["id"], "name": company["name"]}
    return None


def invite_user(actor, payload, request):
    _rate_limit(request)
    if actor.get("role") not in {"platform_admin", "company_admin"}:
        raise HTTPException(status_code=403, detail="Tu cuenta no puede invitar usuarios.")
    email = payload.email.strip().lower()
    if email.count("@") != 1 or "." not in email.rsplit("@", 1)[-1]:
        raise HTTPException(status_code=422, detail="Escribe un correo válido.")
    if actor.get("role") == "company_admin" and payload.company_id != actor.get("company_id"):
        raise HTTPException(status_code=403, detail="Solo puedes invitar usuarios a tu empresa.")
    host = os.environ.get("GEAREYE_PUBLIC_URL", "").strip().rstrip("/")
    parsed_host = urlsplit(host)
    try:
        is_ip_address = bool(parsed_host.hostname and ipaddress.ip_address(parsed_host.hostname))
    except ValueError:
        is_ip_address = False
    if (parsed_host.scheme != "https" or not parsed_host.hostname or is_ip_address
            or parsed_host.hostname == "localhost" or parsed_host.path not in {"", "/"}
            or parsed_host.query or parsed_host.fragment or parsed_host.username or parsed_host.password):
        raise HTTPException(status_code=503, detail="Configura GEAREYE_PUBLIC_URL con un dominio HTTPS antes de enviar invitaciones.")
    with _lock:
        state = _read_state()
        company = next((c for c in state.get("companies", []) if c.get("id") == payload.company_id), None)
        if not company:
            raise HTTPException(status_code=404, detail="No se encontró la empresa seleccionada.")
        users = state.setdefault("users", {})
        pending = state.get("invitations", {}).values()
        if any(key.casefold() == email for key in users) or any(u.get("email", "").casefold() == email for u in users.values()) or any(inv.get("email", "").casefold() == email for inv in pending):
            raise HTTPException(status_code=409, detail="Ese correo ya tiene una cuenta.")
        token = secrets.token_urlsafe(32)
        state.setdefault("invitations", {})[hashlib.sha256(token.encode()).hexdigest()] = {
            "name": payload.name.strip(), "email": email, "company_id": company["id"],
            "company_name": company["name"], "role": payload.role,
            "expires_at": int(time.time()) + 48 * 60 * 60,
        }
        _write_state(state)
    link = f"{host}/app/?invite={token}"
    smtp_host = os.environ.get("GEAREYE_SMTP_HOST", "").strip()
    smtp_from = os.environ.get("GEAREYE_SMTP_FROM", "").strip()
    if not smtp_host or not smtp_from:
        with _lock:
            state = _read_state()
            state.get("invitations", {}).pop(hashlib.sha256(token.encode()).hexdigest(), None)
            _write_state(state)
        raise HTTPException(status_code=503, detail="Falta configurar el correo SMTP de GearEye para enviar invitaciones.")
    message = EmailMessage()
    message["Subject"] = f"Invitación a GearEye · {company['name']}"
    message["From"] = smtp_from
    message["To"] = email
    message.set_content(f"Hola {payload.name.strip()},\n\nTe invitaron a GearEye para consultar la red de {company['name']}.\nAcepta la invitación en las próximas 48 horas: {link}\n\nEl enlace es personal y de un solo uso.")
    try:
        port = int(os.environ.get("GEAREYE_SMTP_PORT", "587"))
        username = os.environ.get("GEAREYE_SMTP_USER", "")
        password = os.environ.get("GEAREYE_SMTP_PASSWORD", "")
        if port == 465:
            with smtplib.SMTP_SSL(smtp_host, port, timeout=15, context=ssl.create_default_context()) as server:
                if username:
                    server.login(username, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(smtp_host, port, timeout=15) as server:
                server.ehlo()
                if os.environ.get("GEAREYE_SMTP_STARTTLS", "true").lower() == "true":
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                if username:
                    server.login(username, password)
                server.send_message(message)
    except (OSError, smtplib.SMTPException, ValueError) as error:
        with _lock:
            state = _read_state()
            state.get("invitations", {}).pop(hashlib.sha256(token.encode()).hexdigest(), None)
            _write_state(state)
        raise HTTPException(status_code=502, detail="No se pudo enviar la invitación. Revisa la configuración SMTP.") from error
    return {"ok": True, "email": email}


def status(request: Request):
    with _lock:
        state = _read_state()
        user = state.get("user")
        claims = _read_token(request.cookies.get(COOKIE_NAME, ""), state, "session")
        username = claims.get("sub") if claims else None
        account = _find_user(state, username)
        authenticated = _valid_session(claims, account, state)
        return {
            "configured": bool(user or state.get("users")),
            "authenticated": authenticated,
            "username": account["username"] if authenticated else None,
            "name": account.get("name") if authenticated else None,
            "email": account.get("email") if authenticated else None,
            "company": account.get("company_name") if authenticated else None,
            "company_id": account.get("company_id") if authenticated else None,
            "role": account.get("role") if authenticated else None,
        }


def _find_user(state, username):
    if not username:
        return None
    users = state.get("users", {})
    account = users.get(username) if isinstance(users, dict) else None
    legacy = state.get("user")
    if account:
        return account
    if legacy and legacy.get("username") == username:
        legacy.setdefault("name", legacy["username"])
        legacy.setdefault("email", "")
        legacy.setdefault("company_name", "GearEye")
        legacy.setdefault("company_id", "default")
        legacy.setdefault("role", "platform_admin")
        state.setdefault("users", {})[username] = legacy
        return legacy
    return None


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
    email = payload.email.strip().lower()
    company_name = payload.company.strip()
    if email.count("@") != 1 or "." not in email.rsplit("@", 1)[-1]:
        raise HTTPException(status_code=422, detail="Escribe un correo válido.")
    if len(company_name) < 2:
        raise HTTPException(status_code=422, detail="Escribe un nombre de empresa válido.")
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
            "name": username,
            "email": email,
            "company_name": company_name,
            "company_id": "default",
            "role": "platform_admin",
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
        state["users"] = {pending["username"]: pending}
        state["companies"] = [{"id": "default", "name": pending["company_name"], "status": "active", "created_at": int(time.time())}]
        state.setdefault("last_totp_counters", {})[pending["username"]] = counter
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
    username = payload.username.strip()
    user = _find_user(state, username)
    if not user:
        user = next((candidate for candidate in state.get("users", {}).values()
                     if candidate.get("email", "").casefold() == username.casefold()), None)
    identity_matches = bool(user) and (
        hmac.compare_digest(username, user["username"])
        or bool(user.get("email") and hmac.compare_digest(username.casefold(), user["email"].casefold()))
    )
    if not user or user.get("disabled") or not identity_matches or not _password_matches(payload.password, user["password"]):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos.")
    now = int(time.time())
    challenge = _sign_token({"sub": user["username"], "jti": secrets.token_urlsafe(16), "iat": now, "exp": now + CHALLENGE_TTL, "purpose": "challenge"}, state["signing_key"])
    return {"challenge": challenge, "expires_in": CHALLENGE_TTL}


def verify_login(payload: VerifyRequest, response: Response, request: Request):
    _rate_limit(request)
    with _lock:
        state = _read_state()
        claims = _read_token(payload.challenge, state, "challenge")
        user = _find_user(state, claims.get("sub") if claims else None)
        if not claims or not user or user.get("disabled"):
            raise HTTPException(status_code=401, detail="El desafío venció. Inicia sesión otra vez.")

        challenge_id = claims.get("jti")
        used_challenges = state.setdefault("used_challenges", [])
        if not challenge_id or challenge_id in used_challenges:
            raise HTTPException(status_code=401, detail="Este desafío ya fue utilizado. Inicia sesión otra vez.")

        counter = _matching_totp_counter(user["totp_secret"], payload.code)
        if counter is None:
            raise HTTPException(status_code=401, detail="Código incorrecto o vencido.")
        previous_counter = state.setdefault("last_totp_counters", {}).get(user["username"], state.get("last_totp_counter", -1))
        if counter <= previous_counter:
            raise HTTPException(status_code=401, detail="Ese código ya fue utilizado. Espera el siguiente código.")

        state["last_totp_counters"][user["username"]] = counter
        used_challenges.append(challenge_id)
        state["used_challenges"] = used_challenges[-1000:]
        _write_state(state)
        _set_session(response, user["username"], state, request)
        return {"ok": True, "username": user["username"]}


def _valid_session(claims, user, state):
    if (not claims or not user or claims.get("sub") != user.get("username") or user.get("disabled")
            or claims.get("ver", 0) != state.get("session_version", 0)):
        return False
    last_activity = claims.get("last_activity", claims.get("iat", 0))
    if not isinstance(last_activity, (int, float)) or time.time() - last_activity >= IDLE_TTL:
        return False
    revoked = state.get("revoked_sessions", [])
    return claims.get("sid") not in {entry.get("sid") for entry in revoked if isinstance(entry, dict)}


async def require_user(request: Request, response: Response):
    state = _read_state()
    claims = _read_token(request.cookies.get(COOKIE_NAME, ""), state, "session")
    user = _find_user(state, claims.get("sub") if claims else None)
    if not _valid_session(claims, user, state):
        raise HTTPException(status_code=401, detail="Inicia sesi\u00f3n para acceder a GearEye.")
    active_company_id.set(user.get("company_id", "default"))
    now = int(time.time())
    refreshed = {**claims, "last_activity": now}
    if request.headers.get("x-geareye-background") != "true":
        response.set_cookie(COOKIE_NAME, _sign_token(refreshed, state["signing_key"]),
            max_age=max(1, min(IDLE_TTL, int(claims["exp"] - now))), httponly=True,
            secure=request.url.scheme == "https", samesite="strict", path="/")
    return user


async def require_company_admin(request: Request, response: Response):
    user = await require_user(request, response)
    if user.get("role") not in {"platform_admin", "company_admin"}:
        raise HTTPException(status_code=403, detail="Esta acción requiere un rol de administrador.")
    return user


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
