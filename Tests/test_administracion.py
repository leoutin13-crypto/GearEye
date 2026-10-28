"""Administración de usuarios e invitaciones: permisos y estados."""

import hashlib
import time

import pytest
from fastapi import HTTPException

from Backend import Authentication as auth


GENERAL = {"username": "general", "role": "platform_admin", "company_id": "default"}
ADMIN_A = {"username": "admin-a@a.co", "role": "company_admin", "company_id": "a"}


def hash_de(token):
    return hashlib.sha256(token.encode()).hexdigest()


@pytest.fixture
def estado(monkeypatch):
    state = auth._read_state()
    state["companies"] = [{"id": "default", "name": "CIDE", "status": "active"},
                          {"id": "a", "name": "Empresa A", "status": "active"},
                          {"id": "b", "name": "Empresa B", "status": "waiting_agent"}]
    state["users"] = {
        "general": {**GENERAL, "name": "General", "email": "general@cide.co"},
        "admin-a@a.co": {**ADMIN_A, "name": "Admin A", "email": "admin-a@a.co"},
        "ana@a.co": {"username": "ana@a.co", "name": "Ana", "email": "ana@a.co", "role": "viewer", "company_id": "a"},
        "beto@b.co": {"username": "beto@b.co", "name": "Beto", "email": "beto@b.co", "role": "viewer", "company_id": "b"},
    }
    state["invitations"] = {
        hash_de("vigente"): {"name": "Carla", "email": "carla@a.co", "company_id": "a", "company_name": "Empresa A",
                             "role": "viewer", "expires_at": int(time.time()) + 3600},
        hash_de("vencida"): {"name": "Dani", "email": "dani@b.co", "company_id": "b", "company_name": "Empresa B",
                             "role": "company_admin", "expires_at": int(time.time()) - 60},
    }
    auth._write_state(state)
    monkeypatch.setattr(auth, "_rate_limit", lambda request: None)
    monkeypatch.setenv("GEAREYE_PUBLIC_URL", "https://geareye.example.com")
    monkeypatch.setenv("GEAREYE_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("GEAREYE_SMTP_FROM", "geareye@example.com")
    enviados = []
    monkeypatch.setattr(auth, "_send_mail", enviados.append)
    return enviados


def cambio(**campos):
    return auth.UserUpdateRequest(**campos)


def test_resumen_incluye_invitaciones_con_su_estado(estado):
    personas = {p["email"]: p for p in auth.admin_overview(GENERAL)["users"]}
    assert personas["carla@a.co"]["status"] == "invited"
    assert personas["dani@b.co"]["status"] == "expired"
    assert personas["general@cide.co"]["is_self"] is True
    assert personas["ana@a.co"]["status"] == "active"


def test_administrador_de_empresa_solo_ve_su_empresa(estado):
    resumen = auth.admin_overview(ADMIN_A)
    assert [c["id"] for c in resumen["companies"]] == ["a"]
    assert resumen["companies"][0]["pending_invitations"] == 1
    assert {p["email"] for p in resumen["users"]} == {"admin-a@a.co", "ana@a.co", "carla@a.co"}


def test_desactivar_y_cambiar_rol(estado):
    assert auth.update_user(ADMIN_A, "ana@a.co", cambio(disabled=True))["status"] == "disabled"
    assert auth._read_state()["users"]["ana@a.co"]["disabled"] is True
    assert auth.update_user(GENERAL, "ana@a.co", cambio(role="company_admin", disabled=False))["role"] == "company_admin"


@pytest.mark.parametrize("actor, usuario, codigo", [
    (ADMIN_A, "beto@b.co", 403),        # otra empresa
    (ADMIN_A, "admin-a@a.co", 409),     # a sí mismo
    (ADMIN_A, "general", 403),          # administrador general
    (GENERAL, "nadie@x.co", 404),
])
def test_cambios_no_permitidos(estado, actor, usuario, codigo):
    with pytest.raises(HTTPException) as error:
        auth.update_user(actor, usuario, cambio(disabled=True))
    assert error.value.status_code == codigo


def test_no_se_puede_asignar_administrador_general():
    with pytest.raises(ValueError):
        cambio(role="platform_admin")


def test_reenviar_invitacion_vencida_cambia_el_enlace(estado):
    resultado = auth.resend_invitation(GENERAL, auth._invite_id(hash_de("vencida")), request=None)
    invitaciones = auth._read_state()["invitations"]
    assert hash_de("vencida") not in invitaciones
    nueva = next(inv for h, inv in invitaciones.items() if auth._invite_id(h) == resultado["id"])
    assert nueva["expires_at"] > time.time() and nueva["email"] == "dani@b.co"
    assert estado[0]["To"] == "dani@b.co" and "administrar" in estado[0].get_content()


def test_anular_invitacion_respeta_la_empresa(estado):
    with pytest.raises(HTTPException) as error:
        auth.revoke_invitation(ADMIN_A, auth._invite_id(hash_de("vencida")))
    assert error.value.status_code == 403
    auth.revoke_invitation(ADMIN_A, auth._invite_id(hash_de("vigente")))
    assert hash_de("vigente") not in auth._read_state()["invitations"]
    with pytest.raises(HTTPException) as error:
        auth.revoke_invitation(ADMIN_A, auth._invite_id(hash_de("vigente")))
    assert error.value.status_code == 404
