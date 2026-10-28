"""Identificación de redes por gateway y vista por red guardada."""

import hashlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

from Backend import Authentication as auth
from Backend import GearEye
from Backend.Models.Dispositivo import Dispositivo
from Backend.Services import Historial
from Backend.Services.TenantContext import active_company_id


@pytest.fixture
def empresa(request):
    """Cada prueba usa su propia base SQLite (una empresa distinta)."""
    token = active_company_id.set(f"prueba-{request.node.name}")
    yield
    active_company_id.reset(token)


def escaneo(gateway_mac, equipos):
    return [Dispositivo(ip="192.168.1.1", mac=gateway_mac, fabricante="TP-Link", estado="activo", tiempo_respuesta=1)] + [
        Dispositivo(ip=ip, mac=mac, estado="activo", tiempo_respuesta=5) for ip, mac in equipos
    ]


def guardar(dispositivos):
    red = Historial.identificar_red("192.168.1.0/24", "192.168.1.1", dispositivos)
    Historial.registrar_eventos_escaneo(dispositivos, network_id=red["id"])
    Historial.guardar_escaneo(dispositivos, network_id=red["id"])
    return red


def test_dos_gateways_con_la_misma_subred_son_redes_distintas(empresa):
    casa = guardar(escaneo("aa-aa-aa-00-00-01", [("192.168.1.20", "aa-aa-aa-00-00-20")]))
    oficina = guardar(escaneo("bb-bb-bb-00-00-01", [("192.168.1.30", "bb-bb-bb-00-00-30"), ("192.168.1.31", "bb-bb-bb-00-00-31")]))
    assert casa["id"] != oficina["id"]
    assert casa["nombre"] == "Red TP-Link · 192.168.1.0/24"

    # Volver a casa reconoce la red ya guardada.
    assert guardar(escaneo("aa-aa-aa-00-00-01", [("192.168.1.20", "aa-aa-aa-00-00-20")]))["id"] == casa["id"]

    redes = Historial.listar_redes()
    assert redes["total"] == 2 and redes["reciente"] == casa["id"]
    por_id = {red["id"]: red for red in redes["redes"]}
    assert por_id[casa["id"]]["equipos"] == 2 and por_id[oficina["id"]]["equipos"] == 3
    assert por_id[oficina["id"]]["gateway_mac"] == "bb-bb-bb-00-00-01"

    ips_oficina = {d["ip"] for d in Historial.obtener_inventario_conocido(oficina["id"])["dispositivos"]}
    assert ips_oficina == {"192.168.1.1", "192.168.1.30", "192.168.1.31"}


def test_cambiar_de_red_no_genera_alertas_de_equipos_ausentes(empresa):
    guardar(escaneo("aa-aa-aa-00-00-01", [("192.168.1.20", "aa-aa-aa-00-00-20")]))
    guardar(escaneo("aa-aa-aa-00-00-01", [("192.168.1.20", "aa-aa-aa-00-00-20")]))
    guardar(escaneo("bb-bb-bb-00-00-01", [("192.168.1.30", "bb-bb-bb-00-00-30")]))
    tipos = {evento["tipo"] for evento in Historial.obtener_eventos()["eventos"]}
    assert "dispositivo_ausente" not in tipos
    assert "dispositivo_nuevo" not in tipos


def test_renombrar_red(empresa):
    red = guardar(escaneo("aa-aa-aa-00-00-01", []))
    assert Historial.renombrar_red(red["id"], "Oficina centro")["nombre"] == "Oficina centro"
    assert Historial.renombrar_red(red["id"], None)["nombre"] == "Red TP-Link · 192.168.1.0/24"
    assert Historial.renombrar_red(9999, "Nada") is None


def test_base_antigua_con_subred_unica_se_migra(empresa):
    company = active_company_id.get()
    path = Historial.DATA_DIR / f"history-{hashlib.sha256(company.encode()).hexdigest()[:24]}.sqlite3"
    Historial.DATA_DIR.mkdir(parents=True, exist_ok=True)
    antigua = sqlite3.connect(path)
    antigua.executescript("""
        CREATE TABLE networks (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
            cidr TEXT NOT NULL UNIQUE, gateway TEXT, created_at REAL NOT NULL, is_demo INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE devices (id INTEGER PRIMARY KEY AUTOINCREMENT, network_id INTEGER REFERENCES networks(id),
            ip TEXT NOT NULL, mac TEXT, name TEXT, manufacturer TEXT, manufacturer_network TEXT, model TEXT,
            device_type TEXT, current_state TEXT NOT NULL DEFAULT 'desconocido', first_seen REAL NOT NULL,
            last_seen REAL NOT NULL, is_demo INTEGER NOT NULL DEFAULT 0, UNIQUE(network_id, ip));
        INSERT INTO networks(name, cidr, gateway, created_at) VALUES ('Red 192.168.1.0/24', '192.168.1.0/24', '192.168.1.1', 1);
        INSERT INTO devices(network_id, ip, mac, current_state, first_seen, last_seen) VALUES (1, '192.168.1.20', 'aa-aa-aa-00-00-20', 'activo', 1, 1);
    """)
    antigua.close()

    redes = Historial.listar_redes()
    assert redes["total"] == 1 and redes["redes"][0]["equipos"] == 1
    # El primer escaneo con la MAC del gateway adopta la red antigua en lugar de duplicarla.
    red = guardar(escaneo("aa-aa-aa-00-00-01", [("192.168.1.20", "aa-aa-aa-00-00-20")]))
    assert red["id"] == 1 and red["gateway_mac"] == "aa-aa-aa-00-00-01"
    # Ya se admite una segunda red con la misma subred.
    assert guardar(escaneo("bb-bb-bb-00-00-01", []))["id"] != 1


def test_api_muestra_la_red_guardada_y_avisa_de_la_red_conectada(empresa, monkeypatch):
    casa = guardar(escaneo("aa-aa-aa-00-00-01", [("192.168.1.20", "aa-aa-aa-00-00-20")]))
    company = active_company_id.get()
    # El servidor está conectado ahora a la oficina.
    monkeypatch.setattr(GearEye, "descubrir_red_local", lambda: {
        "dispositivos": escaneo("bb-bb-bb-00-00-01", [("192.168.1.30", "bb-bb-bb-00-00-30")]),
        "puerta_enlace": "192.168.1.1", "ip_local": "192.168.1.30", "subred": "192.168.1.0/24",
    })
    monkeypatch.setattr(GearEye, "discover_lldp_topology", lambda dispositivos: {"enabled": False, "links": []})

    async def usuario():
        active_company_id.set(company)
        return {"company_id": "default", "role": "admin"}

    GearEye.app.dependency_overrides[auth.require_user] = usuario
    try:
        cliente = TestClient(GearEye.app)
        datos = cliente.get(f"/api/dispositivos?red={casa['id']}").json()
        assert datos["en_vivo"] is False
        assert datos["red"]["id"] == casa["id"]
        assert datos["red_actual"]["gateway_mac"] == "bb-bb-bb-00-00-01"
        assert {d["ip"] for d in datos["dispositivos"]} == {"192.168.1.1", "192.168.1.20"}

        en_vivo = cliente.get("/api/dispositivos").json()
        assert en_vivo["en_vivo"] is True and en_vivo["red"]["id"] == datos["red_actual"]["id"]

        redes = cliente.get("/api/redes").json()
        assert redes["total"] == 2
        assert cliente.get("/api/dispositivos?red=9999").status_code == 404
    finally:
        GearEye.app.dependency_overrides.clear()
