from fastapi.testclient import TestClient

from Backend import Authentication as auth
from Backend.GearEye import app
from Backend.Models.Dispositivo import Dispositivo
from Backend.Services.Historial import guardar_escaneo, registrar_eventos_escaneo


def usuario_prueba():
    return {"company_id": "default", "role": "admin"}


def test_analisis_ia_usa_el_historial_guardado():
    app.dependency_overrides[auth.require_user] = usuario_prueba
    try:
        cidr = "10.20.0.0/24"
        for latencia in (5, 6, 5, 7, 6, 5):
            equipos = [
                Dispositivo(ip="10.20.0.1", mac="aa-00-00-00-00-01", estado="activo", tiempo_respuesta=1),
                Dispositivo(ip="10.20.0.10", mac="aa-00-00-00-00-10", estado="activo", tiempo_respuesta=latencia),
            ]
            registrar_eventos_escaneo(equipos, cidr)
            guardar_escaneo(equipos, cidr, "10.20.0.1")
        guardar_escaneo([
            Dispositivo(ip="10.20.0.1", mac="aa-00-00-00-00-01", estado="activo", tiempo_respuesta=1),
            Dispositivo(ip="10.20.0.10", mac="aa-00-00-00-00-10", estado="activo", tiempo_respuesta=400),
        ], cidr, "10.20.0.1")

        respuesta = TestClient(app).get("/api/analisis-ia")
        assert respuesta.status_code == 200
        datos = respuesta.json()
        assert datos["resumen"]["dispositivos_analizados"] == 2
        assert any(h["tipo"] == "latencia_anomala" and h["ip"] == "10.20.0.10" for h in datos["hallazgos"])
    finally:
        app.dependency_overrides.clear()


def test_analisis_ia_requiere_sesion():
    assert TestClient(app).get("/api/analisis-ia").status_code == 401
