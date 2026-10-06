from fastapi import FastAPI

from Backend.Services.Red import (
    comprobar_dispositivo,
    descubrir_dispositivos
)

from Backend.Services.Diagnostico import analizar_dispositivo


app = FastAPI(
    title="GearEye API",
    version="0.1"
)


@app.get("/")
def inicio():
    return {
        "proyecto": "GearEye",
        "version": "0.1",
        "mensaje": "API funcionando correctamente"
    }


@app.get("/api/dispositivos")
def obtener_dispositivos():
    dispositivos = descubrir_dispositivos()

    return {
        "total": len(dispositivos),
        "dispositivos": dispositivos
    }


@app.get("/api/comprobar/{ip}")
def comprobar_ip(ip: str):
    return comprobar_dispositivo(ip)


@app.get("/api/diagnostico/{ip}")
def diagnostico_ip(ip: str):
    dispositivo = comprobar_dispositivo(ip)
    diagnostico = analizar_dispositivo(dispositivo)

    return {
        "dispositivo": dispositivo,
        "diagnostico": diagnostico
    }