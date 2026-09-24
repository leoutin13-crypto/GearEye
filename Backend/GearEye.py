from fastapi import FastAPI
from Backend.Services.Red import comprobar_dispositivo, descubrir_dispositivos

app = FastAPI(title="GearEye API")


@app.get("/")
def inicio():
    return {
        "proyecto": "GearEye",
        "mensaje": "API funcionando correctamente"
    }


@app.get("/api/dispositivos")
def obtener_dispositivos():
    dispositivos = descubrir_dispositivos()
    return dispositivos


@app.get("/api/comprobar/{ip}")
def comprobar_ip(ip: str):
    estado = comprobar_dispositivo(ip)

    return {
        "ip": ip,
        "activo": estado
    }