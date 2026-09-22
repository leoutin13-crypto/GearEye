from fastapi import FastAPI
from Backend.Services.Red import comprobar_dispositivo

app = FastAPI(title="GearEye API")


@app.get("/")
def inicio():
    return {
        "proyecto": "GearEye",
        "mensaje": "API funcionando correctamente"
    }


@app.get("/api/dispositivos")
def obtener_dispositivos():
    return [
        {
            "nombre": "Router",
            "ip": "192.168.1.1",
            "estado": "activo"
        },
        {
            "nombre": "PC-01",
            "ip": "192.168.1.10",
            "estado": "activo"
        }
    ]

@app.get("/api/comprobar/{ip}")
def comprobar_ip(ip: str):
    estado = comprobar_dispositivo(ip)
    return{
        "ip": ip,
        "activo": estado
    }