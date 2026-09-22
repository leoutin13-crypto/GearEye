from fastapi import FastAPI

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