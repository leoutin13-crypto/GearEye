
from ipaddress import IPv4Address
from typing import Optional

from pydantic import BaseModel, Field, field_validator

class Dispositivo(BaseModel):
    ip: str
    mac: Optional[str] = None
    nombre: Optional[str] = None
    fabricante: Optional[str] = None
    fabricante_red: Optional[str] = None
    modelo: Optional[str] = None
    tipo: str = "desconocido"
    estado: str
    tiempo_respuesta: Optional[float] = Field(default=None, ge=0)
    confianza: str = "por_revisar"
    responsable: Optional[str] = None
    notas: Optional[str] = None

    @field_validator("ip")
    @classmethod
    def validar_ip(cls, valor):
        try:
            IPv4Address(valor)
        except ValueError:
            raise ValueError("La IP no es válida")

        return valor

    @field_validator("estado")
    @classmethod
    def validar_estado(cls, valor):
        estados_validos = {
            "activo",
            "detectado",
            "inactivo"
        }

        if valor not in estados_validos:
            raise ValueError(
                "El estado debe ser: activo, detectado o inactivo"
            )

        return valor

class ListaDispositivos(BaseModel):
    total: int
    dispositivos: list[Dispositivo]
    puerta_enlace: Optional[str] = None
    ip_local: Optional[str] = None
    subred: Optional[str] = None
