from typing import Optional

from pydantic import BaseModel, Field

from Backend.Models.Dispositivo import Dispositivo


class Diagnostico(BaseModel):
    nivel: str
    mensaje: str
    recomendacion: str
    tiempo_respuesta: float = Field(ge=0)
    observaciones: Optional[str] = None


class ResultadoDiagnostico(BaseModel):
    dispositivo: Dispositivo
    diagnostico: Diagnostico