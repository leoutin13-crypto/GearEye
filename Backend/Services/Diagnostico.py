def analizar_dispositivo(dispositivo):
    tiempo = dispositivo["tiempo_respuesta"]
    estado = dispositivo["estado"]

    if estado == "inactivo":
        return {
            "nivel": "critico",
            "mensaje": "El dispositivo no responde al ping."
        }

    if tiempo < 20:
        return {
            "nivel": "normal",
            "mensaje": "La respuesta del dispositivo es rápida."
        }

    if tiempo < 100:
        return {
            "nivel": "advertencia",
            "mensaje": "La respuesta del dispositivo es elevada."
        }

    return {
        "nivel": "critico",
        "mensaje": "La respuesta del dispositivo es muy elevada."
    }