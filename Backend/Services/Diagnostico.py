import re
import socket
import subprocess


PUERTOS_CONOCIDOS = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    3389: "RDP",
    8080: "HTTP alternativo",
}


def analizar_red_avanzado(ip):
    """Run bounded, read-only connectivity checks for one local device."""
    try:
        ping = subprocess.run(
            ["ping", "-n", "5", "-w", "700", ip],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=6,
        )
        ping_output = f"{ping.stdout}\n{ping.stderr}"
        replies = len(re.findall(r"\bTTL\s*=", ping_output, re.IGNORECASE))
        loss_match = re.search(r"\((\d{1,3})\s*%", ping_output)
        loss = int(loss_match.group(1)) if loss_match else round((5 - replies) * 20)
        latency_values = [int(value) for value in re.findall(r"time[=<]\s*(\d+)\s*ms", ping_output, re.IGNORECASE)]
        ping_result = {
            "enviados": 5,
            "recibidos": replies,
            "perdida_pct": max(0, min(100, loss)),
            "latencia_media_ms": round(sum(latency_values) / len(latency_values), 2) if latency_values else None,
        }
    except (subprocess.TimeoutExpired, OSError) as error:
        ping_result = {"enviados": 5, "recibidos": 0, "perdida_pct": 100, "latencia_media_ms": None, "error": str(error)}

    open_ports = []
    for port, service in PUERTOS_CONOCIDOS.items():
        try:
            with socket.create_connection((ip, port), timeout=0.3):
                open_ports.append({"puerto": port, "servicio": service})
        except (OSError, TimeoutError):
            continue

    try:
        trace = subprocess.run(
            ["tracert.exe", "-d", "-h", "12", "-w", "350", ip],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=8,
        )
        hops = [line.strip() for line in trace.stdout.splitlines() if re.match(r"\s*\d+\s+", line)]
        trace_result = {"disponible": bool(hops), "saltos": hops[:12]}
    except (subprocess.TimeoutExpired, OSError) as error:
        trace_result = {"disponible": False, "saltos": [], "error": str(error)}

    return {
        "ip": ip,
        "ping": ping_result,
        "puertos_abiertos": open_ports,
        "puertos_analizados": list(PUERTOS_CONOCIDOS),
        "trazado": trace_result,
        "nota": "El ping usa cinco paquetes. Los puertos son una muestra TCP de solo lectura; los filtros de red pueden ocultar servicios.",
    }


def analizar_dispositivo(dispositivo):
    """Genera un diagnóstico y conserva todos sus atributos de respuesta."""
    estado = dispositivo.estado
    tiempo = dispositivo.tiempo_respuesta
    tipo = dispositivo.tipo

    if estado == "inactivo":
        nivel = "critico"
        mensaje = f"El dispositivo {tipo} no está respondiendo."
        recomendacion = (
            "Verifica que el dispositivo esté encendido, conectado a la red y "
            "que la dirección IP sea correcta."
        )
        observaciones = "El dispositivo no responde a las comprobaciones realizadas."
    elif estado == "detectado":
        nivel = "informativo"
        mensaje = f"El dispositivo {tipo} fue detectado, pero no respondió al ping."
        recomendacion = (
            "Comprueba la conectividad del dispositivo. Algunos equipos "
            "bloquean las solicitudes de ping."
        )
        observaciones = (
            "La detección no confirma que el dispositivo esté disponible "
            "para todos los servicios."
        )
    elif tiempo < 50:
        nivel = "normal"
        mensaje = f"El dispositivo {tipo} presenta un tiempo de respuesta bajo."
        recomendacion = (
            "No se requiere ninguna acción por el momento. Continúa "
            "monitoreando la conexión."
        )
        observaciones = "La latencia medida es inferior a 50 ms."
    elif tiempo < 150:
        nivel = "normal"
        mensaje = f"El dispositivo {tipo} presenta un tiempo de respuesta moderado."
        recomendacion = "Compara nuevas mediciones para determinar si la latencia se mantiene estable."
        observaciones = "La latencia está entre 50 y 149,99 ms."
    elif tiempo < 300:
        nivel = "advertencia"
        mensaje = f"El dispositivo {tipo} presenta un tiempo de respuesta elevado."
        recomendacion = (
            "Revisa la calidad de la conexión, la señal Wi-Fi y la carga de la red. "
            "Realiza varias mediciones antes de concluir que existe un problema."
        )
        observaciones = "La latencia está entre 150 y 299,99 ms."
    else:
        nivel = "critico"
        mensaje = f"El dispositivo {tipo} presenta un tiempo de respuesta muy elevado."
        recomendacion = (
            "Repite la medición y revisa la conexión, la congestión de la red "
            "y la disponibilidad del dispositivo."
        )
        observaciones = (
            "La latencia es igual o superior a 300 ms. Una sola medición "
            "no confirma por sí misma la causa."
        )

    return {
        "nivel": nivel,
        "mensaje": mensaje,
        "recomendacion": recomendacion,
        "tiempo_respuesta": tiempo,
        "observaciones": observaciones,
    }
