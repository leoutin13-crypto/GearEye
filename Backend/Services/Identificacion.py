"""Clasificación de equipos combinando nombre, fabricante, TTL y servicios abiertos.

Cada pista por separado es débil (muchos equipos no publican nombre y los
celulares usan MAC privada), así que se aplican en orden de fiabilidad:
nombre del equipo → servicios característicos → fabricante → TTL.
"""

import re
import select
import socket
import time

# Puertos TCP que identifican la familia del equipo. Solo se intenta abrir la
# conexión; no se envían datos.
PUERTOS_IDENTIFICACION = (
    22, 53, 80, 135, 139, 443, 445, 515, 548, 554, 631, 1883, 3389,
    5000, 5357, 6668, 8001, 8008, 8009, 8080, 8554, 9100, 37777, 62078,
)

SERVICIOS = {
    22: "SSH", 53: "DNS", 80: "HTTP", 135: "RPC de Windows", 139: "NetBIOS", 443: "HTTPS",
    445: "Archivos compartidos (SMB)", 515: "Impresión LPD", 548: "Archivos de Apple (AFP)",
    554: "Video RTSP", 631: "Impresión IPP", 1883: "MQTT (IoT)", 3389: "Escritorio remoto",
    5000: "Panel web (NAS)", 5357: "Descubrimiento de Windows", 6668: "Tuya (IoT)",
    8001: "Control de Smart TV", 8008: "Google Cast", 8009: "Google Cast", 8080: "HTTP alternativo", 8554: "Video RTSP",
    9100: "Impresión directa", 37777: "Video Dahua", 62078: "Sincronización de iPhone/iPad",
}

PALABRAS_NOMBRE = (
    ("impresora", ("NPI", "PRINTER", "PRINT", "LASERJET", "OFFICEJET", "DESKJET", "PIXMA", "ECOTANK",
                   "WORKFORCE", "BRN", "EPSON", "CANON", "KYOCERA", "RICOH", "LEXMARK")),
    ("camara", ("CAM", "IPC", "DVR", "NVR", "HIKVISION", "DAHUA", "EZVIZ", "IMOU")),
    ("tv", ("TV", "BRAVIA", "ROKU", "CHROMECAST", "FIRETV", "FIRE-TV", "AFT", "MESON", "TIZEN", "WEBOS",
            "APPLETV", "APPLE-TV", "SHIELD", "TVBOX")),
    ("movil", ("IPHONE", "IPAD", "ANDROID", "GALAXY", "SM-", "REDMI", "XIAOMI", "POCO", "PIXEL",
               "MOTO", "ONEPLUS", "OPPO", "VIVO", "HONOR", "TABLET")),
    ("servidor", ("NAS", "DISKSTATION", "SYNOLOGY", "QNAP", "SERVER", "SRV", "PROXMOX", "PVE", "ESXI")),
    ("dispositivo_red", ("SWITCH", "ROUTER", "GATEWAY", "UNIFI", "MIKROTIK", "DECO", "ACCESS-POINT", "AP-")),
    ("iot", ("ESP_", "ESP-", "ESP32", "TUYA", "SHELLY", "SONOFF", "TASMOTA", "ECHO", "ALEXA", "NEST",
             "GOOGLE-HOME", "SMART")),
    ("computador", ("COL-CO", "DESKTOP", "LAPTOP", "THINKPAD", "LATITUDE", "ELITEBOOK", "MACBOOK", "MAC-",
                    "IMAC", "COMPUTER", "WORKSTATION", "NOTEBOOK", "PC-", "PC", "OPTIPLEX", "VOSTRO")),
)

FABRICANTES = (
    ("impresora", ("CANON", "EPSON", "BROTHER", "LEXMARK", "KYOCERA", "RICOH", "XEROX", "SEIKO EPSON",
                   "KONICA", "SHARP", "ZEBRA")),
    ("camara", ("HIKVISION", "DAHUA", "AXIS", "EZVIZ", "UNIVIEW", "HANWHA", "REOLINK", "IMOU")),
    ("servidor", ("SYNOLOGY", "QNAP", "WESTERN DIGITAL", "SUPERMICRO", "VMWARE", "PROXMOX")),
    ("dispositivo_red", ("CISCO", "JUNIPER", "UBIQUITI", "MIKROTIK", "ROUTERBOARD", "ARUBA", "NETGEAR",
                         "D-LINK", "TP-LINK", "TPLINK", "VANTIVA", "TECHNICOLOR", "ARRIS", "SAGEMCOM",
                         "ZTE", "FORTINET", "RUCKUS", "CAMBIUM", "TENDA", "ZYXEL", "HUAWEI TECHNOLOGIES")),
    ("iot", ("ESPRESSIF", "TUYA", "SHELLY", "ALLTERCO", "SONOFF", "ITEAD", "AMAZON", "GOOGLE", "NEST",
             "SONOS", "PHILIPS LIGHTING", "SIGNIFY")),
    ("tv", ("ROKU", "LG ELECTRONICS", "TCL", "HISENSE", "VIZIO", "AMLOGIC")),
    ("movil", ("XIAOMI", "OPPO", "VIVO", "ONEPLUS", "MOTOROLA", "REALME", "HONOR", "TECNO", "INFINIX")),
    ("computador", ("LENOVO", "DELL", "HEWLETT", "HP INC", "ASUSTEK", "ACER", "MICRO-STAR", "MSI",
                    "INTEL", "REALTEK", "LITE-ON", "AZUREWAVE", "LIQUID", "MICROSOFT", "GIGA-BYTE")),
    ("computador", ("RASPBERRY",)),
)


def ttl_desde_ping(salida):
    """Return the TTL reported by a Windows or Unix ping, if any."""
    coincidencia = re.search(r"\bTTL\s*[=:]\s*(\d{1,3})", salida or "", re.IGNORECASE)
    return int(coincidencia.group(1)) if coincidencia else None


def sistema_por_ttl(ttl):
    # Los sistemas parten de 64, 128 o 255 y cada salto resta 1; en una LAN casi no hay saltos.
    if ttl is None:
        return None
    if ttl <= 64:
        return "Linux, Android, iOS o macOS"
    if ttl <= 128:
        return "Windows"
    return "Sistema de equipo de red"


def es_mac_privada(mac):
    octetos = re.split(r"[:-]", str(mac or "").strip())
    if len(octetos) != 6:
        return False
    try:
        return bool(int(octetos[0], 16) & 0x02)
    except ValueError:
        return False


def puertos_abiertos(ip, puertos=PUERTOS_IDENTIFICACION, timeout=0.45):
    """Try every port at once with non-blocking connects; return the ones that accepted."""
    pendientes = {}
    abiertos = []
    for puerto in puertos:
        conexion = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conexion.setblocking(False)
        try:
            resultado = conexion.connect_ex((ip, puerto))
        except OSError:
            conexion.close()
            continue
        if resultado == 0:
            abiertos.append(puerto)
            conexion.close()
        else:
            pendientes[conexion] = puerto
    limite = time.monotonic() + timeout
    try:
        while pendientes:
            restante = limite - time.monotonic()
            if restante <= 0:
                break
            _, escribibles, fallidos = select.select([], list(pendientes), list(pendientes), restante)
            if not escribibles and not fallidos:
                break
            for conexion in set(escribibles) | set(fallidos):
                puerto = pendientes.pop(conexion)
                if conexion in escribibles and conexion not in fallidos and \
                        conexion.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                    abiertos.append(puerto)
                conexion.close()
    finally:
        for conexion in pendientes:
            conexion.close()
    return sorted(abiertos)


def _coincide_nombre(nombre, palabras):
    texto = nombre.upper()
    tokens = set(re.split(r"[^A-Z0-9]+", texto))
    for palabra in palabras:
        # Las palabras cortas solo cuentan como token completo ("TV", "PC", "CAM").
        if len(palabra) <= 3 and palabra.isalnum():
            if palabra in tokens or any(token.startswith(palabra) and token[len(palabra):].isdigit() for token in tokens):
                return True
        elif palabra in texto:
            return True
    return False


def _tipo_por_puertos(puertos):
    abiertos = set(puertos or ())
    if abiertos & {9100, 631, 515}:
        return "impresora"
    if abiertos & {554, 8554, 37777}:
        return "camara"
    if 62078 in abiertos:
        return "movil"
    if abiertos & {8008, 8009}:
        return "tv"
    if 3389 in abiertos or {135, 445} <= abiertos or 5357 in abiertos:
        return "computador"
    if abiertos & {1883, 6668}:
        return "iot"
    return None


def clasificar(nombre=None, fabricante_red=None, mac=None, ttl=None, puertos=None):
    """Return (tipo, sistema) with the most reliable available evidence."""
    sistema = "iOS o macOS" if (fabricante_red or "").upper().startswith("APPLE") else sistema_por_ttl(ttl)
    if nombre:
        for tipo, palabras in PALABRAS_NOMBRE:
            if _coincide_nombre(nombre, palabras):
                return tipo, sistema

    tipo = _tipo_por_puertos(puertos)
    if tipo:
        return tipo, sistema

    fabricante = (fabricante_red or "").upper()
    if fabricante.startswith("APPLE"):
        abiertos = set(puertos or ())
        return ("computador" if abiertos & {22, 445, 548, 5000} else "movil"), "iOS o macOS"
    if fabricante.startswith("SAMSUNG"):
        return ("tv" if set(puertos or ()) & {8001, 8008} else "movil"), sistema
    for tipo, marcas in FABRICANTES:
        if any(marca in fabricante for marca in marcas):
            return tipo, sistema

    # Sin nombre ni fabricante útil, el TTL y la MAC privada aún orientan.
    if ttl is not None:
        if ttl > 128:
            return "dispositivo_red", sistema
        if ttl > 64:
            return "computador", sistema
        if es_mac_privada(mac):
            return "movil", sistema
        if 22 in set(puertos or ()):
            return "servidor", sistema
    return "desconocido", sistema
