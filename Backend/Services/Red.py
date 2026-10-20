import ipaddress
import logging

import json

import re

import socket

import subprocess

import time

from concurrent.futures import ThreadPoolExecutor, as_completed

from mac_vendor_lookup import MacLookup

from Backend.Models.Dispositivo import Dispositivo

logger = logging.getLogger(__name__)

def obtener_configuracion_red_local():
    comando = (
        "$ErrorActionPreference = 'Stop'; "
        "$c = Get-NetIPConfiguration | Where-Object { "
        "$_.NetAdapter.Status -eq 'Up' -and "
        "$_.IPv4Address -and $_.IPv4DefaultGateway "
        "} | Select-Object -First 1; "
        "if (-not $c) { exit 2 }; "
        "$a = $c.IPv4Address | Select-Object -First 1; "
        "[pscustomobject]@{ "
        "IPAddress = $a.IPAddress; "
        "PrefixLength = $a.PrefixLength; "
        "Gateway = $c.IPv4DefaultGateway[0].NextHop; "
        "MacAddress = $c.NetAdapter.MacAddress "
        "} | ConvertTo-Json -Compress"
    )

    try:
        resultado = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                comando
            ],
            capture_output=True,
            text=True,
            timeout=8
        )

        if resultado.returncode != 0 or not resultado.stdout.strip():
            if resultado.stderr.strip():
                print(f"Error obteniendo configuración de red: {resultado.stderr.strip()}")
            return None

        datos = json.loads(resultado.stdout.strip())
        ip_local = datos.get("IPAddress")
        prefijo = datos.get("PrefixLength")
        mac = datos.get("MacAddress")
        puerta_enlace = datos.get("Gateway")

        if not ip_local or prefijo is None:
            print(f"Configuración de red incompleta: {datos}")
            return None

        ipaddress.IPv4Address(ip_local)
        red = ipaddress.ip_network(
            f"{ip_local}/{int(prefijo)}",
            strict=False
        )

        if mac:
            mac = mac.strip().lower().replace(":", "-")

        return {
            "ip": ip_local,
            "mac": mac or None,
            "red": red,
            "puerta_enlace": puerta_enlace
        }

    except (
        subprocess.TimeoutExpired,
        OSError,
        ValueError,
        TypeError,
        AttributeError,
        json.JSONDecodeError
    ) as error:
        print(f"No se pudo obtener la configuración de red: {error}")
        return None

def obtener_tabla_arp():

    try:

        resultado = subprocess.run(

            ["arp", "-a"],

            capture_output=True,

            text=True,

            timeout=5

        )

    except (subprocess.TimeoutExpired, OSError):

        return {}

    dispositivos = {}

    for linea in resultado.stdout.splitlines():

        partes = linea.split()

        if len(partes) >= 3:

            ip = partes[0]

            mac = partes[1]

            try:

                ipaddress.IPv4Address(ip)

            except ValueError:

                continue

            if re.fullmatch(r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", mac):

                dispositivos[ip] = mac.lower()

    return dispositivos

def obtener_mac_local():

    configuracion = obtener_configuracion_red_local()

    return configuracion["mac"] if configuracion else None

def obtener_ip_local():

    configuracion = obtener_configuracion_red_local()

    return configuracion["ip"] if configuracion else None

def obtener_datos_equipo_local():

    try:

        resultado = subprocess.run(

            [

                "powershell.exe",

                "-NoProfile",

                "-NonInteractive",

                "-Command",

                "Get-CimInstance Win32_ComputerSystem | "

                "Select-Object Manufacturer, Model | "

                "ConvertTo-Json -Compress"

            ],

            capture_output=True,

            text=True,

            timeout=5

        )

        if resultado.returncode != 0 or not resultado.stdout.strip():

            return None, None

        datos = json.loads(resultado.stdout.strip())

        fabricante = datos.get("Manufacturer")

        modelo = datos.get("Model")

        if fabricante:

            fabricante = fabricante.strip()

        if modelo:

            modelo = modelo.strip()

        return fabricante or None, modelo or None

    except (

        subprocess.TimeoutExpired,

        OSError,

        ValueError,

        TypeError,

        AttributeError,

        json.JSONDecodeError

    ):

        return None, None

def obtener_mac(ip, tabla_arp=None):

    if tabla_arp is None:

        tabla_arp = obtener_tabla_arp()

    return tabla_arp.get(ip)

def obtener_nombre(ip):
    try:
        nombre, _, _ = socket.gethostbyaddr(ip)
        if nombre and nombre.lower() != ip.lower():
            return nombre.rstrip(".")
    except (OSError, socket.herror, socket.gaierror):
        pass


    try:

        resultado = subprocess.run(

            ["nslookup", ip],

            capture_output=True,

            text=True,

            timeout=2

        )

        for linea in resultado.stdout.splitlines():

            linea = linea.strip()

            if linea.startswith(("Name:", "Nombre:")):

                nombre = linea.split(":", 1)[1].strip()

                if nombre and nombre.lower() != ip.lower():

                    return nombre.rstrip(".")

    except (subprocess.TimeoutExpired, OSError):

        pass

    try:

        resultado = subprocess.run(

            ["ping", "-a", "-n", "1", "-w", "500", ip],

            capture_output=True,

            text=True,

            timeout=2

        )

        for linea in resultado.stdout.splitlines():

            coincidencia = re.search(

                r"(?:a|to)\s+(.+?)\s+\[" + re.escape(ip) + r"\]",

                linea,

                re.IGNORECASE

            )

            if coincidencia:

                nombre = coincidencia.group(1).strip()

                if nombre and nombre.lower() != ip.lower():

                    return nombre

    except (subprocess.TimeoutExpired, OSError):

        pass

    try:

        resultado = subprocess.run(

            ["nbtstat", "-A", ip],

            capture_output=True,

            text=True,

            timeout=2

        )

        for linea in resultado.stdout.splitlines():

            linea = linea.strip()

            if "<00>" in linea and "UNIQUE" in linea.upper():

                partes = linea.split()

                if partes:

                    nombre = partes[0].strip()

                    if nombre:

                        return nombre

    except (subprocess.TimeoutExpired, OSError):

        pass

    return None

def obtener_fabricante(mac):
    if not mac:
        return None

    octetos = re.split(r"[:-]", mac.strip())
    if len(octetos) == 6:
        try:
            primer_octeto = int(octetos[0], 16)
        except ValueError:
            primer_octeto = None
        if primer_octeto is not None and primer_octeto & 0x02:
            return "MAC privada"

    try:
        return MacLookup().lookup(mac)
    except Exception as error:
        # Unknown OUIs are expected, especially with randomized private MACs.
        if type(error).__name__ != "VendorNotFoundError":
            logger.debug("No se pudo consultar fabricante para %s", mac, exc_info=True)
        return "Desconocido"

def obtener_tipo(ip, nombre, fabricante_red):

    if nombre:

        nombre_mayusculas = nombre.upper()

        if any(

            palabra in nombre_mayusculas

            for palabra in [

                "COL-CO", "DESKTOP", "LAPTOP", "THINKPAD", "LATITUDE",

                "ELITEBOOK", "MACBOOK", "MAC-", "IMAC", "COMPUTER",

                "WORKSTATION", "NOTEBOOK", "PC-"

            ]

        ):

            return "computador"

        if any(

            palabra in nombre_mayusculas

            for palabra in [

                "NPI", "PRINTER", "PRINT", "LASERJET", "OFFICEJET",

                "DESKJET", "PIXMA", "ECOTANK", "WORKFORCE"

            ]

        ):

            return "impresora"

    if fabricante_red:

        fabricante_mayusculas = fabricante_red.upper()

        if any(

            palabra in fabricante_mayusculas

            for palabra in ["HEWLETT PACKARD", "HP INC", "CANON", "EPSON", "BROTHER"]

        ):

            return "impresora"

        if any(

            palabra in fabricante_mayusculas

            for palabra in ["CISCO", "CISCO MERAKI", "JUNIPER", "UBIQUITI", "MIKROTIK"]

        ):

            return "dispositivo_red"

    return "desconocido"

def comprobar_dispositivo(

    ip,

    mac=None,

    tabla_arp=None,

    mac_local=None,

    ip_local=None,

    datos_equipo_local=None

):

    if ip_local is None or mac_local is None:

        configuracion = obtener_configuracion_red_local()

        if configuracion:

            if ip_local is None:

                ip_local = configuracion["ip"]

            if mac_local is None:

                mac_local = configuracion["mac"]

    inicio = time.perf_counter()

    try:

        resultado = subprocess.run(

            ["ping", "-n", "1", "-w", "500", ip],

            capture_output=True,

            text=True,

            timeout=2

        )

        ping_exitoso = resultado.returncode == 0

    except (subprocess.TimeoutExpired, OSError):

        ping_exitoso = False

    tiempo_respuesta = round((time.perf_counter() - inicio) * 1000, 2)

    if tabla_arp is None:

        tabla_arp = obtener_tabla_arp()

    if ip == ip_local and mac_local:

        mac = mac_local

    elif mac is None:

        mac = obtener_mac(ip, tabla_arp)

    nombre = obtener_nombre(ip)

    fabricante_red = obtener_fabricante(mac)

    tipo = obtener_tipo(ip, nombre, fabricante_red)

    fabricante = (
        fabricante_red
        if fabricante_red and fabricante_red not in {"Desconocido", "MAC privada"}
        else None
    )

    modelo = None

    if ip == ip_local:

        tipo = "computador"

        if datos_equipo_local is None:

            fabricante, modelo = obtener_datos_equipo_local()

        else:

            fabricante, modelo = datos_equipo_local

    if ping_exitoso:

        estado = "activo"

    elif mac is not None:

        estado = "detectado"

    else:

        return Dispositivo(

            ip=ip,

            mac=None,

            nombre=None,

            fabricante=None,

            fabricante_red=None,

            modelo=None,

            tipo="desconocido",

            estado="inactivo",

            tiempo_respuesta=tiempo_respuesta

        )

    return Dispositivo(

        ip=ip,

        mac=mac,

        nombre=nombre,

        fabricante=fabricante,

        fabricante_red=fabricante_red,

        modelo=modelo,

        tipo=tipo,

        estado=estado,

        tiempo_respuesta=tiempo_respuesta

    )

def descubrir_red_local():

    configuracion = obtener_configuracion_red_local()

    if configuracion is None:

        raise RuntimeError(

            "No se pudo obtener la configuración IPv4 de la red local. "

            "Comprueba que haya un adaptador activo con puerta de enlace y revisa los mensajes de PowerShell en la terminal."

        )

    ip_local = configuracion["ip"]

    mac_local = configuracion["mac"]

    red = configuracion["red"]

    puerta_enlace = configuracion["puerta_enlace"]

    red_escaneo = red

    if red.num_addresses > 256:

        red_escaneo = ipaddress.ip_network(f"{ip_local}/24", strict=False)

        if not red_escaneo.subnet_of(red):

            raise RuntimeError(

                f"No se pudo seleccionar un rango de escaneo seguro dentro de {red}."

            )

    ips = [str(ip) for ip in red_escaneo.hosts()]

    if ip_local not in ips:

        ips.append(ip_local)

    if puerta_enlace and puerta_enlace not in ips:

        ips.append(puerta_enlace)

    tabla_arp = obtener_tabla_arp()

    datos_equipo_local = obtener_datos_equipo_local()

    dispositivos = []

    with ThreadPoolExecutor(max_workers=50) as executor:

        futuros = [

            executor.submit(

                comprobar_dispositivo,

                ip,

                None,

                tabla_arp,

                mac_local,

                ip_local,

                datos_equipo_local

            )

            for ip in ips

        ]

        for futuro in as_completed(futuros):

            try:

                dispositivo = futuro.result()

                if dispositivo.estado in ["activo", "detectado"]:

                    if dispositivo.ip == puerta_enlace:

                        dispositivo.tipo = "router"

                    dispositivos.append(dispositivo)

            except Exception as error:

                print(f"Error comprobando dispositivo: {error}")

    tabla_arp = obtener_tabla_arp()

    for dispositivo in dispositivos:

        if dispositivo.mac is None:

            mac = obtener_mac(dispositivo.ip, tabla_arp)

            if mac is not None:

                dispositivo.mac = mac

                dispositivo.fabricante_red = obtener_fabricante(mac)

                if dispositivo.fabricante_red not in {"Desconocido", "MAC privada"}:
                    dispositivo.fabricante = dispositivo.fabricante_red

                if dispositivo.ip != ip_local:

                    dispositivo.tipo = obtener_tipo(

                        dispositivo.ip,

                        dispositivo.nombre,

                        dispositivo.fabricante_red

                    )

    dispositivos.sort(

        key=lambda dispositivo: tuple(int(parte) for parte in dispositivo.ip.split("."))

    )

    return {
        "dispositivos": dispositivos,
        "puerta_enlace": puerta_enlace,
        "ip_local": ip_local,
        "subred": str(red_escaneo),
    }


def descubrir_dispositivos():
    """Return just the device list for callers that do not need network metadata."""
    return descubrir_red_local()["dispositivos"]
