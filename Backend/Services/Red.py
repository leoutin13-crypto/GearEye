import subprocess
import time

from concurrent.futures import ThreadPoolExecutor


def obtener_tabla_arp():
    resultado = subprocess.run(
        ["arp", "-a"],
        capture_output=True,
        text=True
    )

    dispositivos = {}

    for linea in resultado.stdout.splitlines():
        partes = linea.split()

        if len(partes) >= 3:
            ip = partes[0]
            mac = partes[1]

            # Una entrada ARP válida tiene una MAC
            # con formato XX-XX-XX-XX-XX-XX
            if (
                len(mac) == 17
                and mac.count("-") == 5
            ):
                dispositivos[ip] = mac

    return dispositivos


def obtener_mac(ip):
    tabla_arp = obtener_tabla_arp()

    return tabla_arp.get(ip)


def obtener_nombre(ip):
    resultado = subprocess.run(
        ["nslookup", ip],
        capture_output=True,
        text=True
    )

    for linea in resultado.stdout.splitlines():
        linea = linea.strip()

        if linea.startswith("Name:"):
            return linea.split(":", 1)[1].strip()

    resultado = subprocess.run(
        ["nbtstat", "-A", ip],
        capture_output=True,
        text=True
    )

    for linea in resultado.stdout.splitlines():
        linea = linea.strip()

        if "<00>" in linea and "UNIQUE" in linea:
            partes = linea.split()

            if len(partes) >= 1:
                return partes[0]

    return None


def obtener_fabricante(mac):
    if mac is None:
        return None

    prefijo = mac.upper().replace("-", ":")[:8]

    fabricantes = {
        "A8:A0:92": "Apple",
    }

    return fabricantes.get(prefijo, "Desconocido")


def comprobar_dispositivo(ip):
    inicio = time.perf_counter()

    resultado = subprocess.run(
        ["ping", "-n", "1", "-w", "1000", ip],
        capture_output=True,
        text=True
    )

    tiempo_respuesta = round(
        (time.perf_counter() - inicio) * 1000,
        2
    )

    mac = obtener_mac(ip)

    if resultado.returncode == 0:
        nombre = obtener_nombre(ip)
        fabricante = obtener_fabricante(mac)

        return {
            "ip": ip,
            "mac": mac,
            "nombre": nombre,
            "fabricante": fabricante,
            "estado": "activo",
            "tiempo_respuesta": tiempo_respuesta
        }

    if mac is not None:
        nombre = obtener_nombre(ip)
        fabricante = obtener_fabricante(mac)

        return {
            "ip": ip,
            "mac": mac,
            "nombre": nombre,
            "fabricante": fabricante,
            "estado": "detectado",
            "tiempo_respuesta": tiempo_respuesta
        }

    return {
        "ip": ip,
        "mac": None,
        "nombre": None,
        "fabricante": None,
        "estado": "inactivo",
        "tiempo_respuesta": tiempo_respuesta
    }


def descubrir_dispositivos():
    ips = [
        f"192.168.1.{i}"
        for i in range(1, 255)
    ]

    dispositivos = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        resultados = executor.map(
            comprobar_dispositivo,
            ips
        )

        for resultado in resultados:
            if resultado["estado"] in ["activo", "detectado"]:
                dispositivos.append(resultado)

        return dispositivos