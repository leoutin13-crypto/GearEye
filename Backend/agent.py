"""Lightweight GearEye network agent; run one instance inside each customer LAN."""

import json
import os
import time
import urllib.error
import urllib.request

from Backend.Services.Red import descubrir_red_local


SERVER_URL = os.environ.get("GEAREYE_SERVER_URL", "").rstrip("/")
AGENT_TOKEN = os.environ.get("GEAREYE_AGENT_TOKEN", "")
INTERVAL_SECONDS = max(60, int(os.environ.get("GEAREYE_AGENT_INTERVAL", "300")))


def report_scan():
    scan = descubrir_red_local()
    payload = {
        "subred": scan["subred"],
        "puerta_enlace": scan.get("puerta_enlace"),
        "dispositivos": [device.model_dump() for device in scan["dispositivos"]],
    }
    request = urllib.request.Request(
        f"{SERVER_URL}/agent/report",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-GearEye-Agent-Token": AGENT_TOKEN},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        result = json.loads(response.read().decode("utf-8"))
    print(f"Escaneo enviado: {result['dispositivos']} dispositivos, {result['empresa']}.")


def main():
    if not SERVER_URL or not AGENT_TOKEN:
        raise SystemExit("Configura GEAREYE_SERVER_URL y GEAREYE_AGENT_TOKEN antes de iniciar el agente.")
    while True:
        try:
            report_scan()
        except (OSError, ValueError, urllib.error.URLError) as error:
            print(f"No se pudo reportar el escaneo: {error}")
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
