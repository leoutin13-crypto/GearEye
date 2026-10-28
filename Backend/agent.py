"""Lightweight GearEye network agent; run one instance inside each customer LAN."""

import json
import os
from pathlib import Path
import time
import urllib.error
import urllib.request

try:
    from dotenv import load_dotenv

    local_app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    private_env = Path(os.environ.get("GEAREYE_ENV_FILE", local_app_data / "GearEye" / ".env"))
    load_dotenv(private_env, override=False)
except ImportError:
    pass

from Backend.Services.Red import descubrir_red_local
from Backend.Services.Topologia import discover_lldp_topology


SERVER_URL = os.environ.get("GEAREYE_SERVER_URL", "").rstrip("/")
AGENT_TOKEN = os.environ.get("GEAREYE_AGENT_TOKEN", "")
INTERVAL_SECONDS = max(60, int(os.environ.get("GEAREYE_AGENT_INTERVAL", "300")))


def report_scan():
    scan = descubrir_red_local()
    payload = {
        "subred": scan["subred"],
        "puerta_enlace": scan.get("puerta_enlace"),
        "dispositivos": [device.model_dump() for device in scan["dispositivos"]],
        "topologia": discover_lldp_topology(scan["dispositivos"]),
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


def get_monitoring_config():
    request = urllib.request.Request(
        f"{SERVER_URL}/agent/config",
        headers={"X-GearEye-Agent-Token": AGENT_TOKEN, "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read().decode("utf-8"))


def main():
    if not SERVER_URL or not AGENT_TOKEN:
        raise SystemExit("Configura GEAREYE_SERVER_URL y GEAREYE_AGENT_TOKEN antes de iniciar el agente.")
    last_scan = 0.0
    initial_scan_complete = False
    while True:
        try:
            config = get_monitoring_config()
            if not initial_scan_complete:
                # The first scan registers the network so its stored settings can be read.
                report_scan()
                initial_scan_complete = True
                last_scan = time.monotonic()
                continue
            if not config.get("monitoreo_activo", False):
                print("Monitoreo pausado desde GearEye.")
                last_scan = 0.0
                time.sleep(30)
                continue

            interval = max(60, min(1800, int(config.get("intervalo_minutos", 5)) * 60))
            if not last_scan or time.monotonic() - last_scan >= interval:
                report_scan()
                last_scan = time.monotonic()
            time.sleep(min(30, max(1, interval - (time.monotonic() - last_scan))))
        except (OSError, ValueError, urllib.error.URLError) as error:
            print(f"No se pudo reportar el escaneo: {error}")
            time.sleep(min(30, INTERVAL_SECONDS))


if __name__ == "__main__":
    main()
