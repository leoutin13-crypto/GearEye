"""Aísla las pruebas: SQLite temporal y sin leer el .env privado del usuario."""

import os
import sys
import tempfile
from pathlib import Path

_DATA_DIR = tempfile.mkdtemp(prefix="geareye-tests-")
os.environ["GEAREYE_DATA_DIR"] = _DATA_DIR
os.environ["GEAREYE_ENV_FILE"] = str(Path(_DATA_DIR) / "no-existe.env")
os.environ["GEAREYE_DATABASE_URL"] = ""
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
