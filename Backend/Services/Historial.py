"""SQLite persistence for measured device response times."""

import os
import hashlib
import json
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from Backend.Services.Database import DATABASE_URL, connect_postgresql
from Backend.Services.TenantContext import active_company_id


DATA_DIR = Path(
    os.environ.get(
        "GEAREYE_DATA_DIR",
        Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share")) / "GearEye",
    )
)
DATABASE = DATA_DIR / "history.sqlite3"
RETENTION_DAYS = 180
_POSTGRES_SCHEMA_LOCK = threading.Lock()
_POSTGRES_SCHEMAS_READY = set()


def _connect():
    if DATABASE_URL:
        connection = connect_postgresql()
        try:
            company_id = active_company_id.get() or "default"
            schema = "public" if company_id == "default" else "geareye_" + hashlib.sha256(company_id.encode()).hexdigest()[:24]
            if schema != "public":
                connection.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
            connection.execute(f'SET search_path TO "{schema}"')
            if schema not in _POSTGRES_SCHEMAS_READY:
                with _POSTGRES_SCHEMA_LOCK:
                    if schema not in _POSTGRES_SCHEMAS_READY:
                        _ensure_postgresql_schema(connection)
                        connection.commit()
                        _POSTGRES_SCHEMAS_READY.add(schema)
            return connection
        except Exception:
            connection.close()
            raise
    return _connect_sqlite()


def _ensure_postgresql_schema(connection):
    connection.execute(
        """CREATE TABLE IF NOT EXISTS network_topology (
            cidr TEXT PRIMARY KEY,
            captured_at DOUBLE PRECISION NOT NULL,
            data_json TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS networks (
            id BIGSERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            cidr TEXT NOT NULL,
            gateway TEXT,
            gateway_mac TEXT,
            gateway_vendor TEXT,
            alias TEXT,
            network_key TEXT,
            created_at DOUBLE PRECISION NOT NULL,
            last_seen_at DOUBLE PRECISION,
            is_demo BOOLEAN NOT NULL DEFAULT FALSE,
            monitor_enabled BOOLEAN NOT NULL DEFAULT FALSE,
            monitor_interval_minutes INTEGER NOT NULL DEFAULT 5,
            alert_latency_threshold_ms DOUBLE PRECISION NOT NULL DEFAULT 300,
            alert_new_devices BOOLEAN NOT NULL DEFAULT TRUE,
            alert_offline_devices BOOLEAN NOT NULL DEFAULT TRUE
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS devices (
            id BIGSERIAL PRIMARY KEY,
            network_id BIGINT REFERENCES networks(id),
            ip TEXT NOT NULL,
            mac TEXT,
            name TEXT,
            manufacturer TEXT,
            manufacturer_network TEXT,
            model TEXT,
            device_type TEXT,
            current_state TEXT NOT NULL DEFAULT 'desconocido',
            first_seen DOUBLE PRECISION NOT NULL,
            last_seen DOUBLE PRECISION NOT NULL,
            owner TEXT,
            notes TEXT,
            is_demo BOOLEAN NOT NULL DEFAULT FALSE,
            UNIQUE(network_id, ip)
        )"""
    )
    for name, data_type in (
        ("monitor_enabled", "BOOLEAN NOT NULL DEFAULT FALSE"),
        ("monitor_interval_minutes", "INTEGER NOT NULL DEFAULT 5"),
        ("alert_latency_threshold_ms", "DOUBLE PRECISION NOT NULL DEFAULT 300"),
        ("alert_new_devices", "BOOLEAN NOT NULL DEFAULT TRUE"),
        ("alert_offline_devices", "BOOLEAN NOT NULL DEFAULT TRUE"),
        ("gateway_mac", "TEXT"),
        ("gateway_vendor", "TEXT"),
        ("alias", "TEXT"),
        ("network_key", "TEXT"),
        ("last_seen_at", "DOUBLE PRECISION"),
    ):
        connection.execute(f"ALTER TABLE networks ADD COLUMN IF NOT EXISTS {name} {data_type}")
    # Una red se identifica por subred + MAC del gateway (network_key), no solo por subred.
    connection.execute("ALTER TABLE networks DROP CONSTRAINT IF EXISTS networks_cidr_key")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS scan_runs (
            scan_id TEXT PRIMARY KEY,
            captured_at DOUBLE PRECISION NOT NULL,
            network_id BIGINT REFERENCES networks(id),
            is_demo BOOLEAN NOT NULL DEFAULT FALSE,
            is_complete BOOLEAN NOT NULL DEFAULT TRUE
        )"""
    )
    connection.execute("ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS network_id BIGINT REFERENCES networks(id)")
    connection.execute("ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS is_demo BOOLEAN NOT NULL DEFAULT FALSE")
    connection.execute("ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS is_complete BOOLEAN NOT NULL DEFAULT TRUE")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS measurements (
            id BIGSERIAL PRIMARY KEY,
            scan_id TEXT NOT NULL REFERENCES scan_runs(scan_id),
            captured_at DOUBLE PRECISION NOT NULL,
            ip TEXT NOT NULL,
            latency_ms DOUBLE PRECISION,
            state TEXT NOT NULL,
            name TEXT,
            manufacturer TEXT,
            manufacturer_network TEXT,
            model TEXT,
            device_type TEXT,
            mac TEXT,
            device_id BIGINT REFERENCES devices(id),
            is_demo BOOLEAN NOT NULL DEFAULT FALSE
        )"""
    )
    connection.execute(
        """INSERT INTO scan_runs(scan_id, captured_at, is_complete)
           SELECT scan_id, MIN(captured_at),
                  (COUNT(*) > 1 OR MAX(state) <> 'inactivo')
           FROM measurements
           GROUP BY scan_id
           ON CONFLICT (scan_id) DO NOTHING"""
    )
    connection.execute(
        """DO $$ BEGIN
             IF NOT EXISTS (SELECT 1 FROM pg_constraint
                            WHERE conname = 'fk_measurements_scan_runs'
                              AND connamespace = current_schema()::regnamespace) THEN
               ALTER TABLE measurements ADD CONSTRAINT fk_measurements_scan_runs
               FOREIGN KEY (scan_id) REFERENCES scan_runs(scan_id);
             END IF;
           END $$"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS events (
            id BIGSERIAL PRIMARY KEY,
            occurred_at DOUBLE PRECISION NOT NULL,
            ip TEXT NOT NULL,
            device_name TEXT,
            event_type TEXT NOT NULL,
            previous_state TEXT,
            current_state TEXT NOT NULL,
            description TEXT NOT NULL,
            acknowledged_at DOUBLE PRECISION,
            device_id BIGINT REFERENCES devices(id),
            is_demo BOOLEAN NOT NULL DEFAULT FALSE
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS trusted_devices (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            device_name TEXT,
            trusted_at DOUBLE PRECISION NOT NULL,
            device_id BIGINT REFERENCES devices(id),
            is_demo BOOLEAN NOT NULL DEFAULT FALSE
        )"""
    )
    connection.execute(
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS acknowledged_at DOUBLE PRECISION"
    )
    connection.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS device_id BIGINT REFERENCES devices(id)")
    connection.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS is_demo BOOLEAN NOT NULL DEFAULT FALSE")
    connection.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS network_id BIGINT REFERENCES networks(id)")
    for statement in _BACKFILL_NETWORKS:
        connection.execute(statement)
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_networks_key ON networks(network_key)")
    connection.execute("ALTER TABLE measurements ADD COLUMN IF NOT EXISTS device_id BIGINT REFERENCES devices(id)")
    connection.execute("ALTER TABLE measurements ADD COLUMN IF NOT EXISTS is_demo BOOLEAN NOT NULL DEFAULT FALSE")
    connection.execute("ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS network_id BIGINT REFERENCES networks(id)")
    connection.execute("ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS is_demo BOOLEAN NOT NULL DEFAULT FALSE")
    connection.execute("ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS is_complete BOOLEAN NOT NULL DEFAULT TRUE")
    connection.execute("ALTER TABLE trusted_devices ADD COLUMN IF NOT EXISTS device_id BIGINT REFERENCES devices(id)")
    connection.execute("ALTER TABLE trusted_devices ADD COLUMN IF NOT EXISTS is_demo BOOLEAN NOT NULL DEFAULT FALSE")
    connection.execute("ALTER TABLE devices ADD COLUMN IF NOT EXISTS owner TEXT")
    connection.execute("ALTER TABLE devices ADD COLUMN IF NOT EXISTS notes TEXT")
    connection.execute("ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_guess TEXT")
    connection.execute("ALTER TABLE devices ADD COLUMN IF NOT EXISTS open_ports TEXT")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS diagnostics (
            id BIGSERIAL PRIMARY KEY,
            device_id BIGINT REFERENCES devices(id),
            ip TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            latency_ms DOUBLE PRECISION NOT NULL,
            observations TEXT,
            created_at DOUBLE PRECISION NOT NULL,
            is_demo BOOLEAN NOT NULL DEFAULT FALSE
        )"""
    )
    for name in ("name", "manufacturer", "manufacturer_network", "model", "device_type", "mac"):
        column_type = "TEXT"
        connection.execute(
            f"ALTER TABLE measurements ADD COLUMN IF NOT EXISTS {name} {column_type}"
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_measurements_ip_time ON measurements(ip, captured_at DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_time ON events(occurred_at DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_measurements_device_time ON measurements(device_id, captured_at DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_devices_network_ip ON devices(network_id, ip)"
    )
    connection.execute(
        """CREATE MATERIALIZED VIEW IF NOT EXISTS mv_device_performance AS
           SELECT m.ip, COALESCE(d.name, MAX(m.name)) AS device_name,
                  COALESCE(d.is_demo, m.is_demo) AS is_demo,
                  COUNT(*) AS measurement_count,
                  COUNT(*) FILTER (WHERE m.state = 'activo') AS active_count,
                  AVG(m.latency_ms) AS average_latency_ms,
                  MIN(m.latency_ms) AS minimum_latency_ms,
                  MAX(m.latency_ms) AS maximum_latency_ms,
                  MAX(m.captured_at) AS last_seen
           FROM measurements AS m
           LEFT JOIN devices AS d ON d.id = m.device_id
           GROUP BY m.ip, d.name, d.is_demo, m.is_demo"""
    )
    connection.execute(
        """CREATE MATERIALIZED VIEW IF NOT EXISTS mv_network_daily_summary AS
           SELECT COALESCE(n.name, 'Red histórica sin clasificar') AS network_name,
                  COALESCE(n.cidr, 'sin CIDR') AS cidr,
                  to_timestamp(sr.captured_at)::date AS scan_date,
                  COALESCE(n.is_demo, sr.is_demo) AS is_demo,
                  COUNT(DISTINCT sr.scan_id) AS scan_count,
                  COUNT(DISTINCT m.ip) AS device_count,
                  AVG(m.latency_ms) AS average_latency_ms
           FROM scan_runs AS sr
           LEFT JOIN networks AS n ON n.id = sr.network_id
           LEFT JOIN measurements AS m ON m.scan_id = sr.scan_id
           WHERE sr.is_complete = TRUE
           GROUP BY n.name, n.cidr, n.is_demo, sr.is_demo, to_timestamp(sr.captured_at)::date"""
    )


# Backfill shared by both engines: rows from earlier versions get a key and a last-seen time,
# and events learn their network from the device they belong to.
_BACKFILL_NETWORKS = (
    "UPDATE networks SET network_key = cidr || '|' || COALESCE(gateway_mac, '') WHERE network_key IS NULL",
    """UPDATE networks SET last_seen_at = COALESCE(
           (SELECT MAX(captured_at) FROM scan_runs WHERE scan_runs.network_id = networks.id), created_at)
       WHERE last_seen_at IS NULL""",
    """UPDATE events SET network_id = (SELECT network_id FROM devices WHERE devices.id = events.device_id)
       WHERE network_id IS NULL AND device_id IS NOT NULL""",
)

_SQLITE_NETWORKS_TABLE = """CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    cidr TEXT NOT NULL,
    gateway TEXT,
    created_at REAL NOT NULL,
    is_demo INTEGER NOT NULL DEFAULT 0,
    monitor_enabled INTEGER NOT NULL DEFAULT 0,
    monitor_interval_minutes INTEGER NOT NULL DEFAULT 5,
    alert_latency_threshold_ms REAL NOT NULL DEFAULT 300,
    alert_new_devices INTEGER NOT NULL DEFAULT 1,
    alert_offline_devices INTEGER NOT NULL DEFAULT 1,
    gateway_mac TEXT,
    gateway_vendor TEXT,
    alias TEXT,
    network_key TEXT,
    last_seen_at REAL
)"""


def _sqlite_drop_unique_cidr(connection):
    """SQLite cannot drop a UNIQUE constraint, so the table is rebuilt keeping every id."""
    columns = ", ".join(row["name"] for row in connection.execute("PRAGMA table_info(networks)"))
    connection.commit()
    connection.execute("PRAGMA foreign_keys = OFF")
    try:
        connection.execute(_SQLITE_NETWORKS_TABLE.replace("networks", "networks_rebuilt", 1))
        connection.execute(f"INSERT INTO networks_rebuilt({columns}) SELECT {columns} FROM networks")
        connection.execute("DROP TABLE networks")
        connection.execute("ALTER TABLE networks_rebuilt RENAME TO networks")
        connection.commit()
    finally:
        connection.execute("PRAGMA foreign_keys = ON")


def _connect_sqlite():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    company_id = active_company_id.get() or "default"
    path = DATABASE if company_id == "default" else DATA_DIR / f"history-{hashlib.sha256(company_id.encode()).hexdigest()[:24]}.sqlite3"
    connection = sqlite3.connect(path, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 15000")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS network_topology (
            cidr TEXT PRIMARY KEY,
            captured_at REAL NOT NULL,
            data_json TEXT NOT NULL
        )"""
    )
    connection.execute(_SQLITE_NETWORKS_TABLE)
    network_columns = {row["name"] for row in connection.execute("PRAGMA table_info(networks)")}
    for name, data_type in (
        ("monitor_enabled", "INTEGER NOT NULL DEFAULT 0"),
        ("monitor_interval_minutes", "INTEGER NOT NULL DEFAULT 5"),
        ("alert_latency_threshold_ms", "REAL NOT NULL DEFAULT 300"),
        ("alert_new_devices", "INTEGER NOT NULL DEFAULT 1"),
        ("alert_offline_devices", "INTEGER NOT NULL DEFAULT 1"),
        ("gateway_mac", "TEXT"),
        ("gateway_vendor", "TEXT"),
        ("alias", "TEXT"),
        ("network_key", "TEXT"),
        ("last_seen_at", "REAL"),
    ):
        if name not in network_columns:
            connection.execute(f"ALTER TABLE networks ADD COLUMN {name} {data_type}")
    # Earlier versions keyed networks by subnet alone (UNIQUE(cidr)).
    if any(index["origin"] == "u" for index in connection.execute("PRAGMA index_list(networks)")):
        _sqlite_drop_unique_cidr(connection)
    connection.execute(
        """CREATE TABLE IF NOT EXISTS scan_runs (
            scan_id TEXT PRIMARY KEY,
            captured_at REAL NOT NULL,
            network_id INTEGER REFERENCES networks(id),
            is_demo INTEGER NOT NULL DEFAULT 0,
            is_complete INTEGER NOT NULL DEFAULT 1
        )"""
    )
    scan_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scan_runs)")}
    for name, data_type in (("network_id", "INTEGER"), ("is_demo", "INTEGER NOT NULL DEFAULT 0"), ("is_complete", "INTEGER NOT NULL DEFAULT 1")):
        if name not in scan_columns:
            connection.execute(f"ALTER TABLE scan_runs ADD COLUMN {name} {data_type}")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network_id INTEGER REFERENCES networks(id),
            ip TEXT NOT NULL,
            mac TEXT,
            name TEXT,
            manufacturer TEXT,
            manufacturer_network TEXT,
            model TEXT,
            device_type TEXT,
            current_state TEXT NOT NULL DEFAULT 'desconocido',
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            owner TEXT,
            notes TEXT,
            is_demo INTEGER NOT NULL DEFAULT 0,
            UNIQUE(network_id, ip)
        )"""
    )
    device_columns = {row["name"] for row in connection.execute("PRAGMA table_info(devices)")}
    for name in ("owner", "notes", "os_guess", "open_ports"):
        if name not in device_columns:
            connection.execute(f"ALTER TABLE devices ADD COLUMN {name} TEXT")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS measurements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL REFERENCES scan_runs(scan_id),
            captured_at REAL NOT NULL,
            ip TEXT NOT NULL,
            latency_ms REAL,
            state TEXT NOT NULL,
            name TEXT,
            manufacturer TEXT,
            manufacturer_network TEXT,
            model TEXT,
            device_type TEXT,
            mac TEXT,
            device_id INTEGER REFERENCES devices(id),
            is_demo INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    # Backfill complete scans from earlier versions. A lone inactive row was
    # used as a tombstone for an absent device, not as a completed scan.
    connection.execute(
        """
        INSERT OR IGNORE INTO scan_runs(scan_id, captured_at, is_complete)
        SELECT scan_id, MIN(captured_at),
               CASE WHEN COUNT(*) > 1 OR MAX(state) <> 'inactivo' THEN 1 ELSE 0 END
        FROM measurements
        GROUP BY scan_id
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            occurred_at REAL NOT NULL,
            ip TEXT NOT NULL,
            device_name TEXT,
            event_type TEXT NOT NULL,
            previous_state TEXT,
            current_state TEXT NOT NULL,
            description TEXT NOT NULL,
            acknowledged_at REAL,
            device_id INTEGER REFERENCES devices(id),
            is_demo INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    event_columns = {row["name"] for row in connection.execute("PRAGMA table_info(events)")}
    if "acknowledged_at" not in event_columns:
        connection.execute("ALTER TABLE events ADD COLUMN acknowledged_at REAL")
    for name, data_type in (("device_id", "INTEGER"), ("is_demo", "INTEGER NOT NULL DEFAULT 0"), ("network_id", "INTEGER")):
        if name not in event_columns:
            connection.execute(f"ALTER TABLE events ADD COLUMN {name} {data_type}")
    for statement in _BACKFILL_NETWORKS:
        connection.execute(statement)
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_networks_key ON networks(network_key)")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS trusted_devices (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            device_name TEXT,
            trusted_at REAL NOT NULL,
            device_id INTEGER REFERENCES devices(id),
            is_demo INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    trusted_columns = {row["name"] for row in connection.execute("PRAGMA table_info(trusted_devices)")}
    for name, data_type in (("device_id", "INTEGER"), ("is_demo", "INTEGER NOT NULL DEFAULT 0")):
        if name not in trusted_columns:
            connection.execute(f"ALTER TABLE trusted_devices ADD COLUMN {name} {data_type}")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS diagnostics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER REFERENCES devices(id),
            ip TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            latency_ms REAL NOT NULL,
            observations TEXT,
            created_at REAL NOT NULL,
            is_demo INTEGER NOT NULL DEFAULT 0
        )"""
    )
    columns = {row["name"] for row in connection.execute("PRAGMA table_info(measurements)")}
    for name, data_type in (
        ("name", "TEXT"),
        ("manufacturer", "TEXT"),
        ("manufacturer_network", "TEXT"),
        ("model", "TEXT"),
        ("device_type", "TEXT"),
        ("mac", "TEXT"),
        ("device_id", "INTEGER"),
        ("is_demo", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if name not in columns:
            connection.execute(f"ALTER TABLE measurements ADD COLUMN {name} {data_type}")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_measurements_ip_time "
        "ON measurements(ip, captured_at DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_time ON events(occurred_at DESC)"
    )
    connection.commit()
    return connection


def _mac_normalizada(mac):
    return mac.strip().lower().replace(":", "-") if mac else None


def _iso(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if timestamp else None


# Measurements reach their network through the device row they were stored for.
NET_FILTER_SQL = "device_id IN (SELECT id FROM devices WHERE network_id = ?)"

_NETWORK_COLUMNS = "id, name, alias, cidr, gateway, gateway_mac, gateway_vendor, network_key, created_at, last_seen_at"


def _red_publica(row):
    vendor = row["gateway_vendor"]
    return {
        "id": row["id"],
        "nombre": row["alias"] or (f"Red {vendor} · {row['cidr']}" if vendor else f"Red {row['cidr']}"),
        "alias": row["alias"],
        "subred": row["cidr"],
        "gateway": row["gateway"],
        "gateway_mac": row["gateway_mac"],
        "gateway_fabricante": vendor,
        "clave": row["network_key"],
        "primera_vez": _iso(row["created_at"]),
        "ultima_vez": _iso(row["last_seen_at"] or row["created_at"]),
    }


def identificar_red(cidr, gateway=None, dispositivos=()):
    """Return the saved network a scan belongs to, registering it the first time its gateway appears.

    A network is its subnet plus the gateway MAC, so two routers that hand out the same
    subnet (192.168.1.0/24 at home and at the office) are kept as separate networks.
    """
    cidr = cidr or "red-desconocida"
    router = next((device for device in dispositivos if gateway and device.ip == gateway), None)
    gateway_mac = _mac_normalizada(router.mac) if router else None
    gateway_vendor = (router.fabricante or router.fabricante_red) if router else None
    if gateway_vendor in {"Desconocido", "MAC privada"}:
        gateway_vendor = None
    key = f"{cidr}|{gateway_mac or ''}"
    now = time.time()
    connection = _connect()
    try:
        with connection:
            row = connection.execute(
                "SELECT id FROM networks WHERE network_key = ? AND is_demo = FALSE", (key,)
            ).fetchone()
            if row is None:
                # A network saved without a gateway MAC (earlier versions, or a scan where the
                # router missed the ARP table) is claimed the first time its MAC shows up.
                query = "SELECT id FROM networks WHERE cidr = ? AND is_demo = FALSE"
                if gateway_mac:
                    query += " AND gateway_mac IS NULL"
                row = connection.execute(
                    query + " ORDER BY COALESCE(last_seen_at, created_at) DESC LIMIT 1", (cidr,)
                ).fetchone()
            if row is None:
                connection.execute(
                    """INSERT INTO networks(name, cidr, gateway, gateway_mac, gateway_vendor,
                                           network_key, created_at, last_seen_at, is_demo)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, FALSE)""",
                    (f"Red {cidr}", cidr, gateway, gateway_mac, gateway_vendor, key, now, now),
                )
                network_id = connection.execute(
                    "SELECT id FROM networks WHERE network_key = ? AND is_demo = FALSE", (key,)
                ).fetchone()["id"]
            else:
                network_id = row["id"]
                connection.execute(
                    """UPDATE networks SET gateway = COALESCE(?, gateway),
                              gateway_mac = COALESCE(?, gateway_mac),
                              gateway_vendor = COALESCE(?, gateway_vendor),
                              network_key = COALESCE(?, network_key), last_seen_at = ?
                       WHERE id = ?""",
                    (gateway, gateway_mac, gateway_vendor, key if gateway_mac else None, now, network_id),
                )
    finally:
        connection.close()
    return obtener_red(network_id)


def obtener_red(network_id):
    connection = _connect()
    try:
        row = connection.execute(
            f"SELECT {_NETWORK_COLUMNS} FROM networks WHERE id = ? AND is_demo = FALSE", (network_id,)
        ).fetchone()
        return _red_publica(row) if row else None
    finally:
        connection.close()


def listar_redes():
    """List every saved network with its device count and the result of its latest scan."""
    connection = _connect()
    try:
        rows = connection.execute(
            f"""SELECT {", ".join("n." + column for column in _NETWORK_COLUMNS.split(", "))},
                   (SELECT COUNT(*) FROM devices AS d
                    WHERE d.network_id = n.id AND d.is_demo = FALSE) AS device_count,
                   (SELECT COUNT(*) FROM scan_runs AS sr
                    WHERE sr.network_id = n.id AND sr.is_complete = TRUE) AS scan_count,
                   (SELECT COUNT(*) FROM measurements AS m
                    WHERE m.state = 'activo' AND m.scan_id = (
                        SELECT sr.scan_id FROM scan_runs AS sr
                        WHERE sr.network_id = n.id AND sr.is_complete = TRUE
                        ORDER BY sr.captured_at DESC LIMIT 1)) AS active_count
               FROM networks AS n
               WHERE n.is_demo = FALSE
               ORDER BY COALESCE(n.last_seen_at, n.created_at) DESC"""
        ).fetchall()
    finally:
        connection.close()
    redes = []
    for row in rows:
        red = _red_publica(row)
        red.update(equipos=row["device_count"], escaneos=row["scan_count"], activos=row["active_count"])
        redes.append(red)
    return {"total": len(redes), "reciente": redes[0]["id"] if redes else None, "redes": redes}


def renombrar_red(network_id, alias):
    connection = _connect()
    try:
        with connection:
            cursor = connection.execute(
                "UPDATE networks SET alias = ? WHERE id = ? AND is_demo = FALSE", (alias, network_id)
            )
        if cursor.rowcount == 0:
            return None
    finally:
        connection.close()
    return obtener_red(network_id)


def guardar_escaneo(dispositivos, cidr=None, gateway=None, network_id=None):
    """Store one point per discovered device; non-responders have no latency."""
    if not dispositivos:
        return

    scan_id = str(uuid.uuid4())
    captured_at = time.time()
    if network_id is None:
        network_id = identificar_red(cidr, gateway, dispositivos)["id"]

    connection = _connect()
    try:
        with connection:
            device_ids = {}
            for device in dispositivos:
                connection.execute(
                    """INSERT INTO devices(
                           network_id, ip, mac, name, manufacturer, manufacturer_network,
                           model, device_type, current_state, first_seen, last_seen,
                           os_guess, open_ports, is_demo
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE)
                       ON CONFLICT(network_id, ip) DO UPDATE SET
                           mac=excluded.mac, name=excluded.name, manufacturer=excluded.manufacturer,
                           manufacturer_network=excluded.manufacturer_network, model=excluded.model,
                           device_type=excluded.device_type, current_state=excluded.current_state,
                           last_seen=excluded.last_seen,
                           os_guess=COALESCE(excluded.os_guess, devices.os_guess),
                           open_ports=COALESCE(excluded.open_ports, devices.open_ports)""",
                    (network_id, device.ip, device.mac, device.nombre, device.fabricante,
                     device.fabricante_red, device.modelo, device.tipo, device.estado,
                     captured_at, captured_at, device.sistema,
                     ",".join(str(port) for port in device.puertos) or None),
                )
                device_ids[device.ip] = connection.execute(
                    "SELECT id FROM devices WHERE network_id = ? AND ip = ? AND is_demo = FALSE",
                    (network_id, device.ip),
                ).fetchone()["id"]

            insert_scan_run = (
                "INSERT INTO scan_runs(scan_id, captured_at, network_id, is_demo) VALUES (?, ?, ?, FALSE) "
                "ON CONFLICT (scan_id) DO NOTHING"
                if DATABASE_URL
                else "INSERT OR IGNORE INTO scan_runs(scan_id, captured_at, network_id, is_demo) VALUES (?, ?, ?, FALSE)"
            )
            connection.execute(insert_scan_run, (scan_id, captured_at, network_id))
            rows = [
                (scan_id, captured_at, device.ip,
                 device.tiempo_respuesta if device.estado == "activo" else None,
                 device.estado, device.nombre, device.fabricante, device.fabricante_red,
                 device.modelo, device.tipo, device.mac, device_ids[device.ip])
                for device in dispositivos
            ]
            connection.executemany(
                """
                INSERT INTO measurements(
                    scan_id, captured_at, ip, latency_ms, state, name,
                    manufacturer, manufacturer_network, model, device_type, mac, device_id, is_demo
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE)
                """,
                rows,
            )
            for ip, device_id in device_ids.items():
                connection.execute(
                    "UPDATE events SET device_id = ? WHERE ip = ? AND device_id IS NULL AND is_demo = FALSE",
                    (device_id, ip),
                )
                connection.execute(
                    "UPDATE trusted_devices SET device_id = ? WHERE ip = ? AND is_demo = FALSE",
                    (device_id, ip),
                )
            cutoff = captured_at - RETENTION_DAYS * 24 * 60 * 60
            connection.execute("DELETE FROM measurements WHERE captured_at < ? AND is_demo = FALSE", (cutoff,))
            connection.execute(
                """DELETE FROM scan_runs
                   WHERE captured_at < ? AND is_demo = FALSE
                     AND NOT EXISTS (
                         SELECT 1 FROM measurements
                         WHERE measurements.scan_id = scan_runs.scan_id
                     )""",
                (cutoff,),
            )
        if DATABASE_URL:
            _refresh_postgresql_views(connection)
    finally:
        connection.close()


def obtener_inventario_conocido(network_id=None):
    """List devices previously discovered on scanned local networks, or on one of them."""
    connection = _connect()
    try:
        rows = connection.execute(
            """
            SELECT d.ip, d.mac, d.name, d.manufacturer, d.manufacturer_network,
                   d.model, d.device_type, d.first_seen, d.last_seen, n.cidr, d.network_id,
                   d.owner, d.notes, d.os_guess, d.open_ports,
                   (SELECT m.state FROM measurements AS m
                    WHERE m.device_id = d.id AND m.is_demo = FALSE
                    ORDER BY m.captured_at DESC, m.id DESC LIMIT 1) AS latest_state,
                   (SELECT m.latency_ms FROM measurements AS m
                    WHERE m.device_id = d.id AND m.is_demo = FALSE
                    ORDER BY m.captured_at DESC, m.id DESC LIMIT 1) AS latest_latency
            FROM devices AS d
            LEFT JOIN networks AS n ON n.id = d.network_id
            WHERE d.is_demo = FALSE""" + (" AND d.network_id = ?" if network_id is not None else "") + """
            ORDER BY d.last_seen DESC, d.ip
            """,
            (network_id,) if network_id is not None else (),
        ).fetchall()
        trusted_rows = connection.execute(
            "SELECT ip, mac FROM trusted_devices WHERE is_demo = FALSE"
        ).fetchall()
    finally:
        connection.close()

    trusted_ips = {row["ip"]: row["mac"] for row in trusted_rows}
    trusted_macs = {row["mac"].lower().replace(":", "-") for row in trusted_rows if row["mac"]}

    def trust_state(ip, mac):
        normalized = mac.lower().replace(":", "-") if mac else None
        if normalized and normalized in trusted_macs:
            return "confiable"
        if ip in trusted_ips and (trusted_ips[ip] is None or mac is None):
            return "confiable"
        return "por_revisar"

    def iso(timestamp):
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if timestamp else None

    devices = [
        {
            "ip": row["ip"], "mac": row["mac"], "nombre": row["name"],
            "fabricante": row["manufacturer"], "fabricante_red": row["manufacturer_network"],
            "modelo": row["model"], "tipo": row["device_type"] or "desconocido",
            "estado": row["latest_state"] or "inactivo",
            "tiempo_respuesta": row["latest_latency"],
            "primera_deteccion": iso(row["first_seen"]),
            "ultima_deteccion": iso(row["last_seen"]),
            "subred": row["cidr"], "red_id": row["network_id"],
            "responsable": row["owner"], "notas": row["notes"],
            "sistema": row["os_guess"],
            "puertos": [int(port) for port in (row["open_ports"] or "").split(",") if port.isdigit()],
            "confianza": trust_state(row["ip"], row["mac"]),
        }
        for row in rows
    ]
    groups = []
    for red_id in dict.fromkeys(device["red_id"] for device in devices):
        groups.extend(_group_device_identities([device for device in devices if device["red_id"] == red_id]))
    merged = []
    for group in groups:
        latest = max(group, key=lambda device: device["ultima_deteccion"] or "")
        item = dict(latest)
        item["ips"] = sorted({device["ip"] for device in group})
        item["subredes"] = sorted({device["subred"] for device in group if device["subred"]})
        item["primera_deteccion"] = min(
            (device["primera_deteccion"] for device in group if device["primera_deteccion"]),
            default=None,
        )
        item["ultima_deteccion"] = max(
            (device["ultima_deteccion"] for device in group if device["ultima_deteccion"]),
            default=None,
        )
        merged.append(item)
    merged.sort(key=lambda device: device["ultima_deteccion"] or "", reverse=True)
    return {"total": len(merged), "dispositivos": merged}


def _normalized_identity_value(value):
    return " ".join(str(value or "").strip().casefold().split())


def _same_device_identity(left, right):
    left_mac = _normalized_identity_value(left.get("mac")).replace(":", "-")
    right_mac = _normalized_identity_value(right.get("mac")).replace(":", "-")
    if left_mac and right_mac and left_mac == right_mac:
        return True

    left_name = _normalized_identity_value(left.get("nombre") or left.get("name"))
    right_name = _normalized_identity_value(right.get("nombre") or right.get("name"))
    generic_names = {"", "desconocido", "unknown", "dispositivo", "device", "mac privada"}
    if left_name in generic_names or left_name != right_name:
        return False

    # Hostnames can bridge subnet scans when a MAC is missing or changes.
    # Conflicting manufacturer or model data keeps the records separate.
    for key in ("fabricante", "modelo"):
        left_value = _normalized_identity_value(left.get(key))
        right_value = _normalized_identity_value(right.get(key))
        if left_value and right_value and left_value != right_value:
            return False
    return True


def _group_device_identities(devices):
    groups = []
    for device in devices:
        matching = [index for index, group in enumerate(groups)
                    if any(_same_device_identity(device, member) for member in group)]
        if not matching:
            groups.append([device])
            continue
        first = matching[0]
        groups[first].append(device)
        for index in reversed(matching[1:]):
            groups[first].extend(groups.pop(index))
    return groups


def _refresh_postgresql_views(connection):
    if not DATABASE_URL:
        return
    connection.execute("REFRESH MATERIALIZED VIEW mv_device_performance")
    connection.execute("REFRESH MATERIALIZED VIEW mv_network_daily_summary")
    connection.commit()


def registrar_diagnostico(ip, diagnostico):
    connection = _connect()
    try:
        with connection:
            device = connection.execute(
                "SELECT id FROM devices WHERE ip = ? AND is_demo = FALSE ORDER BY last_seen DESC LIMIT 1",
                (ip,),
            ).fetchone()
            connection.execute(
                """INSERT INTO diagnostics(
                       device_id, ip, level, message, recommendation,
                       latency_ms, observations, created_at, is_demo
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, FALSE)""",
                (device["id"] if device else None, ip, diagnostico["nivel"],
                 diagnostico["mensaje"], diagnostico["recomendacion"],
                 diagnostico["tiempo_respuesta"], diagnostico.get("observaciones"), time.time()),
            )
    finally:
        connection.close()


def verificar_base_datos():
    connection = _connect()
    try:
        connection.execute("SELECT 1 AS conectado").fetchone()
        return True
    finally:
        connection.close()


def obtener_red_reciente():
    """Return the network scanned most recently: the one this computer or agent is on."""
    connection = _connect()
    try:
        row = connection.execute(
            f"""SELECT {_NETWORK_COLUMNS} FROM networks WHERE is_demo = FALSE
                ORDER BY COALESCE(last_seen_at, created_at) DESC LIMIT 1"""
        ).fetchone()
        return _red_publica(row) if row else None
    finally:
        connection.close()


def guardar_topologia(cidr, topologia):
    if not cidr or not isinstance(topologia, dict):
        return
    connection = _connect()
    try:
        connection.execute(
            """INSERT INTO network_topology(cidr, captured_at, data_json) VALUES (?, ?, ?)
               ON CONFLICT(cidr) DO UPDATE SET captured_at=excluded.captured_at,
               data_json=excluded.data_json""",
            (str(cidr), time.time(), json.dumps(topologia, ensure_ascii=False)),
        )
        connection.commit()
    finally:
        connection.close()


def obtener_topologia(cidr):
    if not cidr:
        return None
    connection = _connect()
    try:
        row = connection.execute(
            "SELECT data_json FROM network_topology WHERE cidr = ?", (str(cidr),)
        ).fetchone()
        return json.loads(row["data_json"]) if row else None
    finally:
        connection.close()


def obtener_configuracion_operativa(network_id):
    connection = _connect()
    try:
        row = connection.execute(
            """SELECT monitor_enabled, monitor_interval_minutes,
                      alert_latency_threshold_ms, alert_new_devices, alert_offline_devices
               FROM networks WHERE id = ? AND is_demo = FALSE""",
            (network_id,),
        ).fetchone()
        if row is None:
            return {
                "monitoreo_activo": False,
                "intervalo_minutos": 5,
                "umbral_latencia_ms": 300,
                "alertar_dispositivo_nuevo": True,
                "alertar_dispositivo_ausente": True,
            }
        return {
            "monitoreo_activo": bool(row["monitor_enabled"]),
            "intervalo_minutos": row["monitor_interval_minutes"],
            "umbral_latencia_ms": row["alert_latency_threshold_ms"],
            "alertar_dispositivo_nuevo": bool(row["alert_new_devices"]),
            "alertar_dispositivo_ausente": bool(row["alert_offline_devices"]),
        }
    finally:
        connection.close()


def guardar_configuracion_operativa(network_id, configuracion):
    connection = _connect()
    try:
        with connection:
            connection.execute(
                """UPDATE networks SET monitor_enabled = ?, monitor_interval_minutes = ?,
                          alert_latency_threshold_ms = ?, alert_new_devices = ?, alert_offline_devices = ?
                   WHERE id = ? AND is_demo = FALSE""",
                (
                    configuracion["monitoreo_activo"],
                    configuracion["intervalo_minutos"],
                    configuracion["umbral_latencia_ms"],
                    configuracion["alertar_dispositivo_nuevo"],
                    configuracion["alertar_dispositivo_ausente"],
                    network_id,
                ),
            )
        return obtener_configuracion_operativa(network_id)
    finally:
        connection.close()


def _filtro_red(network_id, column="network_id"):
    return (f" AND {column} = ?", (network_id,)) if network_id is not None else ("", ())


def guardar_notas_dispositivo(ip, responsable, notas, network_id=None):
    filtro, parametros = _filtro_red(network_id)
    connection = _connect()
    try:
        with connection:
            row = connection.execute(
                f"""UPDATE devices SET owner = ?, notes = ?
                   WHERE id = (
                       SELECT id FROM devices WHERE ip = ? AND is_demo = FALSE{filtro}
                       ORDER BY last_seen DESC LIMIT 1
                   ) RETURNING ip, owner, notes""",
                (responsable, notas, ip, *parametros),
            ).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def obtener_notas_dispositivo(ip, network_id=None):
    filtro, parametros = _filtro_red(network_id)
    connection = _connect()
    try:
        row = connection.execute(
            f"""SELECT owner, notes FROM devices WHERE ip = ? AND is_demo = FALSE{filtro}
               ORDER BY last_seen DESC LIMIT 1""",
            (ip, *parametros),
        ).fetchone()
        return {"responsable": row["owner"], "notas": row["notes"]} if row else None
    finally:
        connection.close()


def obtener_metadatos_dispositivos(ips, network_id=None):
    if not ips:
        return {}
    placeholders = ", ".join("?" for _ in ips)
    filtro, parametros = _filtro_red(network_id)
    connection = _connect()
    try:
        rows = connection.execute(
            f"SELECT ip, owner, notes FROM devices WHERE is_demo = FALSE AND ip IN ({placeholders}){filtro}",
            (*ips, *parametros),
        ).fetchall()
        return {row["ip"]: {"responsable": row["owner"], "notas": row["notes"]} for row in rows}
    finally:
        connection.close()


def obtener_eventos_exportables(dias=30, network_id=None):
    cutoff = time.time() - dias * 24 * 60 * 60
    filtro, parametros = _filtro_red(network_id)
    connection = _connect()
    try:
        rows = connection.execute(
            f"""SELECT occurred_at, ip, device_name, event_type, previous_state,
                      current_state, description, acknowledged_at
               FROM events WHERE occurred_at >= ? AND is_demo = FALSE{filtro}
               ORDER BY occurred_at DESC""",
            (cutoff, *parametros),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def registrar_eventos_escaneo(dispositivos, cidr=None, network_id=None):
    """Store first sightings and state transitions against the previous scan of the same network."""
    current = {device.ip: device for device in dispositivos}
    # Resolve the network and read settings before opening the write connection:
    # a second SQLite connection would otherwise wait on this one's open transaction.
    if network_id is None:
        network_id = identificar_red(cidr, None, dispositivos)["id"]
    settings = obtener_configuracion_operativa(network_id)
    connection = _connect()
    try:
        now = time.time()
        with connection:
            # Comparing with every network would report the devices of the network
            # the laptop just left as absent, and every device here as new.
            rows = connection.execute(
                f"""
                SELECT m.ip, m.state, m.name, m.latency_ms, m.device_id
                FROM measurements AS m
                JOIN (
                    SELECT ip, MAX(captured_at) AS latest
                    FROM measurements WHERE is_demo = FALSE AND {NET_FILTER_SQL}
                    GROUP BY ip
                ) AS latest_scan ON latest_scan.ip = m.ip AND latest_scan.latest = m.captured_at
                WHERE m.is_demo = FALSE AND m.{NET_FILTER_SQL}
                """,
                (network_id, network_id),
            ).fetchall()
            previous = {row["ip"]: row for row in rows}
            events = []
            first_snapshot = not previous
            missing_measurements = []
            tombstone_scan_id = str(uuid.uuid4())
            for ip, device in current.items():
                old = previous.get(ip)
                if old is None:
                    event_type = (
                        "dispositivo_nuevo"
                        if not first_snapshot and settings["alertar_dispositivo_nuevo"]
                        else None
                    )
                    description = f"Se detect\u00f3 un dispositivo nuevo ({device.estado})."
                    old_state = None
                elif old["state"] != device.estado:
                    event_type = "cambio_estado"
                    description = f"El estado cambi\u00f3 de {old['state']} a {device.estado}."
                    old_state = old["state"]
                else:
                    event_type = None
                    description = None
                    old_state = None
                if event_type:
                    events.append((now, ip, device.nombre or (old["name"] if old else None), event_type, old_state, device.estado, description, old["device_id"] if old else None, network_id))
                if (
                    device.estado == "activo"
                    and device.tiempo_respuesta >= settings["umbral_latencia_ms"]
                    and (old is None or old["latency_ms"] is None or old["latency_ms"] < settings["umbral_latencia_ms"])
                ):
                    events.append((
                        now, ip, device.nombre or (old["name"] if old else None),
                        "latencia_elevada", old["state"] if old else None, device.estado,
                        f"Una medición registró {device.tiempo_respuesta:.1f} ms; confirma si se repite en escaneos posteriores.",
                        old["device_id"] if old else None, network_id,
                    ))

            missing = set(previous) - set(current)
            for ip in missing:
                old = previous[ip]
                if old["state"] == "inactivo":
                    continue
                if settings["alertar_dispositivo_ausente"]:
                    events.append((now, ip, old["name"], "dispositivo_ausente", old["state"], "inactivo", "El dispositivo ya no aparece en el escaneo de red.", old["device_id"], network_id))
                missing_measurements.append((tombstone_scan_id, now, ip, None, "inactivo", old["name"], None, None, None, None, None, old["device_id"]))

            if missing_measurements:
                insert_tombstone_run = (
                    "INSERT INTO scan_runs(scan_id, captured_at, network_id, is_complete, is_demo) VALUES (?, ?, ?, FALSE, FALSE) "
                    "ON CONFLICT(scan_id) DO NOTHING"
                    if DATABASE_URL
                    else "INSERT OR IGNORE INTO scan_runs(scan_id, captured_at, network_id, is_complete, is_demo) VALUES (?, ?, ?, 0, 0)"
                )
                connection.execute(insert_tombstone_run, (tombstone_scan_id, now, network_id))
                connection.executemany(
                    """INSERT INTO measurements(
                        scan_id, captured_at, ip, latency_ms, state, name,
                        manufacturer, manufacturer_network, model, device_type, mac, device_id, is_demo
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE)""",
                    missing_measurements,
                )
            connection.executemany(
                """
                INSERT INTO events(occurred_at, ip, device_name, event_type, previous_state, current_state, description, device_id, network_id, is_demo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE)
                """,
                events,
            )
            connection.execute("DELETE FROM events WHERE occurred_at < ? AND is_demo = FALSE", (now - RETENTION_DAYS * 24 * 60 * 60,))
        return len(events)
    finally:
        connection.close()


def aplicar_confianza(dispositivos):
    """Annotate discovered devices using the local IP/MAC trust list."""
    connection = _connect()
    try:
        rows = connection.execute("SELECT ip, mac FROM trusted_devices WHERE is_demo = FALSE").fetchall()
        trusted = {row["ip"]: row["mac"] for row in rows}
        trusted_macs = {
            row["mac"].lower().replace(":", "-")
            for row in rows if row["mac"]
        }
    finally:
        connection.close()

    for device in dispositivos:
        known_mac = trusted.get(device.ip)
        current_mac = device.mac.lower().replace(":", "-") if device.mac else None
        same_identity = current_mac is not None and current_mac in trusted_macs
        # If either scan has no MAC, the operator's explicit IP approval is used.
        if device.ip in trusted and (same_identity or known_mac is None or device.mac is None):
            device.confianza = "confiable"
        else:
            device.confianza = "por_revisar"
    return dispositivos


def actualizar_confianza(ip, confiable, mac=None, nombre=None):
    connection = _connect()
    try:
        with connection:
            if confiable:
                connection.execute(
                    """INSERT INTO trusted_devices(ip, mac, device_name, trusted_at, device_id, is_demo)
                       VALUES (?, ?, ?, ?,
                           (SELECT id FROM devices WHERE ip = ? AND is_demo = FALSE ORDER BY last_seen DESC LIMIT 1), FALSE)
                       ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac,
                           device_name=excluded.device_name, trusted_at=excluded.trusted_at,
                           device_id=excluded.device_id, is_demo=FALSE""",
                    (ip, mac, nombre, time.time(), ip),
                )
            else:
                connection.execute("DELETE FROM trusted_devices WHERE ip = ?", (ip,))
    finally:
        connection.close()


def obtener_identidad_escaneada(ip):
    """Return the identity from the latest inventory scan, if still present."""
    connection = _connect()
    try:
        row = connection.execute(
            "SELECT mac, name, state FROM measurements WHERE ip = ? AND is_demo = FALSE ORDER BY captured_at DESC LIMIT 1",
            (ip,),
        ).fetchone()
        if row is None or row["state"] == "inactivo":
            return None
        return {"mac": row["mac"], "nombre": row["name"]}
    finally:
        connection.close()


def _severidad_evento(event_type, current_state):
    if event_type in {"dispositivo_nuevo", "latencia_elevada"}:
        return "advertencia"
    if current_state in {"inactivo", "detectado"} or event_type == "dispositivo_ausente":
        return "advertencia"
    return "informativa"


def obtener_alertas(limite=30, network_id=None):
    filtro, parametros = _filtro_red(network_id)
    connection = _connect()
    try:
        total = connection.execute(
            f"SELECT COUNT(*) AS count FROM events WHERE acknowledged_at IS NULL AND is_demo = FALSE{filtro}",
            parametros,
        ).fetchone()["count"]
        rows = connection.execute(
            f"""SELECT id, occurred_at, ip, device_name, event_type, current_state,
                      description, acknowledged_at
               FROM events WHERE acknowledged_at IS NULL AND is_demo = FALSE{filtro}
               ORDER BY occurred_at DESC LIMIT ?""",
            (*parametros, limite),
        ).fetchall()
    finally:
        connection.close()
    alerts = [{
        "id": row["id"],
        "fecha": datetime.fromtimestamp(row["occurred_at"], timezone.utc).isoformat(),
        "ip": row["ip"],
        "nombre": row["device_name"],
        "tipo": row["event_type"],
        "estado_actual": row["current_state"],
        "mensaje": _reparar_mojibake(row["description"]),
        "severidad": _severidad_evento(row["event_type"], row["current_state"]),
    } for row in rows]
    return {
        "total": total,
        "criticas": sum(item["severidad"] == "critica" for item in alerts),
        "advertencias": sum(item["severidad"] == "advertencia" for item in alerts),
        "alertas": alerts,
    }


def reconocer_alerta(alert_id):
    connection = _connect()
    try:
        with connection:
            cursor = connection.execute(
                "UPDATE events SET acknowledged_at = ? WHERE id = ? AND acknowledged_at IS NULL",
                (time.time(), alert_id),
            )
            return cursor.rowcount > 0
    finally:
        connection.close()


def _reparar_mojibake(value):
    if not isinstance(value, str) or not any(marker in value for marker in ("Ã", "Â", "â€", "�")):
        return value
    try:
        repaired = value.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value.replace("\uFFFD", "ó")
    return repaired if repaired != value else value


def obtener_eventos(limite=50, network_id=None):
    filtro, parametros = _filtro_red(network_id)
    connection = _connect()
    try:
        rows = connection.execute(
            "SELECT occurred_at, ip, device_name, event_type, previous_state, current_state, description "
            f"FROM events WHERE is_demo = FALSE{filtro} ORDER BY occurred_at DESC LIMIT ?",
            (*parametros, limite),
        ).fetchall()
    finally:
        connection.close()
    return {
        "total": len(rows),
        "eventos": [
            {
                "fecha": datetime.fromtimestamp(row["occurred_at"], timezone.utc).isoformat(),
                "ip": row["ip"],
                "nombre": row["device_name"],
                "tipo": row["event_type"],
                "estado_anterior": row["previous_state"],
                "estado_actual": row["current_state"],
                "mensaje": _reparar_mojibake(row["description"]),
            }
            for row in rows
        ],
    }


def obtener_datos_informe(dias=7, network_id=None):
    """Return inventory snapshot plus measurements and events for a report."""
    since = time.time() - dias * 24 * 60 * 60
    if network_id is not None:
        por_medicion, parametros = f" AND {NET_FILTER_SQL}", (network_id,)
    else:
        por_medicion, parametros = "", ()
    por_red, _ = _filtro_red(network_id)
    connection = _connect()
    try:
        snapshot_rows = connection.execute(
            f"""
            SELECT m.ip, m.latency_ms, m.state, m.name, m.manufacturer,
                   m.manufacturer_network, m.model, m.device_type, m.mac, m.captured_at,
                   d.owner, d.notes
            FROM measurements AS m
            LEFT JOIN devices AS d ON d.id = COALESCE(m.device_id, (
                SELECT id FROM devices AS current_device
                WHERE current_device.ip = m.ip AND current_device.is_demo = FALSE
                ORDER BY current_device.last_seen DESC LIMIT 1
            ))
            JOIN (
                SELECT ip, MAX(captured_at) AS latest
                FROM measurements WHERE is_demo = FALSE{por_medicion} GROUP BY ip
            ) AS latest ON latest.ip = m.ip AND latest.latest = m.captured_at
            WHERE m.is_demo = FALSE{por_medicion.replace(" AND ", " AND m.", 1)}
            ORDER BY m.ip
            """,
            parametros * 2,
        ).fetchall()
        measurement_rows = connection.execute(
            f"""
            SELECT scan_id, captured_at, ip, latency_ms, state, name, manufacturer,
                   manufacturer_network, model, device_type, mac
            FROM measurements WHERE captured_at >= ? AND is_demo = FALSE{por_medicion}
            ORDER BY captured_at DESC
            """,
            (since, *parametros),
        ).fetchall()
        run_rows = connection.execute(
            f"SELECT scan_id FROM scan_runs WHERE captured_at >= ? AND is_demo = FALSE AND is_complete = TRUE{por_red}",
            (since, *parametros),
        ).fetchall()
        event_rows = connection.execute(
            f"""
            SELECT occurred_at, ip, device_name, event_type, previous_state,
                   current_state, description
            FROM events WHERE occurred_at >= ? AND is_demo = FALSE{por_red}
            ORDER BY occurred_at DESC
            """,
            (since, *parametros),
        ).fetchall()
        trusted_rows = connection.execute("SELECT ip, mac FROM trusted_devices WHERE is_demo = FALSE").fetchall()
    finally:
        connection.close()

    def iso(timestamp):
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()

    trusted_ips = {row["ip"]: row["mac"] for row in trusted_rows}
    trusted_macs = {
        row["mac"].lower().replace(":", "-")
        for row in trusted_rows if row["mac"]
    }

    def trust_state(ip, mac):
        normalized_mac = mac.lower().replace(":", "-") if mac else None
        known_mac = trusted_ips.get(ip)
        if normalized_mac and normalized_mac in trusted_macs:
            return "confiable"
        if ip in trusted_ips and (known_mac is None or mac is None):
            return "confiable"
        return "por_revisar"

    scan_ids = {row["scan_id"] for row in run_rows}
    stats = {}
    for row in measurement_rows:
        entry = stats.setdefault(row["ip"], {"escaneos": set(), "con_respuesta": set(), "latencias": []})
        entry["escaneos"].add(row["scan_id"])
        if row["state"] == "activo":
            entry["con_respuesta"].add(row["scan_id"])
        if row["latency_ms"] is not None:
            entry["latencias"].append(float(row["latency_ms"]))

    latest_by_ip = {row["ip"]: row for row in snapshot_rows}
    for row in measurement_rows:
        latest = latest_by_ip.get(row["ip"])
        if latest is None or row["captured_at"] > latest["captured_at"]:
            latest_by_ip[row["ip"]] = row

    summary_devices = []
    for ip, latest in latest_by_ip.items():
        summary_devices.append({
            "ip": ip, "mac": latest["mac"], "nombre": latest["name"],
            "fabricante": latest["manufacturer"], "modelo": latest["model"],
            "latest": latest,
        })

    summaries = []
    for group in _group_device_identities(summary_devices):
        latest_device = max(group, key=lambda device: device["latest"]["captured_at"])
        latest = latest_device["latest"]
        ips = sorted({device["ip"] for device in group})
        group_stats = [stats[ip] for ip in ips if ip in stats]
        observed_scans = set().union(*(entry["escaneos"] for entry in group_stats)) if group_stats else set()
        responding_scans = set().union(*(entry["con_respuesta"] for entry in group_stats)) if group_stats else set()
        latencies = [latency for entry in group_stats for latency in entry["latencias"]]
        responded = len(responding_scans)
        total_observed = len(observed_scans)
        summaries.append({
            "ip": latest["ip"], "ips": ips,
            "responsable": latest["owner"], "notas": latest["notes"],
            "mac": latest["mac"], "nombre": latest["name"],
            "fabricante": latest["manufacturer"], "fabricante_red": latest["manufacturer_network"],
            "modelo": latest["model"], "tipo": latest["device_type"],
            "estado_actual": latest["state"],
            "confianza": trust_state(latest["ip"], latest["mac"]),
            "escaneos_con_respuesta": responded,
            "escaneos_registrados": total_observed,
            "disponibilidad_pct": round(responded * 100 / total_observed, 2) if total_observed else None,
            "latencia_media_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
            "latencia_minima_ms": round(min(latencies), 2) if latencies else None,
            "latencia_maxima_ms": round(max(latencies), 2) if latencies else None,
        })
    summaries.sort(key=lambda item: (item["nombre"] or "", item["ip"]))

    return {
        "dias": dias,
        "generado_en": datetime.now(timezone.utc).isoformat(),
        "dispositivos": [
            {
                "ip": row["ip"], "latencia_ms": row["latency_ms"],
                "responsable": row["owner"], "notas": row["notes"],
                "estado": row["state"], "nombre": row["name"],
                "fabricante": row["manufacturer"],
                "fabricante_red": row["manufacturer_network"],
                "modelo": row["model"], "tipo": row["device_type"], "mac": row["mac"],
                "confianza": trust_state(row["ip"], row["mac"]),
                "ultima_medicion": iso(row["captured_at"]),
            }
            for row in snapshot_rows
        ],
        "mediciones": [
            {
                "fecha": iso(row["captured_at"]), "ip": row["ip"],
                "latencia_ms": row["latency_ms"], "estado": row["state"],
                "nombre": row["name"], "fabricante": row["manufacturer"],
                "fabricante_red": row["manufacturer_network"],
                "modelo": row["model"], "tipo": row["device_type"], "mac": row["mac"],
            }
            for row in measurement_rows
        ],
        "resumen_dispositivos": summaries,
        "escaneos_completados": len(scan_ids),
        "eventos": [
            {
                "fecha": iso(row["occurred_at"]), "ip": row["ip"],
                "nombre": row["device_name"], "tipo": row["event_type"],
                "estado_anterior": row["previous_state"],
                "estado_actual": row["current_state"],
                "mensaje": _reparar_mojibake(row["description"]),
            }
            for row in event_rows
        ],
    }


def obtener_historial(ip, limite=30):
    connection = _connect()
    try:
        rows = connection.execute(
            """
            SELECT captured_at, latency_ms, state, name, manufacturer,
                   manufacturer_network, model, device_type
            FROM measurements
            WHERE ip = ? AND is_demo = FALSE
            ORDER BY captured_at DESC
            LIMIT ?
            """,
            (ip, limite),
        ).fetchall()
    finally:
        connection.close()

    measurements = [
        {
            "fecha": datetime.fromtimestamp(row["captured_at"], timezone.utc).isoformat(),
            "latencia_ms": row["latency_ms"],
            "estado": row["state"],
            "nombre": row["name"],
            "fabricante": row["manufacturer"],
            "fabricante_red": row["manufacturer_network"],
            "modelo": row["model"],
            "tipo": row["device_type"],
        }
        for row in reversed(rows)
    ]
    return {
        "ip": ip,
        "total": len(measurements),
        "dias_retencion": RETENTION_DAYS,
        "mediciones": measurements,
    }


def obtener_historial_equipo(ips, limite=30, network_id=None):
    ips = list(dict.fromkeys(ips))
    if not ips:
        return {"ips": [], "total": 0, "dias_retencion": RETENTION_DAYS, "mediciones": []}
    placeholders = ", ".join("?" for _ in ips)
    filtro, parametros = (f" AND {NET_FILTER_SQL}", (network_id,)) if network_id is not None else ("", ())
    connection = _connect()
    try:
        rows = connection.execute(
            f"""SELECT captured_at, ip, latency_ms, state, name, manufacturer,
                       manufacturer_network, model, device_type
                FROM measurements
                WHERE ip IN ({placeholders}) AND is_demo = FALSE{filtro}
                ORDER BY captured_at DESC, id DESC
                LIMIT ?""",
            (*ips, *parametros, limite),
        ).fetchall()
    finally:
        connection.close()
    measurements = [
        {
            "fecha": datetime.fromtimestamp(row["captured_at"], timezone.utc).isoformat(),
            "ip": row["ip"], "latencia_ms": row["latency_ms"], "estado": row["state"],
            "nombre": row["name"], "fabricante": row["manufacturer"],
            "fabricante_red": row["manufacturer_network"], "modelo": row["model"],
            "tipo": row["device_type"],
        }
        for row in reversed(rows)
    ]
    return {
        "ips": ips, "total": len(measurements),
        "dias_retencion": RETENTION_DAYS, "mediciones": measurements,
    }


def obtener_datos_analisis(dias=7, puntos_por_ip=30, network_id=None):
    """Return per-IP measurement series and the trust list for the AI analysis."""
    since = time.time() - dias * 24 * 60 * 60
    filtro, parametros = (f" AND m.{NET_FILTER_SQL}", (network_id,)) if network_id is not None else ("", ())
    connection = _connect()
    try:
        rows = connection.execute(
            f"""SELECT m.ip, m.captured_at, m.state, m.latency_ms, m.mac
               FROM measurements AS m
               WHERE m.captured_at >= ? AND m.is_demo = FALSE{filtro}
               ORDER BY m.captured_at, m.id""",
            (since, *parametros),
        ).fetchall()
        trusted_rows = connection.execute(
            "SELECT ip, mac FROM trusted_devices WHERE is_demo = FALSE"
        ).fetchall()
    finally:
        connection.close()
    series = {}
    for row in rows:
        series.setdefault(row["ip"], []).append({
            "estado": row["state"], "latencia_ms": row["latency_ms"], "mac": row["mac"],
        })
    return {
        "series": {ip: points[-puntos_por_ip:] for ip, points in series.items()},
        "ips_confiables": [row["ip"] for row in trusted_rows],
        "macs_confiables": [row["mac"] for row in trusted_rows if row["mac"]],
    }
