"""Copy the local GearEye history into an empty PostgreSQL database."""

import sqlite3

from Backend.Services.Database import uses_postgresql
from Backend.Services.Historial import (
    DATABASE as SQLITE_DATABASE,
    _connect,
    _connect_sqlite,
    _refresh_postgresql_views,
)


TABLE_COLUMNS = {
    "networks": (
        "id", "name", "cidr", "gateway", "created_at", "monitor_enabled",
        "monitor_interval_minutes", "alert_latency_threshold_ms", "alert_new_devices",
        "alert_offline_devices", "is_demo",
    ),
    "devices": (
        "id", "network_id", "ip", "mac", "name", "manufacturer",
        "manufacturer_network", "model", "device_type", "current_state",
        "first_seen", "last_seen", "owner", "notes", "is_demo",
    ),
    "scan_runs": ("scan_id", "captured_at", "network_id", "is_demo", "is_complete"),
    "measurements": (
        "id", "scan_id", "captured_at", "ip", "latency_ms", "state", "name",
        "manufacturer", "manufacturer_network", "model", "device_type", "mac",
        "device_id", "is_demo",
    ),
    "events": (
        "id", "occurred_at", "ip", "device_name", "event_type", "previous_state",
        "current_state", "description", "acknowledged_at", "device_id", "is_demo",
    ),
    "trusted_devices": ("ip", "mac", "device_name", "trusted_at", "device_id", "is_demo"),
    "diagnostics": (
        "id", "device_id", "ip", "level", "message", "recommendation",
        "latency_ms", "observations", "created_at", "is_demo",
    ),
}


def main():
    if not uses_postgresql():
        raise SystemExit("Configura GEAREYE_DATABASE_URL en .env antes de migrar.")
    if not SQLITE_DATABASE.exists():
        raise SystemExit(f"No se encontro la base SQLite: {SQLITE_DATABASE}")

    # Apply SQLite's additive migrations before reading a legacy data file.
    sqlite_schema = _connect_sqlite()
    # _connect_sqlite backfills old scan_runs rows; persist those changes before
    # opening the independent read-only source connection below.
    sqlite_schema.commit()
    sqlite_schema.close()
    source = sqlite3.connect(SQLITE_DATABASE)
    source.row_factory = sqlite3.Row
    target = _connect()
    try:
        occupied = {
            table: target.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"]
            for table in TABLE_COLUMNS
        }
        if any(occupied.values()):
            raise SystemExit(
                "La base PostgreSQL ya contiene registros. La migracion solo escribe en una base vacia."
            )

        copied = {}
        with target:
            for table, columns in TABLE_COLUMNS.items():
                rows = source.execute(f"SELECT {', '.join(columns)} FROM {table}").fetchall()
                if rows:
                    placeholders = ", ".join("?" for _ in columns)
                    statement = (
                        f"INSERT INTO {table} ({', '.join(columns)}) "
                        f"VALUES ({placeholders}) ON CONFLICT DO NOTHING"
                    )
                    values = [
                        tuple(
                            bool(row[column])
                            if column in {"is_demo", "is_complete", "monitor_enabled", "alert_new_devices", "alert_offline_devices"}
                            else row[column]
                            for column in columns
                        )
                        for row in rows
                    ]
                    target.executemany(statement, values)
                copied[table] = len(rows)

            for table in ("networks", "devices", "measurements", "events", "diagnostics"):
                target.execute(
                    f"""SELECT setval(
                        pg_get_serial_sequence('{table}', 'id'),
                        COALESCE(MAX(id), 1), COUNT(*) > 0
                    ) FROM {table}"""
                )

        _refresh_postgresql_views(target)

        print("Migracion terminada. Filas copiadas:")
        for table, count in copied.items():
            print(f"  {table}: {count}")
        print("Los datos de SQLite se conservaron; su esquema se actualizó de forma aditiva.")
    finally:
        source.close()
        target.close()


if __name__ == "__main__":
    main()
