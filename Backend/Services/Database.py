"""Database configuration and small DB-API compatibility layer."""

import os
import sqlite3
from pathlib import Path


try:
    from dotenv import load_dotenv

    local_app_data = Path(
        os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
    )
    default_private_env = local_app_data / "GearEye" / ".env"
    private_env = Path(os.environ.get("GEAREYE_ENV_FILE", default_private_env))
    load_dotenv(private_env, override=False)
except ImportError:
    pass

DATABASE_URL = os.environ.get("GEAREYE_DATABASE_URL", "").strip()

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None


DATABASE_ERRORS = (sqlite3.Error,) + ((psycopg.Error,) if psycopg else ())
DATABASE_CONFIGURATION_ERRORS = (RuntimeError,)
DATABASE_CONNECTION_ERRORS = (*DATABASE_ERRORS, *DATABASE_CONFIGURATION_ERRORS)
STORAGE_ERRORS = (OSError, *DATABASE_ERRORS, *DATABASE_CONFIGURATION_ERRORS)


class PostgresConnection:
    """Expose execute/executemany and SQLite-style question mark parameters."""

    def __init__(self, connection):
        self._connection = connection

    def execute(self, statement, parameters=()):
        return self._connection.execute(statement.replace("?", "%s"), parameters)

    def executemany(self, statement, parameter_sets):
        cursor = self._connection.cursor()
        cursor.executemany(statement.replace("?", "%s"), parameter_sets)
        return cursor

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self._connection.commit()
        else:
            self._connection.rollback()
        return False

    def commit(self):
        self._connection.commit()

    def close(self):
        self._connection.close()


def uses_postgresql():
    return bool(DATABASE_URL)


def backend_name():
    return "PostgreSQL" if uses_postgresql() else "SQLite local"


def connect_postgresql():
    if psycopg is None:
        raise RuntimeError(
            "PostgreSQL est\u00e1 configurado, pero falta psycopg. Ejecuta: pip install -r requirements.txt"
        )
    connection = psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=5,
        application_name="GearEye",
    )
    return PostgresConnection(connection)
