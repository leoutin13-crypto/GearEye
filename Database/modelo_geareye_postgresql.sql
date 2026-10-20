-- Esquema GearEye: siete tablas y dos vistas materializadas.
-- La aplicacion tambien crea y actualiza este esquema al conectarse.
CREATE TABLE IF NOT EXISTS networks (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    cidr TEXT NOT NULL UNIQUE,
    gateway TEXT,
    created_at DOUBLE PRECISION NOT NULL,
    is_demo BOOLEAN NOT NULL DEFAULT FALSE,
    monitor_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    monitor_interval_minutes INTEGER NOT NULL DEFAULT 5,
    alert_latency_threshold_ms DOUBLE PRECISION NOT NULL DEFAULT 300,
    alert_new_devices BOOLEAN NOT NULL DEFAULT TRUE,
    alert_offline_devices BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS devices (
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
);

CREATE TABLE IF NOT EXISTS scan_runs (
    scan_id TEXT PRIMARY KEY,
    captured_at DOUBLE PRECISION NOT NULL,
    network_id BIGINT REFERENCES networks(id),
    is_demo BOOLEAN NOT NULL DEFAULT FALSE,
    is_complete BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS measurements (
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
);

CREATE TABLE IF NOT EXISTS events (
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
);

CREATE TABLE IF NOT EXISTS trusted_devices (
    ip TEXT PRIMARY KEY,
    mac TEXT,
    device_name TEXT,
    trusted_at DOUBLE PRECISION NOT NULL,
    device_id BIGINT REFERENCES devices(id),
    is_demo BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS diagnostics (
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
);

CREATE INDEX IF NOT EXISTS idx_measurements_ip_time ON measurements(ip, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_measurements_device_time ON measurements(device_id, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_devices_network_ip ON devices(network_id, ip);

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_device_performance AS
SELECT m.ip,
       COALESCE(d.name, MAX(m.name)) AS device_name,
       COALESCE(d.is_demo, m.is_demo) AS is_demo,
       COUNT(*) AS measurement_count,
       COUNT(*) FILTER (WHERE m.state = 'activo') AS active_count,
       AVG(m.latency_ms) AS average_latency_ms,
       MIN(m.latency_ms) AS minimum_latency_ms,
       MAX(m.latency_ms) AS maximum_latency_ms,
       MAX(m.captured_at) AS last_seen
FROM measurements AS m
LEFT JOIN devices AS d ON d.id = m.device_id
GROUP BY m.ip, d.name, d.is_demo, m.is_demo;

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_network_daily_summary AS
SELECT COALESCE(n.name, 'Red historica sin clasificar') AS network_name,
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
GROUP BY n.name, n.cidr, n.is_demo, sr.is_demo, to_timestamp(sr.captured_at)::date;
