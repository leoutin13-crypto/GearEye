-- Dataset academico sintetico: exactamente 100 filas demostrativas por tabla.
-- Direcciones TEST-NET; no representan equipos ni trafico reales.
BEGIN;

DELETE FROM trusted_devices WHERE is_demo = TRUE;
DELETE FROM diagnostics WHERE is_demo = TRUE;
DELETE FROM events WHERE is_demo = TRUE;
DELETE FROM measurements WHERE is_demo = TRUE;
DELETE FROM scan_runs WHERE is_demo = TRUE;
DELETE FROM devices WHERE is_demo = TRUE;
DELETE FROM networks WHERE is_demo = TRUE;

INSERT INTO networks(name, cidr, gateway, created_at, is_demo)
SELECT 'DEMO-RD-' || lpad(n::text, 3, '0'),
       '198.51.100.' || (n + 1)::text || '/32', NULL,
       extract(epoch FROM now() - ((100 - n) * interval '1 hour')), TRUE
FROM generate_series(1, 100) AS g(n);

INSERT INTO devices(
    network_id, ip, mac, name, manufacturer, manufacturer_network,
    model, device_type, current_state, first_seen, last_seen, is_demo
)
SELECT nw.id, '198.51.100.' || (g.n + 1)::text,
       '02-00-00-00-' || lpad(to_hex(g.n / 256), 2, '0') || '-' || lpad(to_hex(g.n % 256), 2, '0'),
       'DEMO-EQUIPO-' || lpad(g.n::text, 3, '0'), 'Fabricante de demostracion',
       'Fabricante de demostracion', 'MODELO-DEMO',
       CASE WHEN g.n % 2 = 0 THEN 'computador' ELSE 'desconocido' END,
       CASE WHEN g.n % 5 = 0 THEN 'detectado' ELSE 'activo' END,
       extract(epoch FROM now() - ((100 - g.n) * interval '1 hour')),
       extract(epoch FROM now() - ((100 - g.n) * interval '1 hour')), TRUE
FROM generate_series(1, 100) AS g(n)
JOIN networks AS nw ON nw.name = 'DEMO-RD-' || lpad(g.n::text, 3, '0');

INSERT INTO scan_runs(scan_id, captured_at, network_id, is_demo, is_complete)
SELECT 'demo-scan-' || lpad(g.n::text, 3, '0'),
       extract(epoch FROM now() - ((100 - g.n) * interval '1 hour')),
       nw.id, TRUE, TRUE
FROM generate_series(1, 100) AS g(n)
JOIN networks AS nw ON nw.name = 'DEMO-RD-' || lpad(g.n::text, 3, '0');

INSERT INTO measurements(
    scan_id, captured_at, ip, latency_ms, state, name, manufacturer,
    manufacturer_network, model, device_type, mac, device_id, is_demo
)
SELECT 'demo-scan-' || lpad(g.n::text, 3, '0'),
       extract(epoch FROM now() - ((100 - g.n) * interval '1 hour')),
       d.ip, CASE WHEN g.n % 5 = 0 THEN NULL ELSE 15 + (g.n % 90) END,
       d.current_state, d.name, d.manufacturer, d.manufacturer_network,
       d.model, d.device_type, d.mac, d.id, TRUE
FROM generate_series(1, 100) AS g(n)
JOIN devices AS d ON d.name = 'DEMO-EQUIPO-' || lpad(g.n::text, 3, '0') AND d.is_demo = TRUE;

INSERT INTO events(
    occurred_at, ip, device_name, event_type, previous_state,
    current_state, description, device_id, is_demo
)
SELECT extract(epoch FROM now() - ((100 - g.n) * interval '1 hour')),
       d.ip, d.name, 'evento_demostrativo', NULL, d.current_state,
       'Evento sintetico de ejemplo ' || g.n::text, d.id, TRUE
FROM generate_series(1, 100) AS g(n)
JOIN devices AS d ON d.name = 'DEMO-EQUIPO-' || lpad(g.n::text, 3, '0') AND d.is_demo = TRUE;

INSERT INTO trusted_devices(ip, mac, device_name, trusted_at, device_id, is_demo)
SELECT d.ip, d.mac, d.name,
       extract(epoch FROM now() - ((100 - g.n) * interval '1 hour')),
       d.id, TRUE
FROM generate_series(1, 100) AS g(n)
JOIN devices AS d ON d.name = 'DEMO-EQUIPO-' || lpad(g.n::text, 3, '0') AND d.is_demo = TRUE;

INSERT INTO diagnostics(
    device_id, ip, level, message, recommendation,
    latency_ms, observations, created_at, is_demo
)
SELECT d.id, d.ip, CASE WHEN g.n % 5 = 0 THEN 'informativo' ELSE 'normal' END,
       'Diagnostico demostrativo ' || g.n::text,
       'Dato sintetico para demostrar el modelo de datos.',
       CASE WHEN g.n % 5 = 0 THEN 0 ELSE 15 + (g.n % 90) END,
       'No corresponde a un dispositivo real.',
       extract(epoch FROM now() - ((100 - g.n) * interval '1 hour')), TRUE
FROM generate_series(1, 100) AS g(n)
JOIN devices AS d ON d.name = 'DEMO-EQUIPO-' || lpad(g.n::text, 3, '0') AND d.is_demo = TRUE;

REFRESH MATERIALIZED VIEW mv_device_performance;
REFRESH MATERIALIZED VIEW mv_network_daily_summary;
COMMIT;
