-- Revisa los registros DEMO por tabla y confirma que existan las vistas materializadas.
SELECT COUNT(*) AS tablas_geareye
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN (
      'networks', 'devices', 'scan_runs', 'measurements',
      'events', 'trusted_devices', 'diagnostics'
  );

SELECT 'networks' AS tabla, COUNT(*) AS filas_demo FROM networks WHERE is_demo = TRUE
UNION ALL SELECT 'devices', COUNT(*) FROM devices WHERE is_demo = TRUE
UNION ALL SELECT 'scan_runs', COUNT(*) FROM scan_runs WHERE is_demo = TRUE
UNION ALL SELECT 'measurements', COUNT(*) FROM measurements WHERE is_demo = TRUE
UNION ALL SELECT 'events', COUNT(*) FROM events WHERE is_demo = TRUE
UNION ALL SELECT 'trusted_devices', COUNT(*) FROM trusted_devices WHERE is_demo = TRUE
UNION ALL SELECT 'diagnostics', COUNT(*) FROM diagnostics WHERE is_demo = TRUE
ORDER BY tabla;

SELECT schemaname, matviewname
FROM pg_matviews
WHERE schemaname = 'public'
  AND matviewname IN ('mv_device_performance', 'mv_network_daily_summary')
ORDER BY matviewname;

SELECT 'mv_device_performance' AS vista, COUNT(*) AS filas FROM mv_device_performance
UNION ALL
SELECT 'mv_network_daily_summary', COUNT(*) FROM mv_network_daily_summary;
