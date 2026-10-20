# GearEye: modelo entidad–relación

El esquema PostgreSQL contiene siete tablas. Los campos `is_demo` permiten identificar los datos académicos sintéticos, que no aparecen en el inventario real de la aplicación.

```mermaid
erDiagram
    NETWORKS ||--o{ DEVICES : contiene
    NETWORKS ||--o{ SCAN_RUNS : registra
    SCAN_RUNS ||--o{ MEASUREMENTS : produce
    DEVICES ||--o{ MEASUREMENTS : recibe
    DEVICES ||--o{ EVENTS : genera
    DEVICES ||--o{ TRUSTED_DEVICES : clasifica
    DEVICES ||--o{ DIAGNOSTICS : recibe

    NETWORKS {
        bigint id PK
        text name
        text cidr UK
        text gateway
        float created_at
        boolean monitor_enabled
        integer monitor_interval_minutes
        float alert_latency_threshold_ms
        boolean alert_new_devices
        boolean alert_offline_devices
        boolean is_demo
    }
    DEVICES {
        bigint id PK
        bigint network_id FK
        text ip
        text mac
        text name
        text manufacturer
        text model
        text device_type
        text current_state
        float first_seen
        float last_seen
        text owner
        text notes
        boolean is_demo
    }
    SCAN_RUNS {
        text scan_id PK
        bigint network_id FK
        float captured_at
        boolean is_complete
        boolean is_demo
    }
    MEASUREMENTS {
        bigint id PK
        text scan_id FK
        bigint device_id FK
        text ip
        float captured_at
        float latency_ms
        text state
        boolean is_demo
    }
    EVENTS {
        bigint id PK
        bigint device_id FK
        text ip
        text event_type
        text previous_state
        text current_state
        float occurred_at
        float acknowledged_at
        boolean is_demo
    }
    TRUSTED_DEVICES {
        text ip PK
        bigint device_id FK
        text mac
        text device_name
        float trusted_at
        boolean is_demo
    }
    DIAGNOSTICS {
        bigint id PK
        bigint device_id FK
        text ip
        text level
        text message
        text recommendation
        float latency_ms
        float created_at
        boolean is_demo
    }
```

## Vistas materializadas

- `mv_device_performance`: mediciones, cantidad de respuestas y latencias media, mínima y máxima por dirección IP.
- `mv_network_daily_summary`: escaneos completos, equipos y latencia media por red y día.

GearEye las refresca después de guardar cada escaneo en PostgreSQL. PostgreSQL conserva el resultado materializado y lo vuelve a calcular con `REFRESH MATERIALIZED VIEW` cuando se solicita; la aplicación realiza esa actualización automáticamente al terminar cada escaneo.

El archivo [`../Database/modelo_geareye_postgresql.sql`](../Database/modelo_geareye_postgresql.sql) contiene el esquema ejecutable. [`../Database/seed_demo_postgresql.sql`](../Database/seed_demo_postgresql.sql) genera 100 filas sintéticas por tabla, y [`../Database/verificar_requisitos.sql`](../Database/verificar_requisitos.sql) comprueba las cantidades y las vistas.
