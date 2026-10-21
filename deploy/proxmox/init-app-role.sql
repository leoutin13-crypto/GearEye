\getenv geareye_app_password GEAREYE_DB_PASSWORD

CREATE ROLE geareye_app LOGIN PASSWORD :'geareye_app_password';
GRANT CONNECT, TEMPORARY ON DATABASE geareye TO geareye_app;
GRANT CREATE ON DATABASE geareye TO geareye_app;
GRANT USAGE, CREATE ON SCHEMA public TO geareye_app;
