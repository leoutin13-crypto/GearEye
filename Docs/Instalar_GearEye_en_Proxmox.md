# Instalar GearEye en una VM de Proxmox con Docker

Esta guía usa una **máquina virtual Debian nueva** para el servidor GearEye. No instala Docker en el host de Proxmox ni depende del Debian que está fallando. GearEye, PostgreSQL y Cloudflare Tunnel corren en Docker dentro de la VM. El agente de descubrimiento corre en un equipo Windows conectado por Ethernet a la red que se desea monitorear.

## Antes de empezar

- Acceso a Proxmox y salida a Internet desde la VM.
- ISO oficial de Debian 12 o 13 y un repositorio Git accesible.
- Para acceso público: túnel Cloudflare con token y hostname configurado. El archivo Compose actual requiere estos datos.
- Para enviar invitaciones por correo: credenciales SMTP válidas.
- Para ver puertos físicos: switch gestionable con LLDP habilitado y credenciales SNMP de solo lectura configuradas en el agente Windows.

No compartas los archivos `.env`, tokens Cloudflare, tokens de agente ni credenciales SNMP.

## 1. Crear una VM Debian limpia

En Proxmox, usa **Create VM** (no **Create CT**):

1. Selecciona la ISO de Debian 12 o 13 y el tipo Linux.
2. Asigna 2 núcleos, 4 GB de RAM y un disco de 40 GB como punto de partida.
3. En Network, selecciona el bridge conectado a la LAN, normalmente `vmbr0`, y el modelo VirtIO.
4. Instala Debian con OpenSSH Server y utilidades estándar.
5. En Proxmox, abre **VM → Options → Start at boot** y actívalo.
6. Desde Debian, comprueba Internet y anota la IP: `ip -4 addr`.

Conserva la VM vieja hasta verificar que GearEye y sus datos funcionan en la nueva. Si el instalador de Debian no tiene Internet, primero revisa la interfaz, gateway y DNS de la VM; Docker todavía no es el siguiente paso.

## 2. Instalar Docker Engine y Compose

En la consola de la VM, como `root` o anteponiendo `sudo`, ejecuta el repositorio oficial de Docker para Debian:

```bash
apt update
apt install -y ca-certificates curl git
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: $(. /etc/os-release && echo "$VERSION_CODENAME")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
docker run hello-world
docker compose version
```

Si `apt update` no resuelve nombres, corrige la conectividad DNS/gateway de la VM antes de continuar. No cambies DNS al azar: usa el gateway/DNS real de la red.

## 3. Descargar el código y crear secretos

Usa la URL de GitHub del proyecto. En este ejemplo es el repositorio que ya se clonó antes:

```bash
git clone https://github.com/leoutin13-crypto/GearEye.git /opt/geareye
cd /opt/geareye/deploy/proxmox
cp .env.example .env
chmod 600 .env
openssl rand -hex 32
openssl rand -hex 32
nano .env
```

En `.env`, reemplaza los dos valores de contraseña de PostgreSQL con las dos cadenas generadas. Configura también:

- `GEAREYE_PUBLIC_URL`: URL pública HTTPS que usarán las personas y los agentes.
- `CLOUDFLARE_TUNNEL_TOKEN`: token del conector del túnel.
- `GEAREYE_SMTP_*`: datos del proveedor de correo; sin un SMTP válido no se enviarán las invitaciones.

No subas `.env` al repositorio. Para que la VM reciba los cambios recientes del código, estos primero deben estar en el repositorio al que apunta `git clone`; clonar de nuevo no copia cambios que solo existan en el computador de desarrollo.

## 4. Configurar el túnel

En Cloudflare Zero Trust, crea o reutiliza un túnel y configura una ruta pública:

- Hostname: el mismo hostname de `GEAREYE_PUBLIC_URL`, sin `https://`.
- Servicio: `http://geareye:8000`.

Pega el token en `CLOUDFLARE_TUNNEL_TOKEN`. No abras los puertos 8006 de Proxmox ni 8000 de GearEye en el router. No pongas el panel de Proxmox detrás del túnel. No habilites una pantalla interactiva de Cloudflare Access delante de GearEye mientras los agentes usen la API.

Un Quick Tunnel gratuito entrega un hostname temporal; puede cambiar cuando el túnel se detiene. Para mantener una dirección estable se necesita un túnel nombrado y un hostname DNS que controles.

## 5. Construir e iniciar GearEye

```bash
cd /opt/geareye/deploy/proxmox
docker compose config
docker compose up -d --build
docker compose ps
docker compose logs --tail=100 geareye
docker compose logs --tail=50 cloudflared
```

Abre `GEAREYE_PUBLIC_URL/app/`. Obtén la clave de primera configuración del log de GearEye y úsala una sola vez para crear la cuenta administradora. Configura el autenticador de dos factores. Si la página no carga, revisa `docker compose ps` y los logs de `geareye` y `cloudflared`.

Los contenedores tienen `restart: unless-stopped`. Junto con **Start at boot** de la VM, Docker inicia GearEye, PostgreSQL y el túnel después de reiniciar Proxmox.

## 6. Instalar el agente en la LAN Ethernet

El servidor central no está conectado automáticamente a la LAN de cada cliente. Instala el agente en un PC Windows que sí esté conectado por Ethernet a la red y déjalo encendido mientras se requiere el monitoreo. Usa los comandos de instalación y token de agente que entrega GearEye al registrar la empresa.

Para habilitar topología física, en ese PC crea el archivo privado `%LOCALAPPDATA%\GearEye\.env` usando como referencia `.env.example` de la raíz del repositorio. Configura allí:

- `GEAREYE_SERVER_URL` y `GEAREYE_AGENT_TOKEN` del agente de esa empresa.
- Preferiblemente SNMPv3, un usuario de solo lectura, autenticación SHA-256 y privacidad AES-128. Configura `GEAREYE_SNMP_VERSION=3`, `GEAREYE_SNMP_V3_USER`, `GEAREYE_SNMP_V3_AUTH_KEY` y `GEAREYE_SNMP_V3_PRIV_KEY`.
- Las IP de administración de switches en `GEAREYE_SNMP_TARGETS`, separadas por coma. Es útil cuando el equipo no puede identificarlos automáticamente.
- Habilita LLDP en los switches y permite desde el PC agente el tráfico SNMP UDP/161 hacia las IP de administración.

Si el switch solo admite SNMPv2c, usa una comunidad de **solo lectura** y limita en el switch el acceso SNMP a la IP del agente. No uses la comunidad pública ni la escribas en el navegador o en el servidor público.

Después de iniciar el agente y ejecutar un escaneo, GearEye dibuja los vecinos LLDP y los puertos que reportó el switch. Si no aparecen, revisa el estado de topología en el mapa: GearEye indica si faltan credenciales, si no alcanzó el switch o si el switch no publica vecinos LLDP. No se inventan puertos para equipos sin LLDP.

## 7. Actualizar después de publicar una versión

Haz primero una copia de seguridad. En la VM:

```bash
cd /opt/geareye
git pull
cd deploy/proxmox
docker compose up -d --build
docker compose ps
```

Los volúmenes `geareye_postgres` y `geareye_data` conservan la base de datos y el estado de la aplicación al reconstruir los contenedores. Respáldalos periódicamente fuera de la VM.

## Si la Debian actual está dañada

Crea esta VM nueva en paralelo, comprueba que tenga Internet, instala Docker y despliega allí. No borres ni reutilices discos existentes hasta decidir qué datos necesitas rescatar. Si la versión nueva arranca, cambia el destino de Cloudflare Tunnel a ella y valida el acceso antes de retirar la VM anterior.
