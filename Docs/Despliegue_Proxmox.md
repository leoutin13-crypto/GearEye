# Publicar GearEye en Proxmox

Esta guía prepara GearEye como servicio central para varias empresas. El servidor central puede funcionar en Debian; el agente que descubre equipos debe ejecutarse en Windows dentro de la red de cada empresa, porque el descubrimiento actual usa PowerShell.

## Arquitectura prevista

- Proxmox ejecuta una VM Debian conectada a un bridge de red (normalmente `vmbr0`).
- Docker Compose ejecuta GearEye, PostgreSQL y el conector Cloudflare Tunnel dentro de la VM.
- Cloudflare Tunnel publica `https://geareye.TU-DOMINIO` sin abrir puertos de entrada en el router ni exponer el panel de Proxmox.
- Cada agente Windows envía sus escaneos a ese dominio por HTTPS.

La administración general abre directamente la pantalla de empresas y usuarios. El servidor central no intenta escanear su propia red.

## 1. Conseguir y preparar el dominio

Primero confirma si la organización ya tiene un dominio y autorización para crear un subdominio, por ejemplo `geareye.empresa.com`. Si no existe, alguien autorizado debe registrar uno. No se puede generar un dominio público real solo desde el código.

Para esta guía, el DNS del dominio se administrará con Cloudflare:

1. Añade el dominio a una cuenta Cloudflare autorizada.
2. Si el dominio ya está registrado en otro proveedor, cambia sus nameservers allí por los que indique Cloudflare. Esto no transfiere el registro del dominio; delega el DNS.
3. Sigue la sección siguiente para asociar el subdominio al túnel. Cloudflare creará el registro DNS del hostname del túnel.

Cloudflare Tunnel enlaza un hostname público con el servicio privado y permite apuntar el origen a GearEye por HTTP dentro de la red de contenedores. [Documentación de aplicaciones publicadas](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/) y [registros DNS del túnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/dns/).

## 2. Crear la VM en Proxmox

Como punto de partida, crea una VM Debian 13 o Debian 12 con 2 vCPU, 4 GB de RAM y 40 GB de disco. Conéctala al bridge que tenga salida a Internet y reserva una dirección LAN en el router para que la VM sea fácil de administrar. Proxmox conecta las VMs mediante bridges virtuales, que funcionan como switches para sus interfaces. [Guía oficial de red de Proxmox VE](https://pve.proxmox.com/pve-docs/pve-admin-guide.pdf).

En la consola de la VM, instala Docker Engine y el plugin Docker Compose siguiendo la [guía oficial para Debian](https://docs.docker.com/engine/install/debian/). La VM debe poder salir a Internet para descargar imágenes y mantener el túnel conectado.

## 3. Copiar el proyecto e iniciar la configuración

Coloca una copia actualizada del repositorio dentro de la VM. Desde la carpeta del proyecto:

```bash
cd deploy/proxmox
cp .env.example .env
openssl rand -hex 32
```

Edita `deploy/proxmox/.env`:

- `GEAREYE_DB_ADMIN_PASSWORD` y `GEAREYE_DB_PASSWORD`: genera una cadena distinta para cada una con `openssl rand -hex 32`.
- `GEAREYE_PUBLIC_URL`: escribe el hostname final, por ejemplo `https://geareye.empresa.com`.
- Las variables SMTP: usa los datos SMTP reales del proveedor de correo.
- `CLOUDFLARE_TUNNEL_TOKEN`: lo obtendrás al crear el túnel en el siguiente paso.

No uses `.env.example` directamente ni compartas `.env`: contiene credenciales.

## 4. Crear el túnel y su hostname

En Cloudflare Zero Trust, [crea un túnel](https://developers.cloudflare.com/tunnel/get-started/) y añade una ruta de aplicación pública:

- Hostname: el mismo valor de `GEAREYE_PUBLIC_URL`, sin `https://`.
- Servicio de origen: `http://geareye:8000`.

Copia el token del conector en `CLOUDFLARE_TUNNEL_TOKEN` en `.env`. El servicio `cloudflared` y GearEye comparten una red Docker privada. No hace falta abrir los puertos 80, 443 ni 8000 hacia Internet. No pongas el panel de administración de Proxmox detrás de ese hostname.

No actives un inicio de sesión interactivo de Cloudflare Access en este hostname: el agente de red se autentica con su propio token de GearEye y no puede completar un formulario web de Access.

## 5. Iniciar GearEye

Desde `deploy/proxmox`:

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f geareye
```

Cuando el túnel esté conectado, abre `GEAREYE_PUBLIC_URL/app/`. Consulta el log de inicio para obtener la clave única de configuración (`docker compose logs geareye`), completa el alta inicial del administrador general y configura el autenticador. Luego crea cada empresa desde **Administración**. GearEye enviará a su administrador un correo con la invitación y los comandos para instalar su agente.

## 6. Copias de seguridad

La base de datos PostgreSQL y el estado de autenticación viven en volúmenes persistentes de Docker. Programa respaldos fuera de la VM y conserva una copia de `.env` en un gestor de secretos. Una copia del disco de la VM ayuda a recuperar el servicio, pero no reemplaza los respaldos de PostgreSQL.

## Pendiente antes de publicar

- Elegir/autorizar el dominio y la cuenta que administrará Cloudflare DNS.
- Crear la VM y obtener acceso a su consola.
- Conseguir el token del túnel y credenciales SMTP.
- Sustituir todos los valores de ejemplo en `.env`.
