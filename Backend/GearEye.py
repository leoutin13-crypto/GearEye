from pathlib import Path
from ipaddress import IPv4Address, IPv4Network
from datetime import datetime, timezone
import logging
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from Backend.Models.Dispositivo import Dispositivo, ListaDispositivos
from Backend.Models.Diagnostico import ResultadoDiagnostico

from Backend.Services.Red import (
    comprobar_dispositivo,
    descubrir_red_local,
    obtener_configuracion_red_local,
)

from Backend.Services.Diagnostico import analizar_dispositivo, analizar_red_avanzado
from Backend.Services.Database import (
    DATABASE_CONFIGURATION_ERRORS,
    DATABASE_CONNECTION_ERRORS,
    DATABASE_ERRORS,
    STORAGE_ERRORS,
    backend_name,
)
from Backend.Services.Historial import (
    guardar_escaneo,
    obtener_historial,
    obtener_eventos,
    obtener_datos_informe,
    registrar_eventos_escaneo,
    aplicar_confianza,
    obtener_alertas,
    reconocer_alerta,
    actualizar_confianza,
    obtener_identidad_escaneada,
    verificar_base_datos,
    registrar_diagnostico,
    obtener_configuracion_operativa,
    guardar_configuracion_operativa,
    guardar_notas_dispositivo,
    obtener_notas_dispositivo,
    obtener_eventos_exportables,
    obtener_metadatos_dispositivos,
    obtener_inventario_conocido,
    obtener_red_reciente,
)
from Backend import Authentication as auth
from Backend.Services.TenantContext import active_company_id

app = FastAPI(
    title="GearEye API",
    version="0.1"
)
logger = logging.getLogger("geareye.history")


class ConfianzaRequest(BaseModel):
    confiable: bool


class ConfiguracionOperativa(BaseModel):
    monitoreo_activo: bool
    intervalo_minutos: Literal[1, 5, 15, 30]
    umbral_latencia_ms: float = Field(ge=10, le=10000)
    alertar_dispositivo_nuevo: bool
    alertar_dispositivo_ausente: bool


class NotasDispositivoRequest(BaseModel):
    responsable: str = Field(default="", max_length=120)
    notas: str = Field(default="", max_length=2000)


class AgentScanRequest(BaseModel):
    subred: IPv4Network
    puerta_enlace: IPv4Address | None = None
    dispositivos: list[Dispositivo] = Field(max_length=4096)


def subred_operativa(configuracion):
    red = configuracion["red"]
    if red.num_addresses > 256:
        return str(IPv4Network(f"{configuracion['ip']}/24", strict=False))
    return str(red)


def subred_sesion(usuario):
    if usuario.get("company_id", "default") != "default":
        red = obtener_red_reciente()
        return red["cidr"] if red else None
    configuracion = obtener_configuracion_red_local()
    return subred_operativa(configuracion) if configuracion else None

app.mount(
    "/app",
    StaticFiles(directory=Path(__file__).resolve().parent.parent / "Frontend", html=True),
    name="frontend",
)
app.mount(
    "/manual",
    StaticFiles(directory=Path(__file__).resolve().parent.parent / "Docs", html=True),
    name="manual",
)


@app.get("/api/estado")
def estado_servicio(_user: str = Depends(auth.require_user)):
    try:
        verificar_base_datos()
        return {"api": "operativa", "base_datos": backend_name(), "conectada": True}
    except DATABASE_CONNECTION_ERRORS as error:
        logger.exception("No se pudo conectar con %s", backend_name())
        raise HTTPException(status_code=503, detail=f"No hay conexi?n con {backend_name()}.") from error


@app.post("/agent/report")
def recibir_escaneo_agente(payload: AgentScanRequest, x_geareye_agent_token: str | None = Header(default=None)):
    company = auth.company_for_agent_token(x_geareye_agent_token)
    if not company:
        raise HTTPException(status_code=401, detail="Credencial de agente inválida.")
    if any(IPv4Address(device.ip) not in payload.subred for device in payload.dispositivos):
        raise HTTPException(status_code=422, detail="El escaneo incluye equipos fuera de la subred declarada.")
    active_company_id.set(company["id"])
    cidr = str(payload.subred)
    try:
        registrar_eventos_escaneo(payload.dispositivos, cidr)
        guardar_escaneo(payload.dispositivos, cidr, str(payload.puerta_enlace) if payload.puerta_enlace else None)
    except STORAGE_ERRORS as error:
        logger.exception("El agente no pudo guardar el escaneo de %s", company["name"])
        raise HTTPException(status_code=503, detail="No se pudo guardar el escaneo recibido.") from error
    return {"ok": True, "empresa": company["name"], "dispositivos": len(payload.dispositivos)}


@app.get("/auth/status")
def estado_autenticacion(request: Request):
    return auth.status(request)


@app.post("/auth/setup")
def configurar_cuenta(payload: auth.SetupRequest, request: Request):
    return auth.setup_account(payload, request)


@app.post("/auth/confirm-setup")
def confirmar_configuracion(
    payload: auth.CodeRequest,
    response: Response,
    request: Request,
):
    return auth.confirm_setup(payload, response, request)


@app.post("/auth/login")
def iniciar_sesion(payload: auth.LoginRequest, request: Request):
    return auth.begin_login(payload, request)


@app.post("/auth/verify")
def verificar_codigo(
    payload: auth.VerifyRequest,
    response: Response,
    request: Request,
):
    return auth.verify_login(payload, response, request)


@app.get("/auth/admin/overview")
def resumen_administracion(_user: dict = Depends(auth.require_user)):
    return auth.admin_overview(_user)


@app.post("/auth/admin/companies")
def crear_empresa(payload: auth.CompanyRequest, _user: dict = Depends(auth.require_user)):
    return auth.create_company(_user, payload)


@app.post("/auth/admin/invitations")
def invitar_usuario(payload: auth.InviteRequest, request: Request, _user: dict = Depends(auth.require_user)):
    return auth.invite_user(_user, payload, request)


@app.post("/auth/accept-invitation")
def aceptar_invitacion(payload: auth.AcceptInviteRequest, request: Request):
    return auth.accept_invite(payload, request)


@app.post("/auth/confirm-invitation/{token}")
def confirmar_invitacion(token: str, payload: auth.CodeRequest, response: Response, request: Request):
    return auth.confirm_invite(token, payload, response, request)


@app.post("/auth/logout")
def cerrar_sesion(response: Response, request: Request):
    return auth.logout(response, request)


@app.post("/auth/activity")
def registrar_actividad(_user: str = Depends(auth.require_user)):
    return {"ok": True}

@app.get("/")
def inicio():
    return {
        "proyecto": "GearEye",
        "version": "0.1",
        "mensaje": "API funcionando correctamente"
    }

@app.get(
    "/api/dispositivos",
    response_model=ListaDispositivos
)
def obtener_dispositivos(_user: str = Depends(auth.require_user)):
    try:
        verificar_base_datos()
        if _user.get("company_id", "default") != "default":
            historial = obtener_inventario_conocido()
            dispositivos = [Dispositivo(**device) for device in historial["dispositivos"]]
            red = obtener_red_reciente() or {}
            return {
                "total": len(dispositivos), "dispositivos": dispositivos,
                "puerta_enlace": red.get("gateway"), "ip_local": None,
                "subred": red.get("cidr"),
            }
        escaneo = descubrir_red_local()
        dispositivos = aplicar_confianza(escaneo["dispositivos"])
        metadatos = obtener_metadatos_dispositivos([device.ip for device in dispositivos])
        for device in dispositivos:
            metadata = metadatos.get(device.ip, {})
            device.responsable = metadata.get("responsable")
            device.notas = metadata.get("notas")
    except DATABASE_CONFIGURATION_ERRORS as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except DATABASE_ERRORS as error:
        logger.exception("No se pudo consultar el inventario confiable")
        raise HTTPException(status_code=503, detail="El inventario confiable no estÃ¡ disponible por el momento.") from error

    try:
        registrar_eventos_escaneo(dispositivos, escaneo.get("subred"))
        guardar_escaneo(dispositivos, escaneo.get("subred"), escaneo.get("puerta_enlace"))
    except STORAGE_ERRORS:
        logger.exception("No se pudo guardar el historial del escaneo")

    return {
        "total": len(dispositivos),
        "dispositivos": dispositivos,
        "puerta_enlace": escaneo["puerta_enlace"],
        "ip_local": escaneo["ip_local"],
        "subred": escaneo["subred"],
    }


@app.get("/api/inventario")
def inventario_conocido(_user: str = Depends(auth.require_user)):
    """Return devices previously detected by GearEye on scanned local networks."""
    try:
        verificar_base_datos()
        return obtener_inventario_conocido()
    except DATABASE_ERRORS as error:
        logger.exception("No se pudo consultar el inventario histórico")
        raise HTTPException(status_code=503, detail="El inventario histórico no está disponible por el momento.") from error


@app.get("/api/eventos")
def eventos_red(
    limite: int = Query(default=30, ge=5, le=100),
    _user: str = Depends(auth.require_user),
):
    try:
        return obtener_eventos(limite)
    except STORAGE_ERRORS as error:
        logger.exception("No se pudo consultar la bitácora de eventos")
        raise HTTPException(status_code=503, detail="La bitácora no está disponible por el momento.") from error

@app.get("/api/alertas")
def alertas_red(
    limite: int = Query(default=30, ge=1, le=100),
    _user: str = Depends(auth.require_user),
):
    try:
        return obtener_alertas(limite)
    except STORAGE_ERRORS as error:
        logger.exception("No se pudieron consultar las alertas")
        raise HTTPException(status_code=503, detail="Las alertas no estÃ¡n disponibles por el momento.") from error


@app.post("/api/alertas/{alert_id}/reconocer")
def reconocer_alerta_red(alert_id: int, _user: str = Depends(auth.require_company_admin)):
    try:
        if not reconocer_alerta(alert_id):
            raise HTTPException(status_code=404, detail="La alerta ya fue reconocida o no existe.")
        return {"ok": True, "id": alert_id}
    except DATABASE_ERRORS as error:
        logger.exception("No se pudo reconocer la alerta %s", alert_id)
        raise HTTPException(status_code=503, detail="No se pudo actualizar la alerta.") from error


@app.get("/api/configuracion/monitoreo")
def leer_configuracion_operativa(_user: str = Depends(auth.require_user)):
    cidr = subred_sesion(_user)
    if not cidr:
        raise HTTPException(status_code=503, detail="A?n no se recibi? un escaneo del agente de esta empresa.")
    try:
        return obtener_configuracion_operativa(cidr)
    except STORAGE_ERRORS as error:
        logger.exception("No se pudo consultar la configuraci\u00f3n operativa")
        raise HTTPException(status_code=503, detail="La configuraci\u00f3n no est\u00e1 disponible.") from error


@app.put("/api/configuracion/monitoreo")
def guardar_configuracion_operativa_api(
    payload: ConfiguracionOperativa,
    _user: str = Depends(auth.require_company_admin),
):
    cidr = subred_sesion(_user)
    if not cidr:
        raise HTTPException(status_code=503, detail="A?n no se recibi? un escaneo del agente de esta empresa.")
    try:
        return guardar_configuracion_operativa(cidr, payload.model_dump())
    except STORAGE_ERRORS as error:
        logger.exception("No se pudo guardar la configuraci\u00f3n operativa")
        raise HTTPException(status_code=503, detail="No se pudo guardar la configuraci\u00f3n.") from error


@app.get("/api/dispositivos/{ip}/notas")
def leer_notas_dispositivo(ip: str, _user: str = Depends(auth.require_user)):
    try:
        ip_validada = IPv4Address(ip)
    except ValueError as error:
        raise HTTPException(status_code=422, detail="La direcci\u00f3n debe ser una IPv4 v\u00e1lida.") from error
    cidr = subred_sesion(_user)
    if not cidr or ip_validada not in IPv4Network(cidr):
        raise HTTPException(status_code=403, detail="Solo puedes consultar equipos de la subred local.")
    try:
        result = obtener_notas_dispositivo(str(ip_validada))
        if result is None:
            raise HTTPException(status_code=404, detail="Escanea el equipo antes de consultar sus notas.")
        return result
    except STORAGE_ERRORS as error:
        logger.exception("No se pudieron consultar las notas de %s", ip_validada)
        raise HTTPException(status_code=503, detail="No se pudieron consultar las notas.") from error


@app.put("/api/dispositivos/{ip}/notas")
def guardar_notas_dispositivo_api(
    ip: str,
    payload: NotasDispositivoRequest,
    _user: str = Depends(auth.require_company_admin),
):
    try:
        ip_validada = IPv4Address(ip)
    except ValueError as error:
        raise HTTPException(status_code=422, detail="La direcci\u00f3n debe ser una IPv4 v\u00e1lida.") from error
    cidr = subred_sesion(_user)
    if not cidr or ip_validada not in IPv4Network(cidr):
        raise HTTPException(status_code=403, detail="Solo puedes modificar equipos de la subred local.")
    try:
        result = guardar_notas_dispositivo(
            str(ip_validada), payload.responsable.strip() or None, payload.notas.strip() or None
        )
        if result is None:
            raise HTTPException(status_code=404, detail="Escanea el equipo antes de guardar notas.")
        return {"ok": True, "ip": str(ip_validada), "responsable": result["owner"], "notas": result["notes"]}
    except STORAGE_ERRORS as error:
        logger.exception("No se pudieron guardar las notas de %s", ip_validada)
        raise HTTPException(status_code=503, detail="No se pudieron guardar las notas.") from error


@app.get("/api/eventos.csv")
def exportar_eventos_csv(
    dias: int = Query(default=30, ge=1, le=180),
    _user: str = Depends(auth.require_user),
):
    try:
        events = obtener_eventos_exportables(dias)
    except STORAGE_ERRORS as error:
        logger.exception("No se pudo exportar la bit\u00e1cora")
        raise HTTPException(status_code=503, detail="No se pudo exportar la bit\u00e1cora.") from error
    import csv
    import io
    from datetime import date

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["GearEye - Bit\u00e1cora de red", f"Periodo: {dias} d\u00edas"])
    writer.writerow(["Fecha UTC", "IP", "Dispositivo", "Evento", "Estado anterior", "Estado actual", "Detalle", "Reconocida"])
    for event in events:
        writer.writerow([
            datetime.fromtimestamp(event["occurred_at"], timezone.utc).isoformat(),
            event["ip"], event["device_name"], event["event_type"], event["previous_state"],
            event["current_state"], event["description"], bool(event["acknowledged_at"]),
        ])
    content = "\ufeff" + output.getvalue()
    filename = f"geareye-bitacora-{dias}-dias-{date.today().isoformat()}.csv"
    return StreamingResponse(
        iter([content]), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.put("/api/dispositivos/{ip}/confianza")
def confianza_dispositivo(
    ip: str,
    payload: ConfianzaRequest,
    _user: str = Depends(auth.require_company_admin),
):
    try:
        ip_validada = IPv4Address(ip)
    except ValueError as error:
        raise HTTPException(status_code=422, detail="La direcciÃ³n debe ser una IPv4 vÃ¡lida.") from error
    cidr = subred_sesion(_user)
    if not cidr or ip_validada not in IPv4Network(cidr):
        raise HTTPException(status_code=403, detail="Solo puedes administrar equipos de la subred local.")
    try:
        identidad = obtener_identidad_escaneada(str(ip_validada))
        if payload.confiable and identidad is None:
            raise HTTPException(status_code=404, detail="Escanea la red y selecciona un dispositivo detectado antes de marcarlo.")
        actualizar_confianza(
            str(ip_validada), payload.confiable,
            identidad["mac"] if identidad else None,
            identidad["nombre"] if identidad else None,
        )
        return {"ok": True, "ip": str(ip_validada), "confiable": payload.confiable}
    except STORAGE_ERRORS as error:
        logger.exception("No se pudo actualizar la confianza para %s", ip_validada)
        raise HTTPException(status_code=503, detail="No se pudo guardar el inventario de confianza.") from error


@app.get("/api/informes")
def informe_red(
    dias: int = Query(default=7, ge=1, le=30),
    _user: str = Depends(auth.require_user),
):
    try:
        return obtener_datos_informe(dias)
    except STORAGE_ERRORS as error:
        logger.exception("No se pudo generar el informe de red")
        raise HTTPException(status_code=503, detail="El informe no está disponible por el momento.") from error


@app.get("/api/informes.csv")
def descargar_informe_csv(
    dias: int = Query(default=7, ge=1, le=30),
    _user: str = Depends(auth.require_user),
):
    try:
        informe = obtener_datos_informe(dias)
    except STORAGE_ERRORS as error:
        logger.exception("No se pudo generar el informe CSV de red")
        raise HTTPException(status_code=503, detail="El informe no está disponible por el momento.") from error

    import csv
    import io
    from datetime import date

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["GearEye - Informe de red"])
    writer.writerow(["Generado (UTC)", informe["generado_en"]])
    writer.writerow(["Periodo (dias)", dias])
    writer.writerow([])
    writer.writerow(["INVENTARIO ACTUAL"])
    writer.writerow(["IP", "MAC", "Nombre", "Fabricante", "Fabricante de red", "Modelo", "Tipo", "Estado", "Confianza", "Responsable", "Notas", "Latencia (ms)", "Ultima medicion (UTC)"])
    for device in informe["dispositivos"]:
        writer.writerow([
            device["ip"], device["mac"], device["nombre"], device["fabricante"],
            device["fabricante_red"], device["modelo"], device["tipo"],
            device["estado"], device["confianza"], device["responsable"], device["notas"],
            device["latencia_ms"], device["ultima_medicion"],
        ])
    writer.writerow([])
    writer.writerow(["HISTORIAL DE LATENCIA Y ESTADO"])
    writer.writerow(["Fecha (UTC)", "IP", "MAC", "Nombre", "Fabricante", "Fabricante de red", "Modelo", "Tipo", "Estado", "Latencia (ms)"])
    for measurement in informe["mediciones"]:
        writer.writerow([
            measurement["fecha"], measurement["ip"], measurement["mac"], measurement["nombre"],
            measurement["fabricante"], measurement["fabricante_red"],
            measurement["modelo"], measurement["tipo"], measurement["estado"],
            measurement["latencia_ms"],
        ])
    writer.writerow([])
    writer.writerow(["RESUMEN DE DISPONIBILIDAD Y LATENCIA POR DISPOSITIVO"])
    writer.writerow(["IP", "MAC", "Nombre", "Fabricante", "Tipo", "Estado actual", "Confianza", "Escaneos con respuesta", "Escaneos registrados", "Disponibilidad (%)", "Latencia media (ms)", "Latencia minima (ms)", "Latencia maxima (ms)"])
    for summary in informe["resumen_dispositivos"]:
        writer.writerow([
            summary["ip"], summary["mac"], summary["nombre"], summary["fabricante"],
            summary["tipo"], summary["estado_actual"], summary["confianza"], summary["escaneos_con_respuesta"],
            summary["escaneos_registrados"], summary["disponibilidad_pct"],
            summary["latencia_media_ms"], summary["latencia_minima_ms"], summary["latencia_maxima_ms"],
        ])
    writer.writerow([])
    writer.writerow(["BITACORA DE EVENTOS"])
    writer.writerow(["Fecha (UTC)", "IP", "Nombre", "Evento", "Estado anterior", "Estado actual", "Detalle"])
    for event in informe["eventos"]:
        writer.writerow([
            event["fecha"], event["ip"], event["nombre"], event["tipo"],
            event["estado_anterior"], event["estado_actual"], event["mensaje"],
        ])

    content = "\ufeff" + output.getvalue()
    filename = f"geareye-informe-{dias}-dias-{date.today().isoformat()}.csv"
    return StreamingResponse(
        iter([content]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/comprobar/{ip}", response_model=Dispositivo)
def comprobar_ip(ip: str, _user: str = Depends(auth.require_user)):
    if _user.get("company_id", "default") != "default":
        raise HTTPException(status_code=409, detail="Este diagn?stico se debe ejecutar desde el agente instalado en la red de la empresa.")
    try:
        ip_validada = IPv4Address(ip)
    except ValueError as error:
        raise HTTPException(status_code=422, detail="La direcci\u00f3n debe ser una IPv4 v\u00e1lida.") from error
    cidr = subred_sesion(_user)
    if not cidr or ip_validada not in IPv4Network(cidr):
        raise HTTPException(status_code=403, detail="Solo puedes comprobar equipos de tu subred.")
    return comprobar_dispositivo(str(ip_validada))

@app.get("/api/diagnostico/{ip}", response_model=ResultadoDiagnostico)
def diagnostico_ip(ip: str, _user: str = Depends(auth.require_company_admin)):
    if _user.get("company_id", "default") != "default":
        raise HTTPException(status_code=409, detail="Este diagn?stico se debe ejecutar desde el agente instalado en la red de la empresa.")
    try:
        ip_validada = IPv4Address(ip)
    except ValueError as error:
        raise HTTPException(status_code=422, detail="La direcci\u00f3n debe ser una IPv4 v\u00e1lida.") from error
    cidr = subred_sesion(_user)
    if not cidr or ip_validada not in IPv4Network(cidr):
        raise HTTPException(status_code=403, detail="Solo puedes diagnosticar equipos de tu subred.")
    ip = str(ip_validada)
    dispositivo = comprobar_dispositivo(ip)
    diagnostico = analizar_dispositivo(dispositivo)
    try:
        registrar_diagnostico(ip, diagnostico)
    except STORAGE_ERRORS:
        logger.exception("No se pudo guardar el diagnóstico para %s", ip)

    return {
        "dispositivo": dispositivo,
        "diagnostico": diagnostico
    }


@app.post("/api/diagnostico-avanzado/{ip}")
def diagnostico_avanzado_ip(ip: str, _user: str = Depends(auth.require_company_admin)):
    if _user.get("company_id", "default") != "default":
        raise HTTPException(status_code=409, detail="Este diagn?stico se debe ejecutar desde el agente instalado en la red de la empresa.")
    try:
        ip_validada = IPv4Address(ip)
    except ValueError as error:
        raise HTTPException(status_code=422, detail="La direcci\u00f3n debe ser una IPv4 v\u00e1lida.") from error
    cidr = subred_sesion(_user)
    if not cidr or ip_validada not in IPv4Network(cidr):
        raise HTTPException(status_code=403, detail="El diagn\u00f3stico avanzado solo admite IP de la subred local.")
    return analizar_red_avanzado(str(ip_validada))


@app.get("/api/historial/{ip}")
def historial_ip(
    ip: str,
    limite: int = Query(default=30, ge=5, le=180),
    _user: str = Depends(auth.require_user),
):
    try:
        ip_validada = str(IPv4Address(ip))
    except ValueError as error:
        raise HTTPException(status_code=422, detail="La dirección debe ser una IPv4 válida.") from error

    try:
        return obtener_historial(ip_validada, limite)
    except STORAGE_ERRORS as error:
        logger.exception("No se pudo consultar el historial de latencia")
        raise HTTPException(
            status_code=503,
            detail="El historial de latencia no está disponible por el momento.",
        ) from error
