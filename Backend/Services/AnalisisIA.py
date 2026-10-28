"""Motor de análisis asistido por IA (capítulo 3.4 del documento del proyecto).

Aprende una línea base por dispositivo a partir del historial guardado y
combina esa línea base con reglas de correlación para proponer la causa más
probable de cada incidente. No usa servicios externos: todo se calcula con los
escaneos que GearEye ya almacena.
"""

from statistics import median

# Clasificación de eventos de la sección 3.4.2.
SEVERIDADES = ("operativo", "advertencia", "critico", "intrusion")
ORDEN_SEVERIDAD = {"intrusion": 0, "critico": 1, "advertencia": 2, "operativo": 3}

MIN_MUESTRAS_LINEA_BASE = 5
UMBRAL_Z_ROBUSTO = 3.5
MARGEN_MINIMO_MS = 20.0
CAMBIOS_PARA_INTERMITENCIA = 3
VENTANA_INTERMITENCIA = 10
PROPORCION_CAIDA_MASIVA = 0.5
MIN_CAIDOS_POR_SWITCH = 3


def _mac(value):
    return str(value or "").strip().lower().replace(":", "-") or None


def linea_base(latencias):
    """Return median and MAD (robust spread) for a latency series."""
    valores = [float(value) for value in latencias if value is not None]
    if len(valores) < MIN_MUESTRAS_LINEA_BASE:
        return None
    mediana = median(valores)
    mad = median(abs(value - mediana) for value in valores)
    return {"mediana_ms": round(mediana, 2), "mad_ms": round(mad, 2), "muestras": len(valores)}


def es_latencia_anomala(latencia, base):
    """Robust z-score (Iglewicz-Hoaglin). A small floor avoids alerts on 1 ms jitter."""
    if latencia is None or base is None:
        return False, None
    desviacion = latencia - base["mediana_ms"]
    if desviacion < MARGEN_MINIMO_MS:
        return False, 0.0
    escala = max(base["mad_ms"], 1.0)
    z = 0.6745 * desviacion / escala
    return z >= UMBRAL_Z_ROBUSTO, round(z, 2)


def contar_cambios_estado(estados):
    recientes = [estado == "activo" for estado in estados[-VENTANA_INTERMITENCIA:]]
    return sum(1 for previo, actual in zip(recientes, recientes[1:]) if previo != actual)


def _hallazgo(tipo, severidad, titulo, causa, recomendacion, ip=None, evidencia=None):
    return {
        "tipo": tipo,
        "severidad": severidad,
        "ip": ip,
        "titulo": titulo,
        "causa_probable": causa,
        "recomendacion": recomendacion,
        "evidencia": evidencia or {},
    }


def analizar_red(series, gateway=None, ips_confiables=None, macs_confiables=None, topologia=None):
    """Analyse stored scan series and return findings plus a state per node.

    ``series`` maps each IP to its chronological measurements:
    ``[{"estado": str, "latencia_ms": float | None, "mac": str | None}, ...]``.
    The last item of each series is the current observation.
    """
    ips_confiables = set(ips_confiables or ())
    macs_confiables = {_mac(mac) for mac in macs_confiables or () if mac}
    hallazgos = []
    nodos = {}
    actuales = {ip: puntos[-1] for ip, puntos in series.items() if puntos}

    if not actuales:
        return {
            "resumen": {"dispositivos_analizados": 0, "hallazgos": 0, "salud": None},
            "nodos": {},
            "hallazgos": [],
            "metodo": _metodo(),
        }

    # 1. Gateway: si no responde, el resto de síntomas son consecuencia (3.4.3).
    gateway_caido = False
    if gateway and gateway in actuales and actuales[gateway]["estado"] != "activo":
        gateway_caido = True
        hallazgos.append(_hallazgo(
            "gateway_sin_respuesta", "critico",
            "El gateway no responde",
            "Falla del router principal o pérdida total de la red.",
            "Revisa la energía y el enlace del router antes de diagnosticar otros equipos.",
            ip=gateway,
        ))

    # 2. Caída de segmento o switch: muchos equipos que antes respondían dejan de hacerlo a la vez.
    antes_activos = [ip for ip, puntos in series.items()
                     if len(puntos) >= 2 and puntos[-2]["estado"] == "activo" and ip != gateway]
    caidos_ahora = [ip for ip in antes_activos if actuales[ip]["estado"] != "activo"]
    caidos_por_switch = _caidos_por_switch(topologia, set(caidos_ahora))
    for switch, ips in caidos_por_switch.items():
        hallazgos.append(_hallazgo(
            "falla_switch", "critico",
            f"{len(ips)} equipos del switch {switch} dejaron de responder",
            "Falla de hardware, energía o uplink del switch que los conecta.",
            "Revisa el switch y su enlace troncal; los equipos afectados comparten ese punto.",
            ip=switch, evidencia={"ips_afectadas": sorted(ips)},
        ))
    if (not gateway_caido and not caidos_por_switch and len(antes_activos) >= 4
            and len(caidos_ahora) / len(antes_activos) >= PROPORCION_CAIDA_MASIVA):
        hallazgos.append(_hallazgo(
            "caida_segmento", "critico",
            f"{len(caidos_ahora)} de {len(antes_activos)} equipos dejaron de responder a la vez",
            "Caída de un segmento de la LAN, probablemente un switch o un enlace troncal.",
            "Identifica qué tienen en común los equipos afectados (switch, piso, AP) y revisa ese punto.",
            evidencia={"ips_afectadas": sorted(caidos_ahora)},
        ))

    # 3. Línea base de latencia aprendida por equipo.
    anomalos = []
    for ip, puntos in series.items():
        actual = actuales[ip]
        historico = [punto["latencia_ms"] for punto in puntos[:-1] if punto["estado"] == "activo"]
        base = linea_base(historico)
        anomala, z = es_latencia_anomala(actual["latencia_ms"] if actual["estado"] == "activo" else None, base)
        cambios = contar_cambios_estado([punto["estado"] for punto in puntos])
        nodos[ip] = {
            "estado": _estado_nodo(actual["estado"], cambios),
            "linea_base": base,
            "latencia_actual_ms": actual["latencia_ms"],
            "z_robusto": z,
            "cambios_estado": cambios,
        }
        if anomala:
            anomalos.append(ip)
        if cambios >= CAMBIOS_PARA_INTERMITENCIA:
            hallazgos.append(_hallazgo(
                "conexion_intermitente", "advertencia",
                "Conexión intermitente",
                "El equipo alterna entre responder y no responder: cable dañado, mala señal Wi-Fi o ahorro de energía.",
                "Revisa el cable o la cobertura Wi-Fi y compara con la hora de máxima carga.",
                ip=ip, evidencia={"cambios_en_ultimos_escaneos": cambios},
            ))

    activos = [ip for ip, actual in actuales.items() if actual["estado"] == "activo"]
    if len(activos) >= 4 and len(anomalos) / len(activos) >= PROPORCION_CAIDA_MASIVA:
        hallazgos.append(_hallazgo(
            "congestion_red", "advertencia",
            "La latencia subió en la mayoría de la red",
            "Congestión general: saturación del enlace WAN, del router o un bucle de red.",
            "Revisa el consumo del enlace principal y busca bucles o tráfico masivo.",
            ip=gateway, evidencia={"ips_afectadas": sorted(anomalos)},
        ))
    else:
        for ip in anomalos:
            nodo = nodos[ip]
            hallazgos.append(_hallazgo(
                "latencia_anomala", "advertencia",
                "Latencia fuera de su comportamiento normal",
                "Congestión puntual o problema físico en el cable o la señal de este equipo.",
                "Repite la medición; si persiste, revisa el enlace del equipo.",
                ip=ip, evidencia={
                    "latencia_actual_ms": nodo["latencia_actual_ms"],
                    "mediana_habitual_ms": nodo["linea_base"]["mediana_ms"],
                    "z_robusto": nodo["z_robusto"],
                },
            ))

    # 4. Seguridad básica (3.3.2 y 3.3.3).
    hallazgos.extend(_hallazgos_seguridad(series, actuales, gateway, ips_confiables, macs_confiables, nodos))

    hallazgos.sort(key=lambda item: (ORDEN_SEVERIDAD[item["severidad"]], item["ip"] or ""))
    estados = [nodo["estado"] for nodo in nodos.values()]
    salud = round(100 * estados.count("activo") / len(estados)) if estados else None
    return {
        "resumen": {
            "dispositivos_analizados": len(actuales),
            "hallazgos": len(hallazgos),
            "por_severidad": {nivel: sum(item["severidad"] == nivel for item in hallazgos) for nivel in SEVERIDADES},
            "con_linea_base": sum(1 for nodo in nodos.values() if nodo["linea_base"]),
            "salud": salud,
        },
        "nodos": nodos,
        "hallazgos": hallazgos,
        "metodo": _metodo(),
    }


def _estado_nodo(estado, cambios):
    if cambios >= CAMBIOS_PARA_INTERMITENCIA:
        return "intermitente"
    return "activo" if estado == "activo" else "caido"


def _caidos_por_switch(topologia, caidos):
    if not topologia or not caidos:
        return {}
    por_switch = {}
    for link in topologia.get("links") or []:
        if link.get("remote_ip") in caidos:
            por_switch.setdefault(link.get("switch_ip"), set()).add(link["remote_ip"])
    return {switch: ips for switch, ips in por_switch.items() if switch and len(ips) >= MIN_CAIDOS_POR_SWITCH}


def _hallazgos_seguridad(series, actuales, gateway, ips_confiables, macs_confiables, nodos):
    hallazgos = []
    gateway_mac = _mac(actuales.get(gateway, {}).get("mac")) if gateway else None

    ips_por_mac = {}
    for ip, actual in actuales.items():
        mac = _mac(actual.get("mac"))
        if mac and actual["estado"] != "inactivo":
            ips_por_mac.setdefault(mac, []).append(ip)
    for mac, ips in ips_por_mac.items():
        if len(ips) < 2:
            continue
        suplanta_gateway = mac == gateway_mac
        hallazgos.append(_hallazgo(
            "mac_duplicada", "intrusion" if suplanta_gateway else "advertencia",
            "Una MAC responde por varias IP" + (" incluida la del gateway" if suplanta_gateway else ""),
            "Posible envenenamiento ARP (ARP poisoning)." if suplanta_gateway
            else "Equipo con varias IP o posible suplantación ARP.",
            "Verifica físicamente el equipo con esa MAC y revisa la tabla ARP del router.",
            ip=sorted(ips)[0], evidencia={"mac": mac, "ips": sorted(ips)},
        ))

    for ip, puntos in series.items():
        macs = [_mac(punto.get("mac")) for punto in puntos if _mac(punto.get("mac"))]
        if len(macs) >= 2 and macs[-1] != macs[-2]:
            hallazgos.append(_hallazgo(
                "cambio_mac", "intrusion" if ip == gateway else "advertencia",
                "La IP cambió de MAC",
                "Otro equipo tomó esta IP (DHCP o IP duplicada) o hay suplantación.",
                "Confirma qué equipo usa ahora la IP antes de marcarlo como confiable.",
                ip=ip, evidencia={"mac_anterior": macs[-2], "mac_actual": macs[-1]},
            ))

    # Sin inventario confiable no hay referencia para hablar de intrusos.
    if ips_confiables or macs_confiables:
        for ip, actual in actuales.items():
            mac = _mac(actual.get("mac"))
            if actual["estado"] == "inactivo" or ip == gateway or ip in ips_confiables or (mac and mac in macs_confiables):
                continue
            nodos[ip]["estado"] = "intruso_detectado"
            hallazgos.append(_hallazgo(
                "mac_desconocida", "intrusion",
                "Equipo no reconocido en la red",
                "La MAC no está en el inventario confiable: posible equipo intruso o equipo nuevo sin registrar.",
                "Identifica al responsable y márcalo como confiable, o desconéctalo.",
                ip=ip, evidencia={"mac": mac},
            ))
    else:
        hallazgos.append(_hallazgo(
            "sin_inventario_confiable", "operativo",
            "Aún no hay inventario confiable",
            "Sin una lista de equipos conocidos, GearEye no puede distinguir intrusos.",
            "Abre cada equipo conocido y pulsa «Marcar como confiable».",
        ))
    return hallazgos


def _metodo():
    return (
        "Línea base por equipo (mediana y desviación absoluta mediana) aprendida del historial, "
        f"puntuación Z robusta ≥ {UMBRAL_Z_ROBUSTO} para anomalías de latencia y reglas de "
        "correlación para gateway, switch, segmento, intermitencia y seguridad ARP."
    )
