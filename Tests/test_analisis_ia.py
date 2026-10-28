from Backend.Services.AnalisisIA import analizar_red, es_latencia_anomala, linea_base


def punto(estado="activo", latencia=10.0, mac=None):
    return {"estado": estado, "latencia_ms": latencia if estado == "activo" else None, "mac": mac}


def estable(latencia=10.0, n=8, mac=None):
    return [punto(latencia=latencia + (i % 3), mac=mac) for i in range(n)]


def tipos(resultado):
    return {h["tipo"] for h in resultado["hallazgos"]}


def test_linea_base_requiere_minimo_de_muestras():
    assert linea_base([10, 11, 12]) is None
    base = linea_base([10, 11, 12, 10, 11])
    assert base["mediana_ms"] == 11 and base["muestras"] == 5


def test_latencia_anomala_contra_linea_base_propia():
    base = linea_base([10, 11, 12, 10, 11, 12])
    assert es_latencia_anomala(200, base)[0] is True
    assert es_latencia_anomala(14, base)[0] is False


def test_red_estable_sin_inventario_solo_sugiere_marcar_confiables():
    series = {"192.168.1.1": estable(2), "192.168.1.10": estable(10), "192.168.1.11": estable(15)}
    resultado = analizar_red(series, gateway="192.168.1.1")
    assert tipos(resultado) == {"sin_inventario_confiable"}
    assert resultado["resumen"]["salud"] == 100


def test_gateway_caido_es_critico():
    series = {"192.168.1.1": estable(2) + [punto("inactivo")], "192.168.1.10": estable()}
    resultado = analizar_red(series, gateway="192.168.1.1")
    assert resultado["hallazgos"][0]["tipo"] == "gateway_sin_respuesta"
    assert resultado["hallazgos"][0]["severidad"] == "critico"


def test_caida_simultanea_indica_falla_de_segmento():
    series = {"192.168.1.1": estable(2)}
    for i in range(10, 16):
        series[f"192.168.1.{i}"] = estable() + [punto("inactivo")]
    assert "caida_segmento" in tipos(analizar_red(series, gateway="192.168.1.1"))


def test_lldp_identifica_el_switch_afectado():
    series = {"192.168.1.1": estable(2)}
    links = []
    for i in range(10, 13):
        ip = f"192.168.1.{i}"
        series[ip] = estable() + [punto("inactivo")]
        links.append({"switch_ip": "192.168.1.2", "remote_ip": ip})
    for i in range(20, 30):
        series[f"192.168.1.{i}"] = estable()
    resultado = analizar_red(series, gateway="192.168.1.1", topologia={"links": links})
    falla = next(h for h in resultado["hallazgos"] if h["tipo"] == "falla_switch")
    assert falla["ip"] == "192.168.1.2"
    assert falla["evidencia"]["ips_afectadas"] == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]


def test_latencia_alta_en_un_solo_equipo():
    series = {f"192.168.1.{i}": estable() for i in range(10, 15)}
    series["192.168.1.10"] = estable() + [punto(latencia=250)]
    resultado = analizar_red(series)
    anomalia = next(h for h in resultado["hallazgos"] if h["tipo"] == "latencia_anomala")
    assert anomalia["ip"] == "192.168.1.10"


def test_latencia_alta_en_casi_toda_la_red_es_congestion():
    series = {f"192.168.1.{i}": estable() + [punto(latencia=300)] for i in range(10, 15)}
    assert "congestion_red" in tipos(analizar_red(series))
    assert "latencia_anomala" not in tipos(analizar_red(series))


def test_intermitencia():
    series = {"192.168.1.10": [punto("activo" if i % 2 else "detectado") for i in range(8)]}
    resultado = analizar_red(series)
    assert "conexion_intermitente" in tipos(resultado)
    assert resultado["nodos"]["192.168.1.10"]["estado"] == "intermitente"


def test_mac_del_gateway_en_otra_ip_es_intrusion():
    gw_mac = "aa-bb-cc-dd-ee-01"
    series = {"192.168.1.1": estable(2, mac=gw_mac), "192.168.1.66": estable(mac="AA:BB:CC:DD:EE:01")}
    hallazgo = next(h for h in analizar_red(series, gateway="192.168.1.1")["hallazgos"] if h["tipo"] == "mac_duplicada")
    assert hallazgo["severidad"] == "intrusion"


def test_cambio_de_mac_en_la_misma_ip():
    series = {"192.168.1.10": estable(mac="aa-aa-aa-aa-aa-01") + [punto(mac="aa-aa-aa-aa-aa-02")]}
    assert "cambio_mac" in tipos(analizar_red(series))


def test_equipo_desconocido_con_inventario_confiable():
    series = {"192.168.1.10": estable(mac="aa-aa-aa-aa-aa-01"), "192.168.1.99": estable(mac="aa-aa-aa-aa-aa-99")}
    resultado = analizar_red(series, macs_confiables=["AA:AA:AA:AA:AA:01"])
    intrusos = [h["ip"] for h in resultado["hallazgos"] if h["tipo"] == "mac_desconocida"]
    assert intrusos == ["192.168.1.99"]
    assert resultado["nodos"]["192.168.1.99"]["estado"] == "intruso_detectado"


def test_sin_datos():
    assert analizar_red({})["resumen"]["dispositivos_analizados"] == 0
