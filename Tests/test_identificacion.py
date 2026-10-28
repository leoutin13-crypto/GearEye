import socket

from Backend.Services.Identificacion import (
    clasificar,
    es_mac_privada,
    puertos_abiertos,
    sistema_por_ttl,
    ttl_desde_ping,
)


def test_ttl_desde_ping_windows_en_espanol_e_ingles():
    assert ttl_desde_ping("Respuesta desde 192.168.1.5: bytes=32 tiempo<1m TTL=128") == 128
    assert ttl_desde_ping("Reply from 192.168.1.9: bytes=32 time=3ms TTL=64") == 64
    assert ttl_desde_ping("Tiempo de espera agotado") is None


def test_sistema_por_ttl():
    assert sistema_por_ttl(128) == "Windows"
    assert sistema_por_ttl(63) == "Linux, Android, iOS o macOS"
    assert sistema_por_ttl(255) == "Sistema de equipo de red"


def test_mac_privada():
    assert es_mac_privada("da-91-4e-77-c1-45")
    assert not es_mac_privada("3c-52-82-0a-44-10")


def test_casos_de_la_red_real():
    # Caja Android TV con chip Amlogic: el nombre "mesons4d" la delata.
    assert clasificar("mesons4d-aq222-n", "CHINA DRAGON TECHNOLOGY", None, 64, [])[0] == "tv"
    # Módem Vantiva (antes Technicolor) sin nombre.
    assert clasificar(None, "Vantiva USA LLC", None, 64, [80, 443])[0] == "dispositivo_red"
    # Celular con MAC privada: solo hay TTL 64.
    assert clasificar(None, "MAC privada", "da-91-4e-77-c1-45", 64, [])[0] == "movil"
    # Portátil Windows con MAC privada.
    assert clasificar(None, "MAC privada", "da-91-4e-77-c1-46", 128, [])[0] == "computador"
    assert clasificar("COL-CO01-1137", "LCFC(HeFei) Electronics", None, 128, [445])[0] == "computador"


def test_los_servicios_pesan_mas_que_el_fabricante():
    # HP fabrica computadores e impresoras: el puerto 9100 decide.
    assert clasificar(None, "Hewlett Packard", None, 255, [80, 9100])[0] == "impresora"
    assert clasificar(None, "Hewlett Packard", None, 128, [135, 445])[0] == "computador"
    assert clasificar(None, "Desconocido", None, 64, [554])[0] == "camara"
    assert clasificar(None, "Apple, Inc.", None, 64, [62078]) == ("movil", "iOS o macOS")


def test_palabras_cortas_solo_como_palabra_completa():
    assert clasificar("SALA-TV", None)[0] == "tv"
    assert clasificar("TVENTAS", None)[0] != "tv"
    assert clasificar("PC07", None)[0] == "computador"


def test_sin_pistas_queda_sin_clasificar():
    assert clasificar(None, "Desconocido", None, None, []) == ("desconocido", None)


def test_puertos_abiertos_detecta_un_servicio_local():
    servidor = socket.socket()
    servidor.bind(("127.0.0.1", 0))
    servidor.listen()
    puerto = servidor.getsockname()[1]
    try:
        assert puertos_abiertos("127.0.0.1", (puerto,), timeout=1) == [puerto]
    finally:
        servidor.close()
