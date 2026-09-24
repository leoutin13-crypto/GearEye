import subprocess

from concurrent.futures import ThreadPoolExecutor

def comprobar_dispositivo(ip):
    resultado = subprocess.run(
        ["ping", "-n", "1", "-w", "1000", ip],
        capture_output=True,
        text=True
    )

    return resultado.returncode == 0

def descubrir_dispositivos():
    dispositivos = []
    with ThreadPoolExecutor(max_workers=20) as executor:    
        ips = [f"192.168.1.{i}" for i in range(1, 255)]
        resultados = executor.map(comprobar_dispositivo, ips)
        for i, activo in enumerate(resultados,start=1):
            if activo:
                ip = ips[i - 1]
                dispositivos.append({
                    "ip": ip,
                    "estado": "activo"
                })
                

    return dispositivos
