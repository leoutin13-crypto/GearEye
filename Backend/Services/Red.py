import subprocess

def comprobar_dispositivo(ip):
    resultado = subprocess.run(
        ["ping", "-n", "1", "-w", "1000", ip],
        capture_output=True,
        text=True   
    )

    return resultado.returncode == 0