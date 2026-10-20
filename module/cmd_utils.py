import subprocess

def ejecutar_comando(cmd: str) -> set:
    """Ejecuta un comando bash y devuelve un set con las líneas resultantes."""
    try:
        resultado = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
        return set(resultado.splitlines())
    except subprocess.CalledProcessError:
        return set()