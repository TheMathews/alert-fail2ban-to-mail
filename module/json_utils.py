import json
from pathlib import Path

def guardar_json(ruta: Path, datos: dict):
    """Guarda un diccionario en formato JSON."""
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with open(ruta, 'w', encoding='utf-8') as f:
        json.dump(datos, f, indent=4, ensure_ascii=False)