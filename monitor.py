#!/usr/bin/env python3
"""
Monitor de Seguridad SSH - Alert Fail2Ban To Mail

Este script actúa como un orquestador automatizado para detectar posibles intrusiones en servidores Linux.
Su funcionalidad principal es cruzar datos de bloqueos con accesos exitosos. 

Flujo de ejecución:
1. Carga configuraciones y credenciales desde los archivos JSON (config.json y credenciales.json).
2. Lee los comandos de sistema definidos en la configuración para extraer:
   - Las IPs que han sido baneadas por Fail2Ban.
   - Las líneas de log de inicios de sesión SSH exitosos (Auth log).
3. Utiliza expresiones regulares para extraer la IP y el nombre de usuario comprometido de los accesos exitosos.
4. Cruza los datos para detectar "IPs sospechosas" (IPs que fueron baneadas pero que luego lograron entrar), excluyendo aquellas que estén en lista blanca o que ya hayan sido notificadas.
5. Si detecta intrusiones nuevas, recopila telemetría del servidor y envía una alerta por correo electrónico (HTML) detallando la IP y el usuario afectado.
6. Finalmente, registra las IPs reportadas en 'ips_notificadas.json' para evitar el envío de alertas duplicadas en ejecuciones posteriores y mantener un registro de auditoría.
"""

import os
import re
from pathlib import Path
from datetime import datetime

# Importamos los módulos personalizados
from module.config_loader import ConfigLoader
from module.smtp_client import SMTPSender
from module.telemetry import TelemetryCollector
from module.cmd_utils import ejecutar_comando
from module.json_utils import guardar_json
from module.display_utils import imprimir_resumen_ips

def main():
    # Obtener el directorio base donde reside este script
    BASE_DIR = Path(__file__).parent
    
    # 1. Cargar configuraciones usando ConfigLoader
    loader = ConfigLoader()
    config = loader.load(BASE_DIR / "config" / "config.json")
    creds = loader.load(BASE_DIR / "config" / "credenciales.json")
    
    if not config or not creds:
        print("Error: No se pudieron cargar los archivos de configuración base.")
        return

    rutas = config.get("rutas", {})
    ruta_blanca = BASE_DIR / rutas["lista_blanca"]
    ruta_notificadas = BASE_DIR / rutas["notificadas"]
    
    # 2. Cargar listas de control (JSONs)
    dict_blanca = loader.load(ruta_blanca)
    dict_notificadas = loader.load(ruta_notificadas)
    
    # Extraemos solo las IPs para operar con conjuntos
    ips_blanca = set(dict_blanca.keys())
    ips_notificadas = set(dict_notificadas.keys())

    # 3. Extraer comandos dinámicos desde config.json
    comandos = config.get("comandos", {})
    cmd_baneadas = comandos.get("baneadas", "")
    cmd_aceptadas = comandos.get("aceptadas", "")
    cmd_fallidas = comandos.get("fallidas", "")

    if not cmd_baneadas or not cmd_aceptadas or not cmd_fallidas:
        print("Error: No se han definido todos los comandos en config.json")
        return

    # 4. Ejecutar chequeos en los logs del sistema
    ips_baneadas = ejecutar_comando(cmd_baneadas)
    
    # Lógica de detección: (Baneadas Y Aceptadas) MENOS (Lista Blanca O Ya Notificadas)
    lineas_aceptadas = ejecutar_comando(cmd_aceptadas)
    lineas_fallidas = ejecutar_comando(cmd_fallidas)
    
    # 5. Mapear IP -> Usuario usando Regex
    mapa_accesos = {}
    for linea in lineas_aceptadas:
        match = re.search(r"for\s+(?P<user>\S+)\s+from\s+(?P<ip>[0-9\.]+)", linea)
        if match:
            ip = match.group('ip')
            user = match.group('user')
            mapa_accesos.setdefault(ip, set()).add(user)

    # 6. Mapear IP -> Usuarios fallidos (para enriquecer la vista de baneadas)
    mapa_intentos = {}
    for linea in lineas_fallidas:
        # Permite capturar "invalid user admin" o simplemente "root"
        match = re.search(r"for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[0-9\.]+)", linea)
        if match:
            ip = match.group('ip')
            user = match.group('user')
            mapa_intentos.setdefault(ip, set()).add(user)

    # Si quiero probar el envío de mail descomentar estas 2 lineas siguientes
    #ips_baneadas.add("99.99.99.99")
    #mapa_accesos["99.99.99.99"] = "hacker_test"
    ips_aceptadas = set(mapa_accesos.keys())
   
    # 7. Lógica de detección: (Baneadas Y Aceptadas) MENOS (Lista Blanca O Ya Notificadas)
    ips_sospechosas = (ips_baneadas & ips_aceptadas) - ips_blanca - ips_notificadas

    # === BLOQUE DE VISUALIZACIÓN ===
    print("-" * 50)
    # Le pasamos el mapa de intentos fallidos a las baneadas
    imprimir_resumen_ips("IPs baneadas por Fail2Ban", ips_baneadas, mapa_intentos)
    print("")
    imprimir_resumen_ips("IPs con acceso exitoso", ips_aceptadas, mapa_accesos)
    print("")
    imprimir_resumen_ips("IPs sospechosas (Intrusión)", ips_sospechosas, mapa_accesos, es_alerta=True)
    print("-" * 50)
    # ===============================

    if ips_sospechosas:
        # Preparar configuración SMTP
        smtp_config = creds["smtp"]
        
        # Obtener telemetría para el correo
        telemetry = TelemetryCollector().collect_all()
        hostname = telemetry.get("data", {}).get("hardware", {}).get("hostname", "Servidor Desconocido")
        
        # [ATENCIÓN] Actualiza la inyección del HTML para soportar listas de usuarios:
        ips_html = "".join(
            f"<li><strong>IP: {ip}</strong> | <strong>Usuario(s) comprometido(s): {', '.join(sorted(mapa_accesos[ip]))}</strong></li>" 
            for ip in ips_sospechosas
        )
        
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        timestamp_formateado = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
        template_path = BASE_DIR / "templates" / "alerta_monitor.html"
        
        # 8. Cargar y formatear la plantilla HTML
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                html_content = f.read()
                
            html_content = html_content.replace("{{ ips_sospechosas }}", ips_html)
            html_content = html_content.replace("{{ hostname }}", hostname)
            html_content = html_content.replace("{{ timestamp }}", timestamp_formateado)
        except Exception as e:
            print(f"No se pudo cargar la plantilla HTML: {e}")
            html_content = f"Alerta SSH en {hostname}. IPs sospechosas detectadas: {', '.join(ips_sospechosas)}"

        # 9. Enviar correo de alerta
        remitente = SMTPSender(smtp_config)
        resultado = remitente.enviar_correo(
            destinatario=config["smtp"]["destinatario"],
            asunto=f"⚠️ Alerta Crítica SSH - {hostname} - Posible intrusión",
            cuerpo_html=html_content
        )
        
        # 10. Si el envío es exitoso, registramos las IPs como notificadas
        if resultado.get("success"):
            for ip in ips_sospechosas:
                dict_notificadas[ip] = {
                    "fecha_notificacion": timestamp,
                    "estado": "Pendiente cambio de contraseñas y auditoría de sesión",
                    "revisado": False,
                    "usuario_afectado": mapa_accesos[ip]
                }
            guardar_json(ruta_notificadas, dict_notificadas)
            print(f"Alerta enviada y {len(ips_sospechosas)} IPs registradas en notificadas.")

if __name__ == "__main__":
    main()