# 🛡️ Fail2Ban to Mail - SSH Intrusion Security Monitor

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Security](https://img.shields.io/badge/SecOps-Fail2Ban%20%7C%20SSH-critical?logo=linux&logoColor=white)
![Alerts](https://img.shields.io/badge/Alerts-HTML%20Email%20%2B%20Telemetry-success)

Sistema de monitorización de seguridad automatizado diseñado para servidores Linux. Cruza los registros de bloqueos de **Fail2Ban** (`fail2ban.log`) con los intentos y accesos exitosos por SSH (`auth.log`) para detectar posibles brechas de seguridad o intrusiones avanzadas.

---

## 🚀 Características Principales

* **🔍 Cruce Inteligente de Logs:** Detecta de manera proactiva aquellas direcciones IP que, a pesar de contar con un historial de baneos previos en Fail2Ban, lograron concretar un inicio de sesión exitoso en el sistema.
* **📊 Auditoría en Tiempo Real:** Ofrece una visualización estructurada por terminal del resumen de IPs baneadas, accesos aceptados e intentos sospechosos.
* **📧 Alertas Críticas HTML (ChatOps / SecOps):** Si detecta una intrusión real (excluyendo listas blancas e IPs ya notificadas), recopila telemetría avanzada del host y despacha un correo HTML de alerta detallando los usuarios comprometidos e instrucciones de mitigación.
* **🛡️ Control de Idempotencia:** Registra automáticamente las incidencias reportadas en un histórico (`ips_notificadas.json`) para prevenir la saturación de correos duplicados en ejecuciones posteriores.
* **🔌 Módulo de Telemetría Multiplataforma:** Inyecta metadatos del servidor afectado (OS, IP local, hardware y usuario ejecutor) en las notificaciones para agilizar el proceso de *troubleshooting*.

---

## 🏗️ Estructura del Proyecto

```text
Alert_Fail2Ban_To_Mail/
├── config/
│   ├── config.json             # Rutas de logs, comandos del sistema y correo de destino
│   ├── credenciales.json       # Credenciales del servidor SMTP (Ignorado por Git)
│   ├── lista_blanca_ips.json   # Diccionario de IPs exentas de alertas
│   └── ips_notificadas.json    # Historial persistente de alertas enviadas (Ignorado por Git)
├── module/                     # Módulos reutilizables (Cargador JSON, cliente SMTP, comandos y telemetría)
├── templates/
│   └── alerta_monitor.html     # Plantilla visual HTML para el correo de alerta
├── utils/                      # Utilidades de sistema y gestión de ficheros
├── monitor.py                  # Script principal y orquestador de seguridad
└── requirements.txt            # Dependencias del proyecto