def imprimir_resumen_ips(titulo: str, ips: set, mapa_datos: dict = None, es_alerta: bool = False):
    """
    Imprime por pantalla una lista de IPs y sus usuarios asociados (soportando múltiples usuarios).
    """
    if mapa_datos is None:
        mapa_datos = {}

    print(f"[*] {titulo} ({len(ips)}):")
    
    if not ips:
        if es_alerta:
            print("    - Ninguna. ¡Sistema seguro!")
        else:
            print("    - Ninguna.")
        return

    for ip in sorted(ips):
        usuarios = mapa_datos.get(ip)
        icono = "⚠️ " if es_alerta else ""
        
        if usuarios:
            # Si hay usuarios, los ordenamos y unimos con comas
            usuarios_str = ", ".join(sorted(usuarios))
            print(f"    - {icono}{ip} (Usuarios: {usuarios_str})")
        else:
            # Si es una IP baneada de la que no pillamos el usuario
            print(f"    - {icono}{ip} (Usuarios: Desconocido)")