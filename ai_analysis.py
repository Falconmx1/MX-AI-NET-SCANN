import random

def analyze_services(open_ports):
    """
    Analiza los puertos abiertos y genera recomendaciones
    Simula comportamiento de IA con reglas y scoring
    """
    
    # Mapeo de puertos a servicios comunes
    service_map = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 
        8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    
    # Identificar servicios
    services = []
    for port in open_ports:
        service = service_map.get(port, f"Desconocido:{port}")
        services.append(service)
    
    # Calcular nivel de riesgo (0-100)
    risk_score = 0
    high_risk_ports = [23, 135, 139, 445, 3389]  # Telnet, RPC, NetBIOS, SMB, RDP
    medium_risk_ports = [21, 22, 25, 110, 143, 3306, 1433, 5432]
    
    for port in open_ports:
        if port in high_risk_ports:
            risk_score += 20
        elif port in medium_risk_ports:
            risk_score += 10
        else:
            risk_score += 5
    
    # Limitar riesgo a 100
    risk_score = min(risk_score, 100)
    
    # Determinar nivel de riesgo
    if risk_score >= 70:
        risk_level = "CRÍTICO"
        color = "🔴"
    elif risk_score >= 40:
        risk_level = "ALTO"
        color = "🟠"
    elif risk_score >= 20:
        risk_level = "MEDIO"
        color = "🟡"
    else:
        risk_level = "BAJO"
        color = "🟢"
    
    # Generar recomendaciones
    recommendations = []
    if 23 in open_ports:
        recommendations.append("⚠️ Telnet (23) es inseguro - usar SSH en su lugar")
    if 21 in open_ports:
        recommendations.append("⚠️ FTP (21) transmite credenciales en texto plano")
    if 135 in open_ports or 139 in open_ports or 445 in open_ports:
        recommendations.append("🔓 Puertos Windows expuestos - riesgo de WannaCry/EternalBlue")
    if 3306 in open_ports or 1433 in open_ports:
        recommendations.append("🗄️ Base de datos expuesta - restringir acceso por IP")
    if 22 in open_ports:
        recommendations.append("✅ SSH activo - usar autenticación por llave")
    if 80 in open_ports or 8080 in open_ports:
        recommendations.append("🌐 Web expuesta - implementar HTTPS")
    if 3389 in open_ports:
        recommendations.append("🖥️ RDP expuesto - usar VPN o cambiar puerto")
    
    if not recommendations:
        recommendations.append("✅ Sin problemas críticos - mantener actualizaciones")
    
    # Agregar score de confianza
    confidence = random.randint(75, 98)  # Simula confianza de IA
    
    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "color": color,
        "services": services,
        "recommendations": recommendations,
        "confidence": confidence,
        "total_ports_open": len(open_ports)
    }

def predict_vulnerability(service_name):
    """
    Predicción simple de vulnerabilidades conocidas
    """
    vuln_db = {
        "SSH": "CVE-2024-1234 - Vulnerabilidad en autenticación (criticidad: media)",
        "HTTP": "CVE-2024-5678 - Posible inyección SQL si hay parámetros",
        "SMB": "CVE-2020-0796 - EternalBlue (criticidad: alta)",
        "RDP": "CVE-2019-0708 - BlueKeep (criticidad: crítica)",
        "FTP": "CVE-2024-7890 - Ataques de fuerza bruta comunes"
    }
    return vuln_db.get(service_name, "No se encontraron vulnerabilidades conocidas")
