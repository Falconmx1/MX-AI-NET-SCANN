import math
from datetime import datetime

# Base de datos de vulnerabilidades conocidas (CVE simplificados)
VULNERABILITY_DB = {
    "SSH": [
        {"cve": "CVE-2024-1234", "cvss": 7.5, "description": "Vulnerabilidad en autenticación", "patch_available": True},
        {"cve": "CVE-2023-4567", "cvss": 5.3, "description": "Fuga de información", "patch_available": True}
    ],
    "SMB": [
        {"cve": "CVE-2020-0796", "cvss": 10.0, "description": "EternalBlue - RCE crítico", "patch_available": True},
        {"cve": "CVE-2017-0144", "cvss": 9.3, "description": "WannaCry exploit", "patch_available": True}
    ],
    "RDP": [
        {"cve": "CVE-2019-0708", "cvss": 9.8, "description": "BlueKeep - RCE sin autenticación", "patch_available": True}
    ],
    "MySQL": [
        {"cve": "CVE-2024-1234", "cvss": 6.5, "description": "Inyección SQL en procedimientos", "patch_available": True}
    ],
    "HTTP": [
        {"cve": "CVE-2021-44228", "cvss": 10.0, "description": "Log4Shell (si usa Java)", "patch_available": True}
    ],
    "Telnet": [
        {"cve": "CVE-2020-12345", "cvss": 9.0, "description": "Credenciales en texto plano", "patch_available": False}
    ],
    "FTP": [
        {"cve": "CVE-2019-1234", "cvss": 7.2, "description": "Ataques de fuerza bruta", "patch_available": True}
    ]
}

# Severidad por puerto (peso para calcular riesgo)
PORT_SEVERITY = {
    20: 5, 21: 7, 22: 4, 23: 10, 25: 5, 135: 9, 139: 8, 445: 10, 3389: 9,
    3306: 7, 1433: 7, 5432: 6, 5900: 6, 80: 3, 443: 2, 8080: 4
}

def advanced_analysis(open_ports, services, os_info):
    """
    Análisis avanzado con IA simulada
    """
    
    # Calcular score base de riesgo
    base_risk = 0
    for port in open_ports:
        severity = PORT_SEVERITY.get(port, 3)
        base_risk += severity
    
    # Normalizar a escala 0-100
    max_possible_risk = len(open_ports) * 10 if open_ports else 1
    risk_score = min(100, (base_risk / max_possible_risk) * 100 if open_ports else 0)
    
    # Identificar servicios
    service_names = [s['service'] for s in services]
    detected_vulnerabilities = []
    
    # Buscar vulnerabilidades conocidas
    for service in service_names:
        if service in VULNERABILITY_DB:
            vulns = VULNERABILITY_DB[service]
            for vuln in vulns:
                detected_vulnerabilities.append({
                    "service": service,
                    **vuln
                })
    
    # Ajustar riesgo según vulnerabilidades encontradas
    if detected_vulnerabilities:
        # Incrementar riesgo según CVSS promedio
        avg_cvss = sum(v['cvss'] for v in detected_vulnerabilities) / len(detected_vulnerabilities)
        risk_score = min(100, risk_score + (avg_cvss * 5))
    
    # Evaluar riesgo por nivel
    if risk_score >= 80:
        risk_level = "CRÍTICO"
        risk_color = "🔴"
        urgency = "Inmediata"
    elif risk_score >= 60:
        risk_level = "ALTO"
        risk_color = "🟠"
        urgency = "24-48 horas"
    elif risk_score >= 35:
        risk_level = "MEDIO"
        risk_color = "🟡"
        urgency = "Esta semana"
    elif risk_score >= 15:
        risk_level = "BAJO"
        risk_color = "🟢"
        urgency = "Planificar"
    else:
        risk_level = "MUY BAJO"
        risk_color = "✅"
        urgency = "Monitorear"
    
    # Generar recomendaciones personalizadas
    recommendations = generate_recommendations(open_ports, services, os_info)
    
    # Calcular métricas adicionales
    exposed_services = len(services)
    critical_ports = [p for p in open_ports if PORT_SEVERITY.get(p, 0) >= 8]
    
    # Análisis de superficie de ataque
    attack_surface = {
        "total_ports": len(open_ports),
        "critical_ports": len(critical_ports),
        "unique_services": len(set(service_names)),
        "os_exposure": "Alta" if os_info['detected'] else "Media"
    }
    
    # Score de confianza del análisis
    confidence = calculate_confidence(open_ports, services, os_info)
    
    return {
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "risk_color": risk_color,
        "urgency": urgency,
        "vulnerabilities": detected_vulnerabilities,
        "recommendations": recommendations,
        "metrics": {
            "exposed_services": exposed_services,
            "critical_ports_count": len(critical_ports),
            "attack_surface_score": round(attack_surface['total_ports'] * 0.5 + attack_surface['critical_ports'] * 2, 1)
        },
        "attack_surface": attack_surface,
        "confidence": confidence,
        "timestamp": datetime.now().isoformat()
    }

def generate_recommendations(open_ports, services, os_info):
    """
    Genera recomendaciones específicas basadas en hallazgos
    """
    recommendations = []
    
    # Recomendaciones por puerto
    port_recs = {
        23: "❌ TELNET es inseguro - DESHABILITAR y usar SSH puerto 22",
        21: "⚠️ FTP transmite credenciales en texto plano - migrar a SFTP o FTPS",
        25: "📧 SMTP abierto - riesgo de spam relay, implementar autenticación",
        445: "🔥 SMB CRÍTICO - parchear EternalBlue inmediatamente",
        3389: "🔒 RDP expuesto - usar VPN o RD Gateway con 2FA",
        3306: "🗄️ MySQL expuesto - restringir por firewall y usar SSL",
        1433: "💾 MSSQL expuesto - cambiar puerto por defecto y usar autenticación fuerte",
        5900: "🖥️ VNC expuesto - usar tunneling SSH o VPN",
        80: "🌐 HTTP sin cifrar - implementar HTTPS con Let's Encrypt",
        22: "🔑 SSH activo - deshabilitar root login y usar autenticación por llave",
        8080: "🚪 Proxy HTTP expuesto - implementar autenticación básica"
    }
    
    for port in open_ports:
        if port in port_recs:
            recommendations.append(port_recs[port])
    
    # Recomendaciones por SO
    if os_info['detected']:
        if "Windows" in os_info['os']:
            recommendations.append("🪟 Windows detectado - verificar actualizaciones críticas (MS17-010, CVE-2019-0708)")
            recommendations.append("🛡️ Deshabilitar SMBv1 y NetBIOS si no son necesarios")
        elif "Linux" in os_info['os']:
            recommendations.append("🐧 Linux detectado - verificar SELinux/AppArmor y actualizar kernel")
            recommendations.append("🔐 Revisar /etc/ssh/sshd_config y deshabilitar PermitRootLogin")
    
    # Recomendaciones generales
    if not recommendations:
        recommendations.append("✅ Configuración básica aceptable - mantener buenas prácticas")
    
    # Agregar firewall
    recommendations.append("🛡️ Implementar firewall con reglas de denegación por defecto")
    recommendations.append("📊 Monitorear logs y establecer alertas de escaneo")
    
    return recommendations[:6]  # Limitar a 6 recomendaciones

def calculate_confidence(open_ports, services, os_info):
    """
    Calcula el nivel de confianza del análisis
    """
    confidence = 75  # Base
    
    # Más puertos = más datos = más confianza
    if len(open_ports) > 10:
        confidence += 10
    elif len(open_ports) > 5:
        confidence += 5
    
    # OS detectado aumenta confianza
    if os_info['detected'] and os_info['confidence'] > 70:
        confidence += 10
    
    # Banners obtenidos
    banners_obtained = sum(1 for s in services if s.get('banner') and 'No se pudo' not in s['banner'])
    if banners_obtained > 5:
        confidence += 10
    elif banners_obtained > 2:
        confidence += 5
    
    return min(95, confidence)

def get_general_recommendations():
    """
    Recomendaciones generales de hardening
    """
    return {
        "critical": [
            "Mantener sistemas actualizados (parches de seguridad)",
            "Usar autenticación multifactor (2FA/MFA)",
            "Implementar firewall de red y host-based",
            "Deshabilitar servicios no utilizados"
        ],
        "network": [
            "Segmentar redes críticas",
            "Monitorizar tráfico saliente",
            "Implementar IDS/IPS",
            "Usar VPN para acceso remoto"
        ],
        "best_practices": [
            "Cambiar puertos por defecto",
            "Políticas de contraseñas fuertes",
            "Backups regulares offline",
            "Auditorías periódicas"
        ]
    }
