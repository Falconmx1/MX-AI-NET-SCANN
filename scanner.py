import subprocess
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import platform
import re
from datetime import datetime

# Top 100 puertos más comunes (reducido a 50 para velocidad)
COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 69, 80, 110, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 443,
    445, 465, 514, 515, 546, 547, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1080, 1194, 1433,
    1434, 1723, 1812, 1813, 3306, 3389, 3690, 4369, 5060, 5222, 5432, 5900, 5901, 5984, 6379,
    6667, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9418, 11211, 27017, 27018
]

# Mapeo de puertos a servicios
PORT_SERVICE = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC", 137: "NetBIOS-ns", 138: "NetBIOS-dgm",
    139: "NetBIOS-ssn", 143: "IMAP", 161: "SNMP", 162: "SNMP-trap", 179: "BGP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD", 546: "DHCPv6-client",
    547: "DHCPv6-server", 554: "RTSP", 587: "SMTP-sub", 631: "IPP", 636: "LDAPS", 646: "LDP",
    873: "rsync", 990: "FTPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1434: "MSSQL-mon", 1723: "PPTP", 1812: "RADIUS", 1813: "RADIUS-acct",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4369: "Erlang", 5060: "SIP", 5222: "XMPP",
    5432: "PostgreSQL", 5900: "VNC", 5901: "VNC-1", 5984: "CouchDB", 6379: "Redis",
    6667: "IRC", 8000: "HTTP-alt", 8008: "HTTP-alt", 8080: "HTTP-proxy", 8081: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "HTTP-alt", 9000: "PHP-fpm", 9090: "Prometheus", 9200: "Elasticsearch",
    9418: "Git", 11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB-shard"
}

def scan_host_advanced(ip):
    """
    Escaneo avanzado de host con detección de OS por TTL
    Retorna: (alive, os_info_dict)
    """
    try:
        # Ping con timeout 1 segundo
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', '1', ip]
        
        result = subprocess.run(command, capture_output=True, text=True, timeout=2)
        alive = result.returncode == 0
        
        # Detectar OS por TTL
        os_info = {"detected": False, "os": "Desconocido", "ttl": None, "confidence": 0}
        
        if alive:
            # Extraer TTL de la salida del ping
            output = result.stdout
            ttl_match = re.search(r'ttl[=:](\d+)', output, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                os_info["ttl"] = ttl
                
                if ttl <= 64:
                    os_info["os"] = "Linux/Unix/BSD"
                    os_info["confidence"] = 85
                elif ttl <= 128:
                    os_info["os"] = "Windows (10/11/Server)"
                    os_info["confidence"] = 80
                elif ttl <= 255:
                    os_info["os"] = "Router/Cisco/Solaris"
                    os_info["confidence"] = 70
                
                os_info["detected"] = True
        
        return alive, os_info
    except:
        return False, {"detected": False, "os": "Desconocido", "ttl": None, "confidence": 0}

def scan_port(ip, port, timeout=0.5):
    """
    Escanea un puerto TCP con timeout configurable
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        service = PORT_SERVICE.get(port, f"Desconocido")
        return port, result == 0, service
    except:
        return port, False, "Error"

def scan_ports(ip, ports=None, max_workers=50, timeout=0.5):
    """
    Escaneo masivo de puertos con hilos
    """
    if ports is None:
        ports = COMMON_PORTS
    
    open_ports = []
    services = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        
        for future in as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append(port)
                services.append({"port": port, "service": service})
    
    return open_ports

def get_service_versions(ip, open_ports, timeout=2):
    """
    Banner grabbing básico para obtener versiones de servicios
    """
    versions = []
    
    for port in open_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Enviar petición genérica para obtener banner
            if port == 80 or port == 8080 or port == 8000:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 22:
                # SSH banner
                pass
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                versions.append({
                    "port": port,
                    "service": PORT_SERVICE.get(port, "Desconocido"),
                    "banner": banner[:100]  # Limitar longitud
                })
        except:
            versions.append({
                "port": port,
                "service": PORT_SERVICE.get(port, "Desconocido"),
                "banner": "No se pudo obtener banner"
            })
    
    return versions

def quick_scan(ip):
    """
    Escaneo rápido de los 20 puertos más comunes
    """
    quick_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
    return scan_ports(ip, quick_ports, max_workers=20, timeout=0.3)
