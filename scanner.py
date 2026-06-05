import subprocess
import socket
from concurrent.futures import ThreadPoolExecutor
import platform

def scan_host(ip):
    """
    Verifica si un host está activo usando ping
    """
    # Detectar sistema operativo
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    
    # Construir comando ping
    command = ['ping', param, '1', '-W', '1', ip]
    
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False

def scan_port(ip, port):
    """
    Escanea un puerto TCP específico
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, result == 0
    except:
        return port, False

def scan_ports(ip, ports=None):
    """
    Escanea una lista de puertos usando hilos concurrentes
    """
    if ports is None:
        # Puertos más comunes
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)
    
    open_ports = [port for port, is_open in results if is_open]
    return open_ports
