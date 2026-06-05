import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Puertos UDP comunes
UDP_PORTS = [
    53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 389, 445, 500, 514,
    520, 631, 1434, 1900, 4500, 49152, 5353, 5355
]

UDP_SERVICE_MAP = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP", 135: "RPC",
    137: "NetBIOS-ns", 138: "NetBIOS-dgm", 139: "NetBIOS-ssn", 161: "SNMP",
    162: "SNMP-trap", 389: "LDAP", 445: "SMB", 500: "IKE", 514: "Syslog",
    520: "RIP", 631: "IPP", 1434: "MSSQL-mon", 1900: "UPnP", 4500: "IPsec",
    5353: "mDNS", 5355: "LLMNR"
}

def scan_udp_port(ip, port, timeout=1):
    """
    Escanea un puerto UDP
    Nota: UDP es stateless, esto es una aproximación
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # Enviar datos dummy para provocar respuesta
        if port == 53:  # DNS
            sock.sendto(b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01', (ip, port))
        elif port == 123:  # NTP
            sock.sendto(b'\x1b' + 47 * b'\x00', (ip, port))
        elif port == 161:  # SNMP
            sock.sendto(b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x02\x01\x00\x02\x01\x00\x02\x01\x00\x30\x0d\x30\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00', (ip, port))
        else:
            sock.sendto(b'\x00\x00\x00\x00', (ip, port))
        
        try:
            data, _ = sock.recvfrom(1024)
            if data:
                sock.close()
                return port, True, UDP_SERVICE_MAP.get(port, f"UDP-{port}")
        except socket.timeout:
            pass
        
        sock.close()
        return port, False, None
        
    except Exception as e:
        return port, False, None

def scan_udp_ports(ip, ports=None, max_workers=20):
    """
    Escaneo de puertos UDP
    """
    if ports is None:
        ports = UDP_PORTS
    
    open_ports = []
    services = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_udp_port, ip, port): port for port in ports}
        
        for future in as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append(port)
                services.append({"port": port, "service": service, "protocol": "UDP"})
    
    return open_ports, services
