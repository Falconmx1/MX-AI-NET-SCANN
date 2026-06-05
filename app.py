from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import scanner
import ai_analysis
import json
import os
from datetime import datetime
import threading

app = Flask(__name__)
CORS(app)  # Habilitar CORS para APIs externas

# Almacenamiento de escaneos anteriores
scan_history = []
scan_lock = threading.Lock()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_network_api():
    """API endpoint para escaneo"""
    data = request.json
    target = data.get('target')
    ports = data.get('ports')  # Puertos personalizados opcionales
    
    if not target:
        return jsonify({"error": "Se requiere dirección IP"}), 400
    
    # Verificar host
    host_alive, os_info = scanner.scan_host_advanced(target)
    if not host_alive:
        return jsonify({
            "target": target,
            "alive": False,
            "error": "Host no responde"
        }), 404
    
    # Escanear puertos
    if ports and isinstance(ports, list):
        open_ports = scanner.scan_ports(target, ports)
    else:
        open_ports = scanner.scan_ports(target)  # Top 50 puertos
    
    # Escaneo de versiones (banner grabbing básico)
    services = scanner.get_service_versions(target, open_ports)
    
    # Análisis IA avanzado
    analysis = ai_analysis.advanced_analysis(open_ports, services, os_info)
    
    # Guardar en historial
    scan_record = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "open_ports": open_ports,
        "services": services,
        "analysis": analysis,
        "os": os_info
    }
    
    with scan_lock:
        scan_history.insert(0, scan_record)
        if len(scan_history) > 50:
            scan_history.pop()
    
    return jsonify({
        "target": target,
        "alive": True,
        "os": os_info,
        "open_ports": open_ports,
        "services": services,
        "analysis": analysis,
        "timestamp": scan_record["timestamp"]
    })

@app.route('/api/history', methods=['GET'])
def get_history():
    """Obtener historial de escaneos"""
    with scan_lock:
        return jsonify(scan_history)

@app.route('/api/export/<int:scan_id>', methods=['GET'])
def export_scan(scan_id):
    """Exportar escaneo a JSON"""
    with scan_lock:
        if scan_id < len(scan_history):
            return jsonify(scan_history[scan_id])
    return jsonify({"error": "Escaneo no encontrado"}), 404

@app.route('/api/recommendations', methods=['GET'])
def get_recommendations():
    """Obtener recomendaciones generales de seguridad"""
    return jsonify(ai_analysis.get_general_recommendations())

@app.route('/api/scan/continuous', methods=['POST'])
def continuous_scan():
    """Escaneo continuo cada X segundos"""
    data = request.json
    target = data.get('target')
    interval = data.get('interval', 30)  # Segundos
    
    def background_scan():
        import time
        for _ in range(3):  # 3 iteraciones
            # Lógica de escaneo repetitivo
            time.sleep(interval)
    
    thread = threading.Thread(target=background_scan)
    thread.start()
    
    return jsonify({"message": f"Escaneo continuo iniciado cada {interval} segundos"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
