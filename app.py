from flask import Flask, render_template, request, jsonify
import scanner
import ai_analysis

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_network():
    data = request.json
    target = data.get('target')
    
    if not target:
        return jsonify({"error": "Se requiere una dirección IP"}), 400
    
    # Verificar si el host está activo
    host_alive = scanner.scan_host(target)
    if not host_alive:
        return jsonify({
            "target": target,
            "alive": False,
            "error": "El host no responde al ping"
        }), 404
    
    # Escanear puertos comunes
    open_ports = scanner.scan_ports(target)
    
    # Análisis con IA (simulada)
    analysis = ai_analysis.analyze_services(open_ports)
    
    return jsonify({
        "target": target,
        "alive": True,
        "open_ports": open_ports,
        "analysis": analysis
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
