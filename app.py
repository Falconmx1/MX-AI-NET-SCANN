from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import scanner
import udp_scanner
import ai_analysis
import database
import webhook_manager
from scheduler import scheduler, init_scheduler
from datetime import datetime
import json
import io
import os

app = Flask(__name__)
CORS(app)

# Inicializar scheduler al arrancar
init_scheduler()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan_network_api():
    """API endpoint para escaneo completo (TCP + UDP)"""
    data = request.json
    target = data.get('target')
    scan_type = data.get('scan_type', 'normal')  # quick, normal, full
    stealth = data.get('stealth', False)
    include_udp = data.get('include_udp', True)
    
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
    
    # Determinar puertos según tipo
    if scan_type == 'quick':
        open_ports_tcp, tcp_services = scanner.quick_scan(target, stealth=stealth)
    elif scan_type == 'full':
        open_ports_tcp, tcp_services = scanner.scan_ports(target, max_workers=100, stealth=stealth)
    else:  # normal
        open_ports_tcp, tcp_services = scanner.scan_ports(target, stealth=stealth)
    
    # Escaneo UDP
    open_ports_udp = []
    udp_services = []
    if include_udp:
        open_ports_udp, udp_services = udp_scanner.scan_udp_ports(target)
    
    # Banner grabbing
    services = scanner.get_service_versions(target, open_ports_tcp, stealth=stealth)
    all_services = services + udp_services
    
    # Análisis IA avanzado
    analysis = ai_analysis.advanced_analysis(
        open_ports_tcp + open_ports_udp, 
        all_services, 
        os_info
    )
    
    # Preparar resultado
    scan_result = {
        "target": target,
        "alive": True,
        "timestamp": datetime.now().isoformat(),
        "scan_type": scan_type,
        "stealth_mode": stealth,
        "os": os_info,
        "open_ports_tcp": open_ports_tcp,
        "open_ports_udp": open_ports_udp,
        "services": all_services,
        "analysis": analysis
    }
    
    # Guardar en base de datos
    scan_id = database.save_scan(scan_result)
    scan_result['id'] = scan_id
    
    # Enviar webhooks si hay vulnerabilidades críticas
    if analysis.get('risk_level') in ['CRÍTICO', 'ALTO']:
        webhooks = database.get_webhooks('vulnerability')
        for vuln in analysis.get('vulnerabilities', []):
            if vuln.get('cvss', 0) >= 7:
                webhook_manager.send_vulnerability_alert(webhooks, {
                    'target': target,
                    'vulnerability': vuln.get('cve'),
                    'cvss': vuln.get('cvss')
                })
    
    # Webhook de escaneo completado
    webhooks = database.get_webhooks('scan_completed')
    webhook_manager.send_scan_notification(webhooks, scan_result)
    
    return jsonify(scan_result)

@app.route('/api/history', methods=['GET'])
def get_history():
    """Obtener historial de escaneos"""
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    scans = database.get_scans(limit, offset)
    return jsonify(scans)

@app.route('/api/export/pdf/<int:scan_id>', methods=['GET'])
def export_pdf(scan_id):
    """Exportar escaneo a PDF"""
    scans = database.get_scans(limit=100)
    scan = next((s for s in scans if s['id'] == scan_id), None)
    
    if not scan:
        return jsonify({"error": "Escaneo no encontrado"}), 404
    
    # Generar PDF usando reportlab
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Título
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#00ff9d'))
    story.append(Paragraph(f"MX-AI-NET-SCANN Report", title_style))
    story.append(Spacer(1, 0.3*inch))
    
    # Información del escaneo
    story.append(Paragraph(f"<b>Target:</b> {scan['target']}", styles['Normal']))
    story.append(Paragraph(f"<b>Fecha:</b> {scan['timestamp']}", styles['Normal']))
    story.append(Paragraph(f"<b>Nivel de Riesgo:</b> {scan['risk_level']} ({scan['risk_score']}/100)", styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    # Puertos abiertos
    story.append(Paragraph("<b>Puertos TCP Abiertos:</b>", styles['Heading2']))
    ports_text = ', '.join(map(str, scan['open_ports_tcp'])) if scan['open_ports_tcp'] else 'Ninguno'
    story.append(Paragraph(ports_text, styles['Normal']))
    story.append(Spacer(1, 0.1*inch))
    
    if scan['open_ports_udp']:
        story.append(Paragraph("<b>Puertos UDP Abiertos:</b>", styles['Heading2']))
        ports_text = ', '.join(map(str, scan['open_ports_udp']))
        story.append(Paragraph(ports_text, styles['Normal']))
        story.append(Spacer(1, 0.1*inch))
    
    # Vulnerabilidades
    if scan['analysis'].get('vulnerabilities'):
        story.append(Paragraph("<b>Vulnerabilidades Detectadas:</b>", styles['Heading2']))
        for vuln in scan['analysis']['vulnerabilities']:
            story.append(Paragraph(f"• {vuln.get('cve')} - CVSS: {vuln.get('cvss')}", styles['Normal']))
            story.append(Paragraph(f"  {vuln.get('description', '')}", styles['Normal']))
            story.append(Spacer(1, 0.05*inch))
    
    # Recomendaciones
    story.append(Paragraph("<b>Recomendaciones:</b>", styles['Heading2']))
    for rec in scan['analysis'].get('recommendations', []):
        story.append(Paragraph(f"• {rec}", styles['Normal']))
    
    doc.build(story)
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"scan_report_{scan['target']}_{scan['id']}.pdf",
        mimetype='application/pdf'
    )

@app.route('/api/schedule', methods=['POST'])
def add_scheduled_scan():
    """Agregar escaneo programado"""
    data = request.json
    target = data.get('target')
    cron_expr = data.get('cron_expression')  # ej: "0 */6 * * *" (cada 6 horas)
    scan_type = data.get('scan_type', 'normal')
    webhook_url = data.get('webhook_url')
    
    if not target or not cron_expr:
        return jsonify({"error": "Faltan parámetros"}), 400
    
    scan_id = database.add_scheduled_scan(target, cron_expr, scan_type, webhook_url)
    return jsonify({"id": scan_id, "message": "Escaneo programado agregado"})

@app.route('/api/schedule/list', methods=['GET'])
def list_scheduled_scans():
    """Listar escaneos programados"""
    scans = database.get_scheduled_scans()
    return jsonify(scans)

@app.route('/api/webhook', methods=['POST'])
def add_webhook():
    """Agregar webhook"""
    data = request.json
    name = data.get('name')
    url = data.get('url')
    event_type = data.get('event_type')  # scan_completed, vulnerability, all
    
    if not name or not url:
        return jsonify({"error": "Faltan parámetros"}), 400
    
    hook_id = database.add_webhook(name, url, event_type)
    return jsonify({"id": hook_id, "message": "Webhook agregado"})

@app.route('/api/webhook/list', methods=['GET'])
def list_webhooks():
    """Listar webhooks"""
    event_type = request.args.get('event_type')
    hooks = database.get_webhooks(event_type)
    return jsonify(hooks)

@app.route('/api/config', methods=['GET', 'POST'])
def manage_config():
    """Gestionar configuración"""
    if request.method == 'GET':
        key = request.args.get('key')
        if key:
            value = database.get_config(key)
            return jsonify({key: value})
        else:
            return jsonify({"error": "Se requiere key"}), 400
    else:
        data = request.json
        key = data.get('key')
        value = data.get('value')
        if key:
            database.save_config(key, value)
            return jsonify({"message": "Configuración guardada"})
        return jsonify({"error": "Faltan parámetros"}), 400

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Estadísticas generales"""
    scans = database.get_scans(limit=1000)
    
    total_scans = len(scans)
    if total_scans == 0:
        return jsonify({"total_scans": 0, "avg_risk": 0, "critical_count": 0})
    
    avg_risk = sum(s['risk_score'] for s in scans) / total_scans
    critical_count = sum(1 for s in scans if s['risk_level'] == 'CRÍTICO')
    
    return jsonify({
        "total_scans": total_scans,
        "avg_risk": round(avg_risk, 1),
        "critical_count": critical_count,
        "most_scanned_targets": []
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
