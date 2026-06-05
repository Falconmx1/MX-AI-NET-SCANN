import requests
import json
from datetime import datetime
import threading

def send_webhook(webhook_url, event_type, data):
    """
    Envía notificación a webhook (Discord/Slack/Telegram/Generic)
    """
    try:
        # Detectar tipo de webhook por URL
        if 'discord.com' in webhook_url:
            payload = {
                'content': f"🔔 **{event_type}**\n```json\n{json.dumps(data, indent=2)[:1900]}\n```",
                'username': 'MX-AI-NET-SCANN'
            }
            headers = {'Content-Type': 'application/json'}
            
        elif 'slack.com' in webhook_url:
            payload = {
                'text': f"*{event_type}*\n```json\n{json.dumps(data, indent=2)[:1000]}\n```",
                'username': 'MX-AI-NET-SCANN'
            }
            headers = {'Content-Type': 'application/json'}
            
        elif 'api.telegram.org' in webhook_url:
            # Para Telegram se necesita formato especial
            # URL debería ser: https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>
            # Pero simplificamos
            payload = {
                'text': f"🔔 {event_type}\n\n{json.dumps(data, indent=2)[:500]}",
                'parse_mode': 'HTML'
            }
            headers = {'Content-Type': 'application/json'}
            
        else:
            # Webhook genérico
            payload = {
                'event': event_type,
                'data': data,
                'timestamp': datetime.now().isoformat(),
                'source': 'MX-AI-NET-SCANN'
            }
            headers = {'Content-Type': 'application/json'}
        
        # Enviar en hilo separado para no bloquear
        def send():
            try:
                response = requests.post(webhook_url, json=payload, headers=headers, timeout=5)
                if response.status_code not in [200, 204]:
                    print(f"Webhook error: {response.status_code}")
            except Exception as e:
                print(f"Webhook exception: {e}")
        
        thread = threading.Thread(target=send)
        thread.start()
        return True
        
    except Exception as e:
        print(f"Error sending webhook: {e}")
        return False

def send_scan_notification(webhooks, scan_result):
    """
    Envía notificación de escaneo completado a todos los webhooks
    """
    event_type = 'scan_completed'
    
    # Preparar datos resumidos
    data = {
        'target': scan_result.get('target'),
        'timestamp': scan_result.get('timestamp'),
        'risk_level': scan_result.get('analysis', {}).get('risk_level'),
        'risk_score': scan_result.get('analysis', {}).get('risk_score'),
        'open_ports': len(scan_result.get('open_ports_tcp', [])),
        'vulnerabilities': len(scan_result.get('analysis', {}).get('vulnerabilities', []))
    }
    
    for webhook in webhooks:
        if webhook['event_type'] == 'scan_completed' or webhook['event_type'] == 'all':
            send_webhook(webhook['url'], event_type, data)

def send_vulnerability_alert(webhooks, vuln_data):
    """
    Envía alerta de vulnerabilidad crítica
    """
    event_type = 'critical_vulnerability'
    
    data = {
        'target': vuln_data.get('target'),
        'vulnerability': vuln_data.get('vulnerability'),
        'cvss_score': vuln_data.get('cvss'),
        'urgency': 'IMMEDIATE'
    }
    
    for webhook in webhooks:
        if webhook['event_type'] == 'vulnerability' or webhook['event_type'] == 'all':
            send_webhook(webhook['url'], event_type, data)
