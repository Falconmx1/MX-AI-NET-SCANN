import threading
import time
import schedule
from datetime import datetime
import database
import app as main_app
import json

class ScanScheduler:
    def __init__(self):
        self.running = False
        self.thread = None
    
    def start(self):
        """Inicia el scheduler en un hilo separado"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        print("✅ Scheduler iniciado")
    
    def stop(self):
        """Detiene el scheduler"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def _run(self):
        """Loop principal del scheduler"""
        while self.running:
            # Cargar escaneos programados
            scheduled_scans = database.get_scheduled_scans()
            
            for scan in scheduled_scans:
                self._check_and_run(scan)
            
            time.sleep(60)  # Revisar cada minuto
    
    def _check_and_run(self, scan_config):
        """Verifica si debe ejecutar un escaneo"""
        import cron_converter
        
        try:
            # Parsear expresión cron
            cron = cron_converter.Cron()
            cron.from_string(scan_config['cron_expression'])
            
            # Obtener próxima ejecución
            now = datetime.now()
            next_run = cron.next(now)
            
            # Si no hay last_run o ya pasó la próxima ejecución
            last_run = scan_config.get('last_run')
            if last_run:
                last_run_dt = datetime.fromisoformat(last_run) if last_run else None
                if last_run_dt and next_run > last_run_dt and now >= next_run:
                    self._execute_scan(scan_config, next_run)
            elif now >= next_run:
                self._execute_scan(scan_config, next_run)
                
        except Exception as e:
            print(f"Error checking schedule: {e}")
    
    def _execute_scan(self, scan_config, scheduled_time):
        """Ejecuta un escaneo programado"""
        print(f"🔄 Ejecutando escaneo programado: {scan_config['target']} a las {scheduled_time}")
        
        # Aquí llamaríamos a la función de escaneo
        # Por ahora simulamos
        scan_result = {
            'target': scan_config['target'],
            'timestamp': datetime.now().isoformat(),
            'scan_type': scan_config['scan_type'],
            'open_ports_tcp': [22, 80, 443],
            'open_ports_udp': [53, 123],
            'analysis': {
                'risk_level': 'MEDIO',
                'risk_score': 45
            }
        }
        
        # Guardar resultado
        database.save_scan(scan_result)
        
        # Enviar webhook si está configurado
        if scan_config.get('webhook_url'):
            from webhook_manager import send_webhook
            send_webhook(
                scan_config['webhook_url'],
                'scheduled_scan',
                {
                    'target': scan_config['target'],
                    'timestamp': scan_result['timestamp'],
                    'risk_level': scan_result['analysis']['risk_level']
                }
            )
        
        # Actualizar última ejecución
        next_run = scheduled_time  # Calcular próxima realmente
        database.update_scheduled_scan_last_run(
            scan_config['id'],
            datetime.now().isoformat(),
            next_run.isoformat()
        )

# Instancia global
scheduler = ScanScheduler()

def init_scheduler():
    """Inicializa el scheduler al arrancar la app"""
    scheduler.start()
