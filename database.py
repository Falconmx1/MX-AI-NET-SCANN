import sqlite3
import json
from datetime import datetime
import os

DB_PATH = 'scans.db'

def init_database():
    """Inicializa la base de datos SQLite"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Tabla de escaneos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            open_ports_tcp TEXT,
            open_ports_udp TEXT,
            services TEXT,
            os_info TEXT,
            analysis TEXT,
            risk_score REAL,
            risk_level TEXT
        )
    ''')
    
    # Tabla de escaneos programados
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            cron_expression TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            last_run TEXT,
            next_run TEXT,
            webhook_url TEXT
        )
    ''')
    
    # Tabla de webhooks
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            event_type TEXT NOT NULL,
            enabled INTEGER DEFAULT 1
        )
    ''')
    
    # Tabla de configuración
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

def save_scan(scan_data):
    """Guarda un escaneo en la base de datos"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO scans (
            target, timestamp, scan_type, open_ports_tcp, open_ports_udp,
            services, os_info, analysis, risk_score, risk_level
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_data['target'],
        scan_data['timestamp'],
        scan_data.get('scan_type', 'normal'),
        json.dumps(scan_data.get('open_ports_tcp', [])),
        json.dumps(scan_data.get('open_ports_udp', [])),
        json.dumps(scan_data.get('services', [])),
        json.dumps(scan_data.get('os_info', {})),
        json.dumps(scan_data.get('analysis', {})),
        scan_data.get('risk_score', 0),
        scan_data.get('risk_level', 'DESCONOCIDO')
    ))
    
    conn.commit()
    last_id = cursor.lastrowid
    conn.close()
    return last_id

def get_scans(limit=50, offset=0):
    """Obtiene historial de escaneos"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM scans ORDER BY timestamp DESC LIMIT ? OFFSET ?
    ''', (limit, offset))
    
    rows = cursor.fetchall()
    conn.close()
    
    scans = []
    for row in rows:
        scans.append({
            'id': row[0],
            'target': row[1],
            'timestamp': row[2],
            'scan_type': row[3],
            'open_ports_tcp': json.loads(row[4]) if row[4] else [],
            'open_ports_udp': json.loads(row[5]) if row[5] else [],
            'services': json.loads(row[6]) if row[6] else [],
            'os_info': json.loads(row[7]) if row[7] else {},
            'analysis': json.loads(row[8]) if row[8] else {},
            'risk_score': row[9],
            'risk_level': row[10]
        })
    
    return scans

def add_scheduled_scan(target, cron_expr, scan_type='normal', webhook_url=None):
    """Agrega un escaneo programado"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO scheduled_scans (target, cron_expression, scan_type, webhook_url)
        VALUES (?, ?, ?, ?)
    ''', (target, cron_expr, scan_type, webhook_url))
    
    conn.commit()
    last_id = cursor.lastrowid
    conn.close()
    return last_id

def get_scheduled_scans():
    """Obtiene todos los escaneos programados"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM scheduled_scans WHERE enabled = 1')
    rows = cursor.fetchall()
    conn.close()
    
    scans = []
    for row in rows:
        scans.append({
            'id': row[0],
            'target': row[1],
            'cron_expression': row[2],
            'scan_type': row[3],
            'enabled': row[4],
            'last_run': row[5],
            'next_run': row[6],
            'webhook_url': row[7]
        })
    
    return scans

def update_scheduled_scan_last_run(scan_id, last_run, next_run):
    """Actualiza última ejecución"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE scheduled_scans SET last_run = ?, next_run = ? WHERE id = ?
    ''', (last_run, next_run, scan_id))
    
    conn.commit()
    conn.close()

def add_webhook(name, url, event_type):
    """Agrega un webhook"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO webhooks (name, url, event_type, enabled)
        VALUES (?, ?, ?, 1)
    ''', (name, url, event_type))
    
    conn.commit()
    last_id = cursor.lastrowid
    conn.close()
    return last_id

def get_webhooks(event_type=None):
    """Obtiene webhooks por tipo de evento"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if event_type:
        cursor.execute('SELECT * FROM webhooks WHERE event_type = ? AND enabled = 1', (event_type,))
    else:
        cursor.execute('SELECT * FROM webhooks WHERE enabled = 1')
    
    rows = cursor.fetchall()
    conn.close()
    
    webhooks = []
    for row in rows:
        webhooks.append({
            'id': row[0],
            'name': row[1],
            'url': row[2],
            'event_type': row[3],
            'enabled': row[4]
        })
    
    return webhooks

def save_config(key, value):
    """Guarda configuración"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)
    ''', (key, json.dumps(value)))
    
    conn.commit()
    conn.close()

def get_config(key, default=None):
    """Obtiene configuración"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('SELECT value FROM config WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return json.loads(row[0])
    return default

# Inicializar DB al importar
init_database()
