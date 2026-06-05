# MX-AI-NET-SCANN v2.0

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-brightgreen)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-red)
![AI](https://img.shields.io/badge/AI-Powered-purple)

## 🔥 Escáner de Red con Inteligencia Artificial y Scoring CVSS

</div>

## ✨ Características 2.0

- 🧠 **IA Avanzada** - Scoring CVSS, predicción de exploits
- 🎯 **Top 100 puertos** - Escaneo ultra rápido concurrente
- 🕵️ **Detección de SO** - Por TTL y fingerprinting
- 📊 **Base de datos CVE** - Vulnerabilidades conocidas integradas
- 🌓 **Modo oscuro/claro** - Interfaz adaptable
- 📜 **Historial** - Últimos 50 escaneos guardados
- 💾 **Exportación JSON** - Reportes estructurados
- 🚀 **API REST completa** - Integración con otras herramientas

## 🎯 Puertos escaneados

**Top 50 puertos más críticos:**
20,21,22,23,25,53,69,80,110,123,135,137,138,139,143,161,162,179,389,443,
445,465,514,515,546,547,554,587,631,636,646,873,990,993,995,1080,1194,1433,
1434,1723,1812,1813,3306,3389,3690,4369,5060,5222,5432,5900,5901,5984,6379,
6667,8000,8008,8080,8081,8443,8888,9000,9090,9200,9418,11211,27017,27018


## 🧠 Sistema de IA

### Scoring de Riesgo (0-100)
- **CRÍTICO (80+)**: Parcheo inmediato
- **ALTO (60-79)**: Arreglar en 24-48h
- **MEDIO (35-59)**: Planificar esta semana
- **BAJO (15-34)**: Monitorear
- **MUY BAJO (<15)**: Aceptable

### Vulnerabilidades detectadas
- EternalBlue (SMB)
- BlueKeep (RDP)
- Log4Shell (HTTP/Java)
- Credenciales texto plano (Telnet/FTP)
- Y más basado en CVE reales

## 📦 Instalación

```bash
git clone https://github.com/Falconmx1/MX-AI-NET-SCANN.git
cd MX-AI-NET-SCANN
pip install -r requirements.txt
python app.py
