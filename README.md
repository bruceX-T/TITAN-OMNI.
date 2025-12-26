# 🛡️ TITAN XIII: Suite de Seguridad OMNI

> **Herramienta automatizada de auditoría de seguridad y escaneo de vulnerabilidades.**
> *Desarrollada por BruceX Ops*

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Security](https://img.shields.io/badge/Security-Verified-green)
![Open Source](https://img.shields.io/badge/Open%20Source-Yes-orange)

## 📋 ¿Qué es esto?
TITAN OMNI es una herramienta de ciberseguridad diseñada para **Termux**. Realiza un escaneo de triple capa (Red, Web y SSL) para detectar fallos de seguridad en sitios web.

**🔒 100% Seguro:** Este código es de fuente abierta (Open Source). Eres libre de leer el archivo `titan_scanner.py` para verificar que no contiene código malicioso.

## 🚀 Características
* **🕵️ Escáner de Puertos:** Detecta puertas abiertas en el servidor.
* **🛡️ Auditoría Web:** Verifica si faltan protecciones contra hackers (XSS, Clickjacking).
* **📂 Archivos Expuestos:** Busca archivos sensibles olvidados (como robots.txt).
* **📄 Reportes Automáticos:** Genera un archivo de texto con la solución a los problemas.

## 📲 Instalación en Termux (Copia y Pega)

Escribe estos 3 comandos en tu terminal:

```bash
# 1. Actualizar y descargar requisitos
pkg update && pkg install git python -y
pip install requests

# 2. Clonar la herramienta
git clone https://github.com/bruceX-T/TITAN-OMNI..git

# 3. Entrar a la carpeta
cd TITAN-OMNI.

# 4. Ejecutar la herramienta
python titan_scanner.py

