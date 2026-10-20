#!/usr/bin/env bash
# Nirvana LAN — arranque en Linux/macOS. Uso: ./start.sh [--port 7777] [--lan] [--no-browser]
set -e
cd "$(dirname "$0")"
echo
echo "  =========================================="
echo "   NIRVANA LAN - Auditoría de red local"
echo "   Un fantasma en el sistema"
echo "  =========================================="
echo
command -v python3 >/dev/null || { echo "  ERROR: falta python3 (sudo apt install python3 python3-venv)"; exit 1; }
if [ ! -d .venv ]; then
  echo "  Creando entorno virtual .venv…"
  python3 -m venv .venv
fi
. .venv/bin/activate
pip install -r requirements.txt --quiet --disable-pip-version-check
echo
echo "  Panel: http://localhost:7777   (Ctrl+C para salir)"
echo "  Úsala solo en redes propias o con autorización."
if [ "$EUID" -ne 0 ]; then
  echo "  Nota: sin root el ping funciona igual; la caché ARP se lee de /proc/net/arp."
fi
echo
exec python app.py "$@"
