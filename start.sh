#!/bin/bash
echo ""
echo "  =========================================="
echo "   NIRVANA LAN - Network Audit Tool"
echo "  =========================================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "  ERROR: python3 not found."
    echo "  Install with: sudo apt install python3 python3-pip"
    exit 1
fi

echo "  Python: $(python3 --version)"
echo ""

# Install dependencies
echo "  Installing dependencies..."
pip3 install flask psutil requests --quiet 2>/dev/null || \
pip3 install flask psutil requests --quiet --break-system-packages 2>/dev/null

echo ""
echo "  Starting Nirvana LAN..."
echo "  Browser will open at http://localhost:7777"
echo "  Press Ctrl+C to stop"
echo ""

# Run as root if possible (needed for ARP/ICMP scanning)
if [ "$EUID" -eq 0 ]; then
    python3 app.py
else
    echo "  NOTE: Running without root. Some network features may be limited."
    echo "  For full functionality: sudo bash start.sh"
    echo ""
    python3 app.py
fi
