@echo off
chcp 65001 >nul
echo.
echo  ==========================================
echo   NIRVANA LAN - Auditoria de red local
echo   Un fantasma en el sistema
echo  ==========================================
echo.
python --version >nul 2>&1
if errorlevel 1 (
    echo  ERROR: no se encuentra Python. Instala Python 3.9+ desde python.org
    pause
    exit /b 1
)
echo  Instalando dependencias...
python -m pip install -r "%~dp0requirements.txt" --quiet --disable-pip-version-check
echo.
echo  Abriendo http://localhost:7777  (Ctrl+C para salir)
echo  Usala solo en redes propias o con autorizacion.
echo.
python "%~dp0app.py" %*
pause
