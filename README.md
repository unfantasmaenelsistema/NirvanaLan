# NirvanaLan
Herramienta de auditoría de red local con interfaz web moderna
<div align="center">
  <img src="static/img/logo.png" alt="Nirvana LAN Logo" width="120">
  
  # Nirvana LAN

  **Herramienta de auditoría de red local con interfaz web moderna**

  ![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
  ![Flask](https://img.shields.io/badge/Flask-3.x-black?style=flat-square&logo=flask)
  ![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)
  ![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

  *Descubrimiento de hosts · Escaneo de puertos · Análisis de vulnerabilidades · Reportes*

</div>

---

## ¿Qué es Nirvana LAN?

Nirvana LAN es una herramienta de auditoría de seguridad para redes locales, escrita en Python con interfaz web. Cubre el flujo completo de una auditoría: desde el descubrimiento inicial de dispositivos hasta el análisis de vulnerabilidades y la generación de informes exportables, sin necesidad de APIs externas ni servicios en la nube.

Diseñada para administradores de sistemas, equipos de IT y profesionales de seguridad que necesitan conocer en detalle qué hay en su red y qué riesgos presenta.

---

## Capturas de pantalla

| Dashboard | Descubrimiento | Vulnerabilidades |
|-----------|---------------|-----------------|
| Vista general con métricas y gráficas de riesgo | Escaneo de red con progreso en tiempo real | Listado priorizado por severidad con recomendaciones |

---

## Características

### Fase 1 — Descubrimiento y Enumeración

| Módulo | Descripción |
|--------|-------------|
| **Descubrimiento de red** | Detección automática de interfaz, barrido ping + ARP, soporte IPv4, rangos CIDR personalizables |
| **Identificación de hosts** | Dirección MAC, nombre de host (DNS inverso), fabricante (base OUI integrada) |
| **OS Fingerprinting** | Detección de sistema operativo mediante análisis TTL (Linux / Windows / Dispositivo de red) |
| **Escaneo de puertos** | 63 puertos comunes, top-1000, rango completo 1-65535 o puertos personalizados. Concurrente con hasta 200 hilos |
| **Banner grabbing** | Captura de banners de servicios para identificar versiones de software |
| **Enumeración DNS** | Consultas A, AAAA, MX, NS, TXT, SOA, CNAME. Intento de transferencia de zona (AXFR) |
| **Enumeración SMB** | Recursos compartidos, usuarios (via rpcclient), detección de firma SMB |

### Fase 2 — Análisis de Vulnerabilidades

| Módulo | Descripción |
|--------|-------------|
| **Detección de servicios peligrosos** | 13 checks automáticos: Telnet, FTP sin cifrar, RDP expuesto, SMB (EternalBlue/MS17-010), MongoDB sin auth, Redis expuesto, Elasticsearch abierto, VNC, MSSQL, MySQL, SNMP v1/v2c, etc. |
| **Análisis de banners** | Detecta versiones obsoletas: Apache 2.0/2.1, OpenSSH 4/5, IIS 5/6/7, vsftpd antiguo, Webmin |
| **Risk scoring** | Puntuación 0-100 por host basada en severidad acumulada de hallazgos (CRITICAL×40, HIGH×20, MEDIUM×10, LOW×5) |
| **CVE references** | Referencias a CVEs conocidos: MS17-010, CVE-2019-0708 (BlueKeep), etc. |
| **Escaneo masivo** | Lanza análisis de vulnerabilidades en todos los hosts del inventario con un clic |

### Fase 3 — Gestión y Automatización

| Módulo | Descripción |
|--------|-------------|
| **Inventario de hosts** | Vista de tarjetas con filtro en tiempo real, notas por dispositivo, historial |
| **Reportes HTML** | Informe completo con estilos, tablas y métricas ejecutivas, listo para compartir |
| **Reportes TXT** | Texto plano para documentación, cumplimiento normativo (PCI DSS, HIPAA) o logging |
| **Scheduler** | Programación de escaneos recurrentes (hourly / daily / weekly) |
| **Modo claro/oscuro** | Tema persistente por usuario |
| **Base de datos local** | SQLite embebido, sin dependencias externas, datos 100% locales |

---

## Requisitos

### Obligatorios
- **Python 3.8 o superior**
- pip (incluido con Python)

Las dependencias Python se instalan automáticamente:
```
flask >= 2.0
psutil >= 5.8
requests >= 2.25
```

### Opcionales (amplían funcionalidades)

| Herramienta | Sistema | Función |
|-------------|---------|---------|
| `ping` | Windows / Linux | Descubrimiento de hosts por ICMP (fallback automático a TCP si no está disponible) |
| `arp` | Windows / Linux | Lectura de caché ARP para detección de MACs |
| `ip` / `ifconfig` | Linux | Detección de interfaces de red (fallback de psutil) |
| `dig` | Linux / macOS | Enumeración DNS completa y AXFR |
| `nslookup` | Windows | Enumeración DNS en Windows |
| `smbclient` | Linux | Listado de recursos compartidos SMB |
| `rpcclient` | Linux | Enumeración de usuarios SMB |

> **Nota:** La herramienta funciona sin ninguno de los opcionales usando métodos alternativos (TCP connect, lectura directa de `/proc/net/arp`, etc.). Para máxima efectividad en Linux, ejecutar con `sudo`.

---

## Instalación

### Linux / macOS

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/nirvana-lan.git
cd nirvana-lan

# 2. (Opcional) Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Lanzar (con sudo para funcionalidades ARP/ICMP completas)
sudo python3 app.py
# o usar el script de inicio:
chmod +x start.sh
sudo bash start.sh
```

### Windows

```cmd
REM 1. Clonar el repositorio
git clone https://github.com/tu-usuario/nirvana-lan.git
cd nirvana-lan

REM 2. Instalar dependencias
pip install -r requirements.txt

REM 3. Lanzar
python app.py
REM o hacer doble clic en start.bat
```

### Instalación rápida (sin git)

1. Descargar el ZIP desde [Releases](../../releases)
2. Extraer en cualquier carpeta
3. Ejecutar `start.sh` (Linux) o `start.bat` (Windows)

La aplicación se abre automáticamente en **http://localhost:7777**

---

## Uso

### Inicio rápido

1. **Lanzar** la aplicación con `sudo bash start.sh` o `start.bat`
2. El navegador abre automáticamente `http://localhost:7777`
3. Pulsar **⚡ Quick Scan** en la barra superior para un escaneo inmediato de la red detectada
4. Ver los resultados en **Discovery** → **Discovered Hosts**

### Flujo de trabajo completo

#### 1. Descubrimiento de red (`Discovery`)

```
Sidebar → Discovery
```

- La red local se detecta automáticamente. Si hay varias interfaces, aparecen como chips seleccionables
- Ajustar el rango CIDR si es necesario (ej. `192.168.1.0/24`)
- Activar/desactivar: OS Fingerprinting, resolución de nombres, lookup de fabricante
- Pulsar **▶ Start Discovery Scan**
- Los hosts aparecen en tiempo real en el panel de progreso y en la tabla **Discovered Hosts** al finalizar

#### 2. Escaneo de puertos (`Port Scanner`)

```
Sidebar → Port Scanner
```

- Introducir IP objetivo (o pulsar un host de la lista rápida)
- Seleccionar rango: Common ports (~63), Top 1000, Well-known (1-1024), Full (1-65535) o personalizado
- Los puertos de alto riesgo se resaltan automáticamente con su nivel de riesgo

#### 3. Enumeración de protocolos (`Enumeration`)

```
Sidebar → Enumeration → DNS | SMB
```

**DNS:** Introducir dominio → obtiene registros A, AAAA, MX, NS, TXT e intenta AXFR  
**SMB:** Introducir IP → lista recursos compartidos y usuarios del sistema

#### 4. Análisis de vulnerabilidades (`Vulnerabilities`)

```
Sidebar → Vulnerabilities
```

- Escanear un host concreto o pulsar **⚡ Scan All Known Hosts** para todo el inventario
- Las vulnerabilidades se clasifican por severidad: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Usar los filtros superiores para ver solo una categoría

#### 5. Inventario (`Host Inventory`)

```
Sidebar → Host Inventory
```

- Vista de tarjetas con todos los dispositivos descubiertos
- Búsqueda en tiempo real por IP, hostname, fabricante o MAC
- Clic en cualquier tarjeta para ver el detalle completo, puertos abiertos, vulnerabilidades y añadir notas

#### 6. Reportes (`Reports`)

```
Sidebar → Reports
```

- **HTML Report:** Informe completo con estilos, descargable, apto para presentar a dirección
- **TXT Report:** Texto plano para logs, ticketing o cumplimiento normativo
- **Preview:** Vista previa en el navegador antes de descargar

#### 7. Scheduler

```
Sidebar → Scheduler
```

Configurar escaneos automáticos periódicos (cada hora, diario, semanal) sobre cualquier rango de red.

---

## Estructura del proyecto

```
nirvana-lan/
├── app.py                  # Backend Flask: motor de escaneo, API REST, BD
├── requirements.txt        # Dependencias Python
├── start.sh                # Lanzador Linux/macOS
├── start.bat               # Lanzador Windows
├── README.md
├── db/
│   └── nirvana.db          # Base de datos SQLite (se crea automáticamente)
├── static/
│   ├── css/
│   │   └── style.css       # Estilos UI (tema claro/oscuro, diseño cybersecurity)
│   ├── js/
│   │   └── app.js          # Frontend JavaScript (SPA sin frameworks)
│   └── img/
│       └── logo.png        # Logo de la aplicación
└── templates/
    └── index.html          # Interfaz web completa (Single Page App)
```

### API REST

Todos los endpoints son locales (`localhost:7777`):

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `GET` | `/api/network-info` | Interfaces de red detectadas |
| `GET` | `/api/hosts` | Lista de hosts en inventario |
| `GET` | `/api/hosts/<ip>` | Detalle de un host (puertos, vulns, notas) |
| `POST` | `/api/hosts/<ip>/notes` | Actualizar notas de un host |
| `POST` | `/api/hosts/clear` | Limpiar inventario |
| `POST` | `/api/scan/start` | Iniciar escaneo (discovery/ports/vulns/dns/smb) |
| `GET` | `/api/scan/status/<id>` | Estado de un escaneo en curso |
| `GET` | `/api/vulnerabilities` | Todas las vulnerabilidades encontradas |
| `GET` | `/api/stats` | Estadísticas generales del dashboard |
| `GET` | `/api/report/html` | Descargar informe HTML |
| `GET` | `/api/report/txt` | Descargar informe TXT |
| `GET/POST` | `/api/scheduled` | Gestión de tareas programadas |

---

## Solución de problemas

### No se detecta la interfaz de red

La aplicación usa tres métodos en cascada para detectar la red:
1. psutil (todas las plataformas)
2. `socket.gethostbyname()`
3. `ip addr` / `ipconfig`

Si ninguno funciona, introducir el rango manualmente: `192.168.X.0/24`

En Linux, verificar con:
```bash
ip addr show
# o
ifconfig -a
```

### No encuentra hosts en la red

**Causa más común:** falta de permisos para ping/ARP.

```bash
# Linux: ejecutar con sudo
sudo python3 app.py

# Verificar que ping funciona
ping -c 1 192.168.1.1

# Ver tabla ARP
arp -n
cat /proc/net/arp
```

**Fallback automático:** Si `ping` no está disponible, Nirvana LAN usa TCP connect a puertos comunes (80, 443, 22, 445...) para detectar hosts. Hosts que no tengan ningún puerto abierto pueden no aparecer.

### Error al iniciar en Windows

```cmd
REM Asegurarse de que Python está en el PATH
python --version

REM Instalar dependencias manualmente si falla el .bat
pip install flask psutil requests
```

### La base de datos está corrupta o con esquema antiguo

```bash
# Eliminar la BD para que se regenere limpia
rm db/nirvana.db

# Reiniciar la aplicación
python3 app.py
```

### Puerto 7777 ocupado

Editar `app.py`, última línea, cambiar el puerto:
```python
app.run(host='0.0.0.0', port=8888, debug=False, threaded=True)
```

---

## Consideraciones de seguridad y rendimiento

- **Permisos:** En Linux, ejecutar con `sudo` habilita ping ICMP y lectura directa de ARP. Sin root, el descubrimiento usa TCP connect (ligeramente más lento pero funcional).
- **Rendimiento:** El escaneo de descubrimiento usa hasta 150 hilos concurrentes. Para redes /16 (65534 hosts) el tiempo puede ser considerable; se recomienda trabajar con subredes /24.
- **Tráfico de red:** Un escaneo de descubrimiento /24 genera ~500 paquetes ICMP/TCP en ~10-30 segundos. Puede activar alertas IDS. Usar solo en redes propias o con autorización explícita.
- **Datos locales:** Toda la información se almacena en `db/nirvana.db` (SQLite local). No se envía ningún dato a servidores externos.

---

## Aviso legal

> **⚠️ IMPORTANTE**
>
> Esta herramienta está diseñada exclusivamente para auditorías de seguridad **autorizadas**.
>
> - Usar únicamente en redes de tu propiedad o con permiso explícito por escrito del propietario
> - El escaneo no autorizado de redes puede constituir un delito informático en muchas jurisdicciones
> - El autor no se responsabiliza del uso indebido de esta herramienta
>
> **El uso de Nirvana LAN implica la aceptación de estos términos.**

---

## Contribuir

Las contribuciones son bienvenidas. Para cambios importantes, abre primero un _issue_ para discutir qué te gustaría modificar.

```bash
# Fork + clonar
git clone https://github.com/tu-usuario/nirvana-lan.git

# Crear rama
git checkout -b feature/nueva-funcionalidad

# Commit + push
git commit -m "Add: nueva funcionalidad"
git push origin feature/nueva-funcionalidad

# Abrir Pull Request
```

### Ideas para contribuir

- Soporte para IPv6 en descubrimiento
- Integración con bases de datos CVE (NVD API)
- Exportación a PDF
- Autenticación para escaneos SSH/WMI (escaneos autenticados)
- Plugin para detección de dispositivos IoT
- Notificaciones por email/webhook al finalizar escaneos

---

## Licencia

MIT License — ver [LICENSE](LICENSE) para detalles.

---

<div align="center">
  <sub>Hecho con Python · Flask · SQLite · Vanilla JS</sub>
</div>
