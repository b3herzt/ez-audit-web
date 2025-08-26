<!-- PROJECT TITLE & BADGES -->
<h1 align="center">🕵️‍♂️ ez‑audit‑web</h1>
<p align="center"><i>Framework base, simple y directo, para reconocimiento y auditoría web educativa</i></p>

<p align="center">
  <a href="#-características">Características</a> •
  <a href="#-instalación-rápida">Instalación</a> •
  <a href="#-uso">Uso</a> •
  <a href="#-legal--ética">Legal</a> •
  <a href="#-roadmap">Roadmap</a>
</p>

---

> ⚠️ <b>Solo para fines educativos y pruebas con autorización.</b> Este proyecto facilita ejecutar <i>checks</i> comunes de recon/seguridad (DNS, WHOIS, Nmap, headers, CORS, SSL, etc.). No es una herramienta “enterprise”. Úsalo con responsabilidad.

## 🧬 Filosofía
- <b>EZ</b>: configuración mínima, resultados rápidos.
- <b>Transparente</b>: todo a texto plano para guardar/compartir.
- <b>Extensible</b>: añade/quita pruebas sin pelearte con el código.

## ✨ Características
- Información de dominio: <b>DNS (A/MX)</b>, <b>WHOIS</b>.
- Red: <b>Nmap</b> (rápido/completo/servicios/OS).
- HTTP/S: cabeceras, cookies, <b>security headers</b> (HSTS, CSP, XFO…), <b>Host Header Injection</b>, <b>CORS</b>.
- Fingerprinting & discovery: <b>Gobuster</b>, <b>WhatWeb</b>, <b>Nikto</b>, <b>Sublist3r</b>.
- Criptografía: <b>SSLScan</b>.
- Todo se guarda en un <b>reporte con timestamp</b> (`auditoria_<dominio>_<fecha>.txt`).

## 🚀 Instalación rápida
Requisitos Python:
```bash
pip install -r requirements.txt
```
Herramientas externas (ejemplos Debian/Ubuntu):
```bash
sudo apt update
sudo apt install whois nmap gobuster whatweb nikto sslscan
pip install sublist3r
```

## 🕹 Uso
Interactivo (paso a paso):
```bash
python3 ez_audit_web.py
```
1) Introduce la URL/IP del objetivo (p.ej. `https://ejemplo.com`)  
2) Selecciona pruebas: `1,3,4,6,8,11,13`  
3) Revisa el archivo generado `auditoria_<dominio>_<fecha>.txt`

> Consejo: no subas reportes reales a GitHub; están ignorados por `.gitignore`.

## 🗂 Estructura
```
/
├─ ez_audit_web.py        # script principal (interactivo)
├─ README.md
├─ requirements.txt
├─ LICENSE
└─ .gitignore             # excluye reportes y temporales
```

## 🧪 Checks disponibles
1) DNS A/MX
2) WHOIS
3) Nmap (fast/full/sv/os/custom)
4) Cabeceras HTTP
5) Cookies
6) Security headers (HSTS, CSP, XFO, etc.)
7) Host Header Injection (X-Forwarded-Host)
8) CORS (Access-Control-Allow-Origin)
9) Gobuster (enumeración de directorios)
10) WhatWeb (fingerprinting)
11) Nikto
12) Sublist3r (subdominios)
13) SSLScan

## 🧯 Legal & Ética
- Realiza pruebas <b>exclusivamente</b> con autorización explícita del propietario del objetivo.
- Muchas pruebas generan tráfico que puede activar WAF/IDS/IPS.
- Los autores no se hacen responsables del uso indebido.

## 🛣 Roadmap
- [ ] Versión CLI con <code>argparse</code> (sin inputs interactivos).
- [ ] Salida adicional en <code>JSON</code>.
- [ ] Detección de dependencias y tiempos de espera configurables.
- [ ] Perfiles de escaneo (low/normal/aggressive).
- [ ] Export a HTML/Markdown del reporte.

## 🤝 Contribuciones
¡Bienvenidas! Abre un <i>issue</i> o envía un PR. Revisa primero el README y mantén el estilo simple/legible.

---

<p align="center">
  Hecho con ☕ por Ign Bravo — Licencia MIT
</p>
