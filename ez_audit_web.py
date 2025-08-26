#!/usr/bin/env python3
import requests
import dns.resolver
import subprocess
import signal
from urllib.parse import urlparse
from datetime import datetime
import sys

HEADERS = {"User-Agent": "Mozilla/5.0"}

def out(text, file):
    print(text)
    file.write(text + "\n")

def banner(file):
    text = "\n" + "="*70 + "\n AUDITORÍA WEB - FRAMEWORK BASE (INTERACTIVO)\n" + "="*70 + "\n"
    out(text, file)

def resolve_dns(domain, file):
    out("\n[=== RESOLUCIÓN DNS: A y MX ===]", file)
    out("[Método: dns.resolver]", file)
    try:
        a_records = dns.resolver.resolve(domain, 'A')
        for r in a_records:
            out(f"    A: {r}", file)
    except Exception as e:
        out(f"    [!] No se pudo resolver A: {e}", file)
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for r in mx_records:
            out(f"    MX: {r}", file)
    except Exception as e:
        out(f"    [!] No se pudo resolver MX: {e}", file)

def whois_info(domain, file):
    cmd = f"whois {domain}"
    out("\n[=== INFORMACIÓN WHOIS ===]", file)
    out(f"[Comando ejecutado: {cmd}]", file)
    try:
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        out(result.stdout.strip(), file)
    except FileNotFoundError:
        out("    [!] El comando whois no está instalado. Instálalo con 'apt install whois'.", file)

def nmap_scan(domain, file):
    print("\nOpciones para Nmap:")
    print(" 1) Rápido (top 100 puertos)                [nmap -F]")
    print(" 2) Completo (todos los puertos)            [nmap -p-]")
    print(" 3) Detección de servicios/versión          [nmap -sV]")
    print(" 4) Detección de sistema operativo          [nmap -O]")
    print(" 5) Personalizado (escribe tus opciones)")
    opt = input("Selecciona el tipo de escaneo Nmap (default 1): ").strip() or "1"
    if opt == "1":
        cmd = ["nmap", "-F", domain]
        desc = "Nmap Rápido (top 100 puertos)"
    elif opt == "2":
        cmd = ["nmap", "-p-", domain]
        desc = "Nmap Completo (todos los puertos)"
    elif opt == "3":
        cmd = ["nmap", "-sV", domain]
        desc = "Nmap con detección de servicios/versión"
    elif opt == "4":
        cmd = ["nmap", "-O", domain]
        desc = "Nmap con detección de sistema operativo"
    elif opt == "5":
        custom_opts = input("Escribe tus opciones para Nmap: ").strip().split()
        cmd = ["nmap"] + custom_opts + [domain]
        desc = "Nmap Personalizado"
    else:
        cmd = ["nmap", "-F", domain]
        desc = "Nmap Rápido (top 100 puertos)"
    cmd_str = " ".join(cmd)
    out(f"\n[=== ESCANEO DE PUERTOS CON NMAP ===]", file)
    out(f"[Comando ejecutado: {cmd_str}]", file)
    print(f"\n[+] Ejecutando: {cmd_str}\n")

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, preexec_fn=None)
        while True:
            try:
                for line in process.stdout:
                    print(line, end='')
                    file.write(line)
                process.wait()
                if process.returncode != 0:
                    out(f"\n[!] Nmap terminó con código de error {process.returncode}", file)
                break
            except KeyboardInterrupt:
                print("\n[!] ¿Deseas saltar esta herramienta? [s]altarla / [c]ontinuar esperando / [q]uitar todo")
                res = input("S/C/Q: ").strip().lower()
                if res == "s":
                    process.terminate()
                    print("[!] Escaneo Nmap saltado.\n")
                    break
                elif res == "q":
                    process.terminate()
                    print("[!] Saliendo del script...")
                    sys.exit(0)
                else:
                    print("[+] Continuando...")
                    continue
    except FileNotFoundError:
        out("    [!] Nmap no está instalado. Instálalo con 'apt install nmap'.", file)
    except Exception as e:
        out(f"    [!] Error ejecutando Nmap: {e}", file)

def http_headers(url, file):
    out("\n[=== OBTENER CABECERAS HTTP ===]", file)
    out("[Método: requests.get]", file)
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        for k, v in r.headers.items():
            out(f"    {k}: {v}", file)
    except Exception as e:
        out(f"    [!] Error en la conexión: {e}", file)

def check_cookies(url, file):
    out("\n[=== ANALIZAR COOKIES DE RESPUESTA ===]", file)
    out("[Método: requests.get]", file)
    try:
        r = requests.get(url, headers=HEADERS)
        cookies = r.headers.get('Set-Cookie')
        if cookies:
            out("    Set-Cookie encontrado:", file)
            out("    " + cookies, file)
        else:
            out("    No se encontraron cookies en la respuesta.", file)
    except Exception as e:
        out(f"    [!] Error: {e}", file)

def check_security_headers(url, file):
    out("\n[=== ANÁLISIS DE CABECERAS DE SEGURIDAD HTTP ===]", file)
    out("[Método: requests.get]", file)
    security_headers = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
        "Permissions-Policy", "X-XSS-Protection"
    ]
    try:
        r = requests.get(url, headers=HEADERS)
        for h in security_headers:
            value = r.headers.get(h)
            if value:
                out(f"    {h}: {value}", file)
            else:
                out(f"    [!] {h} NO encontrada.", file)
    except Exception as e:
        out(f"    [!] Error al obtener cabeceras de seguridad: {e}", file)

def host_header_injection(url, file):
    out("\n[=== PRUEBA DE HOST HEADER INJECTION ===]", file)
    out('[Método: requests.get con header "X-Forwarded-Host"]', file)
    try:
        r = requests.get(url, headers={"X-Forwarded-Host": "evil.com"}, allow_redirects=False)
        if "evil.com" in r.text or r.headers.get("Location", "").startswith("https://evil.com"):
            out("    🔥 Vulnerabilidad detectada: redirección o inclusión de evil.com encontrada.", file)
        else:
            out("    ✅ No se detectó manipulación obvia por X-Forwarded-Host.", file)
    except Exception as e:
        out(f"    [!] Falló la prueba de inyección: {e}", file)

def check_cors(url, file):
    out("\n[=== PRUEBA DE POLÍTICA CORS ===]", file)
    out('[Método: requests.get con header "Origin"]', file)
    try:
        r = requests.get(url, headers={"Origin": "https://evil.com"})
        cors = r.headers.get('Access-Control-Allow-Origin')
        if cors == '*':
            out("    ⚠️ CORS está configurado como abierto '*', lo cual es riesgoso.", file)
        elif cors:
            out(f"    CORS permite: {cors}", file)
        else:
            out("    No hay cabecera Access-Control-Allow-Origin en la respuesta.", file)
    except Exception as e:
        out(f"    [!] Error al probar CORS: {e}", file)

def gobuster_scan(url, file):
    default_wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    wordlist = input(f"Diccionario para Gobuster (ENTER para usar default: {default_wordlist}): ").strip()
    if not wordlist:
        wordlist = default_wordlist
    threads = input("Número de threads para Gobuster (ENTER para default 10): ").strip()
    if not threads:
        threads = "10"
    cmd = f"gobuster dir -u {url} -w {wordlist} -t {threads}"
    out("\n[=== ENUMERACIÓN DE DIRECTORIOS CON GOBUSTER ===]", file)
    out(f"[Comando ejecutado: {cmd}]", file)
    print("\n[+] Iniciando Gobuster... esto puede tardar unos minutos dependiendo del objetivo.")
    try:
        cmd_list = ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", threads]
        process = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        while True:
            try:
                for line in process.stdout:
                    if "Progress:" in line:
                        print(line.strip())
                    elif line.strip() and not any(
                        status in line for status in [
                            "Status: 404", "Status: 403", "Status: 401", "Status: 400", "Status: 503", "Status: 502", "Status: 508"
                        ]):
                        print(line, end='')
                        file.write(line)
                process.wait()
                if process.returncode != 0:
                    out(f"\n[!] Gobuster terminó con código de error {process.returncode}", file)
                break
            except KeyboardInterrupt:
                print("\n[!] ¿Deseas saltar esta herramienta? [s]altarla / [c]ontinuar esperando / [q]uitar todo")
                res = input("S/C/Q: ").strip().lower()
                if res == "s":
                    process.terminate()
                    print("[!] Gobuster saltado.\n")
                    break
                elif res == "q":
                    process.terminate()
                    print("[!] Saliendo del script...")
                    sys.exit(0)
                else:
                    print("[+] Continuando...")
                    continue
    except FileNotFoundError:
        out("    [!] Gobuster no está instalado. Instálalo con 'apt install gobuster'.", file)
    except Exception as e:
        out(f"    [!] Error ejecutando Gobuster: {e}", file)

def web_fingerprinting(url, file):
    cmd = f"whatweb {url}"
    out("\n[=== FINGERPRINTING CON WHATWEB ===]", file)
    out(f"[Comando ejecutado: {cmd}]", file)
    try:
        result = subprocess.run(["whatweb", url], capture_output=True, text=True)
        out(result.stdout.strip(), file)
    except FileNotFoundError:
        out("    [!] WhatWeb no está instalado. Instálalo con 'apt install whatweb'.", file)

def nikto_scan(domain, file):
    print("\nOpciones para Nikto:")
    print(" 1) Normal (solo -h)")
    print(" 2) Forzar SSL             (agrega -ssl)")
    print(" 3) User-Agent personalizado")
    print(" 4) Tuning personalizado   (agrega -Tuning)")
    print(" 5) Opciones avanzadas (escribe flags extra)")
    opt = input("Selecciona el tipo de escaneo Nikto (default 1): ").strip() or "1"
    cmd = ["nikto", "-h", domain]
    if opt == "2":
        cmd.append("-ssl")
    elif opt == "3":
        ua = input("Escribe el User-Agent personalizado: ").strip()
        if ua:
            cmd += ["-useragent", ua]
    elif opt == "4":
        tuning = input("Escribe los códigos de tuning (ejemplo: 123bde): ").strip()
        if tuning:
            cmd += ["-Tuning", tuning]
    elif opt == "5":
        extra = input("Escribe las opciones avanzadas de Nikto (ejemplo: -evasion 1): ").strip().split()
        cmd += extra
    cmd_str = " ".join(cmd)
    out(f"\n[=== ESCANEO CON NIKTO ===]", file)
    out(f"[Comando ejecutado: {cmd_str}]", file)
    print(f"\n[+] Ejecutando: {cmd_str}\n")
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        while True:
            try:
                for line in process.stdout:
                    print(line, end='')
                    file.write(line)
                process.wait()
                if process.returncode != 0:
                    out(f"\n[!] Nikto terminó con código de error {process.returncode}", file)
                break
            except KeyboardInterrupt:
                print("\n[!] ¿Deseas saltar esta herramienta? [s]altarla / [c]ontinuar esperando / [q]uitar todo")
                res = input("S/C/Q: ").strip().lower()
                if res == "s":
                    process.terminate()
                    print("[!] Nikto saltado.\n")
                    break
                elif res == "q":
                    process.terminate()
                    print("[!] Saliendo del script...")
                    sys.exit(0)
                else:
                    print("[+] Continuando...")
                    continue
    except FileNotFoundError:
        out("    [!] Nikto no está instalado. Instálalo con 'apt install nikto'.", file)
    except Exception as e:
        out(f"    [!] Error ejecutando Nikto: {e}", file)

def subdomain_enum(domain, file):
    cmd = f"sublist3r -d {domain} -o temp_subs.txt"
    out("\n[=== ENUMERACIÓN DE SUBDOMINIOS CON SUBLIST3R ===]", file)
    out(f"[Comando ejecutado: {cmd}]", file)
    try:
        result = subprocess.run(["sublist3r", "-d", domain, "-o", "temp_subs.txt"], capture_output=True, text=True)
        try:
            with open("temp_subs.txt", "r") as f:
                subs = f.read()
            out(subs, file)
        except Exception as e:
            out("    [!] No se pudieron leer subdominios encontrados.", file)
    except FileNotFoundError:
        out("    [!] Sublist3r no está instalado. Instálalo con 'apt install sublist3r'.", file)

def ssl_scan(domain, file):
    cmd = f"sslscan {domain}"
    out("\n[=== PRUEBA SSL/TLS CON SSLSCAN ===]", file)
    out(f"[Comando ejecutado: {cmd}]", file)
    try:
        result = subprocess.run(["sslscan", domain], capture_output=True, text=True)
        out(result.stdout.strip(), file)
    except FileNotFoundError:
        out("    [!] SSLScan no está instalado. Instálalo con 'apt install sslscan'.", file)

def main():
    target = input("Introduce la URL completa o IP del objetivo (ej: https://ejemplo.com o 192.168.0.1): ").strip()
    if not target.startswith("http"):
        url = "http://" + target
    else:
        url = target
    domain = urlparse(url).netloc if "://" in url else url
    safe_domain = domain.replace(':', '_').replace('/', '_')
    fecha = datetime.now().strftime('%Y%m%d-%H%M%S')
    filename = f"auditoria_{safe_domain}_{fecha}.txt"
    print(f"\n[+] Toda la salida se guardará en: {filename}")

    print("\nSelecciona las pruebas que deseas realizar (puedes escribir varios números separados por coma):")

    print("\n--- INFORMACIÓN DEL DOMINIO Y RED ---")
    print("  1) Resolución DNS (A y MX)")
    print("  2) WHOIS")
    print("  3) Escaneo de puertos (Nmap)")

    print("\n--- AUDITORÍA HTTP/S ---")
    print("  4) Obtener cabeceras HTTP")
    print("  5) Analizar cookies de respuesta")
    print("  6) Análisis de cabeceras de seguridad HTTP")
    print("  7) Prueba de Host Header Injection")
    print("  8) Prueba de CORS")
    print("  9) Enumeración de directorios (Gobuster)")
    print(" 10) Fingerprinting de tecnologías (WhatWeb)")
    print(" 11) Escaneo con Nikto")

    print("\n--- OTROS TESTS ÚTILES ---")
    print(" 12) Enumeración de subdominios (Sublist3r)")
    print(" 13) Prueba SSL/TLS (SSLScan)")

    opciones = input("Opciones: ").replace(" ", "").split(",")

    with open(filename, "w", encoding="utf-8") as file:
        banner(file)
        out(f"Objetivo: {target}", file)
        out(f"Fecha y hora: {fecha}", file)
        out("="*70, file)
        if "1" in opciones:
            resolve_dns(domain, file)
        if "2" in opciones:
            whois_info(domain, file)
        if "3" in opciones:
            nmap_scan(domain, file)
        if "4" in opciones:
            http_headers(url, file)
        if "5" in opciones:
            check_cookies(url, file)
        if "6" in opciones:
            check_security_headers(url, file)
        if "7" in opciones:
            host_header_injection(url, file)
        if "8" in opciones:
            check_cors(url, file)
        if "9" in opciones:
            gobuster_scan(url, file)
        if "10" in opciones:
            web_fingerprinting(url, file)
        if "11" in opciones:
            nikto_scan(domain, file)
        if "12" in opciones:
            subdomain_enum(domain, file)
        if "13" in opciones:
            ssl_scan(domain, file)
        out("\n[✔] Auditoría completada.\n", file)
    print(f"\n[✔] Listo. Revisa el archivo: {filename}\n")

if __name__ == "__main__":
    main()
