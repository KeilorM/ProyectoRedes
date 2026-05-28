import socket
import threading
import fnmatch
import ssl
import os
import tempfile
import csv
import time
import datetime
from datetime import datetime as dt
from collections import defaultdict

# Cryptography imports for MITM TLS
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import DNSName
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BUFFER_SIZE = 4096
BLACKLIST_FILE = "blacklist.txt"
LOG_FILE = "proxy.log"
CA_CERT = "ca.crt"
CA_KEY  = "ca.key"

# =========================
# SHARED STATE (thread-safe)
# =========================
stats_lock = threading.Lock()
stats = {
    "total_requests": 0,
    "total_bytes": 0,
    "blocked": 0,
    "allowed": 0,
    "domains": defaultdict(int),
    "clients": defaultdict(int),
    "requests_log": []   # list of dicts for panel / export
}


# =========================
# LOGGING
# =========================
def log_request(client_ip, domain, method, status, bytes_transferred):
    timestamp = dt.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": timestamp,
        "client_ip": client_ip,
        "domain": domain,
        "method": method,
        "status": status,
        "bytes": bytes_transferred
    }

    with stats_lock:
        write_header = not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=entry.keys())
            if write_header:
                writer.writeheader()
            writer.writerow(entry)

        stats["total_requests"] += 1
        stats["total_bytes"] += bytes_transferred
        stats["domains"][domain] += 1
        stats["clients"][client_ip] += 1
        if status == "BLOCKED":
            stats["blocked"] += 1
        elif status == "ALLOWED":
            stats["allowed"] += 1
        stats["requests_log"].append(entry)
        if len(stats["requests_log"]) > 500:
            stats["requests_log"] = stats["requests_log"][-500:]

    print(f"[{timestamp}] {status} | {client_ip} | {method} | {domain} | {bytes_transferred}B")


# =========================
# LOAD BLACKLIST
# =========================
def load_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
    except:
        return []


def is_blocked(host, blacklist):
    host = host.lower().strip()
    for rule in blacklist:
        rule = rule.lower().strip()
        if rule == host:
            return True
        if "*" in rule:
            if fnmatch.fnmatch(host, rule):
                return True
        if rule.startswith("."):
            if host.endswith(rule):
                return True
    return False


# =========================
# BLOCK PAGE (HTML completo)
# =========================
def send_block_page(sock, domain="este sitio"):
    body = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sitio bloqueado</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');
    :root {{
      --bg: #0a0c0f; --surface: #111418; --border: #1e2530;
      --accent2: #ff4d6d; --text: #c8d0dc; --muted: #5a6475; --card: #13171e;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg); color: var(--text);
      font-family: 'Syne', sans-serif; min-height: 100vh;
      display: flex; flex-direction: column;
    }}
    header {{
      display: flex; align-items: center; justify-content: space-between;
      padding: 20px 32px; border-bottom: 1px solid var(--border);
      background: var(--surface);
    }}
    header h1 {{
      font-size: 1.3rem; font-weight: 800; letter-spacing: 0.08em;
      text-transform: uppercase; color: var(--accent2);
    }}
    .badge {{
      font-family: 'JetBrains Mono', monospace; font-size: 0.7rem;
      padding: 4px 10px; border-radius: 4px;
      border: 1px solid var(--accent2); color: var(--accent2);
    }}
    main {{
      flex: 1; display: flex; align-items: center;
      justify-content: center; padding: 40px 20px;
    }}
    .card {{
      background: var(--card); border: 1px solid var(--border);
      border-top: 3px solid var(--accent2); border-radius: 12px;
      padding: 48px 40px; max-width: 520px; width: 100%; text-align: center;
    }}
    .icon {{ font-size: 56px; margin-bottom: 20px; }}
    h2 {{
      color: var(--accent2); font-size: 1.6rem; font-weight: 800;
      letter-spacing: 0.05em; text-transform: uppercase; margin-bottom: 10px;
    }}
    .domain {{
      background: rgba(255,77,109,0.1); color: var(--accent2);
      border: 1px solid rgba(255,77,109,0.3); border-radius: 6px;
      padding: 10px 20px; display: inline-block;
      font-family: 'JetBrains Mono', monospace; font-size: 1rem;
      margin: 16px 0 24px; word-break: break-all;
    }}
    p {{ color: var(--muted); line-height: 1.7; font-size: 0.9rem; }}
    footer {{
      text-align: center; padding: 16px; font-size: 0.72rem;
      color: var(--muted); border-top: 1px solid var(--border);
      font-family: 'JetBrains Mono', monospace;
    }}
  </style>
</head>
<body>
  <header>
    <h1>&#x26A1; Proxy Monitor</h1>
    <span class="badge">BLOQUEADO</span>
  </header>
  <main>
    <div class="card">
      <div class="icon">&#x1F6AB;</div>
      <h2>Acceso denegado</h2>
      <div class="domain">{domain}</div>
      <p>Este sitio est&#225; restringido por la pol&#237;tica del proxy.<br>
         No es posible acceder a este dominio desde esta red.</p>
    </div>
  </main>
  <footer>Proxy UNA &#8212; Comunicaci&#243;n y Redes de Computadores</footer>
</body>
</html>"""
    encoded = body.encode("utf-8")
    response = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(encoded)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8") + encoded
    try:
        sock.sendall(response)
        time.sleep(1.0)
    except:
        pass


# =========================
# MITM TLS: CERT GENERATION
# =========================
def generate_cert_for_domain(domain):
    """Genera un certificado TLS firmado por la CA local para interceptar HTTPS."""
    with open(CA_CERT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                DNSName(domain),
                DNSName(f"*.{domain}"),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
    key_file  = tempfile.NamedTemporaryFile(delete=False, suffix=".key")
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    cert_file.close()
    key_file.close()
    return cert_file.name, key_file.name


# =========================
# HTTPS HANDLER (MITM TLS)
# FIX: Se eliminaron los bloqueos tempranos (antes del 200 + TLS handshake).
#      Ahora SIEMPRE se responde 200 y se establece TLS primero.
#      El bloqueo ocurre sobre el socket TLS para que el browser pueda
#      leer y renderizar la página HTML de bloqueo correctamente.
# =========================
def handle_https(client_socket, host, client_ip):
    blacklist = load_blacklist()

    # SIEMPRE responder 200 para que el browser inicie el handshake TLS.
    # Sin esto, el browser nunca puede leer ninguna respuesta HTML.
    client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    # Verificar que existen los archivos CA
    if not os.path.exists(CA_CERT) or not os.path.exists(CA_KEY):
        print(f"[ERROR] ca.crt / ca.key no encontrados — no se puede hacer MITM para {host}")
        client_socket.close()
        return

    # Generar certificado falso para este dominio
    try:
        cert_path, key_path = generate_cert_for_domain(host)
    except Exception as e:
        print(f"[ERROR] No se pudo generar cert para {host}: {e}")
        client_socket.close()
        return

    # Envolver socket del cliente con TLS (proxy actúa como servidor TLS)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        tls_client = ctx.wrap_socket(client_socket, server_side=True)
    except Exception as e:
        print(f"[TLS wrap error] {host}: {e}")
        client_socket.close()
        return
    finally:
        os.unlink(cert_path)
        os.unlink(key_path)

    # Leer la request HTTP real (ya descifrada)
    try:
        tls_client.settimeout(15)
        raw = tls_client.recv(8192).decode(errors="ignore")
    except Exception as e:
        print(f"[ERROR] No se pudo leer request TLS de {host}: {e}")
        tls_client.close()
        return

    # Extraer host real del header HTTP (puede diferir del CONNECT)
    effective_host = host
    for line in raw.split("\r\n"):
        if line.lower().startswith("host:"):
            effective_host = line.split(":", 1)[1].strip().split(":")[0]
            break

    print(f"[HTTPS MITM] host={host} | effective={effective_host}")

    # FIX: Bloqueo por dominio SOBRE TLS — el browser descifra y renderiza el HTML
    if is_blocked(effective_host, blacklist):
        print(f"[BLOCKED HTTPS] {effective_host}")
        log_request(client_ip, effective_host, "CONNECT", "BLOCKED", 0)
        send_block_page(tls_client, effective_host)
        tls_client.close()
        return

    # FIX: Keyword check SOBRE TLS — mismo motivo
    request_line = raw.split("\r\n")[0]
    parts = request_line.split()
    url = parts[1] if len(parts) >= 2 else ""
    for rule in blacklist:
        if "*" not in rule and "." not in rule and not rule.startswith("."):
            if rule in url.lower() or rule in effective_host.lower():
                print(f"[BLOCKED HTTPS keyword] '{rule}' en {effective_host}")
                log_request(client_ip, effective_host, "CONNECT", "BLOCKED", 0)
                send_block_page(tls_client, effective_host)
                tls_client.close()
                return

    # Conectar al servidor real con TLS
    try:
        raw_server = socket.create_connection((host, 443), timeout=15)
        server_ctx = ssl.create_default_context()
        tls_server = server_ctx.wrap_socket(raw_server, server_hostname=host)
    except Exception as e:
        print(f"[ERROR] No se pudo conectar a {host}:443 — {e}")
        log_request(client_ip, effective_host, "CONNECT", "ERROR", 0)
        tls_client.close()
        return

    # Reenviar la request original al servidor
    try:
        tls_server.sendall(raw.encode())
    except Exception as e:
        print(f"[ERROR] No se pudo reenviar request a {host}: {e}")
        tls_client.close()
        tls_server.close()
        return

    bytes_counter = [0]

    def forward(src, dst, count=False):
        try:
            src.settimeout(15)
            while True:
                chunk = src.recv(BUFFER_SIZE)
                if not chunk:
                    break
                dst.sendall(chunk)
                if count:
                    bytes_counter[0] += len(chunk)
        except:
            pass

    t1 = threading.Thread(target=forward, args=(tls_client, tls_server, False))
    t2 = threading.Thread(target=forward, args=(tls_server, tls_client, True))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    log_request(client_ip, effective_host, "CONNECT", "ALLOWED", bytes_counter[0])
    tls_client.close()
    tls_server.close()


# =========================
# HTTP HANDLER
# =========================
def handle_http(client_socket, request_text, lines, request_line, client_ip):
    blacklist = load_blacklist()

    parts = request_line.split()
    method = parts[0] if parts else "GET"

    host = None
    for line in lines:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip().split(":")[0]
            break

    if not host:
        client_socket.close()
        return

    full_url = parts[1] if len(parts) >= 2 else ""

    if is_blocked(host, blacklist):
        print(f"[BLOCKED HTTP] {host}")
        log_request(client_ip, host, method, "BLOCKED", 0)
        send_block_page(client_socket, host)
        client_socket.close()
        return

    for rule in blacklist:
        if "*" not in rule and "." not in rule and not rule.startswith("."):
            if rule in full_url.lower() or rule in host.lower():
                print(f"[BLOCKED keyword] '{rule}' in {full_url}")
                log_request(client_ip, host, method, "BLOCKED", 0)
                send_block_page(client_socket, host)
                client_socket.close()
                return

    if len(parts) >= 2 and parts[1].startswith("http://"):
        url = parts[1]
        path = ("/" + url.split("/", 3)[3]) if "/" in url[7:] else "/"
        parts[1] = path
        lines[0] = " ".join(parts)

    new_request = "\r\n".join(lines)
    if not new_request.endswith("\r\n\r\n"):
        new_request += "\r\n"

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.connect((host, 80))
    except Exception as e:
        print(f"[ERROR] Cannot connect to {host}:80 — {e}")
        log_request(client_ip, host, method, "ERROR", 0)
        try:
            body = "<html><body><h1>502 Bad Gateway</h1><p>Could not connect to host.</p></body></html>"
            resp = (
                "HTTP/1.1 502 Bad Gateway\r\n"
                "Content-Type: text/html\r\n"
                f"Content-Length: {len(body.encode())}\r\n"
                "Connection: close\r\n\r\n" + body
            )
            client_socket.sendall(resp.encode())
        except:
            pass
        client_socket.close()
        return

    server_socket.settimeout(15)
    server_socket.sendall(new_request.encode())

    total_bytes = 0
    while True:
        try:
            data = server_socket.recv(BUFFER_SIZE)
            if not data:
                break
            total_bytes += len(data)
            client_socket.sendall(data)
        except socket.timeout:
            break
        except:
            break

    log_request(client_ip, host, method, "ALLOWED", total_bytes)

    server_socket.close()
    client_socket.close()


# =========================
# MAIN HANDLER
# =========================
def handle_client(client_socket, client_address):
    client_ip = client_address[0]
    print(f"[+] Connection from {client_ip}")

    try:
        client_socket.settimeout(15)
        request = client_socket.recv(BUFFER_SIZE)
        if not request:
            client_socket.close()
            return

        request_text = request.decode(errors="ignore")
        lines = request_text.split("\r\n")
        request_line = lines[0]

        print(f"[REQUEST] {request_line}")

        if request_line.startswith("CONNECT"):
            host_port = request_line.split(" ")[1]
            host = host_port.split(":")[0]
            handle_https(client_socket, host, client_ip)
        else:
            handle_http(client_socket, request_text, lines, request_line, client_ip)

    except Exception as e:
        print(f"[ERROR] {e}")
        try:
            client_socket.close()
        except:
            pass


# =========================
# START PROXY
# =========================
def start_proxy(port=8080):
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    if not os.path.exists(CA_CERT) or not os.path.exists(CA_KEY):
        print("   ADVERTENCIA: ca.crt o ca.key no encontrados.")
        print("   Ejecutá gen_ca.py primero para generar la CA.")
        print("   Sin CA, los sitios HTTPS bloqueados mostrarán error del navegador en lugar de la página HTML.\n")

    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind(("0.0.0.0", port))
    proxy_socket.listen(100)
    print(f"[+] Proxy escuchando en el puerto {port}")

    while True:
        client_socket, client_address = proxy_socket.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        thread.daemon = True
        thread.start()


if __name__ == "__main__":
    start_proxy(8080)