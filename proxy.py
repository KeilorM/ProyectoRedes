import socket
import threading
import fnmatch
import struct
import os
import json
import csv
import time
from datetime import datetime
from collections import defaultdict

BUFFER_SIZE = 4096
BLACKLIST_FILE = "blacklist.txt"
LOG_FILE = "proxy.log"

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
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": timestamp,
        "client_ip": client_ip,
        "domain": domain,
        "method": method,
        "status": status,
        "bytes": bytes_transferred
    }

    # Write to log file
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

def send_block_page(client_socket, domain="este sitio"):
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
        f"Content-Length: {{len(encoded)}}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8") + encoded
    try:
        client_socket.sendall(response)
        import time; time.sleep(0.3)
    except:
        pass

# =========================
# SNI EXTRACTION FROM TLS
# =========================
def extract_sni(data):
    """
    Parse the TLS ClientHello handshake to extract the SNI hostname.
    Returns the SNI string or None if not found.
    """
    try:
        idx = 0
        # TLS record header: type(1) + version(2) + length(2)
        if len(data) < 5:
            return None
        record_type = data[idx]
        idx += 1
        if record_type != 0x16:   # 0x16 = Handshake
            return None
        idx += 2  # skip version
        record_len = struct.unpack("!H", data[idx:idx+2])[0]
        idx += 2

        # Handshake header: type(1) + length(3)
        if len(data) < idx + 4:
            return None
        handshake_type = data[idx]
        idx += 1
        if handshake_type != 0x01:  # 0x01 = ClientHello
            return None
        idx += 3  # skip handshake length

        # ClientHello: version(2) + random(32) + session_id_len(1)
        if len(data) < idx + 35:
            return None
        idx += 34  # skip version + random
        session_id_len = data[idx]
        idx += 1 + session_id_len  # skip session id

        # Cipher suites
        if len(data) < idx + 2:
            return None
        cipher_len = struct.unpack("!H", data[idx:idx+2])[0]
        idx += 2 + cipher_len

        # Compression methods
        if len(data) < idx + 1:
            return None
        comp_len = data[idx]
        idx += 1 + comp_len

        # Extensions length
        if len(data) < idx + 2:
            return None
        ext_total_len = struct.unpack("!H", data[idx:idx+2])[0]
        idx += 2

        end = idx + ext_total_len
        while idx + 4 <= end and idx + 4 <= len(data):
            ext_type = struct.unpack("!H", data[idx:idx+2])[0]
            ext_len  = struct.unpack("!H", data[idx+2:idx+4])[0]
            idx += 4
            if ext_type == 0x0000:  # SNI extension
                # server_name_list_len(2) + type(1) + name_len(2) + name
                if len(data) < idx + 5:
                    return None
                idx += 2  # skip list length
                idx += 1  # skip name_type (0 = host_name)
                name_len = struct.unpack("!H", data[idx:idx+2])[0]
                idx += 2
                sni = data[idx:idx+name_len].decode("utf-8", errors="ignore")
                return sni
            idx += ext_len

    except Exception:
        pass
    return None


# =========================
# HTTPS HANDLER (CONNECT)
# =========================
def handle_https(client_socket, host, client_ip):
    blacklist = load_blacklist()

    # --- Peek at TLS ClientHello to get real SNI ---
    # First send 200 so client starts TLS handshake
    # Revisión 1: host del CONNECT (antes de responder nada)
    if is_blocked(host, blacklist):
        print(f"[BLOCKED HTTPS] {host}")
        log_request(client_ip, host, "CONNECT", "BLOCKED", 0)
        client_socket.close()
        return

    # Revisión 1b: keywords en el hostname HTTPS
    for rule in blacklist:
        if "*" not in rule and "." not in rule and not rule.startswith("."):
            if rule in host.lower():
                print(f"[BLOCKED HTTPS keyword] '{rule}' en {host}")
                log_request(client_ip, host, "CONNECT", "BLOCKED", 0)
                client_socket.close()
                return

    # Ahora se envia el 200
    client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    # Peek at the first bytes (TLS ClientHello)
    # Leer el ClientHello para SNI real
    try:
        client_socket.settimeout(15)
        tls_hello = client_socket.recv(8192)
    except:
        tls_hello = b""
    finally:
        client_socket.settimeout(None)

    sni_host = extract_sni(tls_hello) if tls_hello else None
    effective_host = sni_host if sni_host else host

    # Revisión 2: SNI (puede diferir del host del CONNECT)
    if sni_host and sni_host != host and is_blocked(sni_host, blacklist):
        print(f"[BLOCKED SNI] {sni_host}")
        log_request(client_ip, sni_host, "CONNECT", "BLOCKED", 0)
        client_socket.close()
        return

    print(f"[HTTPS] host={host} | SNI={sni_host} | effective={effective_host}")

    if is_blocked(effective_host, blacklist):
        print(f"[BLOCKED HTTPS/SNI] {effective_host}")
        log_request(client_ip, effective_host, "CONNECT", "BLOCKED", 0)
        try:
            client_socket.close()
        except:
            pass
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.connect((host, 443))
        server_socket.settimeout(15)
    except Exception as e:
        print(f"[ERROR] Cannot connect to {host}:443 — {e}")
        log_request(client_ip, effective_host, "CONNECT", "ERROR", 0)
        server_socket.close()
        client_socket.close()
        return

    # Forward the already-peeked ClientHello
    if tls_hello:
        server_socket.sendall(tls_hello)

    bytes_counter = [0]

    def forward(src, dst, count=False):
        try:
            src.settimeout(15)
            while True:
                data = src.recv(BUFFER_SIZE)
                if not data:
                    break
                dst.sendall(data)
                if count:
                    bytes_counter[0] += len(data)
        except:
            pass

    t1 = threading.Thread(target=forward, args=(client_socket, server_socket, False))
    t2 = threading.Thread(target=forward, args=(server_socket, client_socket, True))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    log_request(
        client_ip,
        effective_host,
        "CONNECT",
        "ALLOWED",
        bytes_counter[0]
    )

    client_socket.close()
    server_socket.close()


# =========================
# HTTP HANDLER
# =========================
def handle_http(client_socket, request_text, lines, request_line, client_ip):
    blacklist = load_blacklist()

    # Extract method
    parts = request_line.split()
    method = parts[0] if parts else "GET"

    # Extract host
    host = None
    for line in lines:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip().split(":")[0]
            break

    if not host:
        client_socket.close()
        return

    full_url = parts[1] if len(parts) >= 2 else ""

    # Check domain blacklist
    if is_blocked(host, blacklist):
        print(f"[BLOCKED HTTP] {host}")
        log_request(client_ip, host, method, "BLOCKED", 0)
        send_block_page(client_socket, host)
        client_socket.close()
        return

    # Check keyword blacklist against URL
    for rule in blacklist:
        if "*" not in rule and "." not in rule and not rule.startswith("."):
            if rule in full_url.lower() or rule in host.lower():
                print(f"[BLOCKED keyword] '{rule}' in {full_url}")
                log_request(client_ip, host, method, "BLOCKED", 0)
                send_block_page(client_socket, host)
                client_socket.close()
                return

    # Rewrite request line for origin server
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
    # Ensure log file exists
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind(("0.0.0.0", port))
    proxy_socket.listen(100)
    print(f"[+] Proxy listening on port {port}")

    while True:
        client_socket, client_address = proxy_socket.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        thread.daemon = True
        thread.start()


if __name__ == "__main__":
    start_proxy(8080)