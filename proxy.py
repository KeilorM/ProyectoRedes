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
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=entry.keys())
        if os.path.getsize(LOG_FILE) == 0:
            writer.writeheader()
        writer.writerow(entry)

    # Update in-memory stats
    with stats_lock:
        stats["total_requests"] += 1
        stats["total_bytes"] += bytes_transferred
        stats["domains"][domain] += 1
        stats["clients"][client_ip] += 1
        if status == "BLOCKED":
            stats["blocked"] += 1
        else:
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


def send_block_page(client_socket):
    response = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<html><body><h1>403 Forbidden</h1><p>Blocked by proxy filter.</p></body></html>"
    )
    try:
        client_socket.sendall(response.encode())
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
    client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    # Peek at the first bytes (TLS ClientHello)
    try:
        client_socket.settimeout(3)
        tls_hello = client_socket.recv(4096)
        client_socket.settimeout(None)
    except:
        tls_hello = b""

    sni_host = extract_sni(tls_hello) if tls_hello else None
    effective_host = sni_host if sni_host else host

    print(f"[HTTPS] host={host} | SNI={sni_host} | effective={effective_host}")

    if is_blocked(effective_host, blacklist):
        print(f"[BLOCKED HTTPS/SNI] {effective_host}")
        log_request(client_ip, effective_host, "CONNECT", "BLOCKED", 0)
        try:
            client_socket.close()
        except:
            pass
        return

    log_request(client_ip, effective_host, "CONNECT", "ALLOWED", 0)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.connect((host, 443))
    except Exception as e:
        print(f"[ERROR] Cannot connect to {host}:443 — {e}")
        client_socket.close()
        return

    # Forward the already-peeked ClientHello
    if tls_hello:
        server_socket.sendall(tls_hello)

    bytes_counter = [0]

    def forward(src, dst, count=False):
        try:
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

    # Update bytes transferred
    with stats_lock:
        stats["total_bytes"] += bytes_counter[0]

    client_socket.close()
    server_socket.close()


# =========================
# HTTP HANDLER
# =========================
def handle_http(client_socket, request_text, lines, request_line, client_ip):
    blacklist = load_blacklist()

    # Extract method
    parts = request_line.split(" ")
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
        send_block_page(client_socket)
        client_socket.close()
        return

    # Check keyword blacklist against URL
    for rule in blacklist:
        if "*" not in rule and "." not in rule and not rule.startswith("."):
            if rule in full_url.lower() or rule in host.lower():
                print(f"[BLOCKED keyword] '{rule}' in {full_url}")
                log_request(client_ip, host, method, "BLOCKED", 0)
                send_block_page(client_socket)
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
        client_socket.close()
        return

    server_socket.settimeout(5)
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
