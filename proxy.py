import socket
import threading
import fnmatch

BUFFER_SIZE = 4096
BLACKLIST_FILE = "blacklist.txt"


# =========================
# LOAD BLACKLIST
# =========================
def load_blacklist():
    try:
        with open("blacklist.txt", "r") as f:
            return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
    except:
        return []


def is_blocked(host, blacklist):
    host = host.lower().strip()

    for rule in blacklist:
        rule = rule.lower().strip()

        # Exact match
        if rule == host:
            return True

        # Wildcard support (*.example.com)
        if "*" in rule:
            if fnmatch.fnmatch(host, rule):
                return True

        # Subdomain safe match (solo si es dominio real)
        if rule.startswith("."):
            if host.endswith(rule):
                return True

    return False

def send_block_page(client_socket):
    response = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<h1>403 Forbidden</h1><p>Blocked by proxy filter</p>"
    )
    client_socket.sendall(response.encode())


# =========================
# HTTPS HANDLER (CONNECT)
# =========================
def handle_https(client_socket, host):
    blacklist = load_blacklist()

    print(f"[CHECK HTTPS HOST] {host}")

    if is_blocked(host, blacklist):
        print(f"[BLOCKED HTTPS] {host}")
        client_socket.sendall(
            b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by proxy filter"
        )
        client_socket.close()
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((host, 443))

    client_socket.sendall(
        b"HTTP/1.1 200 Connection Established\r\n\r\n"
    )

    #  Bidirectional tunnel
    def forward(src, dst):
        try:
            while True:
                data = src.recv(BUFFER_SIZE)
                if not data:
                    break
                dst.sendall(data)
        except:
            pass

    t1 = threading.Thread(target=forward, args=(client_socket, server_socket))
    t2 = threading.Thread(target=forward, args=(server_socket, client_socket))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    client_socket.close()
    server_socket.close()


# =========================
# HTTP HANDLER
# =========================
def handle_http(client_socket, request_text, lines, request_line):
    blacklist = load_blacklist()

    # Extract host
    host = None
    for line in lines:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            host = host.split(":")[0]
            break

    if not host:
        client_socket.close()
        return

    print(f"[HOST] {host}")

    # Check blacklist
    if is_blocked(host, blacklist):
        print(f"[BLOCKED HTTP] {host}")
        send_block_page(client_socket)
        client_socket.close()
        return

    # Fix request line (proxy → origin server)
    parts = request_line.split(" ")

     # Guardá la URL COMPLETA antes de modificarla
    full_url = parts[1] if len(parts) >= 2 else ""

    if len(parts) >= 2 and parts[1].startswith("http://"):
        url = parts[1]

        if "/" in url[7:]:
            path = "/" + url.split("/", 3)[3]
        else:
            path = "/"

        parts[1] = path
        lines[0] = " ".join(parts)

    # Check keywords contra URL completa + host
    for rule in blacklist:
        if "*" not in rule and "." not in rule and not rule.startswith("."):
            if rule in full_url.lower() or rule in host.lower():
                print(f"[BLOCKED keyword] '{rule}' found")
                send_block_page(client_socket)
                client_socket.close()
                return

    new_request = "\r\n".join(lines)
    if not new_request.endswith("\r\n\r\n"):
        new_request += "\r\n"
    new_request = new_request.encode()

    print(f"[HTTP] Connecting to {host}:80")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((host, 80))
    server_socket.settimeout(2)

    server_socket.sendall(new_request)

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

    print(f"[+] HTTP Response sent ({total_bytes} bytes)")

    server_socket.close()
    client_socket.close()


# =========================
# MAIN HANDLER
# =========================
def handle_client(client_socket, client_address):
    print(f"[+] Connection from {client_address}")

    try:
        request = client_socket.recv(BUFFER_SIZE)
        if not request:
            client_socket.close()
            return

        request_text = request.decode(errors="ignore")
        lines = request_text.split("\r\n")
        request_line = lines[0]

        print(f"[REQUEST] {request_line}")

        # =========================
        # HTTPS (CONNECT)
        # =========================
        if request_line.startswith("CONNECT"):
            host_port = request_line.split(" ")[1]
            host = host_port.split(":")[0]

            handle_https(client_socket, host)
            return

        # =========================
        # HTTP
        # =========================
        handle_http(client_socket, request_text, lines, request_line)

    except Exception as e:
        print(f"[ERROR] {e}")
        client_socket.close()


# =========================
# START PROXY
# =========================
def start_proxy(port=8080):
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind(("0.0.0.0", port))
    proxy_socket.listen(100)

    print(f"[+] Proxy listening on port {port}")

    while True:
        client_socket, client_address = proxy_socket.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(client_socket, client_address)
        )
        thread.start()


if __name__ == "__main__":
    start_proxy(8080)