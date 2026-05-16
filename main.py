"""
main.py — Punto de entrada: levanta el proxy (8080) y el panel (8888) en paralelo.
"""
import threading
from proxy import start_proxy
from monitor import start_monitor

if __name__ == "__main__":
    t_monitor = threading.Thread(target=start_monitor, args=(8888,), daemon=True)
    t_monitor.start()

    # El proxy corre en el hilo principal
    start_proxy(8080)
