==================================================
  PROXY HTTP CON FILTRADO Y MONITOREO
  Comunicación y Redes de Computadores — I Ciclo 2026
==================================================

REQUISITOS
----------
- Python 3.8 o superior
- Sin dependencias externas (solo stdlib)

ARCHIVOS
--------
  main.py       → Punto de entrada (arranca proxy + panel)
  proxy.py      → Núcleo del proxy HTTP/HTTPS con logs y SNI
  monitor.py    → Panel web de monitoreo (puerto 8888)
  blacklist.txt → Lista de dominios/palabras clave bloqueadas
  proxy.log     → Log CSV generado automáticamente al correr

¿CÓMO EJECUTAR?
-------------
1. Abrir una terminal en la carpeta del proyecto
2. Ejecutar:

       python main.py

   Esto inicia:
     • Proxy   → puerto 8080
     • Panel   → http://localhost:8888

CONFIGURACIÓN
------------------------
En cualquier computadora vamos a Configuración -- Red e Internet y desactivamos la configuración automática del proxy
Luego seleccionamos Proxy -- Configuración manual del proxy -- Le damos a Establecer y agregamos la IPv4  y el puerto 8080.
Una vez hecho esto guardamos la configuración y nuesta computadora estará lista para la realización de pruebas.

ARCHIVO DE BLACKLIST (blacklist.txt)
-------------------------------------
  facebook.com          → dominio exacto
  *.ads.com             → wildcard (cualquier subdominio)
  .malware.net          → cualquier host que termine en .malware.net
  casino                → palabra clave en la URL (HTTP)

FUNCIONALIDADES IMPLEMENTADAS
------------------------------
  ✔ Proxy HTTP (GET, POST, métodos estándar)
  ✔ Tunnel HTTPS con CONNECT
  ✔ Filtrado HTTP: por dominio y palabra clave en URL
  ✔ Filtrado HTTPS: por SNI real del TLS ClientHello
  ✔ Concurrencia con hilos (threading)
  ✔ Logs en archivo CSV (proxy.log)
  ✔ Panel web con métricas en tiempo real (refresco cada 5 s)
      - Total solicitudes
      - MB transferidos
      - Top 5 dominios
      - Bloqueadas vs permitidas (gráfica tipo donut)
      - Clientes activos
      - Tabla de últimas 50 solicitudes
  ✔ Exportación de logs (CSV y JSON desde el panel)

NOTAS TÉCNICAS
--------------
- La inspección SNI lee el TLS ClientHello sin descifrar el contenido.
- El log CSV se escribe en disco en tiempo real (proxy.log).
- El panel se actualiza automáticamente cada 5 segundos.
- Los logs en memoria conservan las últimas 500 entradas.
==================================================
