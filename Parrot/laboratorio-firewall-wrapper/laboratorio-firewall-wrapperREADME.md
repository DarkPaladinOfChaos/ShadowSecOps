# Práctica de Laboratorio: Política de Firewall Default-Deny y Wrapper de Autenticación (Reverse Proxy) sobre Parrot OS

**Autor:** Victor Bastidas
**Programa:** Maestría en Seguridad Informática
**Entorno:** Parrot Security OS (VMware Workstation) — usuario `padawan@parrot`
**Fecha:** 23 de julio de 2026

---

## 1. Objetivo

Replicar en Parrot Security OS una práctica de laboratorio realizada originalmente en Kali Linux, cuyo propósito es ilustrar dos controles de seguridad complementarios sobre un servicio web que expone información sensible:

- **Filtrado de tráfico a nivel de red** mediante `iptables`, aplicando una política de denegación por defecto (*Default-Deny*) con una excepción explícita (*whitelist*) para tráfico local.
- **Control de acceso a nivel de aplicación** mediante un *wrapper* de autenticación (reverse proxy) en Python, que exige un token `Bearer` válido antes de reenviar cualquier solicitud al servicio real.

Este patrón se conoce como **Authentication Wrapper** o **Sidecar Proxy**, y se utiliza en escenarios reales donde no es posible modificar el código fuente de un servicio (aplicaciones legadas, dispositivos IoT, microservicios de terceros) pero sí es necesario añadirle un control de autenticación adicional.

## 2. Entorno de laboratorio

| Componente | Detalle |
|---|---|
| Sistema operativo | Parrot Security OS (máquina virtual, VMware Workstation) |
| Usuario | `padawan@parrot` (con `sudo` para las reglas de firewall) |
| Herramientas | `bash`, `python3`, `curl`, `iptables` (modo compatible con `nf_tables`) |
| Servicio simulado | Servidor HTTP en el puerto **9090** (datos confidenciales de prueba) |
| Proxy de autenticación | Wrapper en el puerto **8080** |
| Terminal | Konsole — todo el laboratorio se ejecutó en una sola consola, sin necesidad de una segunda ventana |

## 3. Desarrollo paso a paso

### Paso 1 — Preparación del entorno y servidor simulado

Se crea el directorio de trabajo y una página HTML que simula un servicio con información confidencial expuesta (credenciales de una base de datos), liberando previamente los puertos 8080 y 9090 por si estaban en uso.

```bash
mkdir -p ~/demo_t2/servidor/web && fuser -k 8080/tcp 9090/tcp 2>/dev/null
echo "<html><body><h1>DATOS INTERNOS CONFIDENCIALES</h1><p>DB: 192.168.1.100 | User: admin | Pass: secreto123</p></body></html>" > ~/demo_t2/servidor/web/index.html
echo "Entorno listo."
```

### Paso 2 — Publicación del servidor web (puerto 9090)

Se levanta un servidor HTTP simple de Python sirviendo el archivo anterior y se valida con `curl` que responde correctamente desde localhost.

```bash
cd ~/demo_t2/servidor/web && python3 -m http.server 9090 &
curl -s http://localhost:9090/
```

El servidor queda escuchando en el puerto 9090 y `curl` devuelve el HTML con los datos confidenciales, confirmando que el servicio está activo antes de aplicar cualquier control de seguridad.

### Paso 3 — Política de firewall Default-Deny

Se agrega una regla en la cadena `INPUT` de `iptables` que descarta (`DROP`) todo el tráfico TCP entrante dirigido al puerto 9090, sin excepción.

```bash
sudo iptables -A INPUT -p tcp --dport 9090 -j DROP
```

A partir de este punto, cualquier intento de acceso al puerto 9090 queda bloqueado por defecto.

### Paso 4 — Regla de lista blanca (whitelist) para localhost

Se inserta al inicio de la cadena `INPUT` (`-I`) una regla que acepta explícitamente el tráfico proveniente de `127.0.0.1` hacia el puerto 9090. Al insertarse antes que la regla `DROP`, tiene prioridad de evaluación sobre esta.

```bash
sudo iptables -I INPUT -p tcp --dport 9090 -s 127.0.0.1 -j ACCEPT
```

Con esta regla, el servidor del Paso 2 vuelve a ser accesible únicamente desde el propio host (localhost), mientras que cualquier origen externo permanece bloqueado por la regla `DROP`.

### Paso 5 — Creación del wrapper de autenticación (puerto 8080)

Se implementa un servidor Python que actúa como proxy inverso frente al servicio real. Valida la cabecera `Authorization` contra un token fijo; si es válido, reenvía la petición al puerto 9090 y agrega la cabecera personalizada `X-Powered-By: SecureWrapper/1.0` como evidencia de que la solicitud pasó por el wrapper. Si el token es inválido o está ausente, responde `401 Unauthorized`.

```bash
cat > ~/demo_t2/wrapper.py << 'WRAPPER'
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request

class WrapperHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if auth != "Bearer token_secreto_2025":
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"401 Unauthorized - Acceso bloqueado por el Wrapper\n")
            print(f"[WRAPPER] DENEGADO desde {self.address_string()}")
            return
        resp = urllib.request.urlopen("http://localhost:9090" + self.path)
        self.send_response(200)
        self.send_header("X-Powered-By", "SecureWrapper/1.0")
        self.end_headers()
        self.wfile.write(resp.read())
        print(f"[WRAPPER] PERMITIDO - reenviando al servidor real")

HTTPServer(("0.0.0.0", 8080), WrapperHandler).serve_forever()
WRAPPER
python3 ~/demo_t2/wrapper.py &
```

**Evidencia — Pasos 1 a 5:** creación del entorno, publicación del servidor en el puerto 9090, aplicación de la política Default-Deny, regla de whitelist y creación de `wrapper.py`.

![Ejecución de los pasos 1 a 5](img/01-setup-firewall-wrapper.png)

### Paso 6 — Pruebas de validación

Se ejecutan cuatro pruebas para verificar el comportamiento combinado del firewall y del wrapper:

1. Acceso directo al puerto 9090 desde localhost (permitido por la whitelist).
2. Acceso al wrapper (puerto 8080) sin token de autorización.
3. Acceso al wrapper con un token incorrecto.
4. Acceso al wrapper con el token correcto.

```bash
curl --connect-timeout 3 -s http://localhost:9090/
curl -s http://localhost:8080/
curl -s -H "Authorization: Bearer token_falso_hacker" http://localhost:8080/
curl -si -H "Authorization: Bearer token_secreto_2025" http://localhost:8080/
```

**Evidencia — Pruebas de validación:** ejecución de las cuatro pruebas y primeros resultados en consola.

![Pruebas de validación](img/02-pruebas-validacion.png)

### Paso 7 — Evidencia detallada con `curl -v`

Para documentar el intercambio HTTP completo (cabeceras de solicitud y de respuesta) se repite la prueba con token válido en modo verboso, filtrando únicamente las líneas de cabecera:

```bash
curl -v -H "Authorization: Bearer token_secreto_2025" http://localhost:8080/ 2>&1 | grep -E "^[<>]" | head -20
```

El resultado confirma el *request* saliente (líneas con `>`: método, host, user-agent y la cabecera `Authorization`) y la respuesta entrante (líneas con `<`: código `200 OK` y la cabecera `X-Powered-By: SecureWrapper/1.0`), evidenciando que la petición fue autenticada, procesada por el wrapper y reenviada correctamente al servidor real.

**Evidencia — Resultados finales y `curl -v`:** resultados de las cuatro pruebas y evidencia verbosa del intercambio de cabeceras HTTP.

![Evidencia curl -v](img/03-evidencia-curl-verbose.png)

## 4. Análisis de resultados

- El puerto 9090 solo es accesible desde localhost (`127.0.0.1`); cualquier origen externo sería descartado por la regla `DROP` de `iptables`, mientras que la regla `ACCEPT` insertada antes permite el tráfico local.
- El wrapper del puerto 8080 rechaza con `401 Unauthorized` toda solicitud sin cabecera `Authorization` o con un token incorrecto, registrando en consola el mensaje `[WRAPPER] DENEGADO`.
- Con el token correcto (`Bearer token_secreto_2025`), el wrapper responde `200 OK`, reenvía la solicitud al servicio real en el puerto 9090 y agrega la cabecera `X-Powered-By: SecureWrapper/1.0` como marca de que la petición pasó por el proxy de autenticación.
- La cabecera `Server: BaseHTTP/0.6 Python/3.13.5` confirma que la respuesta final proviene del servidor `http.server` de Python subyacente.

## 5. Conclusiones

La práctica demuestra cómo combinar dos capas de seguridad independientes —filtrado de red (`iptables`) y autenticación de aplicación (wrapper/reverse proxy)— para proteger un servicio que, por sí mismo, no cuenta con ningún mecanismo de control de acceso.

El patrón de *Authentication Wrapper* resulta especialmente útil frente a servicios legados o de terceros cuyo código no puede modificarse: en lugar de intervenir la aplicación, se antepone un proxy que centraliza la validación de credenciales antes de permitir el paso del tráfico hacia el servicio protegido.

La práctica fue replicada exitosamente en Parrot Security OS, obteniendo resultados idénticos a los de la demostración original en Kali Linux, ya que ambas distribuciones comparten la misma base (Debian) y las mismas herramientas de red (`iptables`, `python3`, `curl`).

---

> ⚠️ **Nota:** Las credenciales (`admin` / `secreto123`) y el token (`token_secreto_2025`) usados en este laboratorio son datos ficticios generados únicamente con fines educativos. No representan sistemas ni credenciales reales.
