# Análisis Forense de Logs y Construcción de Timeline en Parrot OS

**Autor:** Victor Bastidas
**Entorno:** Parrot Security OS (VMware Workstation) — usuario `padawan@parrot`
**Fecha:** 31 de julio de 2026

---

## 1. Objetivo

Aplicar el ciclo completo de una investigación forense básica orientada al análisis de logs del sistema y a la construcción de una línea de tiempo (timeline), como continuación práctica de un laboratorio previo de cadena de custodia realizado en Windows. El objetivo es reproducir la misma metodología (preparación, captura de evidencia volátil, recolección, verificación de integridad y empaquetado) utilizando herramientas nativas de Linux/Parrot OS, e incorporar dos técnicas adicionales no cubiertas anteriormente: la construcción de un timeline unificado de eventos de autenticación y un timeline de metadatos del sistema de archivos (enfoque MACB).

## 2. Entorno de laboratorio

- **Sistema operativo:** Parrot Security OS, ejecutado como máquina virtual en VMware Workstation.
- **Usuario:** `padawan@parrot` (con `sudo` cuando fue requerido).
- **Herramientas utilizadas:** `bash`, `date`, `who`, `ps`, `uptime`, `loginctl`, `journalctl`, `find`, `sha256sum`.
- **Caso de estudio:** se simuló actividad de autenticación fallida (comandos `su` hacia usuarios inexistentes y un `sudo` con clave incorrecta) para generar hallazgos concretos que analizar en el timeline.
- **Directorio de trabajo:** `~/CASO_TIMELINE`, con la evidencia recolectada en la subcarpeta `evidencia/`.

## 3. Desarrollo paso a paso

### Paso 1 — Preparación del entorno del caso

Se crea el directorio de trabajo del caso y se registra el timestamp de inicio del análisis, siguiendo el mismo principio de cadena de custodia aplicado en la práctica previa (equivalente a `FechaYHoraDelInicio.txt` en Windows).

```bash
mkdir -p ~/CASO_TIMELINE/evidencia && cd ~/CASO_TIMELINE
date "+Inicio del análisis: %Y-%m-%d %H:%M:%S %Z" > evidencia/00_FechaHoraInicio.txt
cat evidencia/00_FechaHoraInicio.txt
```

### Paso 2 — Generación de actividad sospechosa simulada

Para tener hallazgos reales que detectar en el timeline (en vez de un log vacío), se generan intencionalmente intentos fallidos de autenticación: cambio a usuarios inexistentes y un `sudo` con contraseña incorrecta. Estos comandos fallan a propósito, dejando su rastro en los logs de autenticación del sistema.

```bash
su - noexiste1 2>/dev/null
su - noexiste2 2>/dev/null
sudo -k; echo "clave_incorrecta" | sudo -S whoami 2>/dev/null
```

### Paso 3 — Captura de evidencia volátil

Se documenta el estado del sistema en el momento del análisis: usuarios conectados, procesos activos y tiempo de actividad. Durante la ejecución de este paso se identificó que las utilidades tradicionales `last` y `lastb` no están disponibles en esta versión de Parrot OS (basada en Debian Trixie), ya que la distribución migró el registro de sesiones del sistema legado `wtmp`/`btmp` hacia `journald` (systemd-logind). Por ello, la captura de sesiones se realizó con `loginctl` y `journalctl` en su lugar.

```bash
which last lastb who ps uptime
dpkg -L util-linux-extra | grep -E "bin/last"
```

![Diagnóstico de la ausencia de last/lastb](capturas/Figura1_ausencia_last-lastb.png)

*Figura 1. Diagnóstico de la ausencia de last/lastb en el sistema: confirmación de que el paquete util-linux-extra no incluye estos binarios en esta versión de Parrot OS.*

Se reemplazan los comandos no disponibles por sus equivalentes nativos de systemd y se captura la evidencia volátil completa:

```bash
{
  echo "=== USUARIOS CONECTADOS ==="; who
  echo "=== SESIONES REGISTRADAS (systemd-logind) ==="; loginctl list-sessions
  echo "=== EVENTOS DE LOGIN/LOGOUT (journald) ==="; sudo journalctl _COMM=systemd-logind --no-pager | tail -50
  echo "=== PROCESOS ACTIVOS ==="; ps aux
  echo "=== TIEMPO ACTIVO DEL SISTEMA ==="; uptime
} > evidencia/01_Evidencia_Volatil.txt

wc -l evidencia/01_Evidencia_Volatil.txt
```

![Evidencia volátil capturada (368 líneas)](capturas/Figura2_evidencia_volatil_368lineas.png)

*Figura 2. Evidencia volátil capturada correctamente (368 líneas), con las cinco secciones completas.*

La consulta directa a `journalctl` con `sudo` permitió reconstruir el historial de sesiones a través de dos arranques distintos del sistema (23 y 30 de julio), incluyendo la hora exacta de apagado del primero y el inicio del segundo.

![Historial de sesiones reconstruido con journalctl](capturas/Figura3_historial_sesiones_journalctl_2boots.png)

*Figura 3. Historial de sesiones reconstruido con journalctl, mostrando dos ciclos de arranque (boots) del sistema con sus timestamps exactos.*

### Paso 4 — Extracción de logs relevantes

Se extraen por separado los registros de los servicios y comandos de interés forense: acceso SSH, cambios de usuario (`su`), elevación de privilegios (`sudo`) y errores generales del sistema.

```bash
sudo journalctl -u ssh --no-pager > evidencia/02_log_ssh.txt 2>/dev/null
sudo journalctl _COMM=su --no-pager > evidencia/03_log_su.txt 2>/dev/null
sudo journalctl _COMM=sudo --no-pager > evidencia/04_log_sudo.txt 2>/dev/null
sudo journalctl -p err..emerg --no-pager > evidencia/05_log_errores.txt
wc -l evidencia/*.txt
```

El log de SSH resultó prácticamente vacío (1 línea), lo cual es en sí mismo un hallazgo válido: indica que el servicio SSH no se encontraba activo durante el periodo analizado, por lo que no representa una superficie de ataque expuesta en este caso. Los logs de `su` y `sudo`, en cambio, capturaron correctamente los intentos fallidos generados en el Paso 2:

![Registro de autenticación fallida en el log de su (FAILED SU)](capturas/Figura4_log_su_FAILED_SU_root.png)

*Figura 4. Registro de autenticación fallida en el log de su: intento de cambio a usuario root rechazado (FAILED SU), con usuario, terminal y mecanismo PAM involucrado.*

### Paso 5 — Construcción del timeline unificado

Se combinan las distintas fuentes de log en un único archivo, ordenado cronológicamente, para obtener una línea de tiempo consolidada de la actividad de autenticación del sistema.

```bash
cat evidencia/02_log_ssh.txt evidencia/03_log_su.txt evidencia/04_log_sudo.txt \
  | grep -v "^--" | sort -k1,3 > evidencia/06_TIMELINE_LOGS.txt
wc -l evidencia/06_TIMELINE_LOGS.txt
```

![Timeline unificado de 365 eventos](capturas/Figura5_timeline_unificado_365eventos.png)

*Figura 5. Timeline unificado de 365 eventos, combinando los logs de su y sudo ordenados cronológicamente, incluyendo actividad administrativa de varios días.*

### Paso 6 — Análisis de hallazgos dentro del timeline

Se filtra el timeline consolidado en busca de patrones de interés forense: fallos de autenticación, credenciales inválidas y accesos denegados.

```bash
echo "=== EVENTOS DE AUTENTICACIÓN FALLIDA ===" > evidencia/07_Analisis_Hallazgos.txt
grep -iE "fail|invalid|incorrect|denied|authentication failure" evidencia/06_TIMELINE_LOGS.txt \
  >> evidencia/07_Analisis_Hallazgos.txt
cat evidencia/07_Analisis_Hallazgos.txt
```

![Diez eventos de autenticación fallida aislados](capturas/Figura6_10_autenticaciones_fallidas.png)

*Figura 6. Diez eventos de autenticación fallida aislados del timeline de 365 eventos totales, distribuidos en cuatro fechas distintas.*

### Paso 7 — Timeline del sistema de archivos (MACB)

Como complemento al timeline de logs, se genera una línea de tiempo de los metadatos de los propios archivos de evidencia recolectados, técnica base del análisis MACB (Modified/Accessed/Changed/Birth) empleado en herramientas forenses como `mactime` de Sleuth Kit. Esto permite demostrar que la evidencia se generó en un orden cronológico coherente.

```bash
find ~/CASO_TIMELINE -type f -printf "%T@ %TY-%Tm-%Td %TH:%TM:%TS | MODIFICADO | %p\n" \
  | sort -n | cut -d' ' -f2- > evidencia/08_Timeline_Filesystem.txt
cat evidencia/08_Timeline_Filesystem.txt
```

![Timeline de metadatos del sistema de archivos (MACB)](capturas/Figura7_timeline_filesystem_MACB.png)

*Figura 7. Timeline de metadatos del sistema de archivos: secuencia cronológica de creación de cada archivo de evidencia, sin saltos ni inconsistencias.*

### Paso 8 — Hashing de integridad de la evidencia

Se genera la huella digital SHA256 de todos los archivos de evidencia recolectados, con el mismo propósito que `certutil -hashfile` en la práctica de Windows: poder demostrar posteriormente que ninguno fue alterado tras su recolección.

```bash
cd ~/CASO_TIMELINE/evidencia
sha256sum * > HASHES_EVIDENCIA.txt
cat HASHES_EVIDENCIA.txt
```

![Huellas digitales SHA256 de la evidencia](capturas/Figura8_hashes_SHA256_evidencia.png)

*Figura 8. Huellas digitales SHA256 de los nueve archivos de evidencia recolectados.*

### Paso 9 — Verificación final del paquete de evidencia

Se registra el timestamp de cierre del análisis en el mismo archivo del timestamp de inicio, y se verifica el listado final de la carpeta de evidencia.

```bash
date "+Fin del análisis: %Y-%m-%d %H:%M:%S %Z" >> ~/CASO_TIMELINE/evidencia/00_FechaHoraInicio.txt
cat ~/CASO_TIMELINE/evidencia/00_FechaHoraInicio.txt
cd ~/CASO_TIMELINE && ls -la evidencia/
```

![Verificación final del paquete de evidencia](capturas/Figura9_verificacion_final_paquete.png)

*Figura 9. Verificación final del paquete de evidencia: 10 archivos completos, con timestamps de inicio (14:34:02) y fin (14:53:17) del análisis.*

## 4. Análisis de resultados

| Archivo | Contenido | Tamaño |
|---|---|---|
| `00_FechaHoraInicio.txt` | Timestamps de inicio y fin del análisis | 89 B |
| `01_Evidencia_Volatil.txt` | Usuarios, sesiones, procesos y uptime | 45.6 KB |
| `02-05_log_*.txt` | Logs de ssh, su, sudo y errores | ~92 KB |
| `06_TIMELINE_LOGS.txt` | 365 eventos combinados y ordenados | 39.5 KB |
| `07_Analisis_Hallazgos.txt` | 10 eventos de autenticación fallida | 1.3 KB |
| `08_Timeline_Filesystem.txt` | Timeline MACB de la evidencia misma | 942 B |
| `HASHES_EVIDENCIA.txt` | SHA256 de los 9 archivos anteriores | 780 B |

- De los 365 eventos de autenticación registrados en el timeline consolidado, 10 (2.7%) correspondieron a intentos fallidos, distribuidos en cuatro fechas distintas (9 de diciembre, 24 de enero, 18 de febrero y 31 de julio), lo que sugiere un patrón recurrente más que un evento aislado.
- El hallazgo más reciente y detallado corresponde al 31 de julio: un intento de `sudo` con contraseña incorrecta ejecutando el comando `whoami`, generado deliberadamente en el Paso 2, quedando registrado con usuario, terminal, directorio de trabajo y comando exacto.
- Se identificaron múltiples sesiones de root abiertas y cerradas en ráfagas cortas, coincidiendo con procesos de auditoría automatizados (`lynis` vía cronjob) detectados también en la evidencia de procesos activos, lo que descarta que se trate de accesos interactivos sospechosos.
- El servicio SSH no se encontraba activo durante el periodo analizado, por lo que no representó una superficie de ataque expuesta en este caso.
- El timeline del sistema de archivos confirmó que la evidencia se generó en orden cronológico estrictamente creciente, sin saltos ni inconsistencias, respaldando la integridad del proceso de recolección.

## 5. Conclusiones

La práctica permitió aplicar el ciclo completo de una investigación forense de logs: preparación, generación de un caso simulado, captura de evidencia volátil, extracción y consolidación de logs, construcción de un timeline analizable, aislamiento de hallazgos y verificación de integridad mediante hashing.

A diferencia de la práctica anterior en Windows (centrada en la cadena de custodia de archivos y procesos), este ejercicio incorporó dos técnicas propias del análisis forense de logs: la construcción de un timeline unificado de eventos de autenticación a partir de múltiples fuentes, y un timeline de metadatos del sistema de archivos (MACB) aplicado a la propia evidencia recolectada.

Un hallazgo metodológico relevante fue la constatación de que las utilidades tradicionales `last`/`lastb` ya no forman parte de la instalación estándar de Parrot OS, evidenciando la transición del ecosistema Linux hacia `journald` como fuente principal de registro de sesiones. Esto reforzó la importancia de verificar la disponibilidad de herramientas antes de asumir un procedimiento como válido, y de documentar las adaptaciones metodológicas realizadas durante la investigación.

En conjunto, la práctica demuestra que el análisis de logs y timeline es una técnica accesible con herramientas nativas del sistema operativo, replicable en un entorno Linux sin necesidad de software forense especializado, y suficiente para detectar patrones de autenticación fallida que ameritarían una investigación más profunda en un caso real.
