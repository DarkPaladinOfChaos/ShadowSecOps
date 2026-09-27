# ShadowSecOps — Análisis Forense y Denegación de Servicio en OT/ICS (Modbus/SCADA)

Laboratorio práctico de ciberseguridad ofensiva/defensiva sobre un entorno OT/ICS simulado (protocolo **Modbus/TCP**), ejecutado sobre dos máquinas virtuales reales (Parrot OS como atacante y Ubuntu como víctima/PLC), con captura de tráfico real, análisis forense reproducible y operacionalización de hallazgos en Jira.

Autor: Victor Bastidas

---

## 1. Resumen del ejercicio

El laboratorio reproduce el ciclo completo de un incidente de seguridad OT/ICS:

1. **Simulación del activo OT**: un PLC simulado con `pymodbus`, expuesto en el puerto 502/TCP.
2. **Reconocimiento (Red Team)**: descubrimiento del servicio Modbus con Nmap (`modbus-discover`) e identificación del dispositivo.
3. **Interacción / explotación**: lecturas legítimas, una **escritura no autorizada** de un holding register (manipulación de un setpoint simulado) y sondeo de un rango fuera de límite (excepción Modbus).
4. **Análisis de tráfico (Blue Team)**: clasificación automática del tráfico capturado por categoría (lectura, escritura, reconocimiento, excepción) y detección de picos de requests.
5. **Análisis forense (4 técnicas)**:
   - Técnica 1 — Integridad de la evidencia (hash SHA-256 del pcap) + timeline cronológico + mapeo a MITRE ATT&CK for ICS.
   - Técnica 2 — Reconstrucción de flujos/sesiones TCP (5-tupla).
   - Técnica 3 — Inspección de PDU Modbus (carving del protocolo) y reconstrucción del cambio de estado del PLC.
   - Técnica 4 — Perfilado estadístico del tráfico (tasa de requests, detección de picos en ventanas de tiempo).
6. **Denegación de Servicio (DoS)**: ataque real de inundación Modbus/TCP multi-hilo desde Parrot contra el PLC, con medición de impacto en la disponibilidad (latencia de un cliente legítimo antes/durante/después) y verificación forense del patrón volumétrico sobre la captura de paquetes.
7. **Resumen ejecutivo con IA**: generación automática de un resumen ejecutivo (API de Anthropic, modelo `claude-sonnet-5`) a partir del reporte técnico consolidado.
8. **Operacionalización (SOC)**: exportación de los hallazgos a **dos tickets de Jira** (uno por cada técnica principal), en formato de ticket de SOC real.

## 2. Entorno

| Rol | Sistema | IP |
|---|---|---|
| Atacante (Red Team) | Parrot OS | `192.168.167.128` |
| Víctima / PLC simulado | Ubuntu | `192.168.167.129` |

Servicio simulado: `pymodbus` (Modbus/TCP, puerto 502), identidad reportada como `ShadowSecOps Labs PLC-SIM-01`.

## 3. Mapeo a MITRE ATT&CK for ICS

| Técnica | Nombre | Dónde se observa |
|---|---|---|
| **T0846** | Remote System Discovery | Reconocimiento con Nmap (`modbus-discover`) |
| **T0861** | Point & Tag Identification | Lecturas repetidas de registros/coils, `Read Device Identification` (fc=43) |
| **T0855** | Unauthorized Command Message | Escritura no autorizada de un holding register (fc=6), sin autenticación |
| **T0814** | Denial of Service | Inundación de peticiones Modbus/TCP multi-hilo contra el PLC |
| **T0826** | Loss of Availability | Impacto medido: degradación de latencia / patrón volumétrico anómalo durante la inundación |

## 4. Scripts (`scripts/`)

| Script | Fase | Descripción |
|---|---|---|
| `plc_simulado.py` | Simulación | Servidor Modbus/TCP simulado (pymodbus) que actúa como el PLC objetivo. |
| `blue_team_analisis.py` | Blue Team | Clasifica el tráfico Modbus capturado por categoría y detecta picos de requests. |
| `forense_analisis.py` | Forense — Técnica 1 | Hash SHA-256 de integridad, timeline cronológico y mapeo a MITRE ATT&CK for ICS. |
| `forense_flujos.py` | Forense — Técnica 2 | Reconstrucción de flujos/sesiones TCP (5-tupla) a partir del pcap. |
| `forense_pdu.py` | Forense — Técnica 3 | Decodificación/inspección de PDU Modbus y reconstrucción del cambio de estado del PLC. |
| `forense_estadistico.py` | Forense — Técnica 4 | Perfilado estadístico del tráfico: tasa de requests y detección de picos en ventanas de tiempo. |
| `verificar_correctitud.py` | Validación | Pruebas de ground-truth para verificar que los hallazgos forenses coinciden con lo realmente ejecutado. |
| `dos_modbus.py` | Ataque | Ataque de Denegación de Servicio (DoS) por inundación Modbus/TCP multi-hilo (MITRE T0814/T0826). Mide latencia de un cliente legítimo antes/durante/después del ataque. |
| `resumen_ejecutivo.py` | IA | Genera un resumen ejecutivo del reporte técnico consolidado usando la API de Anthropic (`claude-sonnet-5`). |
| `jira_ticket.py` | Operacionalización | Exporta el hallazgo de escritura no autorizada (T0855) a un ticket de Jira (SECOPS-6). |
| `jira_ticket_dos.py` | Operacionalización | Exporta el hallazgo de DoS (T0814) a un segundo ticket de Jira (SECOPS-7), del mismo incidente. |

### Cómo reproducirlo (orden de ejecución)

```bash
# --- En Ubuntu (víctima / PLC) ---
python3 plc_simulado.py                      # levanta el PLC simulado en :502
sudo tcpdump -i <interfaz> -w modbus_traffic.pcap tcp port 502

# --- En Parrot (atacante) ---
nmap -p 502 --script modbus-discover 192.168.167.129
python3 -c "from pymodbus.client import ModbusTcpClient; ..."   # lecturas/escritura (ver informe)

# --- De vuelta en Ubuntu, tras detener la captura ---
python3 blue_team_analisis.py modbus_traffic.pcap
python3 forense_analisis.py modbus_traffic.pcap        > reporte_forense.txt
python3 forense_flujos.py modbus_traffic.pcap          >> reporte_forense.txt
python3 forense_pdu.py modbus_traffic.pcap             >> reporte_forense.txt
python3 forense_estadistico.py modbus_traffic.pcap     >> reporte_forense.txt
python3 verificar_correctitud.py modbus_traffic.pcap

# --- Ataque de Denegación de Servicio (DoS) ---
# En Ubuntu: nueva captura
sudo tcpdump -i <interfaz> -w dos_traffic.pcap tcp port 502
# En Parrot: lanzar la inundación
python3 dos_modbus.py 192.168.167.129 6 20 > reporte_dos_ataque.txt
# En Ubuntu, tras detener la captura:
python3 forense_estadistico.py dos_traffic.pcap  > reporte_dos.txt
python3 forense_flujos.py dos_traffic.pcap      >> reporte_dos.txt
cat reporte_forense.txt reporte_dos_ataque.txt reporte_dos.txt > reporte_forense_completo.txt

# --- Resumen ejecutivo con IA ---
export ANTHROPIC_API_KEY="<<< AQUI DEBE IR TU API KEY DE ANTHROPIC >>>"
python3 resumen_ejecutivo.py reporte_forense_completo.txt

# --- Tickets en Jira ---
export JIRA_EMAIL="<<< AQUI DEBE IR TU EMAIL DE JIRA >>>"
export JIRA_API_TOKEN="<<< AQUI DEBE IR TU API TOKEN DE JIRA >>>"
python3 jira_ticket.py reporte_forense.txt resumen_ejecutivo.txt
python3 jira_ticket_dos.py reporte_dos_completo.txt resumen_ejecutivo.txt
```

> **Seguridad**: ninguna credencial (API key de Anthropic, token de Jira) está embebida en el código. Todas se leen desde variables de entorno (`os.environ.get(...)`). Los valores de ejemplo de arriba son placeholders — nunca subas tus claves reales a este repositorio.

## 5. Capturas (`capturas/`)

Numeradas en el orden narrativo del ejercicio:

| # | Archivo | Contenido |
|---|---|---|
| 01 | `01_plc_simulado_arranque.png` | PLC simulado escuchando en el puerto 502 (Ubuntu). |
| 02 | `02_reconocimiento_nmap_modbus_discover.png` | Reconocimiento con Nmap (`modbus-discover`) desde Parrot — T0846. |
| 03 | `03_interaccion_pruebas_pymodbus.png` | Pruebas de interacción (lectura, escritura no autorizada, excepción) desde Parrot. |
| 04 | `04_blue_team_clasificacion_trafico.png` | Clasificación automática del tráfico (Blue Team): 14 eventos, detección de pico de requests. |
| 05 | `05_forense_tecnica1_integridad_timeline_mitre.png` | Técnica 1 — Integridad (SHA-256), timeline y mapeo MITRE ATT&CK for ICS. |
| 06 | `06_forense_tecnica2_flujos_tcp.png` | Técnica 2 — Reconstrucción de flujos/sesiones TCP. |
| 07 | `07_forense_tecnica3_pdu_reconstruccion_estado.png` | Técnica 3 — Decodificación de PDU y reconstrucción del cambio de estado del PLC. |
| 08 | `08_resumen_ejecutivo_ia.png` | Resumen ejecutivo generado con IA, integrando el hallazgo de escritura no autorizada y el de DoS. |
| 09 | `09_ataque_dos_inundacion_modbus_parrot.png` | Ataque DoS por inundación Modbus ejecutado desde Parrot: 5 568 peticiones a 921 req/s. |
| 10 | `10_dos_analisis_forense_estadistico_flujos.png` | Análisis forense del DoS: 4 065 requests Modbus, 652.86 req/s, pico de 1 591 requests en 2 s. |
| 11 | `11_jira_creacion_automatica_ticket_secops6.png` | Creación automática del ticket de incidente SECOPS-6 (API token ofuscado). |
| 12 | `12_jira_ticket_secops6_detalle.png` | Ticket SECOPS-6 en Jira: detalles del incidente, técnicas MITRE y evidencia. |
| 13 | `13_jira_ticket_secops7_dos_detalle.png` | Ticket SECOPS-7 en Jira: hallazgo de DoS/T0814 con métricas reales. |
| 14 | `14_artefactos_generados_carpeta_corrida.png` | Contenido de la carpeta de la corrida con todos los artefactos generados. |

## 6. Hallazgos principales

- **Escritura no autorizada (T0855)**: se modificó un holding register del PLC (`0` → `9999`) sin ningún tipo de autenticación, demostrando la ausencia total de controles de acceso nativos en Modbus/TCP.
- **Denegación de Servicio (T0814/T0826)**: una inundación de 5 568 peticiones Modbus/TCP en 6 segundos (hasta 921 req/s, picos de 1 591 requests en ventanas de 2 s) fue confirmada forense y volumétricamente. El indicador de latencia mostró un patrón inicial contraintuitivo (posible efecto de "arranque en frío"/resolución ARP en la primera conexión de la sesión), documentado honestamente en el informe; el indicador robusto de impacto fue el volumétrico (tasa de requests, picos y número de flujos TCP), no la latencia puntual.
- **Conclusión de seguridad**: Modbus/TCP carece de mecanismos nativos de autenticación, autorización o cifrado. Se recomienda segmentación de red (VLANs/firewalls industriales), monitoreo de anomalías de tráfico Modbus en tiempo real y, donde el hardware lo permita, mecanismos de control de acceso o gateways que validen los comandos de escritura antes de ejecutarlos en campo.

## 7. Herramientas utilizadas

`pymodbus` 3.15, `scapy`, `tcpdump`, `nmap` (script `modbus-discover`), Python 3, API de Anthropic (`claude-sonnet-5`), API REST v3 de Jira Cloud.

## 8. Notas de seguridad

- Ninguna credencial real (API keys, tokens) se incluye en este repositorio; todos los scripts las leen exclusivamente desde variables de entorno.
- Las capturas de pantalla incluidas fueron revisadas una por una antes de publicarse para confirmar que no exponen tokens ni claves reales.
- Este es un entorno **simulado** de laboratorio, aislado, sin conexión a infraestructura OT/ICS real.
