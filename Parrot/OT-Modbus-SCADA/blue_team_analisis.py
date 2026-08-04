#!/usr/bin/env python3
"""
Fase Blue Team - Análisis de tráfico Modbus/TCP
Práctica OT: Reconocimiento, Análisis de Seguridad y Forense en un Entorno OT Simulado (Modbus/SCADA)

Parsea un .pcap con tráfico Modbus TCP (puerto 502), reconstruye cada
transacción (MBAP header + PDU) y la clasifica según heurísticas simples,
sin necesidad de librerías de ML pesadas. Diseñado para correr sobre el
tráfico generado en la Fase Red Team.

Requiere: scapy
    pip install scapy --break-system-packages
"""

import sys
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, TCP, IP
except ImportError:
    print("Falta scapy. Instálalo con: pip install scapy --break-system-packages")
    sys.exit(1)

MODBUS_PORT = 502

# Function codes de interés
READ_CODES = {1, 2, 3, 4}          # coils, discrete inputs, holding regs, input regs
WRITE_CODES = {5, 6, 15, 16, 22, 23}  # write coil/register (single y múltiple, mask write)
DEVICE_INFO_CODE = 43              # 0x2B - Read Device Identification (MEI)

# Ventana de tiempo (segundos) para detectar ráfagas de requests desde una misma IP
BURST_WINDOW = 2.0
BURST_THRESHOLD = 4  # más de N requests en la ventana = sospechoso


def parse_mbap_pdu(payload: bytes):
    """Devuelve dict con los campos del MBAP header + function code, o None si no es válido."""
    if len(payload) < 8:
        return None
    transaction_id = int.from_bytes(payload[0:2], "big")
    protocol_id = int.from_bytes(payload[2:4], "big")
    length = int.from_bytes(payload[4:6], "big")
    unit_id = payload[6]
    function_code = payload[7]

    if protocol_id != 0:
        # No es un frame Modbus válido (protocol id siempre 0 en Modbus TCP)
        return None

    return {
        "transaction_id": transaction_id,
        "unit_id": unit_id,
        "function_code": function_code,
        "raw_len": len(payload),
    }


def classify(record: dict) -> str:
    fc = record["function_code"]
    if fc >= 0x80:  # bit de error activado => excepción
        real_fc = fc - 0x80
        return f"EXCEPCION/PROBING (function_code original {real_fc})"
    if fc in WRITE_CODES:
        return "ESCRITURA (alerta alta - modificación no esperada)"
    if fc == DEVICE_INFO_CODE:
        return "RECONOCIMIENTO (read device identification)"
    if fc in READ_CODES:
        return "LECTURA NORMAL (baseline)"
    return f"DESCONOCIDO (function_code {fc})"


def main(pcap_path: str):
    print(f"Cargando {pcap_path} ...")
    packets = rdpcap(pcap_path)
    print(f"{len(packets)} paquetes en el pcap.\n")

    events = []
    requests_by_src = defaultdict(list)  # ip_src -> lista de timestamps (solo requests al server)

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue
        tcp = pkt[TCP]
        ip = pkt[IP]

        if tcp.dport != MODBUS_PORT and tcp.sport != MODBUS_PORT:
            continue

        payload = bytes(tcp.payload)
        if not payload:
            continue

        record = parse_mbap_pdu(payload)
        if record is None:
            # Tráfico en el puerto 502 que NO es Modbus válido (ej. el ruido SIP que viste antes)
            events.append({
                "time": float(pkt.time),
                "src": ip.src,
                "dst": ip.dst,
                "direccion": "request" if tcp.dport == MODBUS_PORT else "response",
                "clasificacion": "NO-MODBUS (protocolo inválido en puerto 502 - sospechoso)",
                "detalle": f"{len(payload)} bytes no decodificables como Modbus TCP",
            })
            continue

        is_request = tcp.dport == MODBUS_PORT
        clasificacion = classify(record)

        events.append({
            "time": float(pkt.time),
            "src": ip.src,
            "dst": ip.dst,
            "direccion": "request" if is_request else "response",
            "clasificacion": clasificacion,
            "detalle": f"unit_id={record['unit_id']} function_code={record['function_code']}",
        })

        if is_request:
            requests_by_src[ip.src].append(float(pkt.time))

    # --- Reporte cronológico ---
    print("=" * 100)
    print("TIMELINE DE EVENTOS MODBUS")
    print("=" * 100)
    events.sort(key=lambda e: e["time"])
    for e in events:
        ts = datetime.fromtimestamp(e["time"]).strftime("%H:%M:%S.%f")[:-3]
        print(f"[{ts}] {e['src']:>15} -> {e['dst']:<15} ({e['direccion']:<8}) "
              f"| {e['clasificacion']:<55} | {e['detalle']}")

    # --- Detección de ráfagas (posible reconocimiento automatizado) ---
    print("\n" + "=" * 100)
    print("DETECCIÓN DE RÁFAGAS (posible escaneo/reconocimiento automatizado)")
    print("=" * 100)
    any_burst = False
    for src, timestamps in requests_by_src.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window = [t for t in timestamps if timestamps[i] <= t <= timestamps[i] + BURST_WINDOW]
            if len(window) >= BURST_THRESHOLD:
                any_burst = True
                print(f"  ALERTA: {src} envió {len(window)} requests en {BURST_WINDOW}s "
                      f"(ventana iniciando {datetime.fromtimestamp(timestamps[i]).strftime('%H:%M:%S')})")
                break
    if not any_burst:
        print("  Sin ráfagas detectadas (tráfico dentro de umbrales normales).")

    # --- Resumen por categoría ---
    print("\n" + "=" * 100)
    print("RESUMEN POR CATEGORÍA")
    print("=" * 100)
    counts = defaultdict(int)
    for e in events:
        # agrupamos por la primera palabra de la clasificación (LECTURA, ESCRITURA, etc.)
        categoria = e["clasificacion"].split(" ")[0]
        counts[categoria] += 1
    for categoria, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {categoria:<20} {n} evento(s)")

    print(f"\nTotal de eventos Modbus/puerto 502 analizados: {len(events)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: python3 {sys.argv[0]} <ruta_al_pcap>")
        sys.exit(1)
    main(sys.argv[1])
