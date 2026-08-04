#!/usr/bin/env python3
"""
Fase Forense - Timeline unificado, hashing de integridad y mapeo MITRE ATT&CK for ICS
Práctica OT: Reconocimiento, Análisis de Seguridad y Forense en un Entorno OT Simulado (Modbus/SCADA)

1. Calcula el hash SHA-256 del pcap (evidencia de integridad / cadena de custodia).
2. Reconstruye el timeline unificado de eventos Modbus.
3. Mapea cada evento a la técnica correspondiente de MITRE ATT&CK for ICS.
4. Genera un reporte de texto con todo lo anterior, listo para el informe final.

Requiere: scapy
    pip install scapy --break-system-packages
"""

import sys
import hashlib
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, TCP, IP
except ImportError:
    print("Falta scapy. Instálalo con: pip install scapy --break-system-packages")
    sys.exit(1)

MODBUS_PORT = 502
READ_CODES = {1, 2, 3, 4}
WRITE_CODES = {5, 6, 15, 16, 22, 23}
DEVICE_INFO_CODE = 43

# Mapeo de categoría de evento -> técnica MITRE ATT&CK for ICS
MITRE_MAP = {
    "RECONOCIMIENTO": ("T0846", "Remote System Discovery / T0842 Network Sniffing (según contexto)"),
    "LECTURA": ("T0861", "Point & Tag Identification / Data from Information Repositories"),
    "ESCRITURA": ("T0855", "Unauthorized Command Message"),
    "EXCEPCION/PROBING": ("T0846", "Remote System Discovery (respuesta de error ante sondeo de direcciones)"),
    "NO-MODBUS": ("N/A", "Tráfico no-Modbus en puerto ICS — fuera de alcance MITRE ICS, posible ruido de red"),
}


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_mbap_pdu(payload: bytes):
    if len(payload) < 8:
        return None
    protocol_id = int.from_bytes(payload[2:4], "big")
    if protocol_id != 0:
        return None
    return {
        "unit_id": payload[6],
        "function_code": payload[7],
    }


def classify(record: dict) -> str:
    fc = record["function_code"]
    if fc >= 0x80:
        return "EXCEPCION/PROBING"
    if fc in WRITE_CODES:
        return "ESCRITURA"
    if fc == DEVICE_INFO_CODE:
        return "RECONOCIMIENTO"
    if fc in READ_CODES:
        return "LECTURA"
    return "DESCONOCIDO"


def build_timeline(pcap_path: str):
    packets = rdpcap(pcap_path)
    events = []
    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue
        tcp, ip = pkt[TCP], pkt[IP]
        if tcp.dport != MODBUS_PORT and tcp.sport != MODBUS_PORT:
            continue
        payload = bytes(tcp.payload)
        if not payload:
            continue

        is_request = tcp.dport == MODBUS_PORT
        record = parse_mbap_pdu(payload)

        if record is None:
            categoria = "NO-MODBUS"
            detalle = f"{len(payload)} bytes no decodificables como Modbus TCP"
        else:
            categoria = classify(record)
            detalle = f"unit_id={record['unit_id']} function_code={record['function_code']}"

        events.append({
            "time": float(pkt.time),
            "src": ip.src,
            "dst": ip.dst,
            "direccion": "request" if is_request else "response",
            "categoria": categoria,
            "detalle": detalle,
        })

    events.sort(key=lambda e: e["time"])
    return events


def main(pcap_path: str):
    print(f"Procesando {pcap_path} ...\n")

    # --- 1. Hashing de integridad ---
    file_hash = sha256_of_file(pcap_path)
    hash_line = f"SHA-256 ({pcap_path}): {file_hash}"
    print(hash_line)

    # --- 2. Timeline unificado ---
    events = build_timeline(pcap_path)

    # --- 3. Mapeo MITRE ATT&CK for ICS + reporte ---
    report_lines = []
    report_lines.append("=" * 100)
    report_lines.append("REPORTE FORENSE - Entorno OT Simulado (Modbus/SCADA)")
    report_lines.append(f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report_lines.append("=" * 100)
    report_lines.append("")
    report_lines.append("-- INTEGRIDAD DE LA EVIDENCIA --")
    report_lines.append(hash_line)
    report_lines.append("")
    report_lines.append("-- TIMELINE UNIFICADO + MAPEO MITRE ATT&CK for ICS --")
    report_lines.append("")

    tecnica_counts = defaultdict(int)

    for e in events:
        ts = datetime.fromtimestamp(e["time"]).strftime("%H:%M:%S.%f")[:-3]
        tecnica_id, tecnica_desc = MITRE_MAP.get(e["categoria"], ("N/A", "Sin mapeo"))
        tecnica_counts[tecnica_id] += 1
        line = (f"[{ts}] {e['src']:>15} -> {e['dst']:<15} ({e['direccion']:<8}) "
                f"| {e['categoria']:<18} | {tecnica_id:<6} {tecnica_desc}")
        report_lines.append(line)
        report_lines.append(f"           detalle: {e['detalle']}")

    report_lines.append("")
    report_lines.append("-- RESUMEN DE TÉCNICAS MITRE ATT&CK for ICS OBSERVADAS --")
    for tecnica_id, n in sorted(tecnica_counts.items(), key=lambda x: -x[1]):
        report_lines.append(f"  {tecnica_id:<6} — {n} evento(s)")

    report_lines.append("")
    report_lines.append(f"Total de eventos analizados: {len(events)}")

    report_text = "\n".join(report_lines)
    print("\n" + report_text)

    out_path = pcap_path.rsplit("/", 1)[0] + "/reporte_forense.txt"
    with open(out_path, "w") as f:
        f.write(report_text + "\n")
    print(f"\nReporte guardado en: {out_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: python3 {sys.argv[0]} <ruta_al_pcap>")
        sys.exit(1)
    main(sys.argv[1])
