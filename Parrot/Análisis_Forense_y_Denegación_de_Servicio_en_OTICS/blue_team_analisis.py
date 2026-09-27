#!/usr/bin/env python3
import sys
from collections import defaultdict
from datetime import datetime
try:
    from scapy.all import rdpcap, TCP, IP
except ImportError:
    print("Falta scapy. Instálalo con: pip install scapy --break-system-packages"); sys.exit(1)
MODBUS_PORT = 502
READ_CODES = {1, 2, 3, 4}
WRITE_CODES = {5, 6, 15, 16, 22, 23}
DEVICE_INFO_CODE = 43
BURST_WINDOW = 2.0
BURST_THRESHOLD = 4
def parse_mbap_pdu(payload: bytes):
    if len(payload) < 8: return None
    protocol_id = int.from_bytes(payload[2:4], "big")
    unit_id = payload[6]; function_code = payload[7]
    if protocol_id != 0: return None
    return {"unit_id": unit_id, "function_code": function_code, "raw_len": len(payload)}
def classify(record):
    fc = record["function_code"]
    if fc >= 0x80: return f"EXCEPCION/PROBING (function_code original {fc-0x80})"
    if fc in WRITE_CODES: return "ESCRITURA (alerta alta - modificación no esperada)"
    if fc == DEVICE_INFO_CODE: return "RECONOCIMIENTO (read device identification)"
    if fc in READ_CODES: return "LECTURA NORMAL (baseline)"
    return f"DESCONOCIDO (function_code {fc})"
def main(pcap_path):
    print(f"Cargando {pcap_path} ..."); packets = rdpcap(pcap_path)
    print(f"{len(packets)} paquetes en el pcap.\n")
    events = []; requests_by_src = defaultdict(list)
    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)): continue
        tcp = pkt[TCP]; ip = pkt[IP]
        if tcp.dport != MODBUS_PORT and tcp.sport != MODBUS_PORT: continue
        payload = bytes(tcp.payload)
        if not payload: continue
        record = parse_mbap_pdu(payload)
        if record is None:
            events.append({"time": float(pkt.time),"src": ip.src,"dst": ip.dst,
                "direccion": "request" if tcp.dport == MODBUS_PORT else "response",
                "clasificacion": "NO-MODBUS (protocolo inválido en puerto 502 - sospechoso)",
                "detalle": f"{len(payload)} bytes no decodificables como Modbus TCP"}); continue
        is_request = tcp.dport == MODBUS_PORT
        events.append({"time": float(pkt.time),"src": ip.src,"dst": ip.dst,
            "direccion": "request" if is_request else "response","clasificacion": classify(record),
            "detalle": f"unit_id={record['unit_id']} function_code={record['function_code']}"})
        if is_request: requests_by_src[ip.src].append(float(pkt.time))
    print("="*100); print("TIMELINE DE EVENTOS MODBUS"); print("="*100)
    events.sort(key=lambda e: e["time"])
    for e in events:
        ts = datetime.fromtimestamp(e["time"]).strftime("%H:%M:%S.%f")[:-3]
        print(f"[{ts}] {e['src']:>15} -> {e['dst']:<15} ({e['direccion']:<8}) | {e['clasificacion']:<55} | {e['detalle']}")
    print("\n"+"="*100); print("DETECCIÓN DE RÁFAGAS (posible escaneo/reconocimiento automatizado)"); print("="*100)
    any_burst = False
    for src, ts in requests_by_src.items():
        ts.sort()
        for i in range(len(ts)):
            window = [t for t in ts if ts[i] <= t <= ts[i]+BURST_WINDOW]
            if len(window) >= BURST_THRESHOLD:
                any_burst = True
                print(f"  ALERTA: {src} envió {len(window)} requests en {BURST_WINDOW}s (ventana iniciando {datetime.fromtimestamp(ts[i]).strftime('%H:%M:%S')})"); break
    if not any_burst: print("  Sin ráfagas detectadas (tráfico dentro de umbrales normales).")
    print("\n"+"="*100); print("RESUMEN POR CATEGORÍA"); print("="*100)
    counts = defaultdict(int)
    for e in events: counts[e["clasificacion"].split(" ")[0]] += 1
    for cat, n in sorted(counts.items(), key=lambda x: -x[1]): print(f"  {cat:<20} {n} evento(s)")
    print(f"\nTotal de eventos Modbus/puerto 502 analizados: {len(events)}")
if __name__ == "__main__":
    if len(sys.argv) != 2: print(f"Uso: python3 {sys.argv[0]} <ruta_al_pcap>"); sys.exit(1)
    main(sys.argv[1])
