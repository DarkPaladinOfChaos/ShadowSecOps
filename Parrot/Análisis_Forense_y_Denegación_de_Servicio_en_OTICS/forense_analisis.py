#!/usr/bin/env python3
import sys, hashlib
from collections import defaultdict
from datetime import datetime
try:
    from scapy.all import rdpcap, TCP, IP
except ImportError:
    print("Falta scapy."); sys.exit(1)
MODBUS_PORT = 502
READ_CODES = {1, 2, 3, 4}; WRITE_CODES = {5, 6, 15, 16, 22, 23}; DEVICE_INFO_CODE = 43
MITRE_MAP = {
    "RECONOCIMIENTO": ("T0846", "Remote System Discovery / T0842 Network Sniffing (según contexto)"),
    "LECTURA": ("T0861", "Point & Tag Identification / Data from Information Repositories"),
    "ESCRITURA": ("T0855", "Unauthorized Command Message"),
    "EXCEPCION/PROBING": ("T0846", "Remote System Discovery (respuesta de error ante sondeo de direcciones)"),
    "NO-MODBUS": ("N/A", "Tráfico no-Modbus en puerto ICS — fuera de alcance MITRE ICS, posible ruido de red"),
}
def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
    return h.hexdigest()
def parse_mbap_pdu(payload):
    if len(payload) < 8: return None
    if int.from_bytes(payload[2:4], "big") != 0: return None
    return {"unit_id": payload[6], "function_code": payload[7]}
def classify(record):
    fc = record["function_code"]
    if fc >= 0x80: return "EXCEPCION/PROBING"
    if fc in WRITE_CODES: return "ESCRITURA"
    if fc == DEVICE_INFO_CODE: return "RECONOCIMIENTO"
    if fc in READ_CODES: return "LECTURA"
    return "DESCONOCIDO"
def build_timeline(pcap_path):
    packets = rdpcap(pcap_path); events = []
    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)): continue
        tcp, ip = pkt[TCP], pkt[IP]
        if tcp.dport != MODBUS_PORT and tcp.sport != MODBUS_PORT: continue
        payload = bytes(tcp.payload)
        if not payload: continue
        is_request = tcp.dport == MODBUS_PORT
        record = parse_mbap_pdu(payload)
        if record is None:
            categoria = "NO-MODBUS"; detalle = f"{len(payload)} bytes no decodificables como Modbus TCP"
        else:
            categoria = classify(record); detalle = f"unit_id={record['unit_id']} function_code={record['function_code']}"
        events.append({"time": float(pkt.time),"src": ip.src,"dst": ip.dst,
            "direccion": "request" if is_request else "response","categoria": categoria,"detalle": detalle})
    events.sort(key=lambda e: e["time"]); return events
def main(pcap_path):
    print(f"Procesando {pcap_path} ...\n")
    file_hash = sha256_of_file(pcap_path); hash_line = f"SHA-256 ({pcap_path}): {file_hash}"
    print(hash_line)
    events = build_timeline(pcap_path)
    rl = ["="*100, "REPORTE FORENSE - Entorno OT Simulado (Modbus/SCADA)",
          f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "="*100, "",
          "-- INTEGRIDAD DE LA EVIDENCIA --", hash_line, "",
          "-- TIMELINE UNIFICADO + MAPEO MITRE ATT&CK for ICS --", ""]
    tc = defaultdict(int)
    for e in events:
        ts = datetime.fromtimestamp(e["time"]).strftime("%H:%M:%S.%f")[:-3]
        tid, tdesc = MITRE_MAP.get(e["categoria"], ("N/A", "Sin mapeo")); tc[tid] += 1
        rl.append(f"[{ts}] {e['src']:>15} -> {e['dst']:<15} ({e['direccion']:<8}) | {e['categoria']:<18} | {tid:<6} {tdesc}")
        rl.append(f"           detalle: {e['detalle']}")
    rl += ["", "-- RESUMEN DE TÉCNICAS MITRE ATT&CK for ICS OBSERVADAS --"]
    for tid, n in sorted(tc.items(), key=lambda x: -x[1]): rl.append(f"  {tid:<6} — {n} evento(s)")
    rl += ["", f"Total de eventos analizados: {len(events)}"]
    report_text = "\n".join(rl); print("\n"+report_text)
    out_path = pcap_path.rsplit("/",1)[0] + "/reporte_forense.txt" if "/" in pcap_path else "reporte_forense.txt"
    with open(out_path,"w") as f: f.write(report_text+"\n")
    print(f"\nReporte guardado en: {out_path}")
if __name__ == "__main__":
    if len(sys.argv) != 2: print(f"Uso: python3 {sys.argv[0]} <pcap>"); sys.exit(1)
    main(sys.argv[1])
