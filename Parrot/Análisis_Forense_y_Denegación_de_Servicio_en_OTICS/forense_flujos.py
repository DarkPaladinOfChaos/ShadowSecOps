#!/usr/bin/env python3
"""Tecnica forense 2 - Analisis de flujos / reconstruccion de sesiones TCP."""
import sys
from collections import defaultdict
from datetime import datetime
from scapy.all import rdpcap, TCP, IP
def main(pcap):
    pkts = rdpcap(pcap)
    flows = defaultdict(lambda: {"pkts":0,"bytes":0,"t0":None,"t1":None,"syn":0,"fin":0,"rst":0})
    for p in pkts:
        if not (p.haslayer(TCP) and p.haslayer(IP)): continue
        ip, tcp = p[IP], p[TCP]
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        f = flows[key]; t = float(p.time)
        f["pkts"] += 1; f["bytes"] += len(bytes(tcp.payload))
        f["t0"] = t if f["t0"] is None else min(f["t0"], t)
        f["t1"] = t if f["t1"] is None else max(f["t1"], t)
        flags = tcp.flags
        if flags & 0x02: f["syn"] += 1
        if flags & 0x01: f["fin"] += 1
        if flags & 0x04: f["rst"] += 1
    print("="*100); print("ANALISIS DE FLUJOS / SESIONES TCP"); print("="*100)
    print(f"{'Origen':>22} {'->':^4} {'Destino':<22} {'Pkts':>5} {'Payload':>8} {'Dur(s)':>7}  Flags")
    for (s,sp,d,dp), f in sorted(flows.items(), key=lambda x:-x[1]["pkts"]):
        dur = (f["t1"]-f["t0"]) if f["t0"] else 0
        print(f"{s+':'+str(sp):>22} {'->':^4} {d+':'+str(dp):<22} {f['pkts']:>5} {f['bytes']:>8} {dur:>7.2f}  SYN={f['syn']} FIN={f['fin']} RST={f['rst']}")
    print(f"\nTotal de flujos (5-tupla) reconstruidos: {len(flows)}")
    # sesion Modbus principal (dport 502)
    modbus = [(k,v) for k,v in flows.items() if k[3]==502]
    if modbus:
        (s,sp,d,dp),f = max(modbus, key=lambda x:x[1]["pkts"])
        print(f"Sesion Modbus principal: {s} -> {d}:502 | {f['pkts']} paquetes | {f['bytes']} bytes de payload | "
              f"inicio {datetime.fromtimestamp(f['t0']).strftime('%H:%M:%S')} | duracion {f['t1']-f['t0']:.2f}s")
if __name__ == "__main__":
    main(sys.argv[1])
