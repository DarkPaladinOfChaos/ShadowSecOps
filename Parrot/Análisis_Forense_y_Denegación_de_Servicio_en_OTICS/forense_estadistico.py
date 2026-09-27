#!/usr/bin/env python3
"""Tecnica forense 4 - Perfilado del trafico Modbus y deteccion de rafagas."""
import sys
from collections import Counter
from scapy.all import rdpcap, TCP, IP
def u16(b,i): return int.from_bytes(b[i:i+2],"big")
def main(pcap):
    pkts = rdpcap(pcap)
    req_times=[]; fcs=Counter()
    for p in pkts:
        if not (p.haslayer(TCP) and p.haslayer(IP)): continue
        tcp=p[TCP]; pl=bytes(tcp.payload)
        if len(pl)<8 or u16(pl,2)!=0: continue
        fc=pl[7]; fcs[fc]+=1
        if tcp.dport==502: req_times.append(float(p.time))
    req_times.sort()
    print("="*100); print("PERFILADO DEL TRAFICO MODBUS Y DETECCION DE RAFAGAS"); print("="*100)
    print(f"Total de requests Modbus: {len(req_times)}")
    if len(req_times)>=2:
        iats=[req_times[i+1]-req_times[i] for i in range(len(req_times)-1)]
        span=req_times[-1]-req_times[0]
        print(f"Ventana total de actividad: {span:.2f} s")
        print(f"Tasa media de requests: {len(req_times)/span:.2f} req/s" if span>0 else "Tasa: instantanea")
        print(f"Inter-arrival (s): min={min(iats):.3f}  max={max(iats):.3f}  media={sum(iats)/len(iats):.3f}")
        # deteccion de rafaga: max requests en ventana de 2s
        W=2.0; maxwin=0
        for i in range(len(req_times)):
            c=sum(1 for t in req_times if req_times[i]<=t<=req_times[i]+W)
            maxwin=max(maxwin,c)
        print(f"Maximo de requests en ventana de {W}s: {maxwin}  -> {'ANOMALIA (rafaga)' if maxwin>=4 else 'normal'}")
    print("\nDistribucion de function codes:")
    names={1:'Read Coils',3:'Read Holding Regs',6:'Write Single Reg',43:'Read Device ID',131:'Excepcion(0x83)'}
    for fc,n in sorted(fcs.items(), key=lambda x:-x[1]):
        print(f"  FC {fc:<3} {names.get(fc,'?'):<20} {n} evento(s)")
if __name__ == "__main__":
    main(sys.argv[1])
