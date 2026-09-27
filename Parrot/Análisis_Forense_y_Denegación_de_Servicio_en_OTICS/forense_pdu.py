#!/usr/bin/env python3
"""Tecnica forense 3 - Inspeccion profunda de PDU Modbus + reconstruccion del estado del PLC."""
import sys
from datetime import datetime
from scapy.all import rdpcap, TCP, IP
FC = {1:"Read Coils",2:"Read Discrete Inputs",3:"Read Holding Registers",4:"Read Input Registers",
      5:"Write Single Coil",6:"Write Single Register",15:"Write Multiple Coils",16:"Write Multiple Registers",
      43:"Read Device Identification"}
def u16(b,i): return int.from_bytes(b[i:i+2],"big")
def main(pcap):
    pkts = rdpcap(pcap)
    print("="*100); print("INSPECCION PROFUNDA DE PDU MODBUS (carving del protocolo)"); print("="*100)
    writes = []
    last_read_val = {}
    for p in pkts:
        if not (p.haslayer(TCP) and p.haslayer(IP)): continue
        ip,tcp = p[IP],p[TCP]
        if tcp.dport!=502 and tcp.sport!=502: continue
        pl = bytes(tcp.payload)
        if len(pl)<8 or u16(pl,2)!=0: continue
        is_req = tcp.dport==502
        tid=u16(pl,0); uid=pl[6]; fc=pl[7]
        ts = datetime.fromtimestamp(float(p.time)).strftime("%H:%M:%S.%f")[:-3]
        detail=""
        if is_req and fc in (3,4,1,2) and len(pl)>=12:
            detail=f"addr={u16(pl,8)} count={u16(pl,10)}"
        elif is_req and fc==6 and len(pl)>=12:
            addr=u16(pl,8); val=u16(pl,10); detail=f"WRITE addr={addr} value={val}"
            writes.append((ts,ip.src,ip.dst,addr,val))
        elif fc>=0x80:
            detail=f"EXCEPCION exception_code={pl[8] if len(pl)>8 else '?'}"
        elif not is_req and fc==3 and len(pl)>=9:
            n=pl[8]; regs=[u16(pl,9+2*i) for i in range(n//2)]; detail=f"registers={regs}"
            if regs: last_read_val[0]=regs[0]
        role = "REQ " if is_req else "RESP"
        print(f"[{ts}] {role} tid={tid} uid={uid} fc={fc} ({FC.get(fc,'?')}) {detail}")
    print("\n"+"="*100); print("RECONSTRUCCION DEL CAMBIO DE ESTADO DEL PLC"); print("="*100)
    if writes:
        for ts,s,d,addr,val in writes:
            print(f"  [{ts}] {s} -> {d}: escritura NO AUTORIZADA en holding register {addr}, nuevo valor = {val}")
        print(f"  Evidencia de manipulacion: el registro {writes[0][3]} fue modificado (valor final observado = {last_read_val.get(0,'?')}).")
        print(f"  Interpretacion forense: un setpoint del proceso fue alterado sin autenticacion (MITRE T0855).")
    else:
        print("  No se observaron escrituras.")
if __name__ == "__main__":
    main(sys.argv[1])
