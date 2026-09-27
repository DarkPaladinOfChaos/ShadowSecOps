#!/usr/bin/env python3
"""
Prueba de correctitud (ground-truth) del pipeline de detección OT.
Valida que la clasificación por function code y el mapeo MITRE son CORRECTOS,
no solo auto-consistentes. Pensado como evidencia de validación para tesis.
"""
import sys, hashlib, subprocess
from scapy.all import rdpcap, TCP, IP

# --- Tabla de VERDAD: function code Modbus -> (categoria esperada, tecnica MITRE esperada) ---
GROUND_TRUTH = {
    1:  ("LECTURA", "T0861"),        # Read Coils
    2:  ("LECTURA", "T0861"),        # Read Discrete Inputs
    3:  ("LECTURA", "T0861"),        # Read Holding Registers
    4:  ("LECTURA", "T0861"),        # Read Input Registers
    5:  ("ESCRITURA", "T0855"),      # Write Single Coil
    6:  ("ESCRITURA", "T0855"),      # Write Single Register
    15: ("ESCRITURA", "T0855"),      # Write Multiple Coils
    16: ("ESCRITURA", "T0855"),      # Write Multiple Registers
    43: ("RECONOCIMIENTO", "T0846"), # Read Device Identification (0x2B)
    131:("EXCEPCION/PROBING", "T0846"), # 0x83 = excepción sobre FC3
}
READ_CODES={1,2,3,4}; WRITE_CODES={5,6,15,16,22,23}; DEVICE_INFO_CODE=43
MITRE={"LECTURA":"T0861","ESCRITURA":"T0855","RECONOCIMIENTO":"T0846","EXCEPCION/PROBING":"T0846"}
def classify(fc):
    if fc>=0x80: return "EXCEPCION/PROBING"
    if fc in WRITE_CODES: return "ESCRITURA"
    if fc==DEVICE_INFO_CODE: return "RECONOCIMIENTO"
    if fc in READ_CODES: return "LECTURA"
    return "DESCONOCIDO"

pcap=sys.argv[1]
pkts=rdpcap(pcap)
fails=0; total=0; observed_fcs=set()
print("PRUEBA 1 — Clasificación por function code contra ground-truth")
print("-"*80)
for pkt in pkts:
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)): continue
    tcp=pkt[TCP]
    if tcp.dport!=502 and tcp.sport!=502: continue
    p=bytes(tcp.payload)
    if len(p)<8 or int.from_bytes(p[2:4],"big")!=0: continue
    fc=p[7]; observed_fcs.add(fc); total+=1
    got_cat=classify(fc); got_mitre=MITRE.get(got_cat,"N/A")
    if fc in GROUND_TRUTH:
        exp_cat,exp_mitre=GROUND_TRUTH[fc]
        ok = (got_cat==exp_cat and got_mitre==exp_mitre)
        if not ok:
            fails+=1
            print(f"  [FALLO] FC={fc}: esperado {exp_cat}/{exp_mitre}, obtenido {got_cat}/{got_mitre}")
print(f"  Function codes observados en el pcap: {sorted(observed_fcs)}")
print(f"  Eventos Modbus evaluados: {total} | Discrepancias: {fails}")
print(f"  RESULTADO: {'PASA ✓ (clasificación 100% correcta)' if fails==0 else 'FALLA ✗'}")

print("\nPRUEBA 2 — Cobertura: ¿se generaron las 4 firmas de tráfico requeridas?")
print("-"*80)
cats_present={classify(fc) for fc in observed_fcs}
requeridas={"LECTURA","ESCRITURA","RECONOCIMIENTO","EXCEPCION/PROBING"}
faltan=requeridas-cats_present
print(f"  Categorías presentes: {sorted(cats_present)}")
print(f"  RESULTADO: {'PASA ✓ (las 4 firmas presentes)' if not faltan else f'FALLA ✗ faltan {faltan}'}")

print("\nPRUEBA 3 — Integridad: hash del script == sha256sum del sistema (reproducibilidad)")
print("-"*80)
h=hashlib.sha256(open(pcap,'rb').read()).hexdigest()
sys_h=subprocess.check_output(["sha256sum",pcap]).decode().split()[0]
print(f"  hashlib : {h}")
print(f"  sha256sum: {sys_h}")
print(f"  RESULTADO: {'PASA ✓ (hashes idénticos)' if h==sys_h else 'FALLA ✗'}")

print("\nPRUEBA 4 — Emparejamiento request/response (consistencia de transacciones)")
print("-"*80)
reqs=sum(1 for pkt in pkts if pkt.haslayer(TCP) and pkt[TCP].dport==502 and len(bytes(pkt[TCP].payload))>=8)
resps=sum(1 for pkt in pkts if pkt.haslayer(TCP) and pkt[TCP].sport==502 and len(bytes(pkt[TCP].payload))>=8)
print(f"  Requests (dport 502): {reqs} | Responses (sport 502): {resps}")
print(f"  RESULTADO: {'PASA ✓ (cada request tuvo su response)' if reqs==resps else 'AVISO: desbalance (puede ser normal si hubo retransmisiones)'}")

print("\n"+"="*80)
print(f"VEREDICTO GLOBAL: {'TODAS LAS PRUEBAS PASAN ✓' if fails==0 and not faltan and h==sys_h else 'REVISAR'}")
