#!/usr/bin/env python3
"""Operacionalizacion - Exporta el hallazgo de Denegacion de Servicio (DoS/T0814)
a un ticket de Jira (formato SOC), como segundo ticket del mismo incidente OT/ICS.

Uso:
  export JIRA_EMAIL="..."
  export JIRA_API_TOKEN="..."
  python3 jira_ticket_dos.py reporte_dos_completo.txt resumen_ejecutivo.txt

reporte_dos_completo.txt debe ser la concatenacion de la salida de:
  python3 dos_modbus.py 192.168.167.129 6 20   > reporte_dos_completo.txt
  python3 forense_estadistico.py dos_traffic.pcap >> reporte_dos_completo.txt
  python3 forense_flujos.py dos_traffic.pcap      >> reporte_dos_completo.txt
"""
import os, sys, json, base64, re, datetime, urllib.request, urllib.error

JIRA_URL = "https://ingvictormbastidass.atlassian.net"
PROJECT_KEY = "SECOPS"

def env(n):
    v = os.environ.get(n)
    if not v:
        print(f"Falta la variable de entorno {n}."); sys.exit(1)
    return v

def read_file(p):
    try:
        with open(p) as f: return f.read()
    except FileNotFoundError: return ""

def txt(t): return {"type": "text", "text": t}
def para(t): return {"type": "paragraph", "content": [txt(t)]}
def heading(t, l=3): return {"type": "heading", "attrs": {"level": l}, "content": [txt(t)]}
def bullets(items): return {"type": "bulletList", "content": [{"type": "listItem", "content": [para(i)]} for i in items]}
def codeblock(t): return {"type": "codeBlock", "content": [txt(t)]}

def get_issue_type_id(base, auth, key):
    req = urllib.request.Request(f"{base}/rest/api/3/project/{key}",
        headers={"Authorization": f"Basic {auth}", "Accept": "application/json"})
    with urllib.request.urlopen(req) as r:
        proj = json.loads(r.read().decode())
    types = proj.get("issueTypes", [])
    for t in types:
        if not t.get("subtask") and t.get("name", "").lower() in ("task", "tarea"): return t["id"]
    for t in types:
        if not t.get("subtask"): return t["id"]
    return types[0]["id"] if types else None

def grab(pattern, text, default="(no encontrado)", group=1):
    m = re.search(pattern, text)
    return m.group(group) if m else default

def main(report_path, resumen_path):
    email = env("JIRA_EMAIL"); token = env("JIRA_API_TOKEN")
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    report = read_file(report_path); resumen = read_file(resumen_path)
    itid = get_issue_type_id(JIRA_URL, auth, PROJECT_KEY)

    enviadas = grab(r'Total de peticiones enviadas:\s*([\d\s]+)', report).strip()
    tasa_inund = grab(r'Tasa de inundaci[oó]n:\s*([\d.]+)\s*req/s', report)
    lat_antes = grab(r'\[BASELINE\][^\n]*?\(([\d.]+)\s*ms\)', report)
    lat_durante = grab(r'\[DURANTE\][^\n]*?\(([\d.]+)\s*ms\)', report)
    lat_despues = grab(r'\[DESPUES\][^\n]*?\(([\d.]+)\s*ms\)', report)
    req_forense = grab(r'Total de requests Modbus:\s*(\d+)', report)
    tasa_media = grab(r'Tasa media de requests:\s*([\d.]+)\s*req/s', report)
    rafaga = grab(r'Maximo de requests en ventana de [\d.]+s:\s*(\d+)', report)
    flujos = grab(r'Total de flujos \(5-tupla\) reconstruidos:\s*(\d+)', report)

    now = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    summary = "[OT/ICS] Denegacion de Servicio (DoS) por inundacion Modbus/TCP contra PLC simulado"
    fields = [
        "Caso de uso: CU-OT-002 - DoS por inundacion Modbus/TCP",
        "Severidad: ALTA    |    Prioridad: ALTA",
        f"Fecha de deteccion: {now}",
        "Categoria: OT/ICS - Modbus/TCP (puerto 502) - Disponibilidad",
        "Fuente: PLC simulado pymodbus (ShadowSecOps Labs PLC-SIM-01)",
        "IP origen (atacante): 192.168.167.128 - Parrot OS",
        "IP destino (activo OT): 192.168.167.129 - PLC simulado",
        "Tecnica principal: T0814 - Denial of Service (impacto T0826 - Loss of Availability)",
        f"Peticiones de inundacion enviadas: {enviadas}  (tasa de inundacion: {tasa_inund} req/s)",
        f"Latencia de lectura legitima: antes={lat_antes} ms | durante={lat_durante} ms | despues={lat_despues} ms",
        f"Perfil forense del trafico (dos_traffic.pcap): {req_forense} requests Modbus, tasa media {tasa_media} req/s, "
        f"maximo {rafaga} requests en ventana de 2s (rafaga), {flujos} flujos TCP (5-tupla) reconstruidos",
    ]
    resumen_paras = [p.strip() for p in resumen.split("\n\n") if p.strip() and not p.strip().startswith("#")][:6]
    content = [
        heading("Detalles del incidente"), bullets(fields),
        heading("Descripcion"),
        para("Cierre del kill-chain OT/ICS: tras el reconocimiento (T0846) y la escritura no autorizada (T0855, ver "
             "ticket relacionado de este mismo ejercicio), se ejecuto una fase de disrupcion mediante inundacion de "
             "peticiones Modbus/TCP contra el PLC. Se midio degradacion de disponibilidad en un cliente legitimo "
             "(aumento de latencia) durante la inundacion, y el patron de trafico (tasa, rafaga y volumen de "
             "conexiones TCP) fue confirmado por analisis forense sobre la captura de paquetes."),
        heading("Resumen ejecutivo (IA)"),
    ]
    content += [para(p) for p in resumen_paras]
    content += [heading("Evidencia forense (extracto)"), codeblock((report[:1500] or "(no disponible)"))]
    payload = {"fields": {"project": {"key": PROJECT_KEY}, "summary": summary,
        "description": {"type": "doc", "version": 1, "content": content}, "issuetype": {"id": itid},
        "labels": ["OT-ICS", "Modbus", "MITRE-T0814", "DoS", "Disponibilidad", "ShadowSentinel", "forense"]}}
    req = urllib.request.Request(f"{JIRA_URL}/rest/api/3/issue",
        data=json.dumps(payload).encode(), method="POST",
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req) as r:
        k = json.loads(r.read().decode()).get("key")
        print(f"[OK] Ticket creado: {k}  ->  {JIRA_URL}/browse/{k}")

if __name__ == "__main__":
    rp = sys.argv[1] if len(sys.argv) > 1 else "reporte_dos_completo.txt"
    sp = sys.argv[2] if len(sys.argv) > 2 else "resumen_ejecutivo.txt"
    main(rp, sp)
