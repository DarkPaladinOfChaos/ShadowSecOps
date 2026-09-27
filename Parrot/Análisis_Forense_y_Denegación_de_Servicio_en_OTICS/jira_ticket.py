#!/usr/bin/env python3
"""Operacionalizacion - Exporta el hallazgo forense OT a un ticket de Jira (formato SOC)."""
import os, sys, json, base64, re, datetime, urllib.request, urllib.error
JIRA_URL = "https://ingvictormbastidass.atlassian.net"
PROJECT_KEY = "SECOPS"
def env(n):
    v = os.environ.get(n)
    if not v: print(f"Falta la variable de entorno {n}."); sys.exit(1)
    return v
def read_file(p):
    try:
        with open(p) as f: return f.read()
    except FileNotFoundError: return ""
def txt(t): return {"type":"text","text":t}
def para(t): return {"type":"paragraph","content":[txt(t)]}
def heading(t,l=3): return {"type":"heading","attrs":{"level":l},"content":[txt(t)]}
def bullets(items): return {"type":"bulletList","content":[{"type":"listItem","content":[para(i)]} for i in items]}
def codeblock(t): return {"type":"codeBlock","content":[txt(t)]}
def get_issue_type_id(base, auth, key):
    req = urllib.request.Request(f"{base}/rest/api/3/project/{key}",
        headers={"Authorization": f"Basic {auth}", "Accept":"application/json"})
    with urllib.request.urlopen(req) as r:
        proj = json.loads(r.read().decode())
    types = proj.get("issueTypes", [])
    for t in types:
        if not t.get("subtask") and t.get("name","").lower() in ("task","tarea"): return t["id"]
    for t in types:
        if not t.get("subtask"): return t["id"]
    return types[0]["id"] if types else None
def main(report_path, resumen_path):
    email = env("JIRA_EMAIL"); token = env("JIRA_API_TOKEN")
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    report = read_file(report_path); resumen = read_file(resumen_path)
    itid = get_issue_type_id(JIRA_URL, auth, PROJECT_KEY)
    m = re.search(r'SHA-256 \([^)]*\):\s*([0-9a-f]{64})', report)
    sha = m.group(1) if m else "(no encontrado)"
    techs = re.findall(r'(T\d{4})\s+—\s+(\d+)', report)
    tm = re.search(r'Total de eventos analizados:\s*(\d+)', report)
    total = tm.group(1) if tm else "?"
    techs_str = ", ".join(f"{t} x{n}" for t,n in techs) or "T0855, T0846, T0861"
    now = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    summary = "[OT/ICS] Escritura no autorizada a registro de PLC Modbus/TCP sin autenticacion"
    fields = [
        "Caso de uso: CU-OT-001 - Escritura no autorizada a PLC Modbus/TCP",
        "Severidad: ALTA    |    Prioridad: ALTA",
        f"Fecha de deteccion: {now}",
        "Categoria: OT/ICS - Modbus/TCP (puerto 502)",
        "Fuente: PLC simulado pymodbus (ShadowSecOps Labs PLC-SIM-01)",
        "IP origen (atacante): 192.168.167.128 - Parrot OS",
        "IP destino (activo OT): 192.168.167.129 - PLC simulado",
        "Tecnica principal: T0855 - Unauthorized Command Message (function code 6)",
        f"Tecnicas observadas: {techs_str} (total {total} eventos Modbus)",
        f"Evidencia SHA-256 (pcap): {sha}",
    ]
    resumen_paras = [p.strip() for p in resumen.split("\n\n") if p.strip() and not p.strip().startswith("#")][:6]
    content = [heading("Detalles del incidente"), bullets(fields),
        heading("Descripcion"),
        para("Se detecto un comando de escritura no autorizado (function code 6) sobre el holding register 0 del PLC (350 -> 9999), sin autenticacion. Rafaga de 6 requests en 2s y reconocimiento previo del dispositivo."),
        heading("Resumen ejecutivo (IA)")]
    content += [para(p) for p in resumen_paras]
    content += [heading("Evidencia forense (extracto del timeline)"), codeblock((report[:1500] or "(no disponible)"))]
    payload = {"fields":{"project":{"key":PROJECT_KEY},"summary":summary,
        "description":{"type":"doc","version":1,"content":content},"issuetype":{"id":itid},
        "labels":["OT-ICS","Modbus","MITRE-T0855","MITRE-T0846","MITRE-T0861","ShadowSentinel","forense"]}}
    req = urllib.request.Request(f"{JIRA_URL}/rest/api/3/issue",
        data=json.dumps(payload).encode(), method="POST",
        headers={"Authorization":f"Basic {auth}","Content-Type":"application/json","Accept":"application/json"})
    with urllib.request.urlopen(req) as r:
        k = json.loads(r.read().decode()).get("key")
        print(f"[OK] Ticket creado: {k}  ->  {JIRA_URL}/browse/{k}")
if __name__ == "__main__":
    rp = sys.argv[1] if len(sys.argv)>1 else "reporte_forense.txt"
    sp = sys.argv[2] if len(sys.argv)>2 else "resumen_ejecutivo.txt"
    main(rp, sp)
