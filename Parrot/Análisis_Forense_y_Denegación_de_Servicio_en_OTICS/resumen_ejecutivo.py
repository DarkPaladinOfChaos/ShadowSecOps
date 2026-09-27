#!/usr/bin/env python3
"""Fase Forense - Resumen ejecutivo con IA (API de Anthropic)."""
import sys, os
try:
    import anthropic
except ImportError:
    print("Falta anthropic: pip install anthropic"); sys.exit(1)
SYSTEM_PROMPT = """Eres un analista de seguridad OT/ICS redactando el resumen ejecutivo
de un informe de laboratorio de ciberseguridad. Recibiras un reporte tecnico que puede
incluir:
- Un hash SHA-256 de integridad de la evidencia (pcap)
- Un timeline cronologico de eventos Modbus/TCP
- Un mapeo a tecnicas MITRE ATT&CK for ICS (reconocimiento, escritura no autorizada)
- Opcionalmente, resultados de un ataque de Denegacion de Servicio (DoS) por inundacion
  Modbus/TCP: tasa de inundacion, latencia de un cliente legitimo antes/durante/despues,
  y el perfil forense del trafico de la inundacion (tasa de requests, rafagas, flujos TCP).
Escribe un resumen ejecutivo de 4-5 parrafos, en espanol, dirigido a un lector no
necesariamente tecnico, que cubra: (1) que se hizo, (2) hallazgos principales y su
severidad (incluyendo, si el reporte lo contiene, el hallazgo de disponibilidad/DoS),
(3) tecnicas MITRE ATT&CK for ICS observadas y su riesgo real -si hay DoS, cierra el
kill-chain como reconocimiento -> manipulacion -> disrupcion-, (4) conclusion sobre la
postura de seguridad y una recomendacion de alto nivel.
No repitas el timeline linea por linea."""
def main(report_path):
    with open(report_path) as f: report = f.read()
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key: print("Falta ANTHROPIC_API_KEY."); sys.exit(1)
    client = anthropic.Anthropic(api_key=key)
    resp = client.messages.create(model="claude-sonnet-5", max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[{"role":"user","content":f"Aqui esta el reporte forense tecnico:\n\n{report}"}])
    txt = "".join(b.text for b in resp.content if b.type == "text")
    print(txt)
    with open(os.path.join(os.path.dirname(report_path) or ".", "resumen_ejecutivo.txt"),"w") as f:
        f.write(txt+"\n")
if __name__ == "__main__":
    main(sys.argv[1])
