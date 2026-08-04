#!/usr/bin/env python3
"""
Fase Forense - Resumen ejecutivo con IA (API de Anthropic)
Práctica OT: Reconocimiento, Análisis de Seguridad y Forense en un Entorno OT Simulado (Modbus/SCADA)

Toma el reporte_forense.txt (timeline + hashing + mapeo MITRE ya generado)
y le pide a Claude un resumen ejecutivo tipo "informe de incidente",
apto para incluir como cierre del informe de la práctica.

Requiere: anthropic
    pip install anthropic --break-system-packages

Requiere la variable de entorno ANTHROPIC_API_KEY configurada:
    export ANTHROPIC_API_KEY="tu-api-key-aqui"
"""

import sys
import os

try:
    import anthropic
except ImportError:
    print("Falta el SDK de Anthropic. Instálalo con: pip install anthropic --break-system-packages")
    sys.exit(1)


SYSTEM_PROMPT = """Eres un analista de seguridad OT/ICS redactando el resumen ejecutivo
de un informe de laboratorio de ciberseguridad. Recibirás un reporte técnico con:
- Un hash SHA-256 de integridad de la evidencia (pcap)
- Un timeline cronológico de eventos Modbus/TCP
- Un mapeo a técnicas MITRE ATT&CK for ICS

Escribe un resumen ejecutivo de 3-4 párrafos, en español, dirigido a un lector no
necesariamente técnico (ej. un gerente o cliente), que cubra:
1. Qué se hizo (alcance del ejercicio: reconocimiento, interacción, análisis de tráfico).
2. Los hallazgos principales (qué tipo de actividad se detectó y su severidad relativa).
3. Las técnicas MITRE ATT&CK for ICS observadas y su significado en términos de riesgo real.
4. Una conclusión breve sobre la postura de seguridad del entorno simulado (ej. exposición
   sin autenticación, falta de controles de escritura, etc.) y una recomendación de alto nivel.

No repitas el timeline línea por línea, es un resumen, no una transcripción."""


def main(report_path: str):
    if not os.path.exists(report_path):
        print(f"No se encontró el archivo: {report_path}")
        sys.exit(1)

    with open(report_path, "r") as f:
        report_content = f.read()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("No se encontró la variable de entorno ANTHROPIC_API_KEY.")
        print('Configúrala con: export ANTHROPIC_API_KEY="tu-api-key-aqui"')
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    print("Generando resumen ejecutivo con IA...\n")

    response = client.messages.create(
        model="claude-sonnet-5",
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[
            {"role": "user", "content": f"Aquí está el reporte forense técnico:\n\n{report_content}"}
        ],
    )

    summary_text = "".join(block.text for block in response.content if block.type == "text")

    print("=" * 100)
    print("RESUMEN EJECUTIVO")
    print("=" * 100)
    print(summary_text)

    out_dir = os.path.dirname(report_path)
    out_path = os.path.join(out_dir, "resumen_ejecutivo.txt")
    with open(out_path, "w") as f:
        f.write(summary_text + "\n")
    print(f"\nResumen guardado en: {out_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: python3 {sys.argv[0]} <ruta_al_reporte_forense.txt>")
        sys.exit(1)
    main(sys.argv[1])
