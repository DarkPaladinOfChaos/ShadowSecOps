# IOC ThreatIntel Analyzer

> Actividad académica: **MACS 580 · ACT10 · Grupo 7**

Workflow de **n8n** para análisis automatizado de **IOCs** (indicadores de compromiso). A partir de un formulario, consulta la reputación de una **IP** o **URL** en **VirusTotal**, envía los resultados a **Gemini 2.5 Flash** para un veredicto ejecutivo de Threat Intelligence y notifica el resultado por **Telegram**.

> ⚠️ **Aviso de seguridad:** el export original traía claves de API reales en texto plano (Gemini, VirusTotal) y datos de Telegram. Para compartir/entregar usa **`IOC-ThreatIntel-Analyzer_sanitizado.json`**, donde esos valores ya están reemplazados por placeholders. Aun así, **revoca y regenera las claves originales**: quitarlas del archivo no las invalida.

## Archivos

| Archivo | Descripción |
|---------|-------------|
| `IOC-ThreatIntel-Analyzer_sanitizado.json` | Workflow listo para importar, **sin credenciales expuestas** (placeholders). |
| `README-IOC-ThreatIntel-Analyzer.md` | Este documento. |

---

## Descripción general

El flujo se inicia con el envío de un formulario donde el analista indica el tipo de IOC (IP o URL) y su valor. Tras una espera, bifurca según el tipo, consulta el endpoint correspondiente de VirusTotal, pasa el resultado a Gemini para obtener un veredicto estandarizado y lo publica en un chat de Telegram.

```
On form submission ──► Wait (15s) ──► If (Tipo de IOC == "IP")
                                         │
                    ┌────────────────────┴────────────────────┐
                 (true / IP)                              (false / URL)
                    │                                          │
              VirusTotal                          Code in JavaScript (base64url)
              (ip_addresses)                                    │
                    │                                       VirusTotal1
                    │                                        (urls)
                    └───────────────────┬──────────────────────┘
                                        ▼
                                 Gemini Analizar
                                        ▼
                                 Enviar Telegram

Schedule Trigger (cada 1 min)  ──►  (sin conexiones — ver Notas)
```

---

## Nodos

| Nodo | Tipo | Función |
|------|------|---------|
| **On form submission1** | `formTrigger` | Formulario *"Análisis de IoCs"*: campo `Tipo de IOC` (dropdown IP/URL, obligatorio) e `IoC` (valor a analizar). |
| **Wait1** | `wait` | Espera de 15 segundos antes de continuar. |
| **If** | `if` | Bifurca el flujo: si `Tipo de IOC == "IP"` va a VirusTotal (IP); caso contrario, al procesamiento de URL. |
| **VirusTotal** | `httpRequest` | `GET /api/v3/ip_addresses/{IoC}` — reputación de la IP. |
| **Code in JavaScript** | `code` | Codifica la URL en **base64url** para construir el `urlId` que exige la API de VirusTotal. |
| **VirusTotal1** | `httpRequest` | `GET /api/v3/urls/{urlId}` — reputación de la URL. |
| **Gemini Analizar** | `httpRequest` | `POST` a `gemini-2.5-flash:generateContent`. Actúa como analista senior de TI y devuelve veredicto en formato fijo. |
| **Enviar Telegram** | `telegram` | Publica el reporte de Threat Intelligence en el chat configurado. |
| **Schedule Trigger** | `scheduleTrigger` | Ejecución cada 1 minuto. *Sin conexiones de salida — ver Notas.* |

---

## Formato de salida de Gemini

El prompt fuerza una respuesta ejecutiva (máx. 500 caracteres, sin Markdown):

```
🚨 VEREDICTO: MALICIOSO | SOSPECHOSO | LIMPIO
🔍 HALLAZGO: máximo 2 oraciones.
⚠️ RIESGO: ALTO | MEDIO | BAJO
🛡️ ACCIÓN: máximo 3 recomendaciones cortas.
```

---

## Requisitos previos

- Instancia de **n8n**.
- **API key de VirusTotal** — https://www.virustotal.com/
- **API key de Google Gemini** (Generative Language API).
- **Bot y credencial de Telegram** configurados, con el `chatId` de destino.

---

## Configuración

1. **Importar el workflow**
   - En n8n: *Workflows → Import from File* → selecciona `IOC-ThreatIntel-Analyzer_sanitizado.json`.

2. **Cargar las claves** (el archivo trae placeholders; usa llaves nuevas)
   - **VirusTotal:** reemplaza `YOUR_VIRUSTOTAL_API_KEY` en el header `x-apikey` de los nodos *VirusTotal* y *VirusTotal1*. Idealmente usa una credencial *Header Auth* en lugar de texto plano.
   - **Gemini:** reemplaza `YOUR_GEMINI_API_KEY` en el query param `key` del nodo *Gemini Analizar*.
   - **Telegram:** asocia una credencial válida (se pedirá al importar) y coloca tu `chatId` en lugar de `YOUR_TELEGRAM_CHAT_ID`.

3. **Verificar el flujo**
   - Confirma que la rama IP y la rama URL lleguen correctamente a *Gemini Analizar* y luego a *Enviar Telegram*.

---

## Uso

1. Abre la URL del formulario (*On form submission*).
2. Selecciona el **Tipo de IOC** (IP o URL) e ingresa el valor (ej. `8.8.8.8` o `patito.com`).
3. Envía el formulario. El workflow espera 15 s, consulta VirusTotal, analiza con Gemini y envía el veredicto por Telegram.

---

## Notas y limitaciones

- **Claves de API expuestas:** VirusTotal, Gemini y Telegram vienen con valores reales en el JSON. Revócalas y usa credenciales de n8n.
- **Referencia rota en el prompt de Gemini:** el nodo *Gemini Analizar* referencia `$('Separar IOCs').item.json.ioc`, pero **no existe ningún nodo llamado "Separar IOCs"** en el workflow. Esa expresión fallará; debe apuntar al nodo real (p. ej. el valor del formulario o del nodo *Code in JavaScript*).
- **Schedule Trigger huérfano:** está configurado para cada 1 minuto pero no tiene conexiones de salida, por lo que no ejecuta nada. Elimínalo o conéctalo si se pretendía un modo automático.
- **Markdown vs. prompt:** *Enviar Telegram* usa `parse_mode: Markdown`, mientras que el prompt de Gemini pide "No uses Markdown". Alinear ambos para evitar formato inconsistente.
- **Espera fija de 15 s:** el nodo *Wait* es estático; para análisis de URL puede ser insuficiente si VirusTotal aún no terminó de procesar el envío.
- **Workflow inactivo:** `active: false`.

---

## Mejoras sugeridas

- **Mover todas las claves a credenciales** de n8n (Header Auth / credenciales nativas de Telegram y Gemini).
- **Corregir la referencia** `$('Separar IOCs')` en el prompt de Gemini.
- **Normalizar y validar el IOC** de entrada (defang/refang, validar formato IP vs. URL) antes de consultar.
- **Manejo de errores y rate limit** en los nodos VirusTotal (rama de error, reintentos).
- **Enriquecer el reporte** con enlace directo al informe de VirusTotal y el score de detección.
- Decidir el disparador definitivo: formulario manual **o** schedule, no ambos sin conectar.

---

## Metadatos del export

- Nodos: 9
- Fuentes de inteligencia: VirusTotal (`/ip_addresses`, `/urls`)
- Modelo LLM: `gemini-2.5-flash`
- Notificación: Telegram
- `active`: false · `executionOrder`: v1
