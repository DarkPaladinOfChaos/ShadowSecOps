# SentinelAI-Ops

Workflow de **n8n** para enriquecimiento y análisis automatizado de direcciones IP. Consulta el resumen de reputación/amenazas de una IP en **Criminal IP** y envía el resultado a un modelo LLM (**Claude Sonnet 4.6**) para que genere un análisis de seguridad en lenguaje natural.

---

## Descripción general

El flujo parte de una ejecución manual, obtiene inteligencia sobre una IP desde la API de Criminal IP y pasa esa información a una cadena LLM que la interpreta y resume desde la perspectiva de seguridad.

```
When clicking 'Execute workflow'  ──►  HTTP Request (Criminal IP)  ──►  Basic LLM Chain
                                                                              ▲
                                                              Anthropic Chat Model
                                                              (Claude Sonnet 4.6)
```

---

## Nodos

| Nodo | Tipo | Función |
|------|------|---------|
| **When clicking 'Execute workflow'** | `manualTrigger` | Inicia el flujo de forma manual. |
| **HTTP Request** | `httpRequest` (v4.4) | Consulta `GET /v1/ip/summary` de Criminal IP para la IP indicada. Envía `x-api-key` y un `User-Agent`. |
| **Basic LLM Chain** | `chainLlm` (langchain) | Recibe la respuesta de Criminal IP y pide al modelo analizar la información de seguridad de la IP. |
| **Anthropic Chat Model** | `lmChatAnthropic` | Modelo `claude-sonnet-4-6` que alimenta la cadena LLM. Requiere credencial de Anthropic. |
| **When chat message received** | `chatTrigger` (langchain) | Disparador por chat (webhook). *Actualmente sin conexiones de salida — ver Notas.* |

---

## Requisitos previos

- Instancia de **n8n** (con nodos de LangChain habilitados).
- **API key de Criminal IP** — https://www.criminalip.io/
- **Credencial de Anthropic** configurada en n8n (para Claude Sonnet 4.6).

---

## Configuración

1. **Importar el workflow**
   - En n8n: *Workflows → Import from File* y selecciona el `.json`.

2. **API key de Criminal IP**
   - En el nodo **HTTP Request**, reemplaza el valor placeholder del header `x-api-key`:
     ```
     x-api-key: YOUR_API_KEY_HERE   ←  coloca aquí tu clave real
     ```

3. **Credencial de Anthropic**
   - En el nodo **Anthropic Chat Model**, asocia tu credencial de Anthropic.

4. **IP a consultar**
   - Por defecto la URL tiene la IP fija:
     ```
     https://api.criminalip.io/v1/ip/summary?ip=18.232.128.198
     ```
   - Cámbiala por la IP que quieras analizar, o parametrízala (ver Mejoras sugeridas).

---

## Uso

1. Abre el workflow en n8n.
2. Verifica que la API key y la credencial de Anthropic estén configuradas.
3. Haz clic en **Execute workflow**.
4. Revisa la salida del nodo **Basic LLM Chain**: contiene el análisis de seguridad de la IP generado por el modelo.

---

## Notas y limitaciones

- **API key expuesta como placeholder:** el export incluye `YOUR_API_KEY_HERE`. Nunca subas el JSON con una clave real a un repositorio; usa credenciales de n8n en lugar de headers en texto plano.
- **IP hardcodeada:** la dirección `18.232.128.198` está fija en la URL. Cada consultada requiere editar el nodo manualmente.
- **Trigger de chat huérfano:** el nodo *When chat message received* no tiene conexiones de salida, por lo que no hace nada en la ejecución actual.
- **Salida sin destino:** *Basic LLM Chain* no está conectado a ningún nodo posterior; el resultado queda solo dentro del nodo (no se envía a Slack, correo, ticket, etc.).

---

## Mejoras sugeridas

- **Parametrizar la IP:** usar el *Chat Trigger* (ya presente) o un nodo *Set*/formulario para pasar la IP dinámicamente a la URL, p. ej. `?ip={{ $json.ip }}`.
- **Mover la API key a credenciales** de n8n (Header Auth) en vez de un header manual.
- **Conectar la salida del análisis** a un destino: Slack, correo, o creación de ticket (Jira) para integrarlo al flujo del CSOC.
- **Manejo de errores:** rama de error en el HTTP Request para IPs no encontradas o límites de rate de la API.

---

## Metadatos del export

- Nodos: 5
- Modelo LLM: `claude-sonnet-4-6` (Claude Sonnet 4.6)
- Fuente de inteligencia: Criminal IP (`/v1/ip/summary`)
