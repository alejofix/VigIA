import os
import logging
import httpx
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("vigia.ia_bridge")

ZEN_API_KEY = os.getenv("ZEN_API_KEY", "")
ZEN_API_URL = os.getenv("ZEN_API_URL", "https://api.opencode.ai/v1/chat/completions")
ZEN_MODEL = os.getenv("ZEN_MODEL", "big-pickle")


def _call_zen(system_prompt: str, user_prompt: str) -> Optional[str]:
    if not ZEN_API_KEY:
        logger.warning("ZEN_API_KEY no configurada — IA deshabilitada")
        return None

    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                ZEN_API_URL,
                headers={
                    "Authorization": f"Bearer {ZEN_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": ZEN_MODEL,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "max_tokens": 500,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        logger.error(f"Error llamando a Zen: {e}")
        return None


DIAGNOSTICO_SYSTEM_PROMPT = """Eres un asistente experto en redes y CCTV.
Analiza alertas de monitoreo y genera diagnosticos en lenguaje natural
para tecnicos en Colombia. Responde en espanol, claro y conciso."""


def analyze_alert(alerta: dict, contexto_red: str = "") -> str:
    prompt = f"""Contexto de red: {contexto_red}

Alerta detectada:
- Tipo: {alerta.get('tipo', 'desconocido')}
- Dispositivo: {alerta.get('dispositivo_ip', 'N/A')}
- Mensaje: {alerta.get('mensaje', 'Sin detalle')}

Genera un analisis breve (max 3 parrafos) explicando:
1. Posible causa raiz
2. Impacto en la red
3. Accion recomendada para el tecnico"""

    resultado = _call_zen(DIAGNOSTICO_SYSTEM_PROMPT, prompt)
    return resultado or "No se pudo generar analisis automatico."


RESUMEN_SYSTEM_PROMPT = """Eres un asistente de redes que genera reportes ejecutivos.
Resume el estado de la red en espanol para un cliente no tecnico."""


def generate_report_summary(datos_red: dict) -> str:
    prompt = f"""Resumen de red:
- Total dispositivos: {datos_red.get('total', 0)}
- Activos: {datos_red.get('activos', 0)}
- Alertas pendientes: {datos_red.get('alertas', 0)}
- Periodo: {datos_red.get('periodo', 'N/A')}

Genera un parrafo ejecutivo en espanol para el cliente final,
destacando el estado general y cualquier recomendacion importante."""

    resultado = _call_zen(RESUMEN_SYSTEM_PROMPT, prompt)
    return resultado or "Resumen no disponible."
