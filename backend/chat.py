import logging
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.models import Dispositivo, Ping, Alerta, Servicio
from backend.ia_bridge import _call_zen

logger = logging.getLogger("vigia.chat")

CHAT_SYSTEM_PROMPT = """Eres un asistente experto en redes y CCTV integrado en VigIA,
una herramienta de monitoreo de redes local. Los tecnicos te hacen preguntas
en lenguaje natural sobre el estado de la red.

Tienes acceso a datos estructurados de la red. Responde en espanol,
claro, conciso y util para un tecnico en Colombia.

Si la pregunta requiere datos que no estan disponibles, indicalo.
Si no sabes la respuesta, dilo honestamente."""


def _obtener_contexto_red(session: Session) -> str:
    total = session.query(Dispositivo).count()
    activos = session.query(Dispositivo).filter_by(activo=1).count()

    max_ping_id = (
        session.query(Ping.dispositivo_id, func.max(Ping.id).label("max_id"))
        .group_by(Ping.dispositivo_id)
        .subquery()
    )
    ultimos_pings = (
        session.query(
            Dispositivo.ip,
            Dispositivo.hostname,
            Dispositivo.tipo,
            Ping.estado,
            Ping.latencia_ms,
            Ping.timestamp,
        )
        .join(max_ping_id, Ping.id == max_ping_id.c.max_id)
        .join(Dispositivo, Dispositivo.id == Ping.dispositivo_id)
        .limit(100)
        .all()
    )

    up_count = sum(1 for p in ultimos_pings if p.estado == "up")
    down_count = sum(1 for p in ultimos_pings if p.estado in ("down", "timeout"))

    alertas_pend = session.query(Alerta).filter_by(resuelta=0).count()
    alertas_recientes = (
        session.query(Alerta)
        .filter(Alerta.timestamp >= datetime.now() - timedelta(hours=24))
        .count()
    )

    tipos = (
        session.query(Dispositivo.tipo, func.count(Dispositivo.id))
        .group_by(Dispositivo.tipo)
        .all()
    )
    tipos_str = ", ".join(f"{t}: {c}" for t, c in tipos if t)

    latencia_alta = sum(
        1 for p in ultimos_pings
        if p.estado == "up" and p.latencia_ms and p.latencia_ms > 100
    )

    return f"""Resumen actual de la red ({datetime.now().strftime('%Y-%m-%d %H:%M')}):
- Total dispositivos: {total}
- Dispositivos activos en BD: {activos}
- Estado actual (ultimo ping): {up_count} UP, {down_count} DOWN/Timeout
- Alertas pendientes: {alertas_pend}
- Alertas ultimas 24h: {alertas_recientes}
- Dispositivos con latencia alta (>100ms): {latencia_alta}
- Tipos: {tipos_str or 'sin clasificar'}"""


def preguntar(pregunta: str, session: Session) -> str:
    contexto = _obtener_contexto_red(session)

    ultimas_alertas = (
        session.query(Alerta)
        .filter_by(resuelta=0)
        .order_by(Alerta.timestamp.desc())
        .limit(10)
        .all()
    )
    alertas_str = "\n".join(
        f"- [{a.timestamp.strftime('%H:%M')}] {a.tipo}: {a.mensaje or '—'}"
        for a in ultimas_alertas
    )

    user_prompt = f"""Contexto de la red:
{contexto}

Alertas pendientes recientes:
{alertas_str or 'No hay alertas pendientes.'}

Pregunta del tecnico: {pregunta}

Responde de manera clara y util, basandote en los datos proporcionados."""

    resultado = _call_zen(CHAT_SYSTEM_PROMPT, user_prompt)
    return resultado or "No pude procesar tu pregunta. Si tienes configurada la clave de IA, verifica que la API esté accesible."
