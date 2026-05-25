import os
import logging
import smtplib
import httpx
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("vigia.notificaciones")


def _cfg(key: str, default: str = "") -> str:
    return os.getenv(key, default)


def notificar_email(asunto: str, cuerpo: str, destino: Optional[str] = None) -> bool:
    destino = destino or _cfg("NOTIFICAR_EMAIL")
    smtp_host = _cfg("SMTP_HOST")
    if not destino or not smtp_host:
        logger.debug("Email no configurado — omitiendo")
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = _cfg("SMTP_FROM", "vigia@mardan.co")
        msg["To"] = destino
        msg["Subject"] = f"[VigIA] {asunto}"
        msg.attach(MIMEText(cuerpo, "plain", "utf-8"))

        with smtplib.SMTP(smtp_host, int(_cfg("SMTP_PORT", "587"))) as server:
            server.starttls()
            server.login(_cfg("SMTP_USER"), _cfg("SMTP_PASS"))
            server.send_message(msg)

        logger.info(f"Email enviado a {destino}: {asunto}")
        return True
    except Exception as e:
        logger.error(f"Error enviando email: {e}")
        return False


def notificar_webhook(asunto: str, cuerpo: str) -> bool:
    webhook_url = _cfg("WEBHOOK_URL")
    if not webhook_url:
        logger.debug("Webhook no configurado — omitiendo")
        return False

    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(
                webhook_url,
                json={
                    "evento": "alerta_vigia",
                    "asunto": asunto,
                    "cuerpo": cuerpo,
                    "timestamp": datetime.now().isoformat(),
                },
            )
            resp.raise_for_status()
        logger.info(f"Webhook enviado a {webhook_url}: {asunto}")
        return True
    except Exception as e:
        logger.error(f"Error enviando webhook: {e}")
        return False


def notificar(asunto: str, cuerpo: str) -> dict:
    resultados = {}
    if _cfg("SMTP_HOST") and _cfg("NOTIFICAR_EMAIL"):
        resultados["email"] = notificar_email(asunto, cuerpo)
    if _cfg("WEBHOOK_URL"):
        resultados["webhook"] = notificar_webhook(asunto, cuerpo)
    if not resultados:
        logger.info(f"Notificacion omitida (sin canales configurados): {asunto}")
    return resultados
