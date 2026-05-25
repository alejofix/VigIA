import os
import pytest
from unittest.mock import patch, MagicMock


def _clean_env():
    for k in ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS",
              "NOTIFICAR_EMAIL", "WEBHOOK_URL"]:
        os.environ.pop(k, None)


def test_notificar_sin_config():
    _clean_env()
    from backend.notificaciones import notificar

    resultado = notificar("Test", "Cuerpo test")
    assert resultado == {}


@patch("backend.notificaciones.smtplib.SMTP")
def test_notificar_email_fallo(mock_smtp):
    _clean_env()
    os.environ["SMTP_HOST"] = "smtp.test.com"
    os.environ["SMTP_USER"] = "user"
    os.environ["SMTP_PASS"] = "pass"
    from backend.notificaciones import notificar_email

    mock_smtp.side_effect = Exception("Connection refused")

    resultado = notificar_email("Asunto", "Cuerpo", "test@test.com")
    assert resultado is False


@patch("backend.notificaciones.httpx.Client")
def test_notificar_webhook_fallo(mock_client):
    _clean_env()
    os.environ["WEBHOOK_URL"] = "https://hooks.test.com/alert"
    from backend.notificaciones import notificar_webhook

    mock_client.return_value.__enter__.return_value.post.side_effect = Exception("Timeout")

    resultado = notificar_webhook("Asunto", "Cuerpo")
    assert resultado is False


@patch("backend.notificaciones.httpx.Client")
def test_notificar_webhook_ok(mock_client_class):
    _clean_env()
    os.environ["WEBHOOK_URL"] = "https://hooks.test.com/alert"
    from backend.notificaciones import notificar_webhook

    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_client = MagicMock()
    mock_client.post.return_value = mock_response
    mock_client_class.return_value.__enter__.return_value = mock_client

    resultado = notificar_webhook("Asunto", "Cuerpo")
    assert resultado is True
