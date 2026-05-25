import pytest
from backend.ia_bridge import analyze_alert, generate_report_summary


def test_analyze_alert_sin_api_key(monkeypatch):
    monkeypatch.setenv("ZEN_API_KEY", "")
    resultado = analyze_alert({
        "tipo": "caida",
        "dispositivo_ip": "192.168.1.1",
        "mensaje": "Router caido",
    })
    assert resultado == "No se pudo generar analisis automatico."


def test_generate_report_summary_sin_api_key(monkeypatch):
    monkeypatch.setenv("ZEN_API_KEY", "")
    resultado = generate_report_summary({
        "total": 15,
        "activos": 12,
        "alertas": 3,
        "periodo": "2024-01-01 a 2024-01-07",
    })
    assert resultado == "Resumen no disponible."
