import pytest
from backend.chat import _obtener_contexto_red


@pytest.fixture
def db_con_datos():
    import tempfile, os
    from backend.database import init_db, get_session
    from backend.models import Dispositivo, Ping, Alerta

    tmp = tempfile.mktemp(suffix=".db")
    init_db(tmp)
    session = get_session(tmp)()

    d1 = Dispositivo(ip="10.0.0.1", hostname="gw", tipo="router")
    d2 = Dispositivo(ip="10.0.0.2", hostname="cam-01", tipo="camara")
    session.add_all([d1, d2])
    session.commit()

    session.add(Ping(dispositivo_id=d1.id, estado="up", latencia_ms=2.0))
    session.add(Ping(dispositivo_id=d2.id, estado="down", latencia_ms=None))
    session.commit()

    session.add(Alerta(dispositivo_id=d2.id, tipo="caida", mensaje="Camara caida"))
    session.commit()

    yield session
    session.close()
    if os.path.exists(tmp):
        os.remove(tmp)


def test_obtener_contexto_red(db_con_datos):
    contexto = _obtener_contexto_red(db_con_datos)
    assert "Dispositivos" in contexto
    assert "10.0.0.1" in contexto or "Total" in contexto


def test_preguntar_sin_api_key(db_con_datos, monkeypatch):
    monkeypatch.setenv("ZEN_API_KEY", "")
    from backend.chat import preguntar
    resultado = preguntar("cuantos dispositivos hay?", db_con_datos)
    assert "No pude procesar" in resultado


def test_preguntar_formato(db_con_datos, monkeypatch):
    monkeypatch.setenv("ZEN_API_KEY", "")
    from backend.chat import preguntar
    resultado = preguntar("hay dispositivos caidos?", db_con_datos)
    assert resultado is not None
    assert len(resultado) > 0
