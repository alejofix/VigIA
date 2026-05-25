import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock
from backend.database import init_db, get_session
from backend.models import Dispositivo, Ping, Alerta


@pytest.fixture
def setup_db():
    tmp = tempfile.mktemp(suffix=".db")
    init_db(tmp)
    session = get_session(tmp)()

    d1 = Dispositivo(ip="10.0.0.1", hostname="router", tipo="router")
    d2 = Dispositivo(ip="10.0.0.2", hostname="camara-01", tipo="camara")
    session.add_all([d1, d2])
    session.commit()

    session.add(Ping(dispositivo_id=d1.id, estado="up", latencia_ms=2.5))
    session.add(Ping(dispositivo_id=d2.id, estado="down", latencia_ms=None))
    session.commit()

    session.add(Alerta(dispositivo_id=d2.id, tipo="caida", mensaje="Camara caida"))
    session.commit()

    session.close()

    yield tmp

    if os.path.exists(tmp):
        os.remove(tmp)


def test_colectar_datos(setup_db):
    from exportar.generar_reporte import _colectar_datos

    session = get_session(setup_db)()
    try:
        datos = _colectar_datos(session)
        assert datos["total_dispositivos"] == 2
        assert datos["activos"] == 1
        assert datos["caidos"] == 1
        assert len(datos["items"]) == 2
        assert len(datos["alertas"]) == 1
    finally:
        session.close()


def test_generar_html_no_db():
    from exportar.generar_reporte import generar_html

    with pytest.raises(FileNotFoundError):
        generar_html("cliente_inexistente")


def test_generar_txt_no_db():
    from exportar.generar_reporte import generar_txt

    with pytest.raises(FileNotFoundError):
        generar_txt("cliente_inexistente")


@patch("exportar.generar_reporte.os.path.exists", return_value=True)
@patch("exportar.generar_reporte.init_db")
@patch("exportar.generar_reporte.get_session")
def test_generar_html(mock_get_session, mock_init_db, mock_exists, setup_db):
    session = get_session(setup_db)()
    mock_get_session.return_value = lambda: session

    with tempfile.TemporaryDirectory() as tmp_dir:
        import exportar.generar_reporte as mod
        original_dir = mod.REPORTES_DIR
        mod.REPORTES_DIR = tmp_dir

        from exportar.generar_reporte import generar_html
        ruta = generar_html("test_cliente")

        assert ruta.endswith(".html")
        assert os.path.exists(ruta)

        with open(ruta, "r") as f:
            contenido = f.read()
        assert "10.0.0.1" in contenido
        assert "router" in contenido
        assert "Camara caida" in contenido

        mod.REPORTES_DIR = original_dir


@patch("exportar.generar_reporte.os.path.exists", return_value=True)
@patch("exportar.generar_reporte.init_db")
@patch("exportar.generar_reporte.get_session")
def test_generar_txt(mock_get_session, mock_init_db, mock_exists, setup_db):
    session = get_session(setup_db)()
    mock_get_session.return_value = lambda: session

    with tempfile.TemporaryDirectory() as tmp_dir:
        import exportar.generar_reporte as mod
        original_dir = mod.REPORTES_DIR
        mod.REPORTES_DIR = tmp_dir

        from exportar.generar_reporte import generar_txt
        ruta = generar_txt("test_cliente")

        assert ruta.endswith(".txt")
        assert os.path.exists(ruta)

        with open(ruta, "r") as f:
            contenido = f.read()
        assert "10.0.0.1" in contenido
        assert "router" in contenido
        assert "Camara caida" in contenido

        mod.REPORTES_DIR = original_dir
