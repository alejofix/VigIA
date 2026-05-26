import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock
from backend.database import init_db, get_session
from backend.models import Dispositivo, Ping


@pytest.fixture
def session_factory():
    tmp = tempfile.mktemp(suffix=".db")
    init_db(tmp)
    yield get_session(tmp)
    if os.path.exists(tmp):
        os.remove(tmp)


def test_detectar_tipo():
    from agente.nmap_scanner import detectar_tipo

    assert detectar_tipo(["rtsp", "onvif"]) == "camara"
    assert detectar_tipo(["http", "https"]) == "servidor"
    assert detectar_tipo(["snmp", "dhcp"]) == "router"
    assert detectar_tipo(["ssh"]) == "servidor"
    assert detectar_tipo([]) == "desconocido"


@patch("agente.icmp_poller.subprocess.run")
def test_hacer_ping_up(mock_run):
    from agente.icmp_poller import hacer_ping

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "rtt min/avg/max/mdev = 2.054/5.200/8.346/3.146 ms\n0% packet loss"
    mock_run.return_value = mock_proc

    resultado = hacer_ping("192.168.1.1")
    assert resultado["estado"] == "up"
    assert resultado["latencia_ms"] == 5.2
    assert resultado["perdida_pct"] == 0.0


@patch("agente.icmp_poller.subprocess.run")
def test_hacer_ping_down(mock_run):
    from agente.icmp_poller import hacer_ping

    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = "100% packet loss"
    mock_run.return_value = mock_proc

    resultado = hacer_ping("192.168.1.1")
    assert resultado["estado"] == "down"


def test_hacer_ping_exception():
    from agente.icmp_poller import hacer_ping

    resultado = hacer_ping("999.999.999.999")
    assert resultado["estado"] in ("down", "warn")
    assert resultado["perdida_pct"] == 100


def test_obtener_ultimo_estado(session_factory):
    from agente.icmp_poller import obtener_ultimo_estado

    session = session_factory()
    d = Dispositivo(ip="10.0.0.1")
    session.add(d)
    session.commit()

    session.add(Ping(dispositivo_id=d.id, estado="up"))
    session.commit()

    import time
    time.sleep(0.01)

    session.add(Ping(dispositivo_id=d.id, estado="down"))
    session.commit()

    estado = obtener_ultimo_estado(session, d.id)
    assert estado == "down"
    session.close()



