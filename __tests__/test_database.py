import pytest
from sqlalchemy.orm import Session

from backend.database import init_db, get_session
from backend.models import Dispositivo, Ping, Servicio, Alerta, Base


@pytest.fixture
def session():
    init_db()
    return get_session()()


def test_crear_dispositivo(session: Session):
    d = Dispositivo(ip="192.168.1.1", hostname="router", tipo="router")
    session.add(d)
    session.commit()

    assert d.id is not None
    guardado = session.query(Dispositivo).filter_by(ip="192.168.1.1").first()
    assert guardado is not None
    assert guardado.hostname == "router"
    assert guardado.tipo == "router"
    assert guardado.activo == 1


def test_dispositivo_unico_ip(session: Session):
    session.add(Dispositivo(ip="10.0.0.1"))
    session.commit()

    with pytest.raises(Exception):
        session.add(Dispositivo(ip="10.0.0.1"))
        session.commit()


def test_crear_ping(session: Session):
    d = Dispositivo(ip="192.168.1.10")
    session.add(d)
    session.commit()

    p = Ping(dispositivo_id=d.id, estado="up", latencia_ms=5.2, perdida_pct=0.0)
    session.add(p)
    session.commit()

    pings = session.query(Ping).filter_by(dispositivo_id=d.id).all()
    assert len(pings) == 1
    assert pings[0].estado == "up"
    assert pings[0].latencia_ms == 5.2


def test_crear_servicio(session: Session):
    d = Dispositivo(ip="10.0.0.5")
    session.add(d)
    session.commit()

    s = Servicio(dispositivo_id=d.id, puerto=80, protocolo="tcp", servicio="http", estado="abierto")
    session.add(s)
    session.commit()

    servicios = session.query(Servicio).filter_by(dispositivo_id=d.id).all()
    assert len(servicios) == 1
    assert servicios[0].servicio == "http"


def test_crear_alerta(session: Session):
    d = Dispositivo(ip="10.0.0.99")
    session.add(d)
    session.commit()

    a = Alerta(dispositivo_id=d.id, tipo="caida", mensaje="Dispositivo caido")
    session.add(a)
    session.commit()

    assert a.id is not None
    assert a.resuelta == 0


def test_relacion_dispositivo_pings(session: Session):
    d = Dispositivo(ip="192.168.1.1")
    session.add(d)
    session.commit()

    for i in range(3):
        session.add(Ping(dispositivo_id=d.id, estado="up"))
    session.commit()

    d_recargado = session.query(Dispositivo).filter_by(ip="192.168.1.1").first()
    assert len(d_recargado.pings) == 3


def test_cascade_delete(session: Session):
    d = Dispositivo(ip="192.168.1.50")
    session.add(d)
    session.commit()

    session.add(Ping(dispositivo_id=d.id, estado="up"))
    session.add(Alerta(dispositivo_id=d.id, tipo="caida", mensaje="test"))
    session.commit()

    session.delete(d)
    session.commit()

    pings = session.query(Ping).all()
    alertas = session.query(Alerta).all()
    assert len(pings) == 0
    assert len(alertas) == 0


def test_init_db_creates_tables():
    init_db()
    assert "dispositivos" in [t.name for t in Base.metadata.tables.values()]
    assert "pings" in [t.name for t in Base.metadata.tables.values()]
    assert "servicios" in [t.name for t in Base.metadata.tables.values()]
    assert "alertas" in [t.name for t in Base.metadata.tables.values()]
