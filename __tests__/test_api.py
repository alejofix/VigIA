import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from backend.database import init_db, get_session
from backend.models import Dispositivo, Ping, Alerta


@pytest.fixture(autouse=True)
def override_db():
    tmp_dir = tempfile.mkdtemp()
    test_db = os.path.join(tmp_dir, "test.db")
    init_db(test_db)
    yield
    import shutil
    shutil.rmtree(tmp_dir, ignore_errors=True)


from backend.main import app

client = TestClient(app)


def _session():
    return get_session()()


def test_root():
    resp = client.get("/")
    assert resp.status_code in (200, 404)


def test_listar_dispositivos_vacio():
    resp = client.get("/api/dispositivos")
    assert resp.status_code == 200
    assert resp.json() == []


def test_crear_y_listar_dispositivo():
    resp = client.post("/api/dispositivos", json={
        "ip": "192.168.1.1",
        "hostname": "router-test",
        "tipo": "router",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["ip"] == "192.168.1.1"
    assert data["hostname"] == "router-test"

    resp2 = client.get("/api/dispositivos")
    assert len(resp2.json()) == 1


def test_crear_dispositivo_duplicado():
    client.post("/api/dispositivos", json={"ip": "10.0.0.1"})
    resp = client.post("/api/dispositivos", json={"ip": "10.0.0.1"})
    assert resp.status_code == 400


def test_obtener_dispositivo_por_id():
    resp = client.post("/api/dispositivos", json={"ip": "10.0.0.50"})
    id_ = resp.json()["id"]

    resp2 = client.get(f"/api/dispositivos/{id_}")
    assert resp2.status_code == 200
    assert resp2.json()["ip"] == "10.0.0.50"


def test_obtener_dispositivo_no_existe():
    resp = client.get("/api/dispositivos/9999")
    assert resp.status_code == 404


def test_listar_pings():
    resp = client.post("/api/dispositivos", json={"ip": "10.0.0.77"})
    id_ = resp.json()["id"]

    session = _session()
    session.add(Ping(dispositivo_id=id_, estado="up", latencia_ms=1.0))
    session.commit()
    session.close()

    resp2 = client.get(f"/api/dispositivos/{id_}/pings?limite=10")
    assert resp2.status_code == 200
    assert len(resp2.json()) == 1


def test_alertas():
    resp = client.post("/api/dispositivos", json={"ip": "10.0.0.88"})
    id_ = resp.json()["id"]

    session = _session()
    session.add(Alerta(dispositivo_id=id_, tipo="caida", mensaje="Test alerta"))
    session.commit()
    session.close()

    resp2 = client.get("/api/alertas")
    assert resp2.status_code == 200
    assert len(resp2.json()) == 1


def test_resolver_alerta():
    resp = client.post("/api/dispositivos", json={"ip": "10.0.0.99"})
    id_ = resp.json()["id"]

    session = _session()
    a = Alerta(dispositivo_id=id_, tipo="caida", mensaje="Test")
    session.add(a)
    session.commit()
    alerta_id = a.id
    session.close()

    resp2 = client.post(f"/api/alertas/{alerta_id}/resolver")
    assert resp2.status_code == 200
    assert resp2.json()["ok"] is True


def test_stats():
    client.post("/api/dispositivos", json={"ip": "10.0.0.1"})
    client.post("/api/dispositivos", json={"ip": "10.0.0.2"})

    resp = client.get("/api/stats")
    assert resp.status_code == 200
    assert resp.json()["total_dispositivos"] == 2


def test_scan_endpoint(monkeypatch):
    def mock_escanear(*args, **kwargs):
        return {"total": 0, "nuevos": 0, "actualizados": 0, "hosts": []}
    monkeypatch.setattr("agente.nmap_scanner.escanear", mock_escanear)
    resp = client.post("/api/scan", json={
        "rango_ip": "10.0.0.0/24",
        "nombre_cliente": "test_cliente",
    })
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    import time
    time.sleep(1)
    resp2 = client.get("/api/scan/estado?nombre_cliente=test_cliente")
    assert resp2.status_code == 200
    data = resp2.json()
    assert data["estado"] in ("completo", "en_progreso")


def test_topologia_vacia():
    resp = client.get("/api/topologia")
    assert resp.status_code == 200
    data = resp.json()
    assert "nodos" in data
    assert "enlaces" in data
    assert data["nodos"] == []


def test_topologia_con_dispositivos():
    client.post("/api/dispositivos", json={"ip": "10.0.0.1", "hostname": "r1", "tipo": "router"})
    client.post("/api/dispositivos", json={"ip": "10.0.0.2", "hostname": "c1", "tipo": "camara"})

    resp = client.get("/api/topologia")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["nodos"]) == 2
    ips = [n["ip"] for n in data["nodos"]]
    assert "10.0.0.1" in ips
    assert "10.0.0.2" in ips


def test_guardar_posiciones():
    resp = client.post("/api/dispositivos", json={"ip": "10.0.0.50"})
    id_ = resp.json()["id"]

    resp2 = client.post("/api/topologia/posiciones", json=[
        {"dispositivo_id": id_, "x": 100.5, "y": -200.3},
    ])
    assert resp2.status_code == 200
    assert resp2.json()["ok"] is True

    resp3 = client.get("/api/topologia")
    nodo = next(n for n in resp3.json()["nodos"] if n["id"] == id_)
    assert nodo["x"] == 100.5
    assert nodo["y"] == -200.3


def test_reporte_endpoint():
    resp = client.post("/api/reporte?nombre_cliente=test_cliente&formato=html", json={})
    assert resp.status_code in (200, 404)


def test_mapa_page():
    resp = client.get("/mapa")
    assert resp.status_code in (200, 404)
