import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from backend.database import init_db, get_session
from backend.models import Dispositivo


@pytest.fixture(autouse=True)
def tmp_db():
    tmp_dir = tempfile.mkdtemp()
    import backend.database as db_mod
    db_mod.DB_PATH = tmp_dir + "/"
    from backend.main import DB_ACTIVA
    import backend.main as main_mod
    main_mod.DB_ACTIVA = os.path.join(tmp_dir, "cliente_a.db")
    init_db(main_mod.DB_ACTIVA)
    yield
    import shutil
    shutil.rmtree(tmp_dir, ignore_errors=True)


from backend.main import app

client = TestClient(app)


def test_switch_cliente_nuevo():
    resp = client.post("/api/clientes/switch", json={"nombre_cliente": "cliente_b"})
    assert resp.status_code == 200
    assert resp.json()["cliente"] == "cliente_b"


def test_switch_y_crear_dispositivo():
    client.post("/api/clientes/switch", json={"nombre_cliente": "cliente_x"})
    resp = client.post("/api/dispositivos", json={"ip": "10.0.0.1"})
    assert resp.status_code == 201

    resp2 = client.get("/api/dispositivos")
    data = resp2.json()
    assert len(data) == 1
    assert data[0]["ip"] == "10.0.0.1"


def test_clientes_aislados():
    client.post("/api/clientes/switch", json={"nombre_cliente": "cliente_1"})
    client.post("/api/dispositivos", json={"ip": "10.0.0.1"})

    client.post("/api/clientes/switch", json={"nombre_cliente": "cliente_2"})
    client.post("/api/dispositivos", json={"ip": "10.0.0.2"})

    client.post("/api/clientes/switch", json={"nombre_cliente": "cliente_1"})
    resp = client.get("/api/dispositivos")
    assert len(resp.json()) == 1
    assert resp.json()[0]["ip"] == "10.0.0.1"
