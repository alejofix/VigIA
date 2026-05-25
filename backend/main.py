import os
import logging
import random
import math
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import asyncio

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from backend.database import init_db, get_session, get_db_path
from backend.models import Base, Dispositivo, Ping, Alerta, Servicio, PosicionTopologia, Credencial
from backend.schemas import (
    DispositivoCreate, DispositivoOut, PingOut, ServicioOut, AlertaOut,
    ScanRequest, PosicionUpdate, StatsOut, CredencialCreate, CredencialOut,
)
from concurrent.futures import ThreadPoolExecutor
import agente.nmap_scanner as nmap_scanner
from agente.icmp_poller import ciclo_polling
from exportar.generar_reporte import generar as generar_reporte
from backend.chat import preguntar
from backend.notificaciones import notificar
from backend.schemas import ChatRequest, ClienteSwitch, NotificacionRequest

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("vigia.api")

DB_ACTIVA = "data/red_cliente.db"
_executor = ThreadPoolExecutor(max_workers=2)
_scan_tasks = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs("data", exist_ok=True)
    init_db(DB_ACTIVA)
    yield


app = FastAPI(title="VigIA API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

if os.path.exists("frontend"):
    app.mount("/static", StaticFiles(directory="frontend"), name="static")


def _get_session():
    return get_session(DB_ACTIVA)()


@app.get("/", response_class=HTMLResponse)
async def root():
    index_path = "frontend/index.html"
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h1>VigIA API</h1><p>Backend funcionando. Esperando frontend...</p>")


@app.get("/mapa", response_class=HTMLResponse)
async def mapa():
    mapa_path = "frontend/mapa.html"
    if os.path.exists(mapa_path):
        with open(mapa_path, "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h1>Mapa no disponible</h1>")


@app.get("/api/dispositivos", response_model=list[DispositivoOut])
async def listar_dispositivos(activo: int | None = None, tipo: str | None = None, segmento: str | None = None):
    session = _get_session()
    try:
        q = session.query(Dispositivo)
        if activo is not None:
            q = q.filter_by(activo=activo)
        if tipo:
            q = q.filter_by(tipo=tipo)
        if segmento:
            q = q.filter_by(segmento=segmento)
        return q.all()
    finally:
        session.close()


@app.get("/api/segmentos")
async def listar_segmentos():
    session = _get_session()
    try:
        resultados = session.query(Dispositivo.segmento).distinct().all()
        segmentos = sorted(set(r[0] for r in resultados if r[0]))
        return {"segmentos": segmentos}
    finally:
        session.close()


@app.get("/api/dispositivos/{dispositivo_id}", response_model=DispositivoOut)
async def obtener_dispositivo(dispositivo_id: int):
    session = _get_session()
    try:
        d = session.get(Dispositivo, dispositivo_id)
        if not d:
            raise HTTPException(404, "Dispositivo no encontrado")
        return d
    finally:
        session.close()


@app.post("/api/dispositivos", response_model=DispositivoOut, status_code=201)
async def crear_dispositivo(data: DispositivoCreate):
    session = _get_session()
    try:
        existente = session.query(Dispositivo).filter_by(ip=data.ip).first()
        if existente:
            raise HTTPException(400, f"El IP {data.ip} ya existe")
        d = Dispositivo(**data.model_dump())
        d.ultima_vez = datetime.now()
        session.add(d)
        session.commit()
        session.refresh(d)
        return d
    finally:
        session.close()


@app.delete("/api/dispositivos/{dispositivo_id}")
async def eliminar_dispositivo(dispositivo_id: int):
    session = _get_session()
    try:
        d = session.get(Dispositivo, dispositivo_id)
        if not d:
            raise HTTPException(404, "Dispositivo no encontrado")
        session.query(PosicionTopologia).filter_by(dispositivo_id=dispositivo_id).delete()
        session.query(Credencial).filter_by(dispositivo_id=dispositivo_id).delete()
        session.delete(d)
        session.commit()
        return {"ok": True, "mensaje": f"Dispositivo {d.ip} eliminado"}
    finally:
        session.close()


@app.get("/api/dispositivos/{dispositivo_id}/pings", response_model=list[PingOut])
async def listar_pings(dispositivo_id: int, limite: int = Query(50, le=500)):
    session = _get_session()
    try:
        return (
            session.query(Ping)
            .filter_by(dispositivo_id=dispositivo_id)
            .order_by(Ping.timestamp.desc())
            .limit(limite)
            .all()
        )
    finally:
        session.close()


@app.get("/api/dispositivos/{dispositivo_id}/servicios", response_model=list[ServicioOut])
async def listar_servicios(dispositivo_id: int):
    session = _get_session()
    try:
        return (
            session.query(Servicio)
            .filter_by(dispositivo_id=dispositivo_id)
            .all()
        )
    finally:
        session.close()


@app.get("/api/dispositivos/{dispositivo_id}/credenciales")
async def obtener_credenciales(dispositivo_id: int):
    session = _get_session()
    try:
        disp = session.get(Dispositivo, dispositivo_id)
        cred = session.query(Credencial).filter_by(dispositivo_id=dispositivo_id).first()
        if cred:
            return {
                "alias": cred.alias or "",
                "admin_pass": cred.admin_pass or "",
                "usuario": cred.usuario or "",
                "app_pass": cred.app_pass or "",
                "observacion": cred.observacion or "",
                "serial": disp.serial or "",
            }
        return {
            "alias": "",
            "admin_pass": "",
            "usuario": "",
            "app_pass": "",
            "observacion": "",
            "serial": disp.serial or "",
        }
    finally:
        session.close()


@app.post("/api/dispositivos/{dispositivo_id}/credenciales")
async def guardar_credenciales(dispositivo_id: int, data: CredencialCreate):
    session = _get_session()
    try:
        disp = session.get(Dispositivo, dispositivo_id)
        if data.serial and disp:
            disp.serial = data.serial
        cred = session.query(Credencial).filter_by(dispositivo_id=dispositivo_id).first()
        if cred:
            cred.alias = data.alias
            cred.admin_pass = data.admin_pass
            cred.usuario = data.usuario
            cred.app_pass = data.app_pass
            cred.observacion = data.observacion
        else:
            cred = Credencial(
                dispositivo_id=dispositivo_id,
                alias=data.alias,
                admin_pass=data.admin_pass,
                usuario=data.usuario,
                app_pass=data.app_pass,
                observacion=data.observacion,
            )
            session.add(cred)
        session.commit()
        return {"ok": True}
    except Exception as e:
        session.rollback()
        raise HTTPException(500, f"Error guardando credenciales: {str(e)}")
    finally:
        session.close()


@app.get("/api/alertas", response_model=list[AlertaOut])
async def listar_alertas(resuelta: int | None = None, tipo: str | None = None):
    session = _get_session()
    try:
        q = session.query(Alerta)
        if resuelta is not None:
            q = q.filter_by(resuelta=resuelta)
        if tipo:
            q = q.filter_by(tipo=tipo)
        return q.order_by(Alerta.timestamp.desc()).limit(200).all()
    finally:
        session.close()


@app.post("/api/alertas/{alerta_id}/resolver")
async def resolver_alerta(alerta_id: int):
    session = _get_session()
    try:
        a = session.get(Alerta, alerta_id)
        if not a:
            raise HTTPException(404, "Alerta no encontrada")
        a.resuelta = 1
        session.commit()
        return {"ok": True}
    finally:
        session.close()


@app.delete("/api/alertas")
async def borrar_alertas():
    session = _get_session()
    try:
        session.query(Alerta).delete()
        session.commit()
        return {"ok": True, "mensaje": "Alertas eliminadas"}
    finally:
        session.close()


@app.get("/api/stats", response_model=StatsOut)
async def stats():
    session = _get_session()
    try:
        total = session.query(Dispositivo).count()
        activos = session.query(Dispositivo).filter_by(activo=1).count()
        alertas_pend = session.query(Alerta).filter_by(resuelta=0).count()
        warn = session.query(Alerta).filter(Alerta.tipo == "latencia_alta", Alerta.resuelta == 0).count()
        degradados = session.query(Alerta).filter(Alerta.tipo == "degradado", Alerta.resuelta == 0).count()
        caidos = session.query(Alerta).filter(Alerta.tipo == "caida", Alerta.resuelta == 0).count()
        return StatsOut(
            total_dispositivos=total,
            activos=activos,
            warn=warn,
            degradados=degradados,
            caidos=caidos,
            alertas_pendientes=alertas_pend,
        )
    finally:
        session.close()


@app.post("/api/scan")
async def scan_red(data: ScanRequest):
    global DB_ACTIVA
    # Validar que el rango no sea demasiado grande
    for r in data.rango_ip.split(","):
        r = r.strip()
        if "/" in r:
            mascara = int(r.split("/")[1])
            if mascara < 16:
                raise HTTPException(400, f"Rango {r} demasiado grande (máscara /16 o mayor). Escanea subredes más pequeñas.")

    DB_ACTIVA = get_db_path(data.nombre_cliente)
    os.makedirs("data", exist_ok=True)
    init_db(DB_ACTIVA)

    cliente = data.nombre_cliente
    tarea_existente = _scan_tasks.get(cliente)
    if tarea_existente and not tarea_existente.done():
        raise HTTPException(409, f"Ya hay un escaneo en progreso para '{cliente}'. Espera a que termine o cancela con /api/scan/cancelar")

    loop = asyncio.get_event_loop()
    future = loop.run_in_executor(_executor, nmap_scanner.escanear, data.rango_ip, data.nombre_cliente)
    _scan_tasks[cliente] = future

    return {"ok": True, "mensaje": f"Escaneo iniciado para {data.rango_ip}", "cliente": cliente}


@app.get("/api/scan/estado")
async def scan_estado(nombre_cliente: str = "red_cliente"):
    tarea = _scan_tasks.get(nombre_cliente)
    if not tarea:
        return {"estado": "inactivo"}
    if tarea.done():
        exc = tarea.exception()
        if exc:
            del _scan_tasks[nombre_cliente]
            return {"estado": "error", "error": str(exc)}
        resultado = tarea.result()
        del _scan_tasks[nombre_cliente]
        return {"estado": "completo", "resultado": resultado}
    return {"estado": "en_progreso"}


@app.post("/api/seed")
async def seed_data(nombre_cliente: str = "demo"):
    global DB_ACTIVA
    DB_ACTIVA = get_db_path(nombre_cliente)
    os.makedirs("data", exist_ok=True)
    init_db(DB_ACTIVA)
    session = get_session(DB_ACTIVA)()

    try:
        session.query(PosicionTopologia).delete()
        session.query(Alerta).delete()
        session.query(Ping).delete()
        session.query(Dispositivo).delete()

        dispositivos = [
            {"ip": "192.168.1.1", "hostname": "router-mikrotik", "tipo": "router", "mac": "00:1B:44:11:3A:B7", "fabricante": "MikroTik", "segmento": "192.168.1.0/24"},
            {"ip": "192.168.1.10", "hostname": "switch-principal", "tipo": "switch", "mac": "00:1C:42:AB:CD:01", "fabricante": "Cisco", "segmento": "192.168.1.0/24"},
            {"ip": "192.168.1.20", "hostname": "nvr-dahua", "tipo": "servidor", "mac": "04:12:34:56:78:90", "segmento": "192.168.1.0/24"},
            {"ip": "192.168.2.101", "hostname": "camara-entrada", "tipo": "camara", "mac": "AC:CC:12:34:56:01", "fabricante": "Dahua", "segmento": "192.168.2.0/24"},
            {"ip": "192.168.2.102", "hostname": "camara-patio", "tipo": "camara", "mac": "AC:CC:12:34:56:02", "fabricante": "Dahua", "segmento": "192.168.2.0/24"},
            {"ip": "192.168.2.103", "hostname": "camara-bodega", "tipo": "camara", "mac": "AC:CC:12:34:56:03", "fabricante": "Hikvision", "segmento": "192.168.2.0/24"},
            {"ip": "192.168.2.104", "hostname": "camara-oficina", "tipo": "camara", "mac": "AC:CC:12:34:56:04", "fabricante": "Hikvision", "segmento": "192.168.2.0/24"},
            {"ip": "192.168.1.30", "hostname": "pc-admin", "tipo": "pc", "mac": "08:00:27:AB:CD:EF", "fabricante": "Dell", "segmento": "192.168.1.0/24"},
            {"ip": "192.168.1.100", "hostname": "nas-synology", "tipo": "servidor", "mac": "00:11:32:AB:CD:EF", "fabricante": "Synology", "segmento": "192.168.1.0/24"},
            {"ip": "192.168.1.50", "hostname": "access-point", "tipo": "router", "mac": "E0:1F:88:12:34:56", "fabricante": "Ubiquiti", "segmento": "192.168.1.0/24"},
        ]

        ahora = datetime.now()
        for i, d in enumerate(dispositivos):
            disp = Dispositivo(**d, primera_vez=ahora - timedelta(days=random.randint(30, 180)))
            session.add(disp)
            session.flush()

            for h in range(24):
                estado = "up"
                latencia = random.uniform(1, 30)
                if d["tipo"] == "camara" and h in range(3, 6):
                    estado = "down"
                    latencia = None
                elif d["ip"] == "192.168.2.103" and h > 20:
                    estado = "down"
                    latencia = None
                elif random.random() < 0.05:
                    estado = "down"
                    latencia = None

                session.add(Ping(
                    dispositivo_id=disp.id,
                    timestamp=ahora - timedelta(hours=23 - h),
                    estado=estado,
                    latencia_ms=latencia,
                    perdida_pct=0 if estado == "up" else 100,
                ))

            if d["ip"] in ("192.168.2.103", "192.168.2.104"):
                session.add(Alerta(
                    dispositivo_id=disp.id,
                    tipo="caida",
                    mensaje=f"{d['hostname']} ha presentado caidas intermitentes en las ultimas 24h",
                    timestamp=ahora - timedelta(minutes=random.randint(5, 120)),
                ))

            if d["tipo"] == "camara":
                session.add(Servicio(
                    dispositivo_id=disp.id, puerto=80, protocolo="tcp",
                    servicio="http", version="", estado="abierto",
                ))
                session.add(Servicio(
                    dispositivo_id=disp.id, puerto=554, protocolo="tcp",
                    servicio="rtsp", version="", estado="abierto",
                ))
            if d["tipo"] == "router":
                session.add(Servicio(
                    dispositivo_id=disp.id, puerto=22, protocolo="tcp",
                    servicio="ssh", version="OpenSSH", estado="abierto",
                ))

            session.add(PosicionTopologia(
                dispositivo_id=disp.id,
                x=random.uniform(-400, 400),
                y=random.uniform(-300, 300),
            ))

        session.commit()
        return {"ok": True, "total": len(dispositivos), "mensaje": f"Datos de prueba creados: {len(dispositivos)} dispositivos con historial y alertas"}
    except Exception as e:
        session.rollback()
        logger.error(f"Error creando seed: {e}")
        raise HTTPException(500, f"Error: {str(e)}")
    finally:
        session.close()


@app.post("/api/scan/cancelar")
async def scan_cancelar(nombre_cliente: str = "red_cliente"):
    tarea = _scan_tasks.get(nombre_cliente)
    if tarea and not tarea.done():
        tarea.cancel()
    _scan_tasks.pop(nombre_cliente, None)
    return {"ok": True, "mensaje": f"Escaneo cancelado para {nombre_cliente}"}


@app.api_route("/api/poll", methods=["GET", "POST"])
async def poll_manual(nombre_cliente: str = "red_cliente"):
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(_executor, ciclo_polling, nombre_cliente)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(500, f"Error en polling: {str(e)}")


@app.get("/api/clientes")
async def listar_clientes():
    import glob
    archivos = glob.glob(f"data/*.db")
    clientes = [os.path.splitext(os.path.basename(a))[0] for a in archivos]
    return {"clientes": clientes, "activo": os.path.splitext(os.path.basename(DB_ACTIVA))[0]}


@app.post("/api/clientes/switch")
async def cambiar_cliente(data: ClienteSwitch):
    global DB_ACTIVA
    nueva_ruta = get_db_path(data.nombre_cliente)
    if not os.path.exists(nueva_ruta):
        os.makedirs("data", exist_ok=True)
        init_db(nueva_ruta)
    DB_ACTIVA = nueva_ruta
    init_db(DB_ACTIVA)
    return {"ok": True, "cliente": data.nombre_cliente, "db": DB_ACTIVA}


@app.post("/api/chat")
async def chat_endpoint(data: ChatRequest):
    global DB_ACTIVA
    db_path = get_db_path(data.nombre_cliente)
    if not os.path.exists(db_path):
        raise HTTPException(404, "Base de datos del cliente no encontrada")
    init_db(db_path)
    session = get_session(db_path)()
    try:
        respuesta = preguntar(data.pregunta, session)
        return {"respuesta": respuesta}
    except Exception as e:
        logger.error(f"Error en chat: {e}")
        raise HTTPException(500, f"Error procesando pregunta: {str(e)}")
    finally:
        session.close()


@app.post("/api/notificar")
async def notificar_endpoint(data: NotificacionRequest):
    resultados = notificar(data.asunto, data.cuerpo)
    return {"ok": True, "resultados": resultados}


@app.post("/api/reporte")
async def generar_reporte_endpoint(nombre_cliente: str = "red_cliente", formato: str = "html"):
    try:
        ruta = generar_reporte(nombre_cliente, formato)
        return {"ok": True, "ruta": ruta, "formato": formato}
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(500, f"Error generando reporte: {str(e)}")


@app.get("/api/topologia")
async def obtener_topologia():
    session = _get_session()
    try:
        dispositivos = session.query(Dispositivo).filter_by(activo=1).all()
        posiciones = {
            p.dispositivo_id: (p.x, p.y)
            for p in session.query(PosicionTopologia).all()
        }

        import math, random
        nodos = []
        for i, d in enumerate(dispositivos):
            ultimo_ping = (
                session.query(Ping)
                .filter_by(dispositivo_id=d.id)
                .order_by(Ping.timestamp.desc())
                .first()
            )

            estado = "desconocido"
            latencia = None
            if ultimo_ping:
                estado = ultimo_ping.estado
                latencia = ultimo_ping.latencia_ms

            x, y = posiciones.get(d.id)
            if x is None:
                angulo = (2 * math.pi * i) / max(len(dispositivos), 1)
                radio = 250
                x = math.cos(angulo) * radio
                y = math.sin(angulo) * radio
                session.add(PosicionTopologia(dispositivo_id=d.id, x=x, y=y))

            nodos.append({
                "id": d.id,
                "ip": d.ip,
                "hostname": d.hostname,
                "tipo": d.tipo,
                "segmento": d.segmento,
                "estado": estado,
                "latencia": latencia,
                "x": x,
                "y": y,
            })

        session.commit()
        enlaces = [{"from": n["id"], "to": n["id"]} for n in nodos if False]
        return {"nodos": nodos, "enlaces": enlaces}
    finally:
        session.close()


@app.post("/api/topologia/posiciones")
async def guardar_posiciones(posiciones: list[PosicionUpdate]):
    session = _get_session()
    try:
        for p in posiciones:
            existente = session.query(PosicionTopologia).filter_by(
                dispositivo_id=p.dispositivo_id
            ).first()
            if existente:
                existente.x = p.x
                existente.y = p.y
            else:
                session.add(PosicionTopologia(
                    dispositivo_id=p.dispositivo_id,
                    x=p.x,
                    y=p.y,
                ))
        session.commit()
        return {"ok": True}
    finally:
        session.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8080, reload=True)
