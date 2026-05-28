import os
import logging
import random
import math
from datetime import datetime, timedelta
from pydantic import BaseModel
from contextlib import asynccontextmanager
import asyncio

from fastapi import FastAPI, HTTPException, Query, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from sqlalchemy import func, case
from sqlalchemy.orm import Session
import speedtest as st_lib
import uuid

from backend.database import init_db, get_session, get_or_create_cliente
from backend.models import Cliente, Dispositivo, Ping, Alerta, Servicio, PosicionTopologia, Credencial, MacVendorExact, SegmentoExtra
from backend.schemas import (
    DispositivoCreate, DispositivoOut, DispositivoConEstado,
    PingOut, ServicioOut, AlertaOut,
    ScanRequest, PosicionUpdate, StatsOut, CredencialCreate, CredencialOut,
    ChatRequest, NotificacionRequest,
    SegmentoExtraCreate, SegmentoExtraOut,
)
from concurrent.futures import ThreadPoolExecutor
import agente.nmap_scanner as nmap_scanner
from agente.nmap_scanner import reconciliar_dispositivos, descubrir_nuevos, _SNMP_DISPONIBLE
from agente.icmp_poller import ciclo_polling
from agente.snmp_reader import obtener_info_dispositivo
from exportar.generar_reporte import generar as generar_reporte
from backend.chat import preguntar
from backend.notificaciones import notificar

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("vigia.api")

_executor = ThreadPoolExecutor(max_workers=2)
_scan_tasks = {}
_speedtest_tasks = {}
ADMIN_KEY = "qwerty"


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    try:
        session = get_session()
        clientes = session.query(Cliente).all()
        if clientes:
            for cli in clientes:
                try:
                    reconciliar_dispositivos(session, cli.id)
                    logger.info(f"Reconciliación completada para '{cli.nombre}' (ID {cli.id})")
                    disp_count = session.query(Dispositivo).filter_by(cliente_id=cli.id).count()
                    if disp_count > 0:
                        try:
                            segmentos_extra = [s.rango for s in session.query(SegmentoExtra).filter_by(cliente_id=cli.id).all()]
                            res = descubrir_nuevos(session, cli.id, segmentos_extra=segmentos_extra)
                            if res.get("nuevos", 0) > 0:
                                logger.info(f"Auto-descubrimiento para '{cli.nombre}': {res['nuevos']} nuevo(s)")
                        except Exception as e:
                            logger.warning(f"Auto-descubrimiento omitido para '{cli.nombre}': {e}")
                except Exception as e:
                    logger.warning(f"Reconciliación omitida para '{cli.nombre}': {e}")
            logger.info(f"Inicialización completada para {len(clientes)} cliente(s)")
        else:
            logger.info("No hay clientes. La interfaz mostrará opción de crear red al cargar.")
        session.close()
    except Exception as e:
        logger.warning(f"Inicialización omitida: {e}")
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
if os.path.exists("reportes"):
    app.mount("/reportes", StaticFiles(directory="reportes"), name="reportes")


@app.get("/api/health")
async def health():
    return {"status": "ok", "api": "VigIA"}

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
async def listar_dispositivos(
    nombre_cliente: str = Query("red_cliente"),
    activo: int | None = None,
    tipo: str | None = None,
    segmento: str | None = None,
):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        q = session.query(Dispositivo).filter_by(cliente_id=cid)
        if activo is not None:
            q = q.filter_by(activo=activo)
        if tipo:
            q = q.filter_by(tipo=tipo)
        if segmento:
            q = q.filter_by(segmento=segmento)
        return q.all()
    finally:
        session.close()


@app.get("/api/dispositivos/con-estado", response_model=list[DispositivoConEstado])
async def listar_dispositivos_con_estado(nombre_cliente: str = Query("red_cliente")):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        dispositivos = session.query(Dispositivo).filter_by(cliente_id=cid).all()
        ids = [d.id for d in dispositivos]
        if not ids:
            return []

        max_ids = (
            session.query(
                Ping.dispositivo_id,
                func.max(Ping.id).label("max_id"),
            )
            .filter(Ping.dispositivo_id.in_(ids))
            .group_by(Ping.dispositivo_id)
            .subquery()
        )
        ultimos = (
            session.query(Ping)
            .join(max_ids, Ping.id == max_ids.c.max_id)
            .all()
        )
        ping_map = {p.dispositivo_id: p for p in ultimos}
        cred_sub = (
            session.query(
                Credencial.dispositivo_id,
                Credencial.alias,
            )
            .filter(Credencial.dispositivo_id.in_(ids))
            .distinct(Credencial.dispositivo_id)
            .subquery()
        )
        cred_map = {r.dispositivo_id: r.alias for r in session.query(cred_sub).all()}
        return [
            DispositivoConEstado(
                id=d.id,
                cliente_id=d.cliente_id,
                ip=d.ip,
                hostname=d.hostname,
                mac=d.mac,
                fabricante=d.fabricante,
                tipo=d.tipo,
                descripcion=d.descripcion,
                primera_vez=d.primera_vez,
                ultima_vez=d.ultima_vez,
                activo=d.activo,
                segmento=d.segmento,
                serial=d.serial,
                estado=ping_map[d.id].estado if d.id in ping_map else "desconocido",
                latencia_ms=ping_map[d.id].latencia_ms if d.id in ping_map else None,
                alias=cred_map.get(d.id),
                tipo_asignacion_ip=d.tipo_asignacion_ip or "desconocido",
            )
            for d in dispositivos
        ]
    finally:
        session.close()


@app.get("/api/segmentos")
async def listar_segmentos(nombre_cliente: str = Query("red_cliente")):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        resultados = (
            session.query(Dispositivo.segmento)
            .filter_by(cliente_id=cid)
            .distinct()
            .all()
        )
        segmentos = sorted(set(r[0] for r in resultados if r[0]))
        return {"segmentos": segmentos}
    finally:
        session.close()


@app.get("/api/dispositivos/{dispositivo_id}", response_model=DispositivoOut)
async def obtener_dispositivo(dispositivo_id: int, nombre_cliente: str = Query("red_cliente")):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        d = (
            session.query(Dispositivo)
            .filter_by(id=dispositivo_id, cliente_id=cid)
            .first()
        )
        if not d:
            raise HTTPException(404, "Dispositivo no encontrado")
        return d
    finally:
        session.close()


@app.post("/api/dispositivos", response_model=DispositivoOut, status_code=201)
async def crear_dispositivo(data: DispositivoCreate, nombre_cliente: str = Query("red_cliente")):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        existente = (
            session.query(Dispositivo)
            .filter_by(ip=data.ip, cliente_id=cid)
            .first()
        )
        if existente:
            raise HTTPException(400, f"El IP {data.ip} ya existe")
        d = Dispositivo(**data.model_dump(), cliente_id=cid)
        d.ultima_vez = datetime.now()
        session.add(d)
        session.commit()
        session.refresh(d)
        return d
    finally:
        session.close()


class AsignacionIpUpdate(BaseModel):
    tipo_asignacion_ip: str


@app.patch("/api/dispositivos/{dispositivo_id}/asignacion-ip")
async def actualizar_asignacion_ip(
    dispositivo_id: int,
    data: AsignacionIpUpdate,
    nombre_cliente: str = Query("red_cliente"),
):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        d = (
            session.query(Dispositivo)
            .filter_by(id=dispositivo_id, cliente_id=cid)
            .first()
        )
        if not d:
            raise HTTPException(404, "Dispositivo no encontrado")
        d.tipo_asignacion_ip = data.tipo_asignacion_ip
        session.commit()
        return {"ok": True}
    finally:
        session.close()


@app.delete("/api/dispositivos/{dispositivo_id}")
async def eliminar_dispositivo(
    dispositivo_id: int,
    nombre_cliente: str = Query("red_cliente"),
    x_admin_key: str = Header(None),
):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "Clave de seguridad inválida")
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        d = (
            session.query(Dispositivo)
            .filter_by(id=dispositivo_id, cliente_id=cid)
            .first()
        )
        if not d:
            raise HTTPException(404, "Dispositivo no encontrado")
        session.delete(d)
        session.commit()
        return {"ok": True, "mensaje": f"Dispositivo {d.ip} eliminado"}
    finally:
        session.close()


@app.get("/api/dispositivos/{dispositivo_id}/pings", response_model=list[PingOut])
async def listar_pings(
    dispositivo_id: int,
    nombre_cliente: str = Query("red_cliente"),
    limite: int = Query(50, le=500),
):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        disp = (
            session.query(Dispositivo)
            .filter_by(id=dispositivo_id, cliente_id=cid)
            .first()
        )
        if not disp:
            raise HTTPException(404, "Dispositivo no encontrado")
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
async def listar_servicios(dispositivo_id: int, nombre_cliente: str = Query("red_cliente")):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        disp = (
            session.query(Dispositivo)
            .filter_by(id=dispositivo_id, cliente_id=cid)
            .first()
        )
        if not disp:
            raise HTTPException(404, "Dispositivo no encontrado")
        return (
            session.query(Servicio)
            .filter_by(dispositivo_id=dispositivo_id)
            .all()
        )
    finally:
        session.close()


@app.get("/api/dispositivos/{dispositivo_id}/credenciales")
async def obtener_credenciales(
    dispositivo_id: int,
    nombre_cliente: str = Query("red_cliente"),
    x_admin_key: str = Header(None),
):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "Clave de seguridad inválida")
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        disp = (
            session.query(Dispositivo)
            .filter_by(id=dispositivo_id, cliente_id=cid)
            .first()
        )
        if not disp:
            raise HTTPException(404, "Dispositivo no encontrado")
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
async def guardar_credenciales(
    dispositivo_id: int,
    data: CredencialCreate,
    nombre_cliente: str = Query("red_cliente"),
):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        disp = (
            session.query(Dispositivo)
            .filter_by(id=dispositivo_id, cliente_id=cid)
            .first()
        )
        if not disp:
            raise HTTPException(404, "Dispositivo no encontrado")
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
                cliente_id=cid,
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


@app.post("/api/dispositivos/{dispositivo_id}/re-detectar-serial")
async def re_detectar_serial(
    dispositivo_id: int,
    nombre_cliente: str = Query("red_cliente"),
):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        disp = (
            session.query(Dispositivo)
            .filter_by(id=dispositivo_id, cliente_id=cid)
            .first()
        )
        if not disp:
            raise HTTPException(404, "Dispositivo no encontrado")

        if not _SNMP_DISPONIBLE:
            raise HTTPException(400, "SNMP no disponible en este sistema")

        for community in ["public", "private", "snmp", "default", "internal", "monitor", "read", "admin", "secret", "ciscoworks", "cisco", "hponline", "manager"]:
            info = obtener_info_dispositivo(disp.ip, community=community)
            if info and info["snmp_disponible"]:
                serial = info.get("serial")
                if serial:
                    disp.serial = serial
                    session.commit()
                    return {"ok": True, "serial": serial, "community": community}
                return {"ok": True, "serial": None, "community": community, "mensaje": "SNMP disponible pero no se encontró serial"}
        return {"ok": True, "serial": None, "mensaje": "No se pudo conectar por SNMP con ninguna community"}
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(500, f"Error re-detectando serial: {str(e)}")
    finally:
        session.close()


@app.post("/api/dispositivos/{dispositivo_id}/escanear-puertos")
async def escanear_puertos_dispositivo(
    dispositivo_id: int,
    nombre_cliente: str = Query("red_cliente"),
):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        disp = session.query(Dispositivo).filter_by(id=dispositivo_id, cliente_id=cid).first()
        if not disp:
            raise HTTPException(404, "Dispositivo no encontrado")
        session.close()

        loop = asyncio.get_event_loop()
        puertos = await loop.run_in_executor(
            _executor, nmap_scanner.escanear_puertos, dispositivo_id, nombre_cliente,
        )
        return {"ok": True, "puertos": puertos}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error escaneando puertos: {e}")
        raise HTTPException(500, f"Error: {str(e)}")


@app.get("/api/alertas", response_model=list[AlertaOut])
async def listar_alertas(
    nombre_cliente: str = Query("red_cliente"),
    resuelta: int | None = None,
    tipo: str | None = None,
):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        q = (
            session.query(Alerta, Dispositivo.ip)
            .outerjoin(Dispositivo, Alerta.dispositivo_id == Dispositivo.id)
            .filter(Alerta.cliente_id == cid)
        )
        if resuelta is not None:
            q = q.filter(Alerta.resuelta == resuelta)
        if tipo:
            q = q.filter(Alerta.tipo == tipo)
        rows = q.order_by(Alerta.timestamp.desc()).limit(200).all()
        return [
            AlertaOut(
                id=a.id, cliente_id=a.cliente_id, dispositivo_id=a.dispositivo_id,
                tipo=a.tipo, mensaje=a.mensaje, timestamp=a.timestamp,
                resuelta=a.resuelta, analisis_ia=a.analisis_ia, ip=ip,
            )
            for a, ip in rows
        ]
    finally:
        session.close()


@app.post("/api/alertas/{alerta_id}/resolver")
async def resolver_alerta(alerta_id: int, nombre_cliente: str = Query("red_cliente")):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        a = (
            session.query(Alerta)
            .filter_by(id=alerta_id, cliente_id=cid)
            .first()
        )
        if not a:
            raise HTTPException(404, "Alerta no encontrada")
        a.resuelta = 1
        session.commit()
        return {"ok": True}
    finally:
        session.close()


@app.delete("/api/alertas")
async def borrar_alertas(nombre_cliente: str = Query("red_cliente")):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        session.query(Alerta).filter_by(cliente_id=cid).delete()
        session.commit()
        return {"ok": True, "mensaje": "Alertas eliminadas"}
    finally:
        session.close()


class PingCleanRequest(BaseModel):
    dias: int | None = None
    por_dispositivo: int | None = None


@app.post("/api/pings/clean")
async def limpiar_pings(data: PingCleanRequest, nombre_cliente: str = Query("red_cliente")):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        borrados = 0

        if data.dias:
            desde = datetime.now() - timedelta(days=data.dias)
            result = session.query(Ping).filter(
                Ping.cliente_id == cid,
                Ping.timestamp < desde,
            ).delete(synchronize_session=False)
            borrados += result

        if data.por_dispositivo:
            subq = (
                session.query(Ping.id)
                .filter(Ping.cliente_id == cid)
                .order_by(Ping.dispositivo_id, Ping.timestamp.desc())
                .offset(data.por_dispositivo)
            )
            ids = [r[0] for r in session.execute(subq).fetchall()]
            if ids:
                result = session.query(Ping).filter(Ping.id.in_(ids)).delete(synchronize_session=False)
                borrados += result

        session.commit()
        restantes = session.query(Ping).filter_by(cliente_id=cid).count()
        return {"ok": True, "borrados": borrados, "restantes": restantes}
    except Exception as e:
        session.rollback()
        raise HTTPException(500, f"Error limpiando pings: {str(e)}")
    finally:
        session.close()


@app.get("/api/stats", response_model=StatsOut)
async def stats(nombre_cliente: str = Query("red_cliente")):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        total = session.query(func.count(Dispositivo.id)).filter_by(cliente_id=cid).scalar() or 0
        activos = session.query(func.count(Dispositivo.id)).filter_by(cliente_id=cid, activo=1).scalar() or 0
        total_pings = session.query(func.count(Ping.id)).filter_by(cliente_id=cid).scalar() or 0
        alerta_row = session.query(
            func.count(Alerta.id).label("pendientes"),
            func.sum(case((Alerta.tipo == "latencia_alta", 1), else_=0)).label("warn"),
            func.sum(case((Alerta.tipo == "degradado", 1), else_=0)).label("degradados"),
            func.sum(case((Alerta.tipo == "caida", 1), else_=0)).label("caidos"),
        ).filter(Alerta.cliente_id == cid, Alerta.resuelta == 0).first()
        return StatsOut(
            total_dispositivos=total,
            activos=activos,
            warn=alerta_row.warn or 0,
            degradados=alerta_row.degradados or 0,
            caidos=alerta_row.caidos or 0,
            alertas_pendientes=alerta_row.pendientes or 0,
            total_pings=total_pings,
        )
    finally:
        session.close()


@app.post("/api/scan")
async def scan_red(data: ScanRequest):
    for r in data.rango_ip.split(","):
        r = r.strip()
        if "/" in r:
            mascara = int(r.split("/")[1])
            if mascara < 16:
                raise HTTPException(400, f"Rango {r} demasiado grande (máscara /16 o mayor). Escanea subredes más pequeñas.")

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


@app.post("/api/discover")
async def discover_nuevos(nombre_cliente: str = "red_cliente", todas: int = Query(0)):
    try:
        session = get_session()
        if todas:
            clientes = session.query(Cliente).all()
            resultados_totales = {"nuevos": 0, "total": 0, "hosts": [], "por_cliente": {}}
            for cli in clientes:
                try:
                    segmentos_extra = [s.rango for s in session.query(SegmentoExtra).filter_by(cliente_id=cli.id).all()]
                    res = descubrir_nuevos(session, cli.id, segmentos_extra=segmentos_extra)
                    resultados_totales["nuevos"] += res.get("nuevos", 0)
                    resultados_totales["total"] += res.get("total", 0)
                    resultados_totales["hosts"].extend(res.get("hosts", []))
                    resultados_totales["por_cliente"][cli.nombre] = {"nuevos": res.get("nuevos", 0), "total": res.get("total", 0)}
                except Exception as e:
                    logger.warning(f"Descubrimiento falló para '{cli.nombre}': {e}")
            return resultados_totales
        cid = get_or_create_cliente(session, nombre_cliente)
        segmentos_extra = [s.rango for s in session.query(SegmentoExtra).filter_by(cliente_id=cid).all()]
        resultado = descubrir_nuevos(session, cid, segmentos_extra=segmentos_extra)
        return resultado
    except Exception as e:
        raise HTTPException(500, f"Error en descubrimiento: {str(e)}")
    finally:
        session.close()


@app.post("/api/seed")
async def seed_data(nombre_cliente: str = "demo"):
    init_db()
    session = get_session()

    try:
        cid = get_or_create_cliente(session, nombre_cliente)

        session.query(PosicionTopologia).filter_by(cliente_id=cid).delete()
        session.query(Credencial).filter_by(cliente_id=cid).delete()
        session.query(Alerta).filter_by(cliente_id=cid).delete()
        session.query(Ping).filter_by(cliente_id=cid).delete()
        session.query(Servicio).filter_by(cliente_id=cid).delete()
        session.query(Dispositivo).filter_by(cliente_id=cid).delete()

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
            disp = Dispositivo(**d, cliente_id=cid, primera_vez=ahora - timedelta(days=random.randint(30, 180)))
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
                    cliente_id=cid,
                    timestamp=ahora - timedelta(hours=23 - h),
                    estado=estado,
                    latencia_ms=latencia,
                    perdida_pct=0 if estado == "up" else 100,
                ))

            if d["ip"] in ("192.168.2.103", "192.168.2.104"):
                session.add(Alerta(
                    dispositivo_id=disp.id,
                    cliente_id=cid,
                    tipo="caida",
                    mensaje=f"{d['hostname']} ha presentado caidas intermitentes en las ultimas 24h",
                    timestamp=ahora - timedelta(minutes=random.randint(5, 120)),
                ))

            if d["tipo"] == "camara":
                session.add(Servicio(
                    dispositivo_id=disp.id, cliente_id=cid,
                    puerto=80, protocolo="tcp",
                    servicio="http", version="", estado="abierto",
                ))
                session.add(Servicio(
                    dispositivo_id=disp.id, cliente_id=cid,
                    puerto=554, protocolo="tcp",
                    servicio="rtsp", version="", estado="abierto",
                ))
            if d["tipo"] == "router":
                session.add(Servicio(
                    dispositivo_id=disp.id, cliente_id=cid,
                    puerto=22, protocolo="tcp",
                    servicio="ssh", version="OpenSSH", estado="abierto",
                ))

            session.add(PosicionTopologia(
                dispositivo_id=disp.id,
                cliente_id=cid,
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


@app.post("/api/mac-vendor")
async def agregar_mac_vendor(
    body: dict,
    x_admin_key: str = Header(None),
):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "Clave de seguridad inválida")
    session = get_session()
    try:
        mac = body.get("mac", "").upper().strip()
        vendor = body.get("vendor", "").strip()
        confidence = body.get("confidence", 85)
        if not mac or not vendor:
            raise HTTPException(400, "mac y vendor son requeridos")
        existente = session.query(MacVendorExact).filter_by(mac=mac).first()
        creado = False
        if existente:
            existente.vendor = vendor
            existente.confidence = confidence
        else:
            session.add(MacVendorExact(mac=mac, vendor=vendor, confidence=confidence))
            creado = True
        session.commit()
        return {"ok": True, "creado": creado, "mac": mac, "vendor": vendor}
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Error agregando MAC vendor: {e}")
        raise HTTPException(500, f"Error: {str(e)}")
    finally:
        session.close()


@app.post("/api/mac-vendor/import")
async def importar_mac_vendor(
    request: Request,
    x_admin_key: str = Header(None),
):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "Clave de seguridad inválida")
    session = get_session()
    try:
        body = await request.json()
        entries = body.get("entries", [])
        insertados = 0
        actualizados = 0
        for entry in entries:
            mac = entry.get("mac", "").upper().strip()
            vendor = entry.get("vendor", "").strip()
            confidence = entry.get("confidence", 85)
            if not mac or not vendor:
                continue
            existente = session.query(MacVendorExact).filter_by(mac=mac).first()
            if existente:
                existente.vendor = vendor
                existente.confidence = confidence
                actualizados += 1
            else:
                session.add(MacVendorExact(mac=mac, vendor=vendor, confidence=confidence))
                insertados += 1
        session.commit()
        return {"ok": True, "insertados": insertados, "actualizados": actualizados}
    except Exception as e:
        session.rollback()
        logger.error(f"Error importando MAC: {e}")
        raise HTTPException(500, f"Error: {str(e)}")
    finally:
        session.close()


@app.post("/api/reconciliar")
async def reconciliar_red(
    nombre_cliente: str = Query("red_cliente"),
    todas: int = Query(0),
    x_admin_key: str = Header(None),
):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "Clave de seguridad inválida")
    session = get_session()
    try:
        if todas:
            clientes = session.query(Cliente).all()
            totales = {"corregidos_tipo": 0, "corregidos_fab": 0, "api_resueltos": 0, "port_resueltos": 0, "hostnames_resueltos": 0}
            for cli in clientes:
                res = reconciliar_dispositivos(session, cli.id)
                for k in totales:
                    totales[k] += res.get(k, 0)
            return {"ok": True, **totales}
        cid = get_or_create_cliente(session, nombre_cliente)
        res = reconciliar_dispositivos(session, cid)
        return {
            "ok": True,
            "corregidos_tipo": res["corregidos_tipo"],
            "corregidos_fab": res["corregidos_fab"],
            "api_resueltos": res.get("api_resueltos", 0),
            "port_resueltos": res.get("port_resueltos", 0),
            "hostnames_resueltos": res.get("hostnames_resueltos", 0),
        }
    except Exception as e:
        session.rollback()
        logger.error(f"Error en reconciliación: {e}")
        raise HTTPException(500, f"Error: {str(e)}")
    finally:
        session.close()


@app.delete("/api/red")
async def borrar_red(
    x_admin_key: str = Header(None),
    nombre_cliente: str = Query(None),
):
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "Clave de seguridad inválida")

    if not nombre_cliente:
        raise HTTPException(400, "Se requiere nombre_cliente")

    session = get_session()
    try:
        cliente = session.query(Cliente).filter_by(nombre=nombre_cliente).first()
        if not cliente:
            raise HTTPException(404, f"Red '{nombre_cliente}' no encontrada")
        session.delete(cliente)
        session.commit()
        return {"ok": True, "mensaje": f"Red '{nombre_cliente}' eliminada completamente (cascada nativa)"}
    except HTTPException:
        session.rollback()
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Error borrando datos de {nombre_cliente}: {e}")
        raise HTTPException(500, f"Error al borrar datos: {str(e)}")
    finally:
        session.close()


def _ejecutar_speedtest(task_id: str):
    try:
        st = st_lib.Speedtest()
        st.get_best_server()
        st.download()
        st.upload()
        res = st.results.dict()
        _speedtest_tasks[task_id] = {
            "estado": "completo",
            "download_mbps": round(res.get("download", 0) / 1_000_000, 2),
            "upload_mbps": round(res.get("upload", 0) / 1_000_000, 2),
            "ping_ms": round(res.get("ping", 0), 1),
            "servidor": f'{res.get("server", {}).get("sponsor", "?")} ({res.get("server", {}).get("name", "?")})',
            "ip_publica": res.get("client", {}).get("ip", "?"),
        }
    except Exception as e:
        _speedtest_tasks[task_id] = {"estado": "error", "error": str(e)}


@app.post("/api/speedtest")
async def iniciar_speedtest():
    task_id = str(uuid.uuid4())
    _speedtest_tasks[task_id] = {"estado": "en_progreso"}
    _executor.submit(_ejecutar_speedtest, task_id)
    return {"task_id": task_id}


@app.get("/api/speedtest/estado/{task_id}")
async def estado_speedtest(task_id: str):
    data = _speedtest_tasks.get(task_id)
    if not data:
        raise HTTPException(404, "Task no encontrada")
    return data


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
    session = get_session()
    try:
        clientes = (
            session.query(Cliente)
            .outerjoin(Dispositivo, Dispositivo.cliente_id == Cliente.id)
            .group_by(Cliente.id)
            .order_by(func.count(Dispositivo.id).desc())
            .all()
        )
        return {"clientes": [{"id": c.id, "nombre": c.nombre} for c in clientes]}
    finally:
        session.close()


@app.get("/api/clientes/{cliente_id}/segmentos")
async def listar_segmentos_extra(cliente_id: int):
    session = get_session()
    try:
        segmentos = session.query(SegmentoExtra).filter_by(cliente_id=cliente_id).all()
        return {"segmentos": [SegmentoExtraOut.model_validate(s).model_dump() for s in segmentos]}
    finally:
        session.close()


@app.post("/api/clientes/{cliente_id}/segmentos")
async def agregar_segmento_extra(cliente_id: int, data: SegmentoExtraCreate):
    session = get_session()
    try:
        cliente = session.query(Cliente).filter_by(id=cliente_id).first()
        if not cliente:
            raise HTTPException(404, "Cliente no encontrado")
        seg = SegmentoExtra(cliente_id=cliente_id, rango=data.rango, descripcion=data.descripcion)
        session.add(seg)
        session.commit()
        return SegmentoExtraOut.model_validate(seg).model_dump()
    finally:
        session.close()


@app.delete("/api/clientes/{cliente_id}/segmentos/{segmento_id}")
async def eliminar_segmento_extra(cliente_id: int, segmento_id: int):
    session = get_session()
    try:
        seg = session.query(SegmentoExtra).filter_by(id=segmento_id, cliente_id=cliente_id).first()
        if not seg:
            raise HTTPException(404, "Segmento no encontrado")
        session.delete(seg)
        session.commit()
        return {"ok": True}
    finally:
        session.close()


@app.post("/api/chat")
async def chat_endpoint(data: ChatRequest):
    session = get_session()
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
async def obtener_topologia(nombre_cliente: str = Query("red_cliente")):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        dispositivos = session.query(Dispositivo).filter_by(cliente_id=cid, activo=1).all()
        ids = [d.id for d in dispositivos]
        posiciones = {
            p.dispositivo_id: (p.x, p.y)
            for p in session.query(PosicionTopologia).filter(PosicionTopologia.dispositivo_id.in_(ids)).all()
        }

        cred_sub = (
            session.query(
                Credencial.dispositivo_id,
                Credencial.alias,
            )
            .filter(Credencial.dispositivo_id.in_(ids))
            .distinct(Credencial.dispositivo_id)
            .subquery()
        )
        cred_map = {r.dispositivo_id: r.alias for r in session.query(cred_sub).all()}

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

            pos = posiciones.get(d.id)
            if pos is None:
                x = y = None
            else:
                x, y = pos
            if x is None:
                angulo = (2 * math.pi * i) / max(len(dispositivos), 1)
                radio = 250
                x = math.cos(angulo) * radio
                y = math.sin(angulo) * radio
                session.add(PosicionTopologia(dispositivo_id=d.id, cliente_id=cid, x=x, y=y))

            nodos.append({
                "id": d.id,
                "ip": d.ip,
                "hostname": d.hostname,
                "alias": cred_map.get(d.id),
                "mac": d.mac,
                "fabricante": d.fabricante,
                "tipo": d.tipo or "desconocido",
                "segmento": d.segmento,
                "descripcion": d.descripcion,
                "serial": d.serial,
                "tipo_asignacion_ip": d.tipo_asignacion_ip or "desconocido",
                "estado": estado,
                "latencia": latencia,
                "ultima_vez": d.ultima_vez.isoformat() if d.ultima_vez else None,
                "x": x,
                "y": y,
            })

        session.commit()
        enlaces = []
        segmentos = {}
        for n in nodos:
            seg = n.get("segmento")
            if seg:
                segmentos.setdefault(seg, []).append(n)

        for seg, devices in segmentos.items():
            gateway = None
            for d in devices:
                if d["tipo"] == "router":
                    gateway = d
                    break
            if not gateway:
                for d in devices:
                    if d["hostname"] and "_gateway" in d["hostname"].lower():
                        gateway = d
                        break
            if not gateway and len(devices) > 1:
                sorted_devs = sorted(devices, key=lambda x: (x["latencia"] if x["latencia"] is not None else 9999))
                gateway = sorted_devs[0]

            if gateway:
                for d in devices:
                    if d["id"] != gateway["id"]:
                        enlaces.append({"from": gateway["id"], "to": d["id"]})
            elif len(devices) > 1:
                for i in range(len(devices) - 1):
                    enlaces.append({"from": devices[i]["id"], "to": devices[i + 1]["id"]})

        return {"nodos": nodos, "enlaces": enlaces}
    finally:
        session.close()


@app.post("/api/topologia/posiciones")
async def guardar_posiciones(
    posiciones: list[PosicionUpdate],
    nombre_cliente: str = Query("red_cliente"),
):
    session = get_session()
    try:
        cid = get_or_create_cliente(session, nombre_cliente)
        for p in posiciones:
            disp = (
                session.query(Dispositivo)
                .filter_by(id=p.dispositivo_id, cliente_id=cid)
                .first()
            )
            if not disp:
                continue
            existente = session.query(PosicionTopologia).filter_by(
                dispositivo_id=p.dispositivo_id
            ).first()
            if existente:
                existente.x = p.x
                existente.y = p.y
            else:
                session.add(PosicionTopologia(
                    dispositivo_id=p.dispositivo_id,
                    cliente_id=cid,
                    x=p.x,
                    y=p.y,
                ))
        session.commit()
        return {"ok": True}
    finally:
        session.close()


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=True)
