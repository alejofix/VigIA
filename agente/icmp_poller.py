import logging
import time
import os
import subprocess
import re
from datetime import datetime
from sqlalchemy.orm import Session
from backend.models import Dispositivo, Ping, Alerta
from backend.database import get_session, init_db
from backend.notificaciones import notificar
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("vigia.icmp_poller")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))
DB_PATH = os.getenv("DB_PATH", "data/")


def obtener_ultimo_estado(session: Session, dispositivo_id: int) -> str:
    ultimo = session.query(Ping).filter_by(
        dispositivo_id=dispositivo_id
    ).order_by(Ping.id.desc()).first()
    if ultimo:
        return ultimo.estado
    return None


def hacer_ping(ip: str) -> dict:
    try:
        proc = subprocess.run(
            ["ping", "-c", "2", "-W", "2", "-n", ip],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0:
            m = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/', proc.stdout)
            latencia = float(m.group(1)) if m else None
            perdida_m = re.search(r'(\d+)% packet loss', proc.stdout)
            perdida = float(perdida_m.group(1)) if perdida_m else 0
            if perdida > 0 and latencia and latencia > 1222:
                return {"estado": "degradado", "latencia_ms": latencia, "perdida_pct": perdida}
            if latencia and latencia > 444:
                return {"estado": "warn", "latencia_ms": latencia, "perdida_pct": perdida}
            return {"estado": "up", "latencia_ms": latencia, "perdida_pct": perdida}
        else:
            perdida_m = re.search(r'(\d+)% packet loss', proc.stdout)
            perdida = float(perdida_m.group(1)) if perdida_m else 100
            return {"estado": "down", "latencia_ms": None, "perdida_pct": perdida}
    except subprocess.TimeoutExpired:
        return {"estado": "warn", "latencia_ms": None, "perdida_pct": 100}
    except Exception as e:
        logger.error(f"Error inesperado ping a {ip}: {e}")
        return {"estado": "down", "latencia_ms": None, "perdida_pct": 100}


def procesar_dispositivo(session: Session, dispositivo: Dispositivo):
    resultado = hacer_ping(dispositivo.ip)
    estado_anterior = obtener_ultimo_estado(session, dispositivo.id)

    ping = Ping(
        dispositivo_id=dispositivo.id,
        estado=resultado["estado"],
        latencia_ms=resultado["latencia_ms"],
        perdida_pct=resultado["perdida_pct"],
    )
    session.add(ping)

    if estado_anterior != resultado["estado"]:
        if resultado["estado"] == "down":
            alerta = Alerta(
                dispositivo_id=dispositivo.id,
                tipo="caida",
                mensaje=f"Dispositivo {dispositivo.ip} caido tras estar activo",
            )
            session.add(alerta)
            logger.warning(f"ALERTA: {dispositivo.ip} paso a DOWN")
            notificar(
                f"Caida: {dispositivo.ip}",
                f"Dispositivo {dispositivo.ip} ({dispositivo.hostname or 'sin hostname'}) "
                f"ha caido. Tipo: {dispositivo.tipo or 'desconocido'}.",
            )
        elif resultado["estado"] == "degradado":
            alerta = Alerta(
                dispositivo_id=dispositivo.id,
                tipo="degradado",
                mensaje=f"Dispositivo {dispositivo.ip} degradado: perdida {resultado['perdida_pct']:.0f}%, latencia {resultado['latencia_ms']:.0f}ms",
            )
            session.add(alerta)
            logger.warning(f"ALERTA: {dispositivo.ip} degradado")
            notificar(
                f"Degradado: {dispositivo.ip}",
                f"Dispositivo {dispositivo.ip} ({dispositivo.hostname or 'sin hostname'}) "
                f"degradado por perdida de paquetes y latencia alta.",
            )
        elif resultado["estado"] == "warn":
            alerta = Alerta(
                dispositivo_id=dispositivo.id,
                tipo="latencia_alta",
                mensaje=f"Latencia alta en {dispositivo.ip}: {resultado['latencia_ms']:.0f}ms",
            )
            session.add(alerta)
            logger.warning(f"ALERTA: {dispositivo.ip} latencia alta ({resultado['latencia_ms']:.0f}ms)")

    dispositivo.ultima_vez = datetime.now()


def ciclo_polling(nombre_cliente: str, intervalo: int = POLL_INTERVAL):
    db_path = f"data/{nombre_cliente}.db"
    if not os.path.exists(db_path):
        logger.error(f"Base de datos no encontrada: {db_path}")
        return

    init_db(db_path)
    session_factory = get_session(db_path)
    session: Session = session_factory()

    try:
        dispositivos = session.query(Dispositivo).filter_by(activo=1).all()
        if not dispositivos:
            logger.info("No hay dispositivos activos para monitorear")
            return

        logger.info(f"Polling ICMP: {len(dispositivos)} dispositivos")
        for dispositivo in dispositivos:
            procesar_dispositivo(session, dispositivo)

        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Error en ciclo de polling: {e}")
    finally:
        session.close()


def run_loop(nombre_cliente: str, intervalo: int = POLL_INTERVAL):
    logger.info(f"Iniciando ICMP poller para {nombre_cliente} (intervalo={intervalo}s)")
    while True:
        try:
            ciclo_polling(nombre_cliente, intervalo)
        except Exception as e:
            logger.error(f"Error en ciclo: {e}")
        time.sleep(intervalo)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    import sys
    cliente = sys.argv[1] if len(sys.argv) > 1 else "red_cliente"
    run_loop(cliente)
