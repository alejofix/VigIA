import logging
import time
import os
import subprocess
import re
from datetime import datetime
from sqlalchemy.orm import Session
from backend.models import Dispositivo, Ping, Alerta
from backend.database import get_session, init_db, get_or_create_cliente
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


def _leer_tabla_arp() -> dict:
    arp = {}
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    arp[parts[3].lower()] = parts[0]
    except Exception:
        pass
    return arp


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


def _mac_local() -> str:
    try:
        result = os.popen("ip -o addr show 2>/dev/null | grep ' inet ' | grep -v ' lo ' | grep -v docker | head -1").read()
        if result:
            iface = result.strip().split()[1]
            mac = os.popen(f"cat /sys/class/net/{iface}/address 2>/dev/null").read().strip()
            if mac:
                return mac.lower()
    except Exception:
        pass
    return ""


def _alerta_pendiente(session, dispositivo_id: int, tipo: str) -> bool:
    return session.query(Alerta).filter(
        Alerta.dispositivo_id == dispositivo_id,
        Alerta.tipo == tipo,
        Alerta.resuelta == 0,
    ).first() is not None


def procesar_dispositivo(session: Session, dispositivo: Dispositivo, cid: int):
    resultado = hacer_ping(dispositivo.ip)
    estado_anterior = obtener_ultimo_estado(session, dispositivo.id)

    # Verificar MAC contra tabla ARP (solo para dispositivos remotos)
    if dispositivo.mac and dispositivo.mac.lower() != _mac_local():
        arp = _leer_tabla_arp()
        mac_buscada = dispositivo.mac.lower()
        if mac_buscada in arp:
            ip_arp = arp[mac_buscada]
            if ip_arp != dispositivo.ip:
                logger.info(f"MAC {dispositivo.mac} ahora tiene IP {ip_arp} (antes {dispositivo.ip}), actualizando")
                dispositivo.ip = ip_arp

    ping = Ping(
        dispositivo_id=dispositivo.id,
        cliente_id=cid,
        estado=resultado["estado"],
        latencia_ms=resultado["latencia_ms"],
        perdida_pct=resultado["perdida_pct"],
    )
    session.add(ping)

    debe_alertar = estado_anterior != resultado["estado"]
    if resultado["estado"] == "down":
        if debe_alertar or not _alerta_pendiente(session, dispositivo.id, "caida"):
            alerta = Alerta(
                dispositivo_id=dispositivo.id,
                cliente_id=cid,
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
        if debe_alertar or not _alerta_pendiente(session, dispositivo.id, "degradado"):
            alerta = Alerta(
                dispositivo_id=dispositivo.id,
                cliente_id=cid,
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
        if debe_alertar or not _alerta_pendiente(session, dispositivo.id, "latencia_alta"):
            alerta = Alerta(
                dispositivo_id=dispositivo.id,
                cliente_id=cid,
                tipo="latencia_alta",
                mensaje=f"Latencia alta en {dispositivo.ip}: {resultado['latencia_ms']:.0f}ms",
            )
            session.add(alerta)
            logger.warning(f"ALERTA: {dispositivo.ip} latencia alta ({resultado['latencia_ms']:.0f}ms)")

    dispositivo.ultima_vez = datetime.now()


def _descubrir_por_arp(session: Session, cid: int):
    try:
        arp = _leer_tabla_arp()
        existentes = {d.mac.lower() for d in session.query(Dispositivo).filter_by(cliente_id=cid).all() if d.mac}
        local_ip = _ip_local()
        for mac, ip in arp.items():
            if mac not in existentes and ip != local_ip and not ip.startswith("172.17.") and not ip.startswith("172.18."):
                nuevo = Dispositivo(ip=ip, mac=mac, tipo="dispositivo", activo=1, cliente_id=cid)
                session.add(nuevo)
                logger.info(f"Nuevo dispositivo descubierto por ARP: {ip} ({mac})")
    except Exception as e:
        logger.error(f"Error en descubrimiento ARP: {e}")


def _ip_local() -> str:
    try:
        result = os.popen("ip -o addr show 2>/dev/null | grep ' inet ' | grep -v ' lo ' | grep -v docker | head -1").read()
        if result:
            return result.strip().split()[3].split("/")[0]
    except Exception:
        pass
    return ""


def ciclo_polling(nombre_cliente: str, intervalo: int = POLL_INTERVAL):
    init_db()
    session: Session = get_session()
    cid = get_or_create_cliente(session, nombre_cliente)

    try:
        _descubrir_por_arp(session, cid)
        dispositivos = session.query(Dispositivo).filter_by(activo=1, cliente_id=cid).all()
        if not dispositivos:
            logger.info("No hay dispositivos activos para monitorear")
            return

        logger.info(f"Polling ICMP: {len(dispositivos)} dispositivos")
        for dispositivo in dispositivos:
            procesar_dispositivo(session, dispositivo, cid)

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
