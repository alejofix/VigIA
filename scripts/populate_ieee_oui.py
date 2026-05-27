import sys
import logging
import httpx
from io import StringIO
sys.path.insert(0, "/opt/lampp/htdocs/VigIA")

from backend.database import get_session, init_db
from backend.models import OuiVendor, PortHeuristic

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("populate_ieee")

IEEE_URL = "https://standards-oui.ieee.org/oui/oui.txt"

PORT_SEED = [
    (554, "tcp", "Hikvision/Dahua", 65),
    (80, "tcp", "Hikvision/Dahua", 40),
    (37777, "tcp", "Dahua", 70),
    (37778, "tcp", "Dahua", 70),
    (8000, "tcp", "Hikvision", 65),
    (8291, "tcp", "MikroTik", 75),
    (8728, "tcp", "MikroTik", 70),
    (8729, "tcp", "MikroTik", 70),
    (8843, "tcp", "Ubiquiti", 65),
    (27117, "tcp", "Ubiquiti", 65),
    (22, "tcp", "Cisco", 40),
    (161, "udp", "Cisco", 45),
    (20002, "tcp", "TP-Link", 60),
    (3389, "tcp", "Microsoft Windows", 55),
    (445, "tcp", "Microsoft Windows", 40),
    (139, "tcp", "Microsoft Windows", 40),
    (5900, "tcp", "Linux/VNC", 40),
    (5000, "tcp", "Synology", 70),
    (5001, "tcp", "Synology", 70),
    (631, "tcp", "Impresora", 50),
    (515, "tcp", "Impresora", 50),
    (23, "tcp", "Switch/Gestionable", 30),
]


def seed_port_heuristic():
    init_db()
    session = get_session()
    try:
        seen = set()
        deduped = []
        for puerto, proto, vendor, conf in PORT_SEED:
            key = (puerto, proto)
            if key not in seen:
                seen.add(key)
                deduped.append(PortHeuristic(puerto=puerto, protocolo=proto, vendor=vendor, confidence=conf))
        existentes = session.query(PortHeuristic).count()
        if existentes > 0:
            logger.info(f"Ya hay {existentes} reglas port_heuristic en BD. Saltando.")
            return
        session.add_all(deduped)
        session.commit()
        logger.info(f"Insertadas {len(deduped)} reglas port_heuristic")
    except Exception as e:
        session.rollback()
        logger.error(f"Error: {e}")
        raise
    finally:
        session.close()


def download_ieee_oui():
    init_db()
    session = get_session()
    try:
        logger.info(f"Descargando {IEEE_URL} ...")
        resp = httpx.get(IEEE_URL, timeout=30.0, follow_redirects=True)
        if resp.status_code != 200:
            logger.error(f"HTTP {resp.status_code}")
            return
        count = 0
        batch = []
        for line in resp.text.splitlines():
            if "(base 16)" in line:
                parts = line.strip().split()
                if len(parts) >= 4:
                    oui = parts[0].replace("-", ":").upper()
                    vendor = " ".join(parts[3:]).strip().rstrip(",")
                    existente = session.query(OuiVendor).filter_by(oui=oui, source="ieee").first()
                    if not existente:
                        batch.append(OuiVendor(oui=oui, vendor=vendor, source="ieee", confidence=70))
                        count += 1
        if batch:
            session.add_all(batch)
            session.commit()
        logger.info(f"Insertados {count} nuevos OUI IEEE de {len(resp.text.splitlines())} líneas")
    except Exception as e:
        session.rollback()
        logger.error(f"Error descargando IEEE: {e}")
        raise
    finally:
        session.close()


if __name__ == "__main__":
    seed_port_heuristic()
    download_ieee_oui()
