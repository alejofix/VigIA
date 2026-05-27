import sys
import logging
sys.path.insert(0, "/opt/lampp/htdocs/VigIA")

from backend.database import get_engine, get_session, init_db
from backend.models import Base, OuiVendor
from agente.nmap_scanner import VENDOR_OUI

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("migrar_oui")

def migrar():
    init_db()
    session = get_session()
    try:
        existentes = session.query(OuiVendor).filter_by(source="custom").count()
        if existentes > 0:
            logger.info(f"Ya hay {existentes} OUI custom en BD. Saltando migración.")
            return
        batch = []
        for oui, vendor in VENDOR_OUI.items():
            batch.append(OuiVendor(oui=oui, vendor=vendor, source="custom", confidence=80))
        session.add_all(batch)
        session.commit()
        logger.info(f"Migrados {len(batch)} OUI a oui_vendor (source='custom')")
    except Exception as e:
        session.rollback()
        logger.error(f"Error en migración: {e}")
        raise
    finally:
        session.close()

if __name__ == "__main__":
    migrar()
