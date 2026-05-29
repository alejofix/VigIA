#!/usr/bin/env python3
"""
Importa asignaciones MAC→vendor a la tabla mac_vendor_exact desde un CSV.

Uso:
    python3 scripts/importar_mac_vendor.py archivo.csv

Formato CSV (sin cabecera):
    XX:XX:XX:XX:XX:XX,Nombre Fabricante,95
    XX:XX:XX:XX:XX:XX,Nombre Fabricante

Confianza es opcional (default 85).
"""
import sys
import csv
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("importar_mac_vendor")

from backend.database import init_db, get_session
from backend.models import MacVendorExact
from agente.nmap_scanner import _normalizar_mac


def importar_csv(ruta: str):
    init_db()
    session = get_session()
    try:
        insertados = 0
        omitidos = 0
        with open(ruta, newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                row = [c.strip() for c in row]
                if len(row) < 2:
                    continue
                mac = _normalizar_mac(row[0])
                vendor = row[1]
                conf = int(row[2]) if len(row) > 2 and row[2] else 85
                if not mac or not vendor:
                    continue
                existente = session.query(MacVendorExact).filter_by(mac=mac).first()
                if existente:
                    existente.vendor = vendor
                    existente.confidence = conf
                    omitidos += 1
                else:
                    session.add(MacVendorExact(mac=mac, vendor=vendor, confidence=conf))
                    insertados += 1
        session.commit()
        logger.info(f"Importados {insertados} nuevos, actualizados {omitidos}")
    except Exception as e:
        session.rollback()
        logger.error(f"Error: {e}")
        raise
    finally:
        session.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    importar_csv(sys.argv[1])
