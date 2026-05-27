import logging
from typing import Optional
from pysnmp.hlapi import (
    getCmd, CommunityData, UdpTransportTarget,
    ContextData, ObjectType, ObjectIdentity,
    SnmpEngine, nextCmd
)

logger = logging.getLogger("vigia.snmp_reader")

SISTEMA_OID = "1.3.6.1.2.1.1.1.0"
NOMBRE_OID = "1.3.6.1.2.1.1.5.0"
INTERFACES_OID = "1.3.6.1.2.1.2.2.1.2"

# OIDs comunes para número de serie
SERIAL_OIDS = [
    "1.3.6.1.2.1.47.1.1.1.1.11.1",      # entPhysicalSerialNum (genérico)
    "1.3.6.1.2.1.43.5.1.1.17.1",        # prtGeneralSerialNumber (impresoras)
    "1.3.6.1.4.1.9.9.99.1.1.1.1.3.1",   # Cisco
    "1.3.6.1.4.1.9.3.6.3.0",            # Cisco (alternativo)
    "1.3.6.1.4.1.318.1.1.1.1.1.1.0",    # APC
    "1.3.6.1.4.1.674.10898.100.1.2.0",  # Dell
    "1.3.6.1.4.1.2636.3.40.1.4.1.1.1.1",# Juniper
    "1.3.6.1.4.1.171.11.1.1.2.0",       # HP / Aruba
    "1.3.6.1.4.1.198.1.1.1.1.1.0",      # Huawei
    "1.3.6.1.4.1.14988.1.1.1.1.1.0",    # MikroTik
    "1.3.6.1.4.1.41112.1.4.1.1.1.0",    # Ubiquiti
    "1.3.6.1.4.1.12356.101.1.1.1.0",    # Fortinet
    "1.3.6.1.4.1.14823.1.1.2.1.1.0",    # Aruba (alternativo)
    "1.3.6.1.4.1.8072.3.2.10",          # Net-SNMP (Linux)
    "1.3.6.1.4.1.4413.1.1.1.1.1.1.0",  # TP-Link
    "1.3.6.1.4.1.890.1.1.1.1.1.0",     # Zyxel
    "1.3.6.1.4.1.4526.1.1.1.1.1.0",    # D-Link
    "1.3.6.1.4.1.211.1.1.1.1.1.0",     # Extreme
    "1.3.6.1.4.1.25506.1.1.1.1.1.0",   # H3C / Comware
    "1.3.6.1.4.1.6486.1.1.1.1.1.0",    # Alcatel-Lucent
    "1.3.6.1.4.1.8744.1.1.1.1.1.0",    # Grandstream
    "1.3.6.1.4.1.2435.1.1.1.1.1.0",    # Allied Telesis
    "1.3.6.1.4.1.6527.1.1.1.1.1.0",    # Nokia/Alcatel SR
    "1.3.6.1.4.1.14179.1.1.1.1.1.0",   # Ruckus
    "1.3.6.1.4.1.28507.1.1.1.1.1.0",   # Meraki
]


def leer_snmp(ip: str, oid: str, community: str = "public", puerto: int = 161) -> Optional[str]:
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, puerto), timeout=3, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        error_indication, error_status, error_index, var_binds = next(iterator)

        if error_indication:
            logger.debug("SNMP error en %s OID %s: %s", ip, oid, error_indication)
            return None
        if error_status:
            logger.debug("SNMP error-status en %s OID %s: %s", ip, oid, error_status.prettyPrint())
            return None

        for var_bind in var_binds:
            return str(var_bind[1])

    except Exception as e:
        logger.debug("SNMP exception en %s OID %s: %s", ip, oid, e)
        return None


def leer_interfaces(ip: str, community: str = "public", puerto: int = 161) -> list:
    interfaces = []
    try:
        iterator = nextCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, puerto), timeout=3, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(INTERFACES_OID)),
            lexicographicMode=False,
        )

        for error_indication, error_status, error_index, var_binds in iterator:
            if error_indication:
                break
            for var_bind in var_binds:
                interfaces.append(str(var_bind[1]))

    except Exception:
        pass

    return interfaces


def leer_serial(ip: str, community: str = "public", puerto: int = 161) -> Optional[str]:
    for oid in SERIAL_OIDS:
        valor = leer_snmp(ip, oid, community, puerto)
        if valor and not valor.startswith(".") and len(valor.strip()) > 1:
            return valor.strip()
    return None


def obtener_info_dispositivo(ip: str, community: str = "public") -> dict:
    sistema = leer_snmp(ip, SISTEMA_OID, community)
    nombre = leer_snmp(ip, NOMBRE_OID, community)
    interfaces = leer_interfaces(ip, community)
    serial = leer_serial(ip, community)

    return {
        "ip": ip,
        "sistema": sistema,
        "nombre": nombre,
        "interfaces": interfaces,
        "serial": serial,
        "snmp_disponible": sistema is not None,
    }
