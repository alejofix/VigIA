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
    "1.3.6.1.4.1.9.9.99.1.1.1.1.3.1",   # Cisco
    "1.3.6.1.4.1.318.1.1.1.1.1.1.0",    # APC
    "1.3.6.1.4.1.674.10898.100.1.2.0",  # Dell
    "1.3.6.1.4.1.2636.3.40.1.4.1.1.1.1",# Juniper
    "1.3.6.1.4.1.171.11.1.1.2.0",       # HP
    "1.3.6.1.4.1.198.1.1.1.1.1.0",      # Huawei
]


def leer_snmp(ip: str, oid: str, community: str = "public", puerto: int = 161) -> Optional[str]:
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, puerto), timeout=1, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        error_indication, error_status, error_index, var_binds = next(iterator)

        if error_indication:
            return None
        if error_status:
            return None

        for var_bind in var_binds:
            return str(var_bind[1])

    except Exception:
        return None


def leer_interfaces(ip: str, community: str = "public", puerto: int = 161) -> list:
    interfaces = []
    try:
        iterator = nextCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, puerto), timeout=1, retries=0),
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
