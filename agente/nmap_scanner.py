import logging
import random
import math
import os
import re
import nmap
from datetime import datetime
from sqlalchemy.orm import Session
from backend.models import Dispositivo, Servicio, PosicionTopologia
from backend.database import get_session, init_db
try:
    from agente.snmp_reader import obtener_info_dispositivo
    _SNMP_DISPONIBLE = True
except Exception:
    _SNMP_DISPONIBLE = False

    def obtener_info_dispositivo(ip, community="public"):
        return None

logger = logging.getLogger("vigia.nmap_scanner")


def _mac_local(ip: str) -> str:
    try:
        result = os.popen(f"ip -o addr show to {ip} 2>/dev/null").read()
        if result:
            iface = result.split()[1]
            mac = os.popen(f"cat /sys/class/net/{iface}/address 2>/dev/null").read().strip()
            if mac:
                return mac
    except Exception:
        pass
    return ""


def _iface_red() -> str:
    try:
        out = os.popen("ip route show default 2>/dev/null").read()
        m = re.search(r"dev\s+(\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    try:
        out = os.popen("route -n 2>/dev/null | grep '^0.0.0.0'").read()
        m = re.search(r"(\S+)\s*$", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def _mac_arp(ip: str) -> str:
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] == ip and parts[3] != "00:00:00:00:00:00":
                    return parts[3]
    except Exception:
        pass
    return ""


VENDOR_OUI = {
    "00:1B:44": "MikroTik",
    "00:1C:42": "Cisco",
    "04:12:34": "Dahua",
    "AC:CC:12": "Dahua",
    "00:08:5D": "Hikvision",
    "08:00:27": "Oracle/VirtualBox",
    "00:11:32": "Synology",
    "E0:1F:88": "Ubiquiti",
    "00:50:C2": "MikroTik",
    "74:4C:A1": "Lenovo",
    "F8:8F:CA": "Apple",
    "00:1E:C2": "Dell",
    "00:23:AE": "Samsung",
    "00:25:9E": "Huawei",
    "00:27:10": "Xiaomi",
    "3C:77:E6": "TP-Link",
    "50:C7:BF": "TP-Link",
    "C0:4A:00": "TP-Link",
    "00:22:6B": "D-Link",
    "18:FE:34": "ZTE",
    "48:22:54": "Huawei",
    "98:DA:C4": "Huawei",
    "A4:77:33": "Xiaomi",
    "00:9A:CD": "Hikvision",
    "3C:07:54": "Dahua",
    "E0:3C:E6": "Dahua/NVR",
    "BC:AD:28": "Dell",
    "3C:DF:BD": "Intel",
    "00:1F:29": "Asus",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:1A:A0": "HP",
    "3C:52:82": "HP",
    "F0:DE:F1": "HP",
    "38:F3:AB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
}


def _vendor_oui(mac: str) -> str:
    prefix = mac.upper()[:8]
    return VENDOR_OUI.get(prefix, "")

SERVICIO_A_TIPO = {
    "http": "servidor",
    "https": "servidor",
    "ssh": "servidor",
    "rtsp": "camara",
    "onvif": "camara",
    "snmp": "router",
    "dhcp": "router",
    "dns": "servidor",
}


def detectar_tipo(servicios: list) -> str:
    if not servicios:
        return "desconocido"
    nombres = [s.lower() for s in servicios if s]
    if "rtsp" in nombres or "onvif" in nombres:
        return "camara"
    if "http" in nombres or "https" in nombres:
        return "servidor"
    if "snmp" in nombres or "dhcp" in nombres:
        return "router"
    return "dispositivo"


def _detectar_segmento(rango_ip: str) -> str:
    limpio = rango_ip.strip()
    if "/" in limpio:
        partes = limpio.split("/")
        octetos = partes[0].split(".")
        if len(octetos) == 4:
            return f"{octetos[0]}.{octetos[1]}.{octetos[2]}.0/{partes[1]}"
    return limpio


def _escáner_un_rango(nm, rango: str, timeout: int) -> list[dict]:
    rango = str(rango).strip()
    # Primer pase: escaneo por ARP en la interfaz activa
    iface = _iface_red()
    args = f"-sn -n -T4 --max-retries 3 -e {iface}" if iface else "-sn -n -T4 --max-retries 3 -e wlp4s0"
    nm.scan(hosts=rango, arguments=args)
    hosts = []
    for ip in nm.all_hosts():
        mac = ""
        vendor = ""
        if "addresses" in nm[ip]:
            mac = nm[ip]["addresses"].get("mac", "")
        if "vendor" in nm[ip] and mac in nm[ip]["vendor"]:
            vendor = nm[ip]["vendor"][mac]
        hosts.append({"ip": ip, "mac": mac, "vendor": vendor})
    # Segundo pase: ARP cache ya caliente, atrapa hosts que no respondieron la primera vez
    if len(hosts) < 5:
        try:
            nm.scan(hosts=rango, arguments=args)
            vistos = {h["ip"] for h in hosts}
            for ip in nm.all_hosts():
                if ip not in vistos:
                    mac = ""
                    vendor = ""
                    if "addresses" in nm[ip]:
                        mac = nm[ip]["addresses"].get("mac", "")
                    if "vendor" in nm[ip] and mac in nm[ip]["vendor"]:
                        vendor = nm[ip]["vendor"][mac]
                    hosts.append({"ip": ip, "mac": mac, "vendor": vendor})
        except Exception:
            pass
    return hosts


def _agregar_o_actualizar(session, ip, hostname, mac, fabricante, tipo, servicios, serial_snmp, descripcion_snmp):
    octetos = ip.split(".")
    segmento_ip = f"{octetos[0]}.{octetos[1]}.{octetos[2]}.0/24" if len(octetos) == 4 else ""
    existente = session.query(Dispositivo).filter_by(ip=ip).first()
    if existente:
        existente.hostname = hostname or existente.hostname
        existente.mac = mac or existente.mac
        existente.fabricante = fabricante or existente.fabricante
        existente.tipo = tipo or existente.tipo
        existente.segmento = existente.segmento or segmento_ip
        existente.serial = serial_snmp or existente.serial
        existente.ultima_vez = datetime.now()
        if descripcion_snmp and not existente.descripcion:
            existente.descripcion = descripcion_snmp
        dispositivo_db = existente
        actualizado = True
    else:
        dispositivo_db = Dispositivo(
            ip=ip, hostname=hostname, mac=mac, fabricante=fabricante,
            tipo=tipo, segmento=segmento_ip, serial=serial_snmp,
            descripcion=descripcion_snmp or "",
            ultima_vez=datetime.now(),
        )
        session.add(dispositivo_db)
        actualizado = False
    session.flush()
    pos_existente = session.query(PosicionTopologia).filter_by(dispositivo_id=dispositivo_db.id).first()
    if not pos_existente:
        angulo = random.uniform(0, 2 * math.pi)
        radio = random.uniform(80, 350)
        session.add(PosicionTopologia(
            dispositivo_id=dispositivo_db.id,
            x=math.cos(angulo) * radio,
            y=math.sin(angulo) * radio,
        ))
    for s in servicios:
        serv_existente = session.query(Servicio).filter_by(
            dispositivo_id=dispositivo_db.id, puerto=s["puerto"], protocolo=s["protocolo"],
        ).first()
        if not serv_existente:
            session.add(Servicio(
                dispositivo_id=dispositivo_db.id,
                puerto=s["puerto"], protocolo=s["protocolo"],
                servicio=s["servicio"], version=s["version"], estado=s["estado"],
            ))
    return dispositivo_db, actualizado


def escanear(rango_ip: str, nombre_cliente: str, timeout: int = 300) -> dict:
    db_path = f"data/{nombre_cliente}.db"
    init_db(db_path)
    session_factory = get_session(db_path)
    session: Session = session_factory()

    try:
        nm = nmap.PortScanner()
        rangos = [r.strip() for r in rango_ip.split(",") if r.strip()]
        hosts_info = []
        for rango in rangos:
            logger.info(f"Escaneando {rango} ...")
            hosts_info.extend(_escáner_un_rango(nm, rango, timeout))

        hosts_info_dict = {}
        for h in hosts_info:
            hosts_info_dict[h["ip"]] = h
        hosts_descubiertos = list(hosts_info_dict.keys())
        logger.info(f"Hosts encontrados: {len(hosts_descubiertos)} - {hosts_descubiertos}")

        nuevos = 0
        actualizados = 0
        resultados = []

        # Fase 1: agregar todos los hosts descubiertos por ARP de inmediato
        for ip in hosts_descubiertos:
            info = hosts_info_dict.get(ip, {})
            mac = info.get("mac", "") or _mac_arp(ip) or _mac_local(ip)
            fabricante = info.get("vendor", "") or _vendor_oui(mac)
            disp, upd = _agregar_o_actualizar(
                session, ip, "", mac, fabricante,
                "dispositivo", [], None, None,
            )
            if not upd:
                nuevos += 1
            else:
                actualizados += 1
            resultados.append({"ip": ip, "hostname": "", "mac": mac, "fabricante": fabricante, "tipo": "dispositivo", "puertos": []})

        session.commit()

        # Fase 2: escaneo de servicios (solo actualiza info, no cuenta como nuevo)
        for ip in hosts_descubiertos:
            try:
                nm.scan(hosts=ip, arguments="-sV -T4 --version-intensity 2 --top-ports 200 --host-timeout 60s")
            except Exception:
                continue
            if ip not in nm.all_hosts():
                continue
            host_data = nm[ip]
            hostname = ""
            if "hostnames" in host_data and host_data["hostnames"]:
                hostname = host_data["hostnames"][0].get("name", "")

            info = hosts_info_dict.get(ip, {})
            mac = info.get("mac", "") or _mac_arp(ip) or _mac_local(ip)
            fabricante = info.get("vendor", "")
            if "addresses" in host_data:
                mac = host_data["addresses"].get("mac", "") or mac
                if "vendor" in host_data and mac in host_data["vendor"]:
                    fabricante = host_data["vendor"][mac] or fabricante
            if mac and not fabricante:
                fabricante = _vendor_oui(mac)

            puertos_abiertos = []
            servicios_detectados = []

            if "tcp" in host_data:
                for puerto, p_info in host_data["tcp"].items():
                    if p_info.get("state") == "open":
                        servicio_nombre = p_info.get("name", "")
                        puertos_abiertos.append({
                            "puerto": puerto, "protocolo": "tcp",
                            "servicio": servicio_nombre,
                            "version": p_info.get("version", ""),
                            "estado": "abierto",
                        })
                        if servicio_nombre:
                            servicios_detectados.append(servicio_nombre)

            tipo = detectar_tipo(servicios_detectados)

            info_snmp = obtener_info_dispositivo(ip, community="public")
            if info_snmp and info_snmp["snmp_disponible"]:
                serial_snmp = info_snmp.get("serial")
                desc_snmp = info_snmp.get("sistema", "")[:120] if info_snmp.get("sistema") else None
            else:
                serial_snmp = None
                desc_snmp = None

            _agregar_o_actualizar(
                session, ip, hostname, mac, fabricante,
                tipo, puertos_abiertos,
                serial_snmp, desc_snmp,
            )

            for r in resultados:
                if r["ip"] == ip:
                    r.update({
                        "hostname": hostname, "fabricante": fabricante,
                        "tipo": tipo, "puertos": puertos_abiertos,
                    })
                    break

        session.commit()
        logger.info(f"Escaneo completado: {nuevos} nuevos, {actualizados} actualizados")
        return {
            "total": len(hosts_descubiertos),
            "nuevos": nuevos,
            "actualizados": actualizados,
            "hosts": resultados,
        }

    except Exception as e:
        session.rollback()
        logger.exception(f"Error durante escaneo: {e}")
        raise
    finally:
        session.close()
