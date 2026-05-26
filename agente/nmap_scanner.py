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
    # ── Routers / Switches / Equipos de red ──
    "00:00:0C": "Cisco",
    "00:01:42": "Cisco",
    "00:05:5E": "Cisco",
    "00:05:9A": "Cisco",
    "00:06:5B": "Cisco",
    "00:06:5C": "Cisco",
    "00:1C:42": "Cisco",
    "00:18:BA": "Cisco",
    "00:1B:D4": "Cisco",
    "00:1E:13": "Cisco",
    "00:1E:7A": "Cisco",
    "00:1F:9E": "Cisco",
    "00:1F:CA": "Cisco",
    "00:21:1B": "Cisco",
    "00:23:0E": "Cisco",
    "00:23:EB": "Cisco",
    "24:70:72": "Cisco",
    "8C:60:4F": "Cisco",
    "B0:AA:77": "Cisco",
    "D4:3D:7E": "Cisco",
    "00:1B:44": "MikroTik",
    "00:50:C2": "MikroTik",
    "4C:5F:70": "MikroTik",
    "64:D1:54": "MikroTik",
    "E4:8D:8C": "MikroTik",
    "F4:F2:6D": "MikroTik",
    "E0:1F:88": "Ubiquiti",
    "00:15:6D": "Ubiquiti",
    "00:27:22": "Ubiquiti",
    "04:18:D6": "Ubiquiti",
    "24:5E:BE": "Ubiquiti",
    "68:72:51": "Ubiquiti",
    "74:83:C2": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "80:2A:A8": "Ubiquiti",
    "D0:21:4A": "Ubiquiti",
    "DC:9F:DB": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti",
    "3C:77:E6": "TP-Link",
    "50:C7:BF": "TP-Link",
    "C0:4A:00": "TP-Link",
    "00:1E:63": "TP-Link",
    "14:CF:92": "TP-Link",
    "1C:3B:F3": "TP-Link",
    "20:E8:29": "TP-Link",
    "30:B5:C2": "TP-Link",
    "34:08:04": "TP-Link",
    "54:AF:97": "TP-Link",
    "60:31:97": "TP-Link",
    "64:0F:28": "TP-Link",
    "70:4C:A5": "TP-Link",
    "84:C7:EA": "TP-Link",
    "90:F6:52": "TP-Link",
    "A0:F3:C1": "TP-Link",
    "AC:15:18": "TP-Link",
    "B0:BE:83": "TP-Link",
    "B4:B0:24": "TP-Link",
    "C8:3A:35": "TP-Link",
    "D4:6E:0E": "TP-Link",
    "D8:0D:17": "TP-Link",
    "E8:48:B8": "TP-Link",
    "F4:EC:38": "TP-Link",
    "F8:0D:43": "TP-Link",
    "00:22:6B": "D-Link",
    "1C:5F:2B": "D-Link",
    "28:10:7B": "D-Link",
    "58:6D:8F": "D-Link",
    "C0:3F:0E": "D-Link",
    "CC:B2:55": "D-Link",
    "E0:B4:19": "D-Link",
    "F0:7D:68": "D-Link",
    "00:1A:A0": "HP",
    "3C:52:82": "HP",
    "F0:DE:F1": "HP",
    "48:22:54": "Huawei",
    "98:DA:C4": "Huawei",
    "00:25:9E": "Huawei",
    "04:DD:4C": "Huawei",
    "24:46:C8": "Huawei",
    "2C:54:91": "Huawei",
    "34:97:F6": "Huawei",
    "54:41:3A": "Huawei",
    "5C:35:3B": "Huawei",
    "64:16:8F": "Huawei",
    "6C:92:BF": "Huawei",
    "80:2E:14": "Huawei",
    "8C:3B:AD": "Huawei",
    "94:DA:56": "Huawei",
    "A0:57:E3": "Huawei",
    "BC:76:70": "Huawei",
    "C0:9B:3A": "Huawei",
    "18:FE:34": "ZTE",
    "00:1F:29": "Asus",
    "10:BF:48": "Asus",
    "14:2D:7E": "Asus",
    "1C:87:2C": "Asus",
    "24:4B:FE": "Asus",
    "28:2C:B2": "Asus",
    "40:16:9E": "Asus",
    "50:C7:BF": "Asus",
    "54:04:A6": "Asus",
    "5C:DC:96": "Asus",
    "60:92:17": "Asus",
    "68:2E:2B": "Asus",
    "70:4D:7B": "Asus",
    "74:D0:2B": "Asus",
    "78:24:AF": "Asus",
    "80:32:53": "Aruba",
    "A0:21:B7": "Aruba",
    "A8:BD:1A": "Aruba",
    "CC:2D:E0": "Aruba",
    "00:19:06": "Netgear",
    "20:E5:2A": "Netgear",
    "2C:33:11": "Netgear",
    "30:46:9A": "Netgear",
    "44:94:FC": "Netgear",
    "50:6A:03": "Netgear",
    "80:3F:5D": "Netgear",
    "98:15:1F": "Netgear",
    "9C:3D:CF": "Netgear",
    "A0:14:3D": "Netgear",
    "A0:40:41": "Netgear",
    "B0:39:56": "Netgear",
    "C0:3F:0E": "Netgear",
    "D0:37:45": "Netgear",
    "DC:EF:09": "Netgear",
    "E0:3C:E6": "Netgear",
    "F4:3F:2B": "Netgear",
    "00:19:77": "Juniper",
    "28:58:7A": "Juniper",
    "40:9B:CD": "Juniper",
    "4C:96:14": "Juniper",
    "A8:C2:05": "Juniper",
    "CC:DF:EC": "Juniper",
    "E0:DC:FF": "Juniper",
    "00:05:86": "Extreme Networks",
    "00:E0:52": "Extreme Networks",
    "3C:2C:30": "Extreme Networks",
    "3C:D9:2B": "Extreme Networks",
    "00:0F:EA": "Intelbras",
    "08:BE:09": "Intelbras",
    "0C:7D:7B": "Intelbras",
    "64:09:80": "Intelbras",
    "E0:B1:4C": "Intelbras",

    # ── Cámaras / CCTV ──
    "04:12:34": "Dahua",
    "AC:CC:12": "Dahua",
    "3C:07:54": "Dahua",
    "E0:3C:E6": "Dahua",
    "9C:EB:E8": "Dahua",
    "00:08:5D": "Hikvision",
    "00:9A:CD": "Hikvision",
    "10:1B:54": "Hikvision",
    "44:6C:42": "Hikvision",
    "48:A2:E6": "Hikvision",
    "A4:30:67": "Hikvision",
    "0C:C4:7A": "Uniview",
    "4C:9E:80": "Uniview",
    "7C:2E:0C": "Uniview",
    "00:30:54": "Axis",
    "04:40:86": "Axis",
    "AC:CC:8E": "Axis",
    "B8:A3:86": "Axis",
    "C0:8E:57": "Axis",
    "00:0B:DB": "Bosch",
    "00:1C:4A": "Bosch",
    "48:A6:8D": "Bosch",
    "00:0B:8F": "Geovision",
    "00:17:C8": "Vivotek",
    "EC:43:F6": "Vivotek",
    "00:02:D1": "ACTi",
    "00:19:4F": "Mobotix",
    "00:1B:3F": "Hanwha",
    "00:09:18": "Hanwha",
    "08:62:66": "Honeywell",
    "44:55:4C": "Honeywell",
    "00:05:37": "Tyco",
    "00:12:3F": "Avermedia",

    # ── Celulares / Smartphones ──
    "F8:8F:CA": "Apple",
    "00:23:AE": "Samsung",
    "A4:77:33": "Xiaomi",
    "00:27:10": "Xiaomi",
    "18:FE:34": "OnePlus",
    "9C:FC:E8": "OnePlus",
    "E8:48:B8": "Xiaomi",
    "00:25:9E": "Huawei",
    "5C:02:72": "Samsung",
    "9C:28:EF": "Samsung",
    "7C:11:BE": "Google",
    "A4:77:58": "Google",
    "18:FB:9B": "LG",
    "E0:CB:4E": "LG",
    "58:CB:52": "LG",
    "70:5D:23": "Motorola",
    "00:15:0D": "Motorola",
    "9C:35:EB": "Motorola",
    "C8:1F:BE": "Motorola",
    "00:23:76": "Nokia",
    "28:16:65": "Nokia",
    "4C:17:EB": "Nokia",
    "60:57:18": "Nokia",
    "00:0A:28": "Sony",
    "4C:E1:73": "Sony",
    "6C:6E:97": "Sony",
    "D0:AE:EC": "Sony",
    "00:1A:8C": "BlackBerry",
    "B0:75:D5": "BlackBerry",
    "BC:6A:16": "Realme",
    "C8:5A:CF": "Realme",
    "10:F6:81": "Oppo",
    "98:3C:8F": "Oppo",
    "70:D9:31": "Vivo",
    "D0:5A:0A": "Vivo",
    "C8:20:2F": "OnePlus",
    "D8:12:65": "OnePlus",
    "2C:05:47": "OnePlus",

    # ── Tarjetas de red / NICs ──
    "3C:DF:BD": "Intel",
    "00:1B:21": "Intel",
    "00:1E:67": "Intel",
    "00:1F:3C": "Intel",
    "00:1F:29": "Intel",
    "00:24:D6": "Intel",
    "00:26:55": "Intel",
    "00:26:C6": "Intel",
    "00:27:13": "Intel",
    "00:30:64": "Intel",
    "4C:ED:DE": "Intel",
    "8C:1D:96": "Intel",
    "A0:36:9F": "Intel",
    "A0:48:1C": "Intel",
    "AC:1F:6B": "Intel",
    "B4:96:91": "Intel",
    "BC:AE:C5": "Intel",
    "E0:B9:BA": "Intel",
    "F0:1F:AF": "Intel",
    "00:E0:4C": "Realtek",
    "00:E0:4C": "Realtek",
    "08:00:27": "Realtek",
    "10:BF:48": "Realtek",
    "52:54:00": "Realtek",
    "74:DA:EA": "Realtek",
    "9C:2E:A1": "Realtek",
    "D8:5D:E2": "Realtek",
    "00:0A:F7": "Broadcom",
    "00:10:18": "Broadcom",
    "00:10:5A": "Broadcom",
    "00:14:5E": "Broadcom",
    "00:17:F2": "Broadcom",
    "00:1B:11": "Broadcom",
    "00:23:68": "Broadcom",
    "14:10:9F": "Broadcom",
    "3C:07:54": "Broadcom",
    "6C:3B:6B": "Broadcom",
    "A4:1F:72": "Broadcom",
    "AC:84:C6": "Broadcom",
    "00:0D:88": "MediaTek",
    "00:1A:EF": "MediaTek",
    "04:4F:4C": "MediaTek",
    "08:11:96": "MediaTek",
    "28:16:2E": "MediaTek",
    "2C:3E:CF": "MediaTek",
    "48:22:1B": "MediaTek",
    "64:7E:46": "MediaTek",
    "6C:B0:CE": "MediaTek",
    "B0:7D:64": "MediaTek",
    "C8:6C:87": "MediaTek",
    "00:0E:6A": "Qualcomm/Atheros",
    "00:03:7F": "Qualcomm/Atheros",
    "00:13:10": "Qualcomm/Atheros",
    "00:15:AF": "Qualcomm/Atheros",
    "00:20:D6": "Qualcomm/Atheros",
    "00:23:CD": "Qualcomm/Atheros",
    "04:F0:21": "Qualcomm/Atheros",
    "08:3E:8E": "Qualcomm/Atheros",
    "0C:84:DC": "Qualcomm/Atheros",
    "28:6C:07": "Qualcomm/Atheros",
    "3C:7D:0A": "Qualcomm/Atheros",
    "40:9B:90": "Qualcomm/Atheros",
    "48:F9:F1": "Qualcomm/Atheros",
    "64:1C:67": "Qualcomm/Atheros",
    "70:62:B8": "Qualcomm/Atheros",
    "78:8C:B5": "Qualcomm/Atheros",
    "7C:03:4C": "Qualcomm/Atheros",
    "80:D1:6B": "Qualcomm/Atheros",
    "84:DB:2F": "Qualcomm/Atheros",
    "8C:7B:9D": "Qualcomm/Atheros",
    "94:B9:7E": "Qualcomm/Atheros",
    "A0:F3:C1": "Qualcomm/Atheros",
    "AC:14:61": "Qualcomm/Atheros",
    "B0:48:7A": "Qualcomm/Atheros",
    "B8:3E:59": "Qualcomm/Atheros",
    "C0:4A:00": "Qualcomm/Atheros",
    "C8:3A:35": "Qualcomm/Atheros",
    "CC:B2:55": "Qualcomm/Atheros",
    "D0:37:45": "Qualcomm/Atheros",
    "D4:6E:0E": "Qualcomm/Atheros",
    "D8:0D:17": "Qualcomm/Atheros",
    "D8:96:95": "Qualcomm/Atheros",
    "40:8D:0A": "Ralink",
    "00:0C:43": "Ralink",
    "00:1F:1F": "Ralink",
    "04:0C:CE": "Ralink",
    "14:CF:92": "Ralink",
    "1C:5F:2B": "Ralink",
    "28:28:5D": "Ralink",
    "2C:B0:5D": "Ralink",
    "3C:7A:8A": "Ralink",
    "50:3E:AA": "Ralink",
    "54:E6:FC": "Ralink",
    "64:0F:28": "Ralink",
    "68:2E:2B": "Ralink",
    "74:DA:EA": "Ralink",
    "84:C7:EA": "Ralink",
    "8C:A6:DF": "Ralink",
    "94:D9:B3": "Ralink",
    "B0:48:7A": "Ralink",
    "B8:7C:6F": "Ralink",
    "BC:F6:85": "Ralink",
    "C0:3F:0E": "Ralink",
    "C8:3A:35": "Ralink",
    "D4:CA:6D": "Ralink",
    "D8:1C:79": "Ralink",
    "E0:3C:E6": "Ralink",
    "E4:D3:32": "Ralink",
    "F0:2F:74": "Ralink",
    "F4:3F:2B": "Ralink",
    "F4:EC:38": "Ralink",
    "F8:0D:43": "Ralink",
    "FC:2F:40": "Ralink",

    # ── PCs / Laptops / Servidores ──
    "BC:AD:28": "Dell",
    "00:1E:C2": "Dell",
    "00:14:22": "Dell",
    "00:1A:1B": "Dell",
    "00:1C:23": "Dell",
    "00:21:70": "Dell",
    "08:00:27": "Dell",
    "14:18:77": "Dell",
    "18:03:73": "Dell",
    "34:81:72": "Dell",
    "54:E0:32": "Dell",
    "98:4B:E1": "Dell",
    "B8:AC:6F": "Dell",
    "F0:1F:AF": "Dell",
    "74:4C:A1": "Lenovo",
    "00:1A:4B": "Lenovo",
    "38:2C:4A": "Lenovo",
    "3C:E3:6B": "Lenovo",
    "48:51:B7": "Lenovo",
    "60:6C:66": "Lenovo",
    "6C:0B:84": "Lenovo",
    "80:C6:3B": "Lenovo",
    "B8:8D:12": "Lenovo",
    "E4:1F:13": "Lenovo",
    "F4:0F:24": "Lenovo",
    "00:1A:A0": "HP",
    "3C:52:82": "HP",
    "F0:DE:F1": "HP",
    "14:99:E2": "HP",
    "2C:FD:A1": "HP",
    "4C:5F:70": "HP",
    "5C:95:AE": "HP",
    "64:8A:6F": "HP",
    "84:A9:3E": "HP",
    "9C:8C:6E": "HP",
    "A0:21:B7": "HP",
    "A0:5E:6B": "HP",
    "B8:6B:23": "HP",
    "E0:07:1B": "HP",
    "E8:39:35": "HP",
    "00:1F:29": "Asus",
    "10:BF:48": "Asus",
    "14:2D:7E": "Asus",
    "1C:87:2C": "Asus",
    "28:2C:B2": "Asus",
    "5C:DC:96": "Asus",
    "80:32:53": "Asus",
    "AC:22:0B": "Asus",
    "B0:6A:2A": "Asus",
    "B8:5A:F7": "Asus",
    "B8:6A:73": "Asus",
    "00:0E:AD": "Acer",
    "00:17:31": "Acer",
    "00:1B:B9": "Acer",
    "00:23:8B": "Acer",
    "2C:33:11": "Acer",
    "38:E7:D8": "Acer",
    "50:3E:AA": "Acer",
    "80:3F:5D": "Acer",
    "B0:39:56": "Acer",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:1C:14": "VMware",
    "00:0F:4B": "Xen",
    "00:16:3E": "Xen",
    "08:00:27": "Oracle/VirtualBox",
    "00:11:32": "Synology",
    "00:0F:E2": "QNAP",
    "24:5E:BE": "QNAP",
    "00:1C:B3": "Supermicro",
    "08:3E:8E": "Supermicro",
    "3C:EC:EF": "Supermicro",
    "00:25:90": "Microsoft",
    "00:15:5D": "Microsoft/Hyper-V",
    "00:03:FF": "Microsoft/Hyper-V",
    "08:00:27": "PCS Systemtechnik",

    # ── IoT / Raspberries ──
    "38:F3:AB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi",
    "00:0E:8E": "Arduino",
    "54:32:04": "Arduino",
    "84:0D:8E": "Arduino",
    "A4:CF:12": "ESPressif",
    "24:6F:28": "ESPressif",
    "18:FE:34": "ESPressif",
    "5C:CF:7F": "ESPressif",
    "EC:FA:BC": "ESPressif",
    "AC:D0:74": "ESPressif",
    "68:C6:3A": "ESPressif",
    "2C:F4:32": "ESPressif",
    "80:7D:3B": "ESPressif",
    "48:3F:DA": "ESPressif",
    "24:0A:C4": "ESPressif",
    "08:3A:8D": "ESPressif",
    "C0:5B:27": "NVIDIA",
    "04:92:26": "NVIDIA",
    "00:04:4B": "NVIDIA",
    "48:B0:2D": "NVIDIA",
    "34:6F:24": "Intelbras",
    "48:22:54": "Intelbras",
    "74:4C:A1": "Intelbras",
    "80:32:53": "Intelbras",
}


HOSTNAME_FABRICANTE = [
    ("iPhone", "Apple"), ("iPad", "Apple"), ("iPod", "Apple"), ("MacBook", "Apple"),
    ("iMac", "Apple"), ("Mac Pro", "Apple"), ("Mac mini", "Apple"), ("Apple TV", "Apple"),
    ("HomePod", "Apple"),
    ("SM-", "Samsung"), ("SAMSUNG", "Samsung"), ("Galaxy", "Samsung"),
    ("GT-", "Samsung"), ("GALAXY", "Samsung"),
    ("Redmi", "Xiaomi"), ("Mi ", "Xiaomi"), ("POCO", "Xiaomi"),
    ("M200", "Xiaomi"), ("M210", "Xiaomi"), ("M201", "Xiaomi"), ("M211", "Xiaomi"),
    ("Xiaomi", "Xiaomi"), ("MI ", "Xiaomi"),
    ("HUAWEI", "Huawei"), ("Huawei", "Huawei"), ("Mate", "Huawei"),
    ("P30", "Huawei"), ("P40", "Huawei"), ("P50", "Huawei"), ("Y9", "Huawei"),
    ("Nova", "Huawei"), ("Honor", "Huawei"),
    ("OnePlus", "OnePlus"), ("ONEPLUS", "OnePlus"),
    ("Pixel", "Google"),
    ("Moto ", "Motorola"), ("Moto-", "Motorola"), ("motorola", "Motorola"),
    ("MotoG", "Motorola"), ("Moto E", "Motorola"), ("edge+", "Motorola"),
    ("LG-", "LG"), ("LGM", "LG"), ("LM-", "LG"),
    ("Nokia", "Nokia"), ("NOKIA", "Nokia"),
    ("Sony", "Sony"), ("Xperia", "Sony"),
    ("OPPO", "Oppo"), ("Oppo", "Oppo"),
    ("Vivo", "Vivo"), ("vivo", "Vivo"),
    ("Realme", "Realme"), ("realme", "Realme"), ("RMA", "Realme"),
    ("TECNO", "Tecno"), ("Infinix", "Infinix"),
    ("ThinkPad", "Lenovo"), ("IdeaPad", "Lenovo"), ("Legion", "Lenovo"),
    ("Yoga", "Lenovo"), ("Lenovo", "Lenovo"),
    ("ASUS", "Asus"), ("TUF", "Asus"), ("ROG", "Asus"),
    ("DESKTOP-", "Windows PC"), ("LAPTOP-", "Windows Laptop"),
]


def _es_mac_aleatoria(mac: str) -> bool:
    """Las MACs con bit U/L=1 son locales/aleatorias (no se puede identificar fabricante por OUI)."""
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def detectar_fabricante(mac: str, vendor_nmap: str = "", hostname: str = "") -> str:
    if vendor_nmap and vendor_nmap.strip():
        return vendor_nmap.strip()
    prefix = mac.upper()[:8] if mac else ""
    if prefix in VENDOR_OUI:
        return VENDOR_OUI[prefix]
    if hostname:
        h = hostname.strip()
        for patron, marca in HOSTNAME_FABRICANTE:
            if h.startswith(patron) or patron in h:
                return marca
    if mac and mac != "00:00:00:00:00:00":
        if _es_mac_aleatoria(mac):
            return ""
        return "desconocido"
    return ""

SERVICIO_A_TIPO = {
    "http": "servidor",
    "https": "servidor",
    "ssh": "servidor",
    "rtsp": "camara",
    "onvif": "camara",
    "snmp": "router",
    "dhcp": "router",
    "dns": "servidor",
    "domain": "servidor",
    "kerberos": "servidor",
    "ldap": "servidor",
    "msrpc": "servidor",
    "smtp": "servidor",
    "pop3": "servidor",
    "imap": "servidor",
    "mysql": "servidor",
    "postgresql": "servidor",
    "mssql": "servidor",
    "ftp": "servidor",
    "samba": "servidor",
    "nfs": "servidor",
    "ipp": "impresora",
    "printer": "impresora",
}


PRIORIDAD_TIPO = {"camara": 5, "impresora": 4, "servidor": 3, "router": 2, "computadora": 1, "dispositivo": 0, "desconocido": -1}


def detectar_tipo(servicios: list) -> str:
    if not servicios:
        return "desconocido"
    nombres = [s.lower() for s in servicios if s]
    encontrado = ""
    for servicio, tipo in SERVICIO_A_TIPO.items():
        for n in nombres:
            if servicio in n:
                if PRIORIDAD_TIPO.get(tipo, 0) > PRIORIDAD_TIPO.get(encontrado, -1):
                    encontrado = tipo
    return encontrado or "dispositivo"


def detectar_tipo_por_hostname(hostname: str) -> str:
    if not hostname:
        return ""
    h = hostname.strip().lower()
    if h in ("_gateway", "gateway", "router", "router.asus.com", "router.router", "my.router"):
        return "router"
    if h.startswith("ap-") or h.startswith("wap-") or "accesspoint" in h:
        return "router"
    if "switch" in h:
        return "router"
    if h.startswith("cam-") or h.startswith("ipcam") or "camera" in h or "camara" in h:
        return "camara"
    if "printer" in h or "print" in h or "npi" in h:
        return "impresora"
    if "server" in h or "servidor" in h or "nas" in h or "synology" in h or "qnap" in h:
        return "servidor"
    if "laptop" in h or "notebook" in h or "desktop" in h or "pc-" in h:
        return "computadora"
    return ""


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
        fabricante = detectar_fabricante(mac, vendor)
        hosts.append({"ip": ip, "mac": mac, "fabricante": fabricante})
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
                    fabricante = detectar_fabricante(mac, vendor)
                    hosts.append({"ip": ip, "mac": mac, "fabricante": fabricante})
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
        if tipo:
            prioridad = {"camara": 5, "impresora": 4, "servidor": 3, "router": 2, "computadora": 1, "dispositivo": 0, "desconocido": -1}
            if prioridad.get(tipo, 0) >= prioridad.get(existente.tipo or "", 0):
                existente.tipo = tipo
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
            fabricante = info.get("fabricante", "") or detectar_fabricante(mac, info.get("vendor", ""))
            tipo_inicial = "dispositivo" if not session.query(Dispositivo).filter_by(ip=ip).first() else ""
            disp, upd = _agregar_o_actualizar(
                session, ip, "", mac, fabricante,
                tipo_inicial, [], None, None,
            )
            if not upd:
                nuevos += 1
            else:
                actualizados += 1
            resultados.append({"ip": ip, "hostname": "", "mac": mac, "fabricante": fabricante, "tipo": tipo_inicial or "dispositivo", "puertos": []})

        session.commit()

        # Fase 2: escaneo de servicios + detección de SO (si hay permisos)
        for ip in hosts_descubiertos:
            try:
                nm.scan(hosts=ip, arguments="-sV -O -T4 --version-intensity 2 --top-ports 200 --host-timeout 90s")
            except Exception:
                try:
                    nm.scan(hosts=ip, arguments="-sT -sV -T4 --version-intensity 2 --top-ports 200 --host-timeout 90s")
                except Exception:
                    continue
            if ip not in nm.all_hosts():
                continue
            host_data = nm[ip]
            hostname = ""
            if "hostnames" in host_data and host_data["hostnames"]:
                hostname = host_data["hostnames"][0].get("name", "")

            so_detectado = ""
            if "osmatch" in host_data and host_data["osmatch"]:
                mejor_os = host_data["osmatch"][0]
                so_nombre = mejor_os.get("name", "")
                so_detectado = so_nombre
                if "osclass" in mejor_os and mejor_os["osclass"]:
                    vendor_os = mejor_os["osclass"][0].get("vendor", "")
                    if vendor_os:
                        so_detectado = f"{vendor_os} - {so_nombre}"

            info = hosts_info_dict.get(ip, {})
            mac = info.get("mac", "") or _mac_arp(ip) or _mac_local(ip)
            fabricante = info.get("fabricante", "")
            if "addresses" in host_data:
                mac = host_data["addresses"].get("mac", "") or mac
                if "vendor" in host_data and mac in host_data["vendor"]:
                    fabricante = detectar_fabricante(mac, host_data["vendor"][mac], hostname)
            if mac and not fabricante:
                fabricante = detectar_fabricante(mac, hostname=hostname)

            # Fallback de fabricante por SO detectado
            if not fabricante and so_detectado:
                so_lower = so_detectado.lower()
                if "ios" in so_lower or "iphone" in so_lower or "ipad" in so_lower or "darwin" in so_lower or "mac os" in so_lower or "macos" in so_lower:
                    fabricante = "Apple"
                elif "android" in so_lower:
                    fabricante = "Android"
                elif "windows" in so_lower:
                    fabricante = "Windows"
                elif "apple" in so_lower:
                    fabricante = "Apple"
                elif "google" in so_lower:
                    fabricante = "Google"
                elif "samsung" in so_lower:
                    fabricante = "Samsung"
                elif "huawei" in so_lower:
                    fabricante = "Huawei"
                elif "linux" in so_lower:
                    fabricante = "Linux"

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
            if tipo in ("dispositivo", "desconocido", ""):
                tipo_hostname = detectar_tipo_por_hostname(hostname)
                if tipo_hostname and PRIORIDAD_TIPO.get(tipo_hostname, 0) > PRIORIDAD_TIPO.get(tipo, -1):
                    tipo = tipo_hostname

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
