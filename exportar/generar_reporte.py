import os
import logging
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session

from backend.database import init_db, get_session, get_or_create_cliente
from backend.models import Dispositivo, Ping, Alerta, Credencial
from backend.ia_bridge import generate_report_summary

logger = logging.getLogger("vigia.reporte")

REPORTES_DIR = "reportes"


def _colectar_datos(session: Session, nombre_cliente: str = "", cid: int = 0) -> dict:
    dispositivos = session.query(Dispositivo).filter_by(cliente_id=cid).order_by(Dispositivo.ip).all()

    total = len(dispositivos)
    activos = 0
    caidos = 0
    items = []

    for d in dispositivos:
        ultimo_ping = (
            session.query(Ping)
            .filter_by(dispositivo_id=d.id)
            .order_by(Ping.id.desc())
            .first()
        )

        estado = "desconocido"
        latencia = None
        if ultimo_ping:
            estado = ultimo_ping.estado
            latencia = ultimo_ping.latencia_ms

        historial = (
            session.query(Ping)
            .filter_by(dispositivo_id=d.id)
            .order_by(Ping.id.desc())
            .limit(24)
            .all()
        )

        cred = session.query(Credencial).filter_by(dispositivo_id=d.id).first()

        if estado == "up":
            activos += 1
        elif estado in ("down", "timeout"):
            caidos += 1

        items.append({
            "ip": d.ip,
            "hostname": d.hostname or "—",
            "mac": d.mac or "—",
            "serial": d.serial or "—",
            "tipo": d.tipo or "desconocido",
            "fabricante": d.fabricante or "—",
            "alias": cred.alias if cred else "—",
            "usuario": cred.usuario if cred else "—",
            "admin_pass": cred.admin_pass if cred else "—",
            "app_pass": cred.app_pass if cred else "—",
            "observacion": cred.observacion if cred else "—",
            "estado": estado,
            "latencia": latencia,
            "ultima_vez": d.ultima_vez,
            "historial": [
                {
                    "timestamp": p.timestamp,
                    "estado": p.estado,
                    "latencia_ms": p.latencia_ms,
                }
                for p in historial
            ],
        })

    alertas_pendientes = (
        session.query(Alerta)
        .filter_by(resuelta=0, cliente_id=cid)
        .order_by(Alerta.timestamp.desc())
        .limit(50)
        .all()
    )

    alertas_data = [
        {
            "id": a.id,
            "tipo": a.tipo,
            "mensaje": a.mensaje,
            "timestamp": a.timestamp,
        }
        for a in alertas_pendientes
    ]

    resumen_ia = generate_report_summary({
        "total": total,
        "activos": activos,
        "alertas": len(alertas_pendientes),
        "periodo": datetime.now().strftime("%Y-%m-%d %H:%M"),
    })

    return {
        "cliente": nombre_cliente,
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "tecnico": "Alejandro Montenegro",
        "total_dispositivos": total,
        "activos": activos,
        "caidos": caidos,
        "items": items,
        "alertas": alertas_data,
        "resumen_ia": resumen_ia,
    }


def generar_html(nombre_cliente: str) -> str:
    init_db()
    session = get_session()
    cid = get_or_create_cliente(session, nombre_cliente)

    try:
        datos = _colectar_datos(session, nombre_cliente, cid)

        template_dir = Path(__file__).resolve().parent.parent / "frontend"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        template = env.get_template("reporte_template.html")
        html = template.render(**datos)

        os.makedirs(REPORTES_DIR, exist_ok=True)
        filename = f"reporte_{nombre_cliente}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(REPORTES_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"Reporte HTML generado: {filepath}")
        return filepath
    finally:
        session.close()


def generar_txt(nombre_cliente: str) -> str:
    init_db()
    session = get_session()
    cid = get_or_create_cliente(session, nombre_cliente)

    try:
        datos = _colectar_datos(session, nombre_cliente, cid)
        lineas = []
        lineas.append("=" * 60)
        lineas.append(f"  VigIA - Reporte de Red")
        lineas.append(f"  Cliente: {nombre_cliente}")
        lineas.append(f"  Fecha: {datos['fecha']}")
        lineas.append("=" * 60)
        lineas.append("")
        lineas.append(f"Resumen:")
        lineas.append(f"  Total dispositivos: {datos['total_dispositivos']}")
        lineas.append(f"  Activos:           {datos['activos']}")
        lineas.append(f"  Caidos:            {datos['caidos']}")
        lineas.append(f"  Alertas pendientes: {len(datos['alertas'])}")
        lineas.append("")

        if datos["resumen_ia"] and "No se pudo" not in datos["resumen_ia"] and "no disponible" not in datos["resumen_ia"]:
            lineas.append(f"Analisis IA:")
            lineas.append(f"  {datos['resumen_ia']}")
            lineas.append("")

        lineas.append("-" * 120)
        lineas.append("Dispositivos:")
        lineas.append("-" * 120)
        lineas.append(f"{'IP':<16} {'Hostname':<16} {'MAC':<18} {'Alias':<14} {'Usuario':<14} {'Clave Admin':<14} {'Clave App':<14} {'Estado':<10} {'Latencia':<8}")
        lineas.append("-" * 120)
        for d in datos["items"]:
            lat = f"{d['latencia']:.0f}ms" if d["latencia"] is not None else "—"
            lineas.append(f"{d['ip']:<16} {d['hostname']:<16} {d['mac']:<18} {d['alias']:<14} {d['usuario']:<14} {d['admin_pass']:<14} {d['app_pass']:<14} {d['estado']:<10} {lat:<8}")
        lineas.append("")

        if datos["alertas"]:
            lineas.append("-" * 60)
            lineas.append("Alertas pendientes:")
            lineas.append("-" * 60)
            for a in datos["alertas"]:
                ts = a["timestamp"].strftime("%Y-%m-%d %H:%M") if a["timestamp"] else "—"
                lineas.append(f"  [{ts}] {a['tipo']}: {a['mensaje'] or '—'}")
            lineas.append("")

        lineas.append("=" * 60)
        lineas.append("  Generado por VigIA v0.1 - MARDAN Colombia")
        lineas.append("=" * 60)

        contenido = "\n".join(lineas)

        os.makedirs(REPORTES_DIR, exist_ok=True)
        filename = f"reporte_{nombre_cliente}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(REPORTES_DIR, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(contenido)

        logger.info(f"Reporte TXT generado: {filepath}")
        return filepath
    finally:
        session.close()


def generar(nombre_cliente: str, formato: str = "html"):
    if formato == "html":
        return generar_html(nombre_cliente)
    elif formato == "txt":
        return generar_txt(nombre_cliente)
    else:
        raise ValueError(f"Formato no soportado: {formato}")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    cliente = sys.argv[1] if len(sys.argv) > 1 else "red_cliente"
    fmt = sys.argv[2] if len(sys.argv) > 2 else "html"
    ruta = generar(cliente, fmt)
    print(f"Reporte generado: {ruta}")
