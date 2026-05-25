import os
import logging
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session

from backend.database import init_db, get_session
from backend.models import Dispositivo, Ping, Alerta
from backend.ia_bridge import generate_report_summary

logger = logging.getLogger("vigia.reporte")

REPORTES_DIR = "reportes"


def _colectar_datos(session: Session) -> dict:
    dispositivos = session.query(Dispositivo).order_by(Dispositivo.ip).all()

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
        .filter_by(resuelta=0)
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
        "cliente": "",
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "tecnico": "",
        "total_dispositivos": total,
        "activos": activos,
        "caidos": caidos,
        "items": items,
        "alertas": alertas_data,
        "resumen_ia": resumen_ia,
    }


def generar_html(nombre_cliente: str) -> str:
    db_path = f"data/{nombre_cliente}.db"
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Base de datos no encontrada: {db_path}")

    init_db(db_path)
    session = get_session(db_path)()

    try:
        datos = _colectar_datos(session)
        datos["cliente"] = nombre_cliente

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
    db_path = f"data/{nombre_cliente}.db"
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Base de datos no encontrada: {db_path}")

    init_db(db_path)
    session = get_session(db_path)()

    try:
        datos = _colectar_datos(session)
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

        lineas.append("-" * 60)
        lineas.append("Dispositivos:")
        lineas.append("-" * 60)
        lineas.append(f"{'IP':<16} {'Hostname':<20} {'MAC':<18} {'Serial':<16} {'Fabricante':<14} {'Tipo':<14} {'Estado':<10} {'Latencia':<10}")
        lineas.append("-" * 60)
        for d in datos["items"]:
            lat = f"{d['latencia']:.0f}ms" if d["latencia"] is not None else "—"
            lineas.append(f"{d['ip']:<16} {d['hostname']:<20} {d['mac']:<18} {d['serial']:<16} {d['fabricante']:<14} {d['tipo']:<14} {d['estado']:<10} {lat:<10}")
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
