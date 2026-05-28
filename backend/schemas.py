from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime


class DispositivoCreate(BaseModel):
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    fabricante: Optional[str] = None
    tipo: Optional[str] = None
    descripcion: Optional[str] = None
    tipo_asignacion_ip: Optional[str] = "desconocido"


class DispositivoOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    cliente_id: int
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    fabricante: Optional[str] = None
    tipo: Optional[str] = None
    descripcion: Optional[str] = None
    primera_vez: Optional[datetime] = None
    ultima_vez: Optional[datetime] = None
    activo: int = 1
    segmento: Optional[str] = None
    serial: Optional[str] = None
    tipo_asignacion_ip: Optional[str] = "desconocido"
    vendor_method: Optional[str] = None
    vendor_confidence: Optional[int] = None
    hostname_method: Optional[str] = None
    hostname_confidence: Optional[int] = None


class PingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    cliente_id: int
    dispositivo_id: int
    timestamp: datetime
    estado: str
    latencia_ms: Optional[float] = None
    perdida_pct: Optional[float] = None


class ServicioOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    cliente_id: int
    dispositivo_id: int
    puerto: int
    protocolo: Optional[str] = None
    servicio: Optional[str] = None
    version: Optional[str] = None
    estado: Optional[str] = None


class AlertaOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    cliente_id: int
    dispositivo_id: int
    tipo: str
    mensaje: Optional[str] = None
    timestamp: datetime
    resuelta: int = 0
    analisis_ia: Optional[str] = None
    ip: Optional[str] = None


class ScanRequest(BaseModel):
    rango_ip: str
    nombre_cliente: str


class PosicionUpdate(BaseModel):
    dispositivo_id: int
    x: float
    y: float


class StatsOut(BaseModel):
    total_dispositivos: int
    activos: int
    warn: int = 0
    degradados: int = 0
    caidos: int
    alertas_pendientes: int
    total_pings: int = 0


class ChatRequest(BaseModel):
    pregunta: str
    nombre_cliente: str = "red_cliente"


class NotificacionRequest(BaseModel):
    asunto: str
    cuerpo: str


class DispositivoConEstado(DispositivoOut):
    estado: str = "desconocido"
    latencia_ms: Optional[float] = None
    alias: Optional[str] = None


class CredencialCreate(BaseModel):
    dispositivo_id: int
    alias: Optional[str] = ""
    admin_pass: Optional[str] = ""
    usuario: Optional[str] = ""
    app_pass: Optional[str] = ""
    observacion: Optional[str] = ""
    serial: Optional[str] = ""


class CredencialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    dispositivo_id: int
    alias: Optional[str] = ""
    admin_pass: Optional[str] = ""
    usuario: Optional[str] = ""
    app_pass: Optional[str] = ""
    observacion: Optional[str] = ""
