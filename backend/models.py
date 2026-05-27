from sqlalchemy import (
    Column, Integer, Text, String, Float, DateTime,
    ForeignKey, UniqueConstraint, Index, func
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Cliente(Base):
    __tablename__ = "clientes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    nombre = Column(String(255), nullable=False, unique=True)

    dispositivos = relationship("Dispositivo", back_populates="cliente_rel", cascade="all, delete-orphan")


class Dispositivo(Base):
    __tablename__ = "dispositivos"
    __table_args__ = (
        UniqueConstraint("cliente_id", "ip", name="uq_cliente_ip"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    cliente_id = Column(Integer, ForeignKey("clientes.id", ondelete="CASCADE"), nullable=False)
    ip = Column(String(45), nullable=False)
    hostname = Column(Text)
    mac = Column(Text)
    fabricante = Column(Text)
    tipo = Column(Text)
    descripcion = Column(Text)
    primera_vez = Column(DateTime, server_default=func.now())
    ultima_vez = Column(DateTime)
    segmento = Column(Text)
    serial = Column(Text)
    activo = Column(Integer, default=1)
    tipo_asignacion_ip = Column(Text, default="desconocido")
    vendor_method = Column(Text)
    vendor_confidence = Column(Integer)
    hostname_method = Column(Text)
    hostname_confidence = Column(Integer)

    cliente_rel = relationship("Cliente", back_populates="dispositivos")
    pings = relationship("Ping", back_populates="dispositivo", cascade="all, delete-orphan")
    servicios = relationship("Servicio", back_populates="dispositivo", cascade="all, delete-orphan")
    alertas = relationship("Alerta", back_populates="dispositivo", cascade="all, delete-orphan")
    credenciales = relationship("Credencial", back_populates="dispositivo", cascade="all, delete-orphan")


class Ping(Base):
    __tablename__ = "pings"
    __table_args__ = (
        Index("ix_pings_dispositivo_id", "dispositivo_id"),
        Index("ix_pings_timestamp", "timestamp"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    cliente_id = Column(Integer, ForeignKey("clientes.id", ondelete="CASCADE"), nullable=False)
    dispositivo_id = Column(Integer, ForeignKey("dispositivos.id", ondelete="CASCADE"))
    timestamp = Column(DateTime, server_default=func.now())
    estado = Column(Text)
    latencia_ms = Column(Float)
    perdida_pct = Column(Float)

    dispositivo = relationship("Dispositivo", back_populates="pings")


class Servicio(Base):
    __tablename__ = "servicios"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cliente_id = Column(Integer, ForeignKey("clientes.id", ondelete="CASCADE"), nullable=False)
    dispositivo_id = Column(Integer, ForeignKey("dispositivos.id", ondelete="CASCADE"))
    puerto = Column(Integer)
    protocolo = Column(Text)
    servicio = Column(Text)
    version = Column(Text)
    estado = Column(Text)
    timestamp = Column(DateTime, server_default=func.now())

    dispositivo = relationship("Dispositivo", back_populates="servicios")


class Alerta(Base):
    __tablename__ = "alertas"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cliente_id = Column(Integer, ForeignKey("clientes.id", ondelete="CASCADE"), nullable=False)
    dispositivo_id = Column(Integer, ForeignKey("dispositivos.id", ondelete="CASCADE"))
    tipo = Column(Text)
    mensaje = Column(Text)
    timestamp = Column(DateTime, server_default=func.now())
    resuelta = Column(Integer, default=0)
    analisis_ia = Column(Text)

    dispositivo = relationship("Dispositivo", back_populates="alertas")


class PosicionTopologia(Base):
    __tablename__ = "posiciones_topologia"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cliente_id = Column(Integer, ForeignKey("clientes.id", ondelete="CASCADE"), nullable=False)
    dispositivo_id = Column(Integer, ForeignKey("dispositivos.id", ondelete="CASCADE"), unique=True)
    x = Column(Float, default=0)
    y = Column(Float, default=0)


class Credencial(Base):
    __tablename__ = "credenciales"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cliente_id = Column(Integer, ForeignKey("clientes.id", ondelete="CASCADE"), nullable=False)
    dispositivo_id = Column(Integer, ForeignKey("dispositivos.id", ondelete="CASCADE"))
    alias = Column(Text)
    admin_pass = Column(Text)
    usuario = Column(Text)
    app_pass = Column(Text)
    observacion = Column(Text)

    dispositivo = relationship("Dispositivo", back_populates="credenciales")


class OuiVendor(Base):
    __tablename__ = "oui_vendor"
    __table_args__ = (
        UniqueConstraint("oui", "source", name="uq_oui_source"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    oui = Column(String(8), nullable=False)
    vendor = Column(String(255), nullable=False)
    source = Column(String(10), default="custom")
    confidence = Column(Integer, default=70)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class MacVendorExact(Base):
    __tablename__ = "mac_vendor_exact"

    id = Column(Integer, primary_key=True, autoincrement=True)
    mac = Column(String(17), nullable=False, unique=True)
    vendor = Column(String(255), nullable=False)
    confidence = Column(Integer, default=100)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class PortHeuristic(Base):
    __tablename__ = "port_heuristic"
    __table_args__ = (
        UniqueConstraint("puerto", "protocolo", name="uq_port_protocol"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    puerto = Column(Integer, nullable=False)
    protocolo = Column(String(10), default="tcp")
    vendor = Column(String(255), nullable=False)
    confidence = Column(Integer, default=60)
