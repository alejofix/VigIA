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
