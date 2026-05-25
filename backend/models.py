from sqlalchemy import (
    Column, Integer, Text, Float, DateTime,
    ForeignKey, func
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Dispositivo(Base):
    __tablename__ = "dispositivos"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(Text, nullable=False, unique=True)
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

    pings = relationship("Ping", back_populates="dispositivo", cascade="all, delete-orphan")
    servicios = relationship("Servicio", back_populates="dispositivo", cascade="all, delete-orphan")
    alertas = relationship("Alerta", back_populates="dispositivo", cascade="all, delete-orphan")


class Ping(Base):
    __tablename__ = "pings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dispositivo_id = Column(Integer, ForeignKey("dispositivos.id"))
    timestamp = Column(DateTime, server_default=func.now())
    estado = Column(Text)
    latencia_ms = Column(Float)
    perdida_pct = Column(Float)

    dispositivo = relationship("Dispositivo", back_populates="pings")


class Servicio(Base):
    __tablename__ = "servicios"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dispositivo_id = Column(Integer, ForeignKey("dispositivos.id"))
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
    dispositivo_id = Column(Integer, ForeignKey("dispositivos.id"))
    tipo = Column(Text)
    mensaje = Column(Text)
    timestamp = Column(DateTime, server_default=func.now())
    resuelta = Column(Integer, default=0)
    analisis_ia = Column(Text)

    dispositivo = relationship("Dispositivo", back_populates="alertas")


class PosicionTopologia(Base):
    __tablename__ = "posiciones_topologia"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dispositivo_id = Column(Integer, ForeignKey("dispositivos.id"), unique=True)
    x = Column(Float, default=0)
    y = Column(Float, default=0)


class Credencial(Base):
    __tablename__ = "credenciales"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dispositivo_id = Column(Integer, ForeignKey("dispositivos.id"))
    admin_pass = Column(Text)
    usuario = Column(Text)
    app_pass = Column(Text)
    observacion = Column(Text)

    dispositivo = relationship("Dispositivo")
