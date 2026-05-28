import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, Session
from backend.models import Base, Cliente

logger = logging.getLogger("vigia.database")

DATABASE_URL = os.getenv("DATABASE_URL", "mysql+pymysql://root@127.0.0.1/vigia?charset=utf8mb4")

_engine = None
_engine_sqlite = {}

def get_engine(db_path=None):
    global _engine
    if db_path:
        if db_path not in _engine_sqlite:
            _engine_sqlite[db_path] = create_engine(f"sqlite:///{db_path}", echo=False)
        return _engine_sqlite[db_path]
    if _engine is None:
        _engine = create_engine(DATABASE_URL, echo=False, pool_recycle=3600)
    return _engine

def init_db(db_path=None):
    Base.metadata.create_all(get_engine(db_path))
    if db_path:
        logger.info(f"Tablas creadas/verificadas en SQLite: {db_path}")
    else:
        logger.info("Tablas creadas/verificadas en MariaDB")

_session_factory = None
_session_factory_sqlite = {}

def get_session(db_path=None):
    global _session_factory
    if db_path:
        if db_path not in _session_factory_sqlite:
            _session_factory_sqlite[db_path] = scoped_session(sessionmaker(bind=get_engine(db_path)))
        return _session_factory_sqlite[db_path]
    if _session_factory is None:
        _session_factory = scoped_session(sessionmaker(bind=get_engine()))
    return _session_factory


def get_or_create_cliente(session: Session, nombre: str) -> int:
    c = session.query(Cliente).filter_by(nombre=nombre).first()
    if not c:
        c = Cliente(nombre=nombre)
        session.add(c)
        session.flush()
    return c.id
