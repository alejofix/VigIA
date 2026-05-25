import os
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DB_PATH", "data/")
os.makedirs(DB_PATH, exist_ok=True)


def get_db_path(nombre_cliente: str) -> str:
    return os.path.join(DB_PATH, f"{nombre_cliente}.db")


def create_engine_for_db(db_path: str):
    engine = create_engine(f"sqlite:///{db_path}", echo=False)

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


_session_registry = {}


def get_session(db_path: str):
    if db_path not in _session_registry:
        engine = create_engine_for_db(db_path)
        session_factory = scoped_session(sessionmaker(bind=engine))
        _session_registry[db_path] = session_factory
    return _session_registry[db_path]


def init_db(db_path: str):
    from backend.models import Base
    engine = create_engine_for_db(db_path)
    Base.metadata.create_all(engine)
    return engine
