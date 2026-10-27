

import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

load_dotenv()

db_host = os.getenv("DB_HOST", "127.0.0.1")

db_url = URL.create(
    drivername="mysql+pymysql",
    username=os.getenv("DB_USER", "root"),
    password=os.getenv("DB_PASSWORD", ""),
    host=db_host,
    port=int(os.getenv("DB_PORT", "3306")),
    database=os.getenv("DB_NAME", "guru"),
    query={"ssl": {}} if db_host != "127.0.0.1" else {},
)

engine = create_engine(
    db_url,
    pool_pre_ping=True,
    pool_recycle=1800,
)


def probar_conexion():
    with engine.connect() as conexion:
        resultado = conexion.execute(text("SELECT DATABASE()"))
        return resultado.scalar_one()
