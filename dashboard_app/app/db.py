import psycopg2
from config import Config

def get_conn():
    return psycopg2.connect(**Config.DB_PARAMS)
