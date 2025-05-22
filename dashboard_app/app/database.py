from psycopg2.pool import SimpleConnectionPool
from app import app

# Initialize connection pool
pool = SimpleConnectionPool(
    minconn=1,
    maxconn=10,
    dbname=app.config['DB_NAME'],
    user=app.config['DB_USER'],
    password=app.config['DB_PASSWORD'],
    host=app.config['DB_HOST']
)

def get_db_connection():
    return pool.getconn()

def release_db_connection(conn):
    pool.putconn(conn)

# Database connection context manager
class DatabaseConnection:
    def __enter__(self):
        self.conn = get_db_connection()
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            app.logger.error(f"Database error: {exc_val}")
        release_db_connection(self.conn)

# Clean up database connections when the application stops
@app.teardown_appcontext
def shutdown_session(exception=None):
    pool.closeall() 
