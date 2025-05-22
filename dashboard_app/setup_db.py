from app import DatabaseConnection
import bcrypt
from config import Config

def setup_database():
    with DatabaseConnection() as conn:
        with conn.cursor() as cur:
            # Basis tabellen
            cur.execute("""
                CREATE TABLE IF NOT EXISTS gebruikers (
                    id SERIAL PRIMARY KEY,
                    gebruikersnaam TEXT UNIQUE NOT NULL,
                    wachtwoord TEXT NOT NULL,
                    is_admin BOOLEAN DEFAULT FALSE,
                    reset_token TEXT,
                    reset_token_expiry TIMESTAMP
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS gebruikers_log (
                    id SERIAL PRIMARY KEY,
                    gebruiker TEXT NOT NULL,
                    actie TEXT NOT NULL,
                    tijdstip TIMESTAMP NOT NULL
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scanresultaten (
                    id SERIAL PRIMARY KEY,
                    ip TEXT,
                    poort INTEGER,
                    status TEXT,
                    protocol TEXT,
                    service TEXT,
                    tijdstip TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # DORA Metrics tabellen
            cur.execute("""
                CREATE TABLE IF NOT EXISTS deployments (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    version TEXT,
                    status TEXT,
                    lead_time_minutes INTEGER,
                    description TEXT
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    severity TEXT,
                    description TEXT,
                    resolution_time_minutes INTEGER,
                    status TEXT,
                    impact_description TEXT,
                    resolution_steps TEXT
                )
            """)
            
            # NIS2 Compliance tabellen
            cur.execute("""
                CREATE TABLE IF NOT EXISTS risk_assessments (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    asset_name TEXT,
                    risk_level TEXT,
                    mitigation_steps TEXT,
                    next_review_date DATE,
                    responsible_person TEXT,
                    current_controls TEXT
                )
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS supply_chain_audits (
                    id SERIAL PRIMARY KEY,
                    vendor_name TEXT,
                    audit_date DATE,
                    compliance_status TEXT,
                    risk_level TEXT,
                    action_items TEXT,
                    last_assessment_date DATE,
                    next_assessment_date DATE,
                    critical_findings TEXT
                )
            """)
            
            # Create default admin user if it doesn't exist
            cur.execute("SELECT id FROM gebruikers WHERE gebruikersnaam = 'admin'")
            if not cur.fetchone():
                password = "Admin123!@#"
                hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                cur.execute(
                    "INSERT INTO gebruikers (gebruikersnaam, wachtwoord, is_admin) VALUES (%s, %s, %s)",
                    ('admin', hashed.decode('utf-8'), True)
                )
                print("Default admin user created with password:", password)
                print("PLEASE CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN!")
            
            conn.commit()

if __name__ == '__main__':
    setup_database()
    print("Database setup complete!") 