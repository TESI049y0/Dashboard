import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

class Config:
    # Database Configuration
    DB_NAME = os.getenv('DB_NAME', 'pentest_monitoring')
    DB_USER = os.getenv('DB_USER', 'dashboard_user')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'your_secure_password')
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    
    # Application Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(32))
    SCAN_SERVICE_URL = os.getenv('SCAN_SERVICE_URL', 'http://192.168.10.11:5000')
    
    # Security Configuration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes
    
    # Flask Security Headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:",
        'X-Frame-Options': 'SAMEORIGIN',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block'
    }
