# Security Dashboard

Een beveiligde dashboard applicatie voor het monitoren van security metrics, DORA metrics, en NIS2 compliance.

## Features

- Beveiligde authenticatie en autorisatie
- Security scanning resultaten
- DORA metrics visualisatie
- NIS2 compliance monitoring
- Supply chain security audits
- Risico assessments

## Installatie

1. Clone de repository:
```bash
git clone [repository-url]
cd dashboard_app
```

2. Maak een virtual environment aan:
```bash
python -m venv venv
source venv/bin/activate  # Op Windows: venv\Scripts\activate
```

3. Installeer de dependencies:
```bash
pip install -r requirements.txt
```

4. Maak een .env bestand aan met de volgende variabelen:
```
DB_NAME=pentest_monitoring
DB_USER=your_db_user
DB_PASSWORD=your_secure_password
DB_HOST=localhost
SECRET_KEY=your-secret-key-here
SCAN_SERVICE_URL=http://your-scan-service-url
```

5. Start de applicatie:
```bash
python run.py
```

## Beveiliging

Deze applicatie implementeert verschillende beveiligingsmaatregelen:
- HTTPS/SSL encryption
- Secure headers (HSTS, CSP, etc.)
- Database connection pooling
- Password complexity requirements
- Session management
- Role-based access control

## Development

Voor development:
1. Installeer de development dependencies:
```bash
pip install -r requirements-dev.txt
```

2. Run de tests:
```bash
pytest
```

## Productie Deployment

Voor productie deployment:
1. Gebruik een productie-grade WSGI server (bijv. Gunicorn)
2. Zet SSL/TLS op
3. Configureer een reverse proxy (bijv. Nginx)
4. Gebruik environment variables voor alle gevoelige data

## License

[Your License Here] 