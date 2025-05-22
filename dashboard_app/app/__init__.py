from flask import Flask
from config import Config
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.config.from_object(Config)

# Initialize security extensions
talisman = Talisman(
    app,
    force_https=True,
    session_cookie_secure=True,
    feature_policy={
        'geolocation': '\'none\'',
        'midi': '\'none\'',
        'notifications': '\'none\'',
        'push': '\'none\'',
        'sync-xhr': '\'none\'',
        'microphone': '\'none\'',
        'camera': '\'none\'',
        'magnetometer': '\'none\'',
        'gyroscope': '\'none\'',
        'speaker': '\'none\'',
        'vibrate': '\'none\'',
        'fullscreen': '\'none\'',
        'payment': '\'none\'',
    }
)

csrf = CSRFProtect(app)
mail = Mail(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

from app import routes

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    from .routes import dashboard_routes, auth_routes, admin_routes
    app.register_blueprint(dashboard_routes.bp)
    app.register_blueprint(auth_routes.bp)
    app.register_blueprint(admin_routes.bp)

    return app
