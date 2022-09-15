from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bootstrap import Bootstrap
from cryptography.fernet import Fernet

from config import Config
from encryptor import Encryptor

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'
bootstrap = Bootstrap(app)
fernet = Fernet(app.config['FERNET_KEY'])

# Initialize the Encryptor
encryptor = Encryptor(app.config['ENCRYPTOR_KEY'])

# Import and register blueprints
from Application.errors import bp as errors_bp
app.register_blueprint(errors_bp)

from Application.admin import bp as admin_bp
app.register_blueprint(admin_bp, url_prefix='/admin')

from Application.auth import bp as auth_bp
app.register_blueprint(auth_bp, url_prefix='/auth')

from Application import routes, models
