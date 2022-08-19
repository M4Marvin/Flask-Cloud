from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bootstrap import Bootstrap

from config import Config
from encryptor import Encryptor
import cv2

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
bootstrap = Bootstrap(app)

# Initialize the Encryptor
encryptor = Encryptor(app.config['ENCRYPTOR_KEY'])

from Application import routes, models, errors
