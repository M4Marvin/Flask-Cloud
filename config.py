"""
Config file for the flask application and database.
"""
import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    """
    Common configurations
    """
    SECRET_KEY = '0deed0f720723e2698852a60'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'data/sql/app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable flask-sqlalchemy modification tracker
    DEBUG = True
    FLASK_ENV = 'development'

    UPLOAD_FOLDER = os.path.join(basedir, 'data/uploads')
    UPLOAD_EXTENSIONS = {'png', 'jpg', 'gif', 'txt', 'pdf'}
    TEMP_FOLDER = os.path.join(basedir, 'data/temp')
    ENCODINGS_FOLDER = os.path.join(basedir, 'data/encodings')
    CHECKPOINTS_FOLDER = os.path.join(basedir, 'data/checkpoints')

    # Flask-Admin
    ADMIN_USER = 'admin'
    ADMIN_PASSWORD = 'admin'
    FLASK_ADMIN_SWATCH = 'cerulean'

    # AES Encryptor config
    ENCRYPTOR_KEY = SECRET_KEY



