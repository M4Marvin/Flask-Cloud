from flask import Blueprint

bp = Blueprint('auth', __name__)

from Application.auth import routes
