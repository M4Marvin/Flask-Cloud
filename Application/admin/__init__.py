from flask import Blueprint

bp = Blueprint('admin', __name__)

from Application.admin import routes
