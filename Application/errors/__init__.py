from flask import Blueprint

bp = Blueprint('errors', __name__)

# This import statement is at the bottom to avoid circular imports
from Application.errors import handlers
