import sys
import logging

logging.basicConfig(level=logging.DEBUG, filename='/var/www/html/FlaskApp/FlaskApp.log', format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

sys.path.insert(0, '/var/www/html/FlaskApp')
sys.path.insert(0, '/var/www/html/FlaskApp/Application')

from Application import app as application