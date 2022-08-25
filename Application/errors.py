from flask import render_template
from Application import app, db


@app.errorhandler(404)
def not_found_error(error):
    print(error)
    return render_template('errors/404.html', title='404 - Page Not Found'), 404


@app.errorhandler(500)
def internal_error(error):
    print(error)
    db.session.rollback()
    return render_template('errors/500.html', title='500'), 500
