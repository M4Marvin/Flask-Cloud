from datetime import datetime

from flask import request

from Application import db, fernet, app
from Application.faceAuth import add_authentication
from Application.models import User, Admin, Log, Upload, UserBase


def add_admin(username, password, email, job_id):
    admin = Admin()
    admin.username = username
    admin.password = password
    admin.email = email
    admin.job_id = job_id
    db.session.add(admin)
    db.session.commit()
    print('Admin ' + username + ' added')

    add_authentication(admin.id)
    return admin


def add_log(user_id, action_type):
    log = Log()
    log.user_id = user_id
    action_type = fernet.encrypt(action_type.encode())
    log.actionType = action_type
    log.done_at = datetime.now()
    log.ip_address = request.remote_addr
    db.session.add(log)
    db.session.commit()
    print('Log added')

    return log


def add_user(username, password, email, job_id):
    user = User()
    user.username = username
    user.password = password
    user.email = email
    user.job_id = job_id
    db.session.add(user)
    try:
        db.session.commit()
    except Exception as e:
        print(e)
        db.session.rollback()
        return False
    print('User ' + username + ' added')

    return user


def add_upload(user_id, filename, size):
    upload = Upload()
    upload.user_id = user_id
    upload.filename = filename
    upload.size = size
    db.session.add(upload)
    db.session.commit()
    return upload


def delete_user_db(username):
    user = User.query.filter_by(username=username).first_or_404()
    db.session.delete(user)
    db.session.commit()

    print('User ' + username + ' deleted')

    # Delete all uploads for content
    Upload.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    print('All uploads deleted')

    # Delete all logs for content
    Log.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    print('All logs deleted')

    print('User ' + username + ' deleted')


def edit_user_db(username, email, about_me):
    user = User.query.filter_by(username=username).first_or_404()
    user.email = email
    user.about_me = about_me
    user.last_updated = datetime.now()
    db.session.commit()
    print('User ' + user.username + ' edited')
    return user


def get_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return user


def get_user_by_id(user_id):
    user = UserBase.query.filter_by(id=user_id).first_or_404()
    return user


def delete_upload(upload_id):
    upload = Upload.query.filter_by(id=upload_id).first_or_404()
    db.session.delete(upload)
    db.session.commit()
    print('Upload ' + upload.filename + ' deleted')


def delete_all_uploads():
    Upload.query.delete()
    db.session.commit()
    print('All uploads deleted')


def delete_all_users():
    # Get usernames of all users
    users = User.query.all()
    for user in users:
        print("Deleting user: " + user.username)
        delete_user_db(user.username)


def verify_user_db(user_id):
    user = User.query.filter_by(id=user_id).first_or_404()
    user.verified = True
    user.last_updated = datetime.now()
    db.session.commit()


def block_user_db(user_id):
    print(f'Blocking user with id {user_id}')
    user = User.query.filter_by(id=user_id).first_or_404()
    user.verified = False
    user.last_updated = datetime.now()
    db.session.commit()


def increment_login_count(user_id):
    user_id = int(user_id)
    user = UserBase.query.filter_by(id=user_id).first_or_404()
    user.login_count += 1
    user.last_updated = datetime.now()
    db.session.commit()


def reset_db():
    """
    This function resets the database.
    """
    delete_all_uploads()
    delete_all_users()
    print('Database reset')



