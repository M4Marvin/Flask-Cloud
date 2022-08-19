from Application.models import User, Admin, Log, Upload, UserBase, Behavior
from Application import db
from datetime import datetime
from Application.faceAuth import verify_image, generate_encoding, authenticate_image

"""
    The database structure is as follows:
    UserBase - 
        User
        Admin
    Log
    Upload (A record is added when a user uploads a file)
         
"""


def add_admin(username, password, email):
    admin = Admin()
    admin.username = username
    admin.password = password
    admin.email = email
    db.session.add(admin)
    db.session.commit()
    print('Admin ' + username + ' added')

    add_authentication(admin.id)
    return admin


def add_log(user_id, action_type):
    log = Log()
    log.user_id = user_id
    log.actionType = action_type
    log.done_at = datetime.now()
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
    print('User ' + username + ' added')

    behavior = Behavior()
    behavior.user_id = user.id
    db.session.add(behavior)

    db.session.commit()

    return user.id


def add_upload(user_id, filename, size):
    upload = Upload()
    upload.user_id = user_id
    upload.filename = filename
    upload.size = size
    db.session.add(upload)
    db.session.commit()
    return upload


def delete_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    db.session.delete(user)
    # Remove user from UserBase as well
    user = UserBase.query.filter_by(username=username).first_or_404()
    db.session.delete(user)
    # Delete all uploads for user
    Upload.query.filter_by(user_id=user.id).delete()
    # Delete all logs for user
    Log.query.filter_by(user_id=user.id).delete()

    db.session.commit()
    print('User ' + username + ' deleted')


def edit_user(username, email, about_me):
    user = User.query.filter_by(username=username).first_or_404()
    user.email = email
    user.about_me = about_me
    user.last_updated = datetime.now()
    db.session.commit()
    print('User ' + username + ' edited')


def get_user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return user


def get_user_by_id(user_id):
    user = User.query.filter_by(id=user_id).first_or_404()
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
        delete_user(user.username)


def add_authentication(user_id, image):
    user = User.query.filter_by(id=user_id).first_or_404()

    if verify_image(image):
        try:
            generate_encoding(image, user_id)
            user.authenticated = True
            db.session.commit()
            return "Success"
        except Exception as e:
            return "Error: " + str(e)
        finally:
            db.session.close()
    else:
        return "Invalid image"


def authenticate(user_id, image):
    if verify_image(image):
        try:
            if authenticate_image(image, user_id):
                return "Authentication successful"
            else:
                return "Authentication failed"
        except Exception as e:
            return "Authentication failed with error: " + str(e)
    else:
        return "Invalid image"
