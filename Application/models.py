from datetime import datetime
from hashlib import md5

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from Application import db, login


# Base class for all users of the system (Users, Admins, etc.)
class UserBase(UserMixin, db.Model):
    __tablename__ = 'user_base'

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.String(20), unique=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    type = db.Column(db.String(80), nullable=False)
    faceAuth = db.Column(db.Boolean, default=False)
    login_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now())
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.now())
    last_updated = db.Column(db.DateTime, nullable=False, default=datetime.now())
    last_login_time = db.Column(db.DateTime, default=datetime.now())

    __mapper_args__ = {
        'polymorphic_identity': 'user_base',
        'polymorphic_on': type
    }

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def __repr__(self):
        return '<User %r>' % self.username

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)

    def generate_key(self):
        # Generate an encryption key for the user based on the time of creation
        return md5(self.created_at.strftime('%Y-%m-%d %H:%M:%S').encode('utf-8')).hexdigest()


# Connects the UserBase class to the login system
@login.user_loader
def load_user(user_id):
    return UserBase.query.get(int(user_id))


class Admin(UserBase):
    __tablename__ = 'admin'
    __mapper_args__ = {'polymorphic_identity': 'admin'}
    id = db.Column(db.Integer, db.ForeignKey('user_base.id'), primary_key=True)

    def __repr__(self):
        return '<Admin %r>' % self.username

    def serialize(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'type': self.type,
            'faceAuth': self.faceAuth,
            'created_at': self.created_at,
            'about_me': self.about_me,
            'last_seen': self.last_seen,
            'last_updated': self.last_updated
        }


class User(UserBase):
    __tablename__ = 'user'
    __mapper_args__ = {'polymorphic_identity': 'user'}
    id = db.Column(db.Integer, db.ForeignKey('user_base.id'), primary_key=True)
    uploads = db.relationship('Upload', backref='user', lazy='dynamic')
    verified = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<User %r>' % self.username

    def serialize(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'type': self.type,
            'faceAuth': self.faceAuth,
            'created_at': time_to_string(self.created_at),
            'about_me': self.about_me,
            'last_seen': last_seen_to_string(self.last_seen),
            'last_updated': time_to_string(self.last_updated),
            'avatar': self.avatar(64),
            'uploads': [upload.serialize() for upload in self.uploads],
            'verified': self.verified,
            'login_count': self.login_count,
            'last_login_time': last_seen_to_string(self.last_login_time),
            'job_id': self.job_id
        }


class Upload(db.Model):
    __tablename__ = 'upload'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(80), nullable=False)
    size = db.Column(db.Integer, nullable=False)  # Size of the file in bytes
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user_base.id'), nullable=False)

    def __repr__(self):
        return '<Upload %r>' % self.filename

    def serialize(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'created_at': time_to_string(self.created_at),
            'user_id': self.user_id,
            'size': size_to_string(self.size)
        }


class Log(db.Model):
    __tablename__ = 'log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user_base.id'))
    actionType = db.Column(db.String(80), nullable=False)  # Type of action
    done_at = db.Column(db.DateTime, nullable=False, default=datetime.now())

    def __repr__(self):
        return '<Log %r>' % self.actionType

    def serialize(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'actionType': self.actionType,
            'done_at': last_seen_to_string(self.done_at)
        }


class Behavior(db.Model):
    __tablename__ = 'behavior'
    user_id = db.Column(db.Integer, db.ForeignKey('user_base.id'), primary_key=True)
    lower_login_time = db.Column(db.DateTime, nullable=False, default=datetime.now())
    upper_login_time = db.Column(db.DateTime, nullable=False, default=datetime.now())
    lower_logout_time = db.Column(db.DateTime, nullable=False, default=datetime.now())
    upper_logout_time = db.Column(db.DateTime, nullable=False, default=datetime.now())
    lower_upload_count = db.Column(db.Integer, nullable=False, default=0)
    upper_upload_count = db.Column(db.Integer, nullable=False, default=0)
    lower_download_count = db.Column(db.Integer, nullable=False, default=0)
    upper_download_count = db.Column(db.Integer, nullable=False, default=0)
    lower_delete_count = db.Column(db.Integer, nullable=False, default=0)
    upper_delete_count = db.Column(db.Integer, nullable=False, default=0)


def last_seen_to_string(time):
    """
    Get time from between creation and now
    """
    if not time:
        return 'Never'
    time_since = datetime.now() - time
    if time_since.days > 0:
        return '{} days ago'.format(time_since.days)
    elif time_since.seconds > 60:
        return '{} hours ago'.format(time_since.seconds // 3600)
    else:
        return '{} minutes ago'.format(time_since.seconds // 60)


def size_to_string(size):
    """
    Convert size in bytes to kb, mb, gb
    """
    if size < 1024:
        return str(size) + " bytes"
    elif size < 1048576:
        return str(round(size / 1024, 2)) + " kb"
    elif size < 1073741824:
        return str(round(size / 1048576, 2)) + " mb"
    else:
        return str(round(size / 1073741824, 2)) + " gb"


def time_to_string(time):
    """
    Convert time to human-readable format
    """
    if not time:
        return 'Never'
    return time.strftime('%Y-%m-%d %H:%M:%S')
