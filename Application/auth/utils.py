from datetime import timedelta

import cv2
import numpy as np
from flask import session
from flask_login import login_user

from Application import db
from Application.database import add_log
from Application.faceAuth import authenticate_image, generate_encoding
from Application.models import UserBase


def face_authenticate(image, user_id):
    """
    Convert the image to a numpy array and pass it to the authenticate_image function.
    :param image: image to authenticate
    :param user_id: id of the user to authenticate
    :return: Status code
    """
    if image is None or image == "" or user_id is None:
        return 400

    image = np.fromstring(image.read(), np.uint8)
    image = cv2.imdecode(image, cv2.IMREAD_COLOR)

    if not authenticate_image(user_id, image):
        return 401

    return 200


def init_session(user_id):
    """
    Used to initialize a session for a user by id.
    :param user_id: id of the user to initialize the session for
    """
    session['user_id'] = user_id
    session['num_deletes'] = 0
    session['num_renames'] = 0
    session['invalid_requests'] = 0
    session['init_num_uploads'] = get_upload_count(user_id)


def get_upload_count(user_id):
    """
    Get the number of uploads for a user by id.
    :param user_id: id of the user to get the upload count for
    :return: number of uploads
    """
    uploads = UserBase.query.get(user_id).uploads
    return uploads.count()


def login_user_(user_id):
    """
    Used to log in a user by id.
    """
    user = UserBase.query.get(user_id)
    login_user(user, duration=timedelta(days=30), remember=True)
    increment_login_count(user_id)
    add_log(user_id, "Login")


def increment_login_count(user_id):
    """
    Increment the login count for the user with the given user_id.
    :param user_id: id of the user to increment the login count for
    :return: None
    """
    user = UserBase.query.get(int(user_id))
    user.login_count += 1
    db.session.commit()


def add_face_authentication(image, user_id):
    """
    Convert image stream into numpy array image and add to database
    :param image: image stream
    :param user_id: user id
    :return: status code
    """
    try:
        # Convert image stream to numpy array
        image = np.fromstring(image.read(), np.uint8)
        image = cv2.imdecode(image, cv2.IMREAD_COLOR)

        # Add face to database
        if generate_encoding(user_id, image):
            return 200
        return 400

    except Exception as e:
        print(f'Error: {e}')
        return 500
