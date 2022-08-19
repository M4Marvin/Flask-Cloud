import os

import face_recognition
import cv2

import numpy as np

from Application import app

"""
This is a simple face authentication system.
It takes a picture of the user and then compares it to a stored encoding.
If the encoding matches, the user is authenticated.
If not, the user is denied.

It also generates a new encoding and stores it for the user.
"""


def save_encoding(encoding, id_encoding):
    """
    This function saves the encoding as a text file.
    """
    path = os.path.join(app.config['ENCODINGS_FOLDER'], str(id_encoding) + '.txt')
    np.savetxt(path, encoding)


def get_encoding(id_encoding):
    """
    This function gets the encoding for the user.
    """
    file_path = os.path.join(app.config['ENCODINGS_FOLDER'], str(id_encoding) + ".txt")
    encoding = np.loadtxt(file_path)
    return encoding


def authenticate_image(id_encoding, image):
    """
    This function authenticates the user.
    """
    image_path = os.path.join(app.config['ENCODINGS_FOLDER'], str(id_encoding) + ".jpg")
    encoding = face_recognition.face_encodings(image)[0]
    stored_encoding = get_encoding(id_encoding)
    match = face_recognition.compare_faces([stored_encoding], encoding, 0.5)[0]

    return match


def generate_encoding(id_encoding, image):
    """
    This function generates the encoding for the user.
    """
    encoding = face_recognition.face_encodings(image)[0]
    print(type(encoding))
    save_encoding(encoding, id_encoding)


def verify_image(image):
    """
    This function verifies that the image contains exactly one face.
    """
    faces = face_recognition.face_locations(image)
    if len(faces) != 1:
        return False
    return True


def add_authentication(id_encoding):
    """
    This function opens camera and takes a picture of the user and generates the encoding.
    """
    # Open camera
    cap = cv2.VideoCapture(0)

    # Take picture on keypress 'q'
    while True:
        ret, frame = cap.read()
        cv2.imshow('frame', frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    # Close camera
    cap.release()
    cv2.destroyAllWindows()

    # Generate encoding
    generate_encoding(id_encoding, frame)
    print("Encoding generated.")

    return True


def authenticate(id_encoding):
    """
    This function authenticates the user by opening camera and taking a picture of the user.
    """
    # Open camera
    cap = cv2.VideoCapture(0)

    # Take picture on keypress 'q'
    while True:
        ret, frame = cap.read()
        cv2.imshow('frame', frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    # Close camera
    cap.release()
    cv2.destroyAllWindows()

    # Authenticate
    match = authenticate_image(id_encoding, frame)
    if match:
        print("Authentication successful.")
    else:
        print("Authentication failed.")
    return match

