import os
import cv2
import face_recognition
import numpy as np

from Application import app
from Application.facetools import FaceDetection, LivenessDetection

resNet_checkpoint_path = os.path.join(app.config['CHECKPOINTS_FOLDER'], 'InceptionResnetV1_vggface2.onnx')
deepPix_checkpoint_path = os.path.join(app.config['CHECKPOINTS_FOLDER'], 'OULU_Protocol_2_model_0_0.onnx')

faceDetector = FaceDetection(max_num_faces=1)
livenessDetector = LivenessDetection(checkpoint_path=deepPix_checkpoint_path)


def get_liveness_score(frame):
    faces, _ = faceDetector(frame)
    face_arr = faces[0]
    return livenessDetector(face_arr)


def save_encoding(encoding, id_encoding):
    """
    This function saves the encoding as a text file.
    """
    path = os.path.join(app.config['ENCODINGS_FOLDER'], str(id_encoding) + '.txt')
    np.savetxt(path, encoding)


def get_encoding(id_encoding):
    """
    This function gets the encoding for the content.
    """
    file_path = os.path.join(app.config['ENCODINGS_FOLDER'], str(id_encoding) + ".txt")
    encoding = np.loadtxt(file_path)
    return encoding


def authenticate_image(id_encoding, image):
    """
    This function authenticates the content.
    """
    encoding = face_recognition.face_encodings(image)[0]
    stored_encoding = get_encoding(id_encoding)
    match = face_recognition.compare_faces([stored_encoding], encoding, 0.5)[0]

    return match


def generate_encoding(id_encoding, image):
    """
    This function generates the encoding for the content.
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
    if get_liveness_score(image) < 0.8:
        return False
    return True


def add_authentication(id_encoding):
    """
    This function opens camera and takes a picture of the content and generates the encoding.
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
    This function authenticates the content by opening camera and taking a picture of the content.
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
    if verify_image(frame):
        match = authenticate_image(id_encoding, frame)
        if match:
            print("Authentication successful.")
        else:
            print("Authentication failed.")
        return match
    else:
        print("Invalid Image.")
        return False
