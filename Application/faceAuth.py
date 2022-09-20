import os
import cv2
import numpy as np
import onnxruntime
import csv
import time

from Application import app
from Application.facetools import FaceDetection, LivenessDetection, IdentityVerification

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
    face_bank_file_name = str(id_encoding) + ".csv"
    identity_checker = IdentityVerification(checkpoint_path=resNet_checkpoint_path,
                                            facebank_path=os.path.join(app.config['FACE_BANK_FOLDER'],
                                                                       face_bank_file_name))

    # Calculate the time taken for each step
    start_time = time.time()

    faces, _ = faceDetector(image)
    print(f'Face detection time: {time.time() - start_time}')

    if len(faces) != 1:
        return False

    face_arr = faces[0]
    _, mean_sim_score = identity_checker(face_arr)
    print(f'Identity verification time: {time.time() - start_time}')

    liveness_score = livenessDetector(face_arr)
    print(f'Liveness detection time: {time.time() - start_time}')

    print(f"Liveness score: {liveness_score}")
    print(f"Mean similarity score: {mean_sim_score}")

    if liveness_score < 0.1 or mean_sim_score > 1:
        return False
    return True


def generate_encoding(id_encoding, image):
    """
    This function generates the encoding for the face
    """
    resnet = onnxruntime.InferenceSession(resNet_checkpoint_path, providers=["CPUExecutionProvider"])
    face_bank_file_name = str(id_encoding) + ".csv"

    faces, _ = faceDetector(image)
    face_arr = faces[0]

    if len(faces) != 1:
        return False

    face_arr = np.moveaxis(face_arr, -1, 0)
    input_arr = np.expand_dims((face_arr - 127.5) / 128.0, 0)
    embeddings = resnet.run(["output"], {"input": input_arr.astype(np.float32)})[0]

    # Create the folder if it doesn't exist
    if not os.path.exists(app.config['FACE_BANK_FOLDER']):
        os.makedirs(app.config['FACE_BANK_FOLDER'])

    with open(os.path.join(app.config['FACE_BANK_FOLDER'], face_bank_file_name), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(embeddings.flatten().tolist())

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
    return authenticate_image(id_encoding, frame)
