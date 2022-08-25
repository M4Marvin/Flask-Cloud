import base64
import os
import os.path

from Cryptodome import Random
from Cryptodome.Cipher import AES


def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


def decrypt(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")


def encrypt(message, key):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(message))


class Encryptor:
    def __init__(self, key):
        self.key = key

    def encrypt_file(self, file_name, key):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = encrypt(plaintext, key.encode('utf-8'))
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt_file(self, file_name, key):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = decrypt(ciphertext, key.encode("utf-8"))
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)
