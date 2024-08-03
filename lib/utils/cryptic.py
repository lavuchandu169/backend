import hashlib
import os
import pickle
import base64
import uuid
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

PRIVATE_KEY = "I am Batman"

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_object(obj, password):
    serialized_obj = pickle.dumps(obj)
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(serialized_obj) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return salt + iv + encrypted_data

def decrypt_object(encrypted_data, password):
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_data = encrypted_data[32:]
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    serialized_obj = unpadder.update(padded_data) + unpadder.finalize()
    obj = pickle.loads(serialized_obj)
    return obj

def to_fixed_length_alphanumeric(data, length=25):
    hash_obj = hashlib.sha256(data).digest()
    b64_encoded = base64.urlsafe_b64encode(hash_obj)[:length]
    return b64_encoded.decode('utf-8').replace('=', '')[:length]

def encrypt_to_fixed_length_string(obj, password=PRIVATE_KEY, length=25):
    encrypted_data = encrypt_object(obj, password)
    identifier = to_fixed_length_alphanumeric(uuid.uuid4().bytes, length)
    return {"identifier": identifier, "encrypted_data": encrypted_data}

def decrypt_from_fixed_length_string(encrypted_data, password=PRIVATE_KEY):
    return decrypt_object(encrypted_data, password)

def hash_string(string):
    result = hashlib.sha256(string.encode())
    return result.hexdigest()
