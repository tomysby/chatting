import os
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def generate_rsa_keypair():
    logging.info("Generating RSA key pair")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def aes_encrypt(data, password):
    logging.info("Starting AES encryption")
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = kdf.derive(password.encode('utf-8'))
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + (16 - len(data) % 16) * ' '
    encrypted_data = encryptor.update(padded_data.encode('utf-8')) + encryptor.finalize()
    logging.info("AES encryption completed")
    return b64encode(salt + iv + encrypted_data).decode('utf-8')

def aes_decrypt(data, password):
    logging.info("Starting AES decryption")
    encrypted_data = b64decode(data)
    salt, iv, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = kdf.derive(password.encode('utf-8'))
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    logging.info("AES decryption completed")
    return decrypted_data.decode('utf-8').strip()

def rsa_encrypt(data, public_key):
    logging.info("Starting RSA encryption")
    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    encrypted = public_key.encrypt(data.encode('utf-8'), oaep_padding)
    logging.info("RSA encryption completed")
    return b64encode(encrypted).decode('utf-8')

def rsa_decrypt(data, private_key):
    logging.info("Starting RSA decryption")
    encrypted = b64decode(data)
    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    decrypted = private_key.decrypt(encrypted, oaep_padding)
    logging.info("RSA decryption completed")
    return decrypted.decode('utf-8')

def hash_data(data):
    logging.info("Starting hash SHA-256")
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data.encode('utf-8'))
    hashed_data = digest.finalize()
    logging.info("Hashing completed")
    return b64encode(hashed_data).decode('utf-8')

# Fungsi untuk verifikasi hash
def verify_hash(data, hashed_value):
    logging.info("Verifying hash-256")
    computed_hash = hash_data(data)
    if computed_hash == hashed_value:
        logging.info("Hash verification successful")
        return True
    else:
        logging.error("Hash verification failed")
        return False
