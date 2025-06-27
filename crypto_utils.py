import os
import base64
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

KEY_DIR = "keys"
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, "public_key.pem")
AES_KEY_SIZE = 32  # 256 bits

def generate_keys(password: bytes):
    os.makedirs(KEY_DIR, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(encrypted_private_key)

    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key_pem)

def load_private_key(password: bytes):
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key_data = f.read()
    return serialization.load_pem_private_key(
        private_key_data,
        password=password,
        backend=default_backend()
    )

def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def hybrid_encrypt_file(input_path, output_path, public_key):
    aes_key = os.urandom(AES_KEY_SIZE)
    iv = os.urandom(16)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    _, ext = os.path.splitext(input_path)
    ext_bytes = ext.encode()
    ext_length = len(ext_bytes)

    with open(output_path, "wb") as f:
        f.write(encrypted_key)
        f.write(iv)
        f.write(struct.pack("B", ext_length))
        f.write(ext_bytes)
        f.write(ciphertext)

def hybrid_decrypt_file(input_path, output_path, private_key):
    with open(input_path, "rb") as f:
        encrypted_key = f.read(256)
        iv = f.read(16)
        ext_length = struct.unpack("B", f.read(1))[0]
        ext = f.read(ext_length).decode()
        ciphertext = f.read()

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    if not output_path.endswith(ext):
        output_path += ext

    with open(output_path, "wb") as f:
        f.write(plaintext)

def hybrid_encrypt_message(message: bytes, public_key) -> str:
    aes_key = os.urandom(AES_KEY_SIZE)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    payload = encrypted_key + iv + ciphertext
    return base64.b64encode(payload).decode()

def hybrid_decrypt_message(encoded_payload: str, private_key) -> bytes:
    payload = base64.b64decode(encoded_payload)
    encrypted_key = payload[:256]
    iv = payload[256:272]
    ciphertext = payload[272:]

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
