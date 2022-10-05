import base64
import hashlib
import hmac
import bcrypt
from cryptography.fernet import Fernet
import jwt
import time


def deco(func):
    start = time.time()
    print(func.__name__)
    func()
    end = time.time()
    print(end - start)
    print()


@deco
def test_sha256():
    """
    secure hash algorithm
    data -> data
    example: TLS, SSL, SSH
    """
    h = hashlib.new("sha256")
    h.update(b"hello world")
    r = h.hexdigest()
    print(r)


@deco
def test_hmac():
    """
    hash-based message authentication code
    key, msg, algorithm -> signature
    example: api authentication
    """
    key = "4b0b9de7c57b16c69f1cac1f7d5bd8a6332f7640f67538527437e04bded7ed6d"
    byte_key = bytes(key, "UTF-8")
    msg = "hello world".encode()
    h = hmac.new(byte_key, msg, hashlib.sha256).hexdigest()
    print(h)


@deco
def test_jwt():
    """
    json web tokens (standard)
    token = header.payload.signature
    payload, secret, algorithm -> token
    token, secret -> success/error
    example: api authentication
    """
    encoded = jwt.encode({"sub": "123"}, "secret", algorithm="HS256")
    r = jwt.decode(encoded, "secret", algorithms=["HS256"])
    print(r)


@deco
def test_base64():
    """
    base64 encoding
    binary data -> text
    text -> binary data
    example: binary data in html, jwt tokens
    """
    s = "hello world"
    bytes_obj = bytes(s, "UTF-8")
    encoded = base64.b64encode(bytes_obj)
    print(encoded)
    decoded = base64.b64decode(encoded)
    print(decoded.decode())


@deco
def test_bcrypt():
    """
    bcrypt password hashing
    slow hash
    password, salt -> hashed password
    example: username and password login
    """
    password = b"super secret password"
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    if bcrypt.checkpw(password, hashed):
        print("it matches")
    else:
        print("it does not match")


@deco
def test_cryptography():
    """
    encryption and decryption
    msg, key -> encrypted msg
    encrypted msg, key -> decrypted msg
    example: password protected note taking app
    """
    msg = "hello world"
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encMsg = fernet.encrypt(msg.encode())
    decMsg = fernet.decrypt(encMsg).decode()
    print("original str: ", msg)
    print("encrypted str: ", encMsg)
    print("decrypted str: ", decMsg)
