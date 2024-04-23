from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import os
import struct
import security_folder.authenticate as authenticate

#Plan to use aes encryption with key derivation and hmac
#adding error handling for corrupted data and secure file deletion

def generate_key(password, salt, iterations=100000):
    return PBKDF2(password, salt, dkLen=16, count=iterations)

def encrypt_file(file_path, password):
    salt = get_random_bytes(16)
    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    hmac = HMAC.new(key, digestmod=SHA256)

    with open(file_path, "rb") as file:
        file_data = file.read()

    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
    hmac.update(encrypted_data)

    with open(file_path, "wb") as file:
        file.write(salt + cipher.iv + hmac.digest() + encrypted_data)

def decrypt_file(file_path, password):
    with open(file_path, "rb") as file:
        salt = file.read(16)
        iv = file.read(16)
        hmac_old = file.read(32)
        encrypted_data = file.read()

    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(encrypted_data)

    if hmac.digest() != hmac_old:
        print("ERROR: Wrong password or corrupted data")
        return

    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    with open(file_path, "wb") as file:
        file.write(decrypted_data)



def main(username, file_path):
    password = input("Enter your password: ")

    if not os.path.exists(file_path):
        print("ERROR: File not found")
        return

    if not os.path.isfile(file_path):
        print("ERROR: Path is not a file")
        return

    operation = input("Enter the operation to perform (encrypt/decrypt): ")

    if operation == "encrypt":
        authenticate.auth_file(username, "encrypt", file_path, "aes");
        encrypt_file(file_path, password)
    elif operation == "decrypt":
        authenticate.auth_file(username, "decrypt", file_path, "aes");
        decrypt_file(file_path, password)
    else:
        print("ERROR: Invalid operation")
