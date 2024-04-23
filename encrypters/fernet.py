from cryptography.fernet import Fernet


def generate_key():
    key = Fernet.generate_key()
    with open("secret_fernet.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret_fernet.key", "rb").read()

def encrypt_file(file_path):
    key = load_key()
    f = Fernet(key)

    with open(file_path, "rb") as file:
        file_data = file.read()

    encrypted_data = f.encrypt(file_data)

    with open(file_path, "wb") as file:
        file.write(encrypted_data)

    print("File encrypted successfully.")
    


def decrypt_file(file_path):
    key = load_key()
    f = Fernet(key)

    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = f.decrypt(encrypted_data)

    with open(file_path, "wb") as file:
        file.write(decrypted_data)

    print("File decrypted successfully.")