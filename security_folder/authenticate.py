import getpass
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import binascii
from security_folder import logins

import json
# Load the authorized_users dictionary from a file
try:
    with open('./security_folder/authorized_users.json', 'r') as f:
        authorized_users = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    print("Authorized users file not found or invalid. Creating a new one.")
    authorized_users = {}

# Define a dictionary of authorized users and their salt and derived keys
#hashing the password and storing the salt and derived key

def create_user():
    option = input("Do you want to create a new user? (y/n): ")
    if option.lower() != "y":
        return False
  
    username = input("Enter a new username: ")
    if username in authorized_users:
        print("Username already exists.")
        return False

    while True:
        password = getpass.getpass("Enter a new password: ")
        password_confirm = getpass.getpass("Confirm your password: ")
        if password == password_confirm:
            break
        else:
            print("Passwords do not match. Please try again.")

    salt = get_random_bytes(16)
    derived_key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)

    authorized_users[username] = {
        "salt": binascii.hexlify(salt).decode(),
        "key": binascii.hexlify(derived_key).decode()
    }
    with open('authorized_users.json', 'w') as f:
        json.dump(authorized_users, f)

    print("User created successfully.")
    return True

def authenticate_user():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")

    if username in authorized_users:
        salt = binascii.unhexlify(authorized_users[username]["salt"])
        stored_key = binascii.unhexlify(authorized_users[username]["key"])

        derived_key = PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
        if derived_key == stored_key:
            print("Successful login.")
            return (username, True)
        else:
            print("Invalid password.")
            return (username, False)   
    else:
        print("User not found.")
        exit() 



def auth():
    username_attempt = authenticate_user()
    username = username_attempt[0]
    attempt = username_attempt[1]
    if not attempt:
        logins.manage_login_attempts(username, False)
        print("You are not authorized to perform this operation.")
        exit()
    else:
        logins.manage_login_attempts(username, True)
        return username

def auth_file(username, ed_type, file_path, encrypt_type):
    if ed_type == "encrypt":
        if "files" not in authorized_users[username]:
            authorized_users[username]["files"] = []
        if (file_path, encrypt_type) not in authorized_users[username]["files"]:
            authorized_users[username]["files"].append((file_path, encrypt_type))
        with open('authorized_users.json', 'w') as f:
            json.dump(authorized_users, f)
    elif ed_type == "decrypt":
        if "files" not in authorized_users[username]:
            print("You are not authorized to perform this operation.")
            exit()

        files = authorized_users[username]["files"]
        for file in files:
            if file[0] == file_path:
                if file[1] == encrypt_type:
                    authorized_users[username]["files"].remove(file)
                    with open('authorized_users.json', 'w') as f:
                        json.dump(authorized_users, f)
                else:
                    print("This file cannot be decrypted by this method.")
                    exit()
            else:
                print("You are not authorized to perform this operation.")
                exit()
