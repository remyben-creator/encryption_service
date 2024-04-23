#files
from encrypters import fernet, aes
from security_folder import logins
import security_folder.authenticate as authenticate


#libraries
import os
import argparse

def parser_help_file(file_path):
    if file_path is None:
        print("Please provide a file path.")
        exit()
    if not os.path.exists(file_path):
        print("File not found.")
        exit()

if __name__ == "__main__":
    authenticate.create_user()
    username = authenticate.auth()
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file using Fernet or hand-made AES encryption.")
    parser.add_argument("operation", choices=["encrypt", "decrypt", "aes", "security"], help="Operation to perform")
    parser.add_argument("file_path", nargs='?', default=None, help="Path to the file to encrypt or decrypt")

    args = parser.parse_args()
    

    if args.operation == "encrypt":
        parser_help_file(args.file_path)
        authenticate.auth_file(username, "encrypt", args.file_path, "fernet");
        fernet.generate_key()
        fernet.encrypt_file(args.file_path)
    elif args.operation == "decrypt":
        parser_help_file(args.file_path)
        authenticate.auth_file(username, "decrypt", args.file_path, "fernet");
        fernet.decrypt_file(args.file_path)
    elif args.operation == "aes":
        parser_help_file(args.file_path)
        aes.main(username, args.file_path)
    elif args.operation == "security":
        logins.get_login_attempts(username)
