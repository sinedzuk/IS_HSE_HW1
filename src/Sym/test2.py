from cryptography.fernet import Fernet

key = Fernet.generate_key()

with open("fernet_key", "wb") as key_file:
    key_file.write(key)
