from cryptography.fernet import Fernet

# Генерация ключа
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Шифрование данных
message_syncron = "Привет, как у тебя дела?!"
data_syncron = message_syncron.encode('utf-8')  # Кодирование строки в байты с помощью UTF-8
encrypted_data = cipher_suite.encrypt(data_syncron)

# Дешифрование данных
decrypted_data = cipher_suite.decrypt(encrypted_data)


print("Исходные данные:", message_syncron)
print("Зашифрованные данные:", encrypted_data)
print("Расшифрованные данные:", decrypted_data.decode('utf-8'))





from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Генерация пары ключей (публичный и приватный)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Шифрование данных
message = "Привет, как у тебя дела?!"
data = message.encode('utf-8')

encrypted_data = public_key.encrypt(
    data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Дешифрование данных
decrypted_data = private_key.decrypt(
    encrypted_data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Исходные данные:", message)
print("Зашифрованные данные:", encrypted_data)
print("Расшифрованные данные:", decrypted_data.decode('utf-8'))  # Декодирование байтов обратно в строку
