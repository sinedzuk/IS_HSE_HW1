from cryptography.fernet import Fernet

# Генерируем ключ
key = Fernet.generate_key()

# Записываем ключ в файл "key.txt"
with open("key.txt", "wb") as key_file:
    key_file.write(key)

print("Сгенерированный ключ сохранен в файле 'key.txt'")
