import json
from os import error
import re
from pathlib import Path
from typing import final
from Crypto.Hash import MD4
from Crypto.Cipher import DES

data_file = Path("data.bin")
iv_file = Path("iv.bin")
key_file = Path("key.txt")
key = None
data = {}

# Получение ключа из файла
def get_key():
  if (key_file.is_file()):
    with key_file.open(mode="rb") as file:
      return file.read()

  return False

# Хэш-функция для ключа шифрования.
# Ограничение в 8 байт из-за особенностей работы алгоритма шифрования.
def hash_key(new_key):
  hash = MD4.new()
  hash.update(new_key.encode("utf-8"))
  return hash.hexdigest()[:8].encode()

# Валидация ключа шифрования.
# Считается верным, если не вызывает ошибок.
def validate_hash_key(new_key):
  global key
  key = new_key

  if (not is_data_present()):
    return True, "Успех"

  try:
    load_data()
  except Exception:
    return False, "Неверный ключ шифрования!"
  else:
    return True, "Успех"

# Хеширование и сохранение введённого ключа.
def generate_key(new_key):
  global key
  key = hash_key(new_key)
  save_key()

# Сохранение текущего ключа в файл.
def save_key():
  with key_file.open(mode="wb") as file:
    file.write(key)

# Загрузка и дешифровка данных из файлов.
def load_data():
  # IV - Initialize Vector, вектор инициализации, необходимый для работы DES-шифрования
  iv = ""

  with iv_file.open(mode="rb") as file:
    iv = file.read()

  cipher = DES.new(key, DES.MODE_OFB, iv)

  with data_file.open(mode="rb") as file:
    global data
    data = json.loads(cipher.decrypt(file.read()).decode())

# Проверка присутствия данных в папке программы.
def is_data_present():
  return data_file.is_file() and iv_file.is_file()

# Инициализация данных. Создание аккаунта администратора и файла данных.
def init():
  if (not is_data_present()):
    data_file.touch()
    create_user({
      "login": "ADMIN",
      "password": "",
      "admin": True,
      "first_login": True
    })

  load_data()

# Шифрование и сохранение данных
def save_data():
  cipher = DES.new(key, DES.MODE_OFB)

  with iv_file.open(mode="wb") as file:
    file.write(cipher.iv)

  with data_file.open(mode="wb") as file:
    file.write(cipher.encrypt(json.dumps(data).encode()))

# Счетчик попыток ввода пароля
attempts = 0

# Аутентификация пользователя
def auth(login, password):
  if (login == ""):
    return False, "Не введён логин"
  
  if (not login in data):
    return False, "Пользователь не найден"
  
  user_data = data[login]

  if (not match_password(user_data, password)):
    global attempts
    attempts += 1

    if (attempts >= 3):
      return -1, "3 попытки неверного ввода пароля"

    return False, "Неверный пароль (%s/3)" % attempts

  if (user_data["blocked"]):
    return False, "Пользователь заблокирован"

  attempts = 0
  return True, "Успех"

# Создание пользователя
def create_user(raw_data):
  if (not "login" in raw_data):
    return False, "Отсутствует логин"

  if (raw_data["login"] in data):
    return False, "Такой пользователь уже существует"

  password = raw_data["password"] if ("password" in raw_data) else ""

  # Данные пользователя берутся по умолчанию, если не указаны в raw_data.
  user_data = {
    "login": raw_data["login"],
    "password": hash_password(password), # Пароль хранится в хешированном виде
    "admin": raw_data["admin"] if ("admin" in raw_data) else False,
    "blocked": raw_data["blocked"] if ("blocked" in raw_data) else False,
    "check_password": raw_data["check_password"] if ("check_password" in raw_data) else True,
    "first_login": raw_data["first_login"] if ("first_login" in raw_data) else True,
  }
  
  data[user_data["login"]] = user_data
  save_data()

  return True, "Успех"

# Получение пользователя по логину
def get_user(login):
  return data[login]

# Проверка пароля пользователя
def match_password(user_data, password):
  return user_data["password"] == hash_password(password)

# Хэширование пароля
def hash_password(password):
  hash = MD4.new()
  hash.update(password.encode("utf-8"))
  return hash.hexdigest()

# Проверка соответствия пароля требованиям
def check_password(password):
  return re.search(r'\w', password) and re.search(r'\d', password) and re.search(r'[\+\-\*\/]', password)

# Изменение пароля
def change_password(user_data, cur_pass, new_pass, new_pass_repeat):
  if (not match_password(user_data, cur_pass)):
    return False, "Неверный текущий пароль"
  
  if (new_pass != new_pass_repeat):
    return False, "Введённые пароли не совпадают"
  
  if (user_data["check_password"] and not check_password(new_pass)):
    return False, "Пароль должен содержать буквы, цифры и знаки арифметических операций"

  data[user_data["login"]]["password"] = hash_password(new_pass)
  save_data()

  return True, "Пароль успешно изменён"

# Удаление метки первой авторизации
def first_login(user_data):
  data[user_data["login"]]["first_login"] = False
  save_data()

# Изменение параметра проверки пароля пользователя
def set_check_password(login, enabled):
  data[login]["check_password"] = enabled
  save_data()

# Изменение параметра блокировки пользователя
def set_blocked(login, enabled):
  data[login]["blocked"] = enabled
  save_data()
