from PyQt5 import QtWidgets, uic
import sys

app = QtWidgets.QApplication([])

import security

# Получение ключа из файла
key = security.get_key()
can_start = True

if (not key):
  if (security.is_data_present()):
    # Если ключа нет, но имеются зашифрованные данные, спрашиваем у пользователя парольную фразу для расшифровки.
    new_key, done = QtWidgets.QInputDialog.getText(None, "Ключ расшифрования", "Введите ключ расшифрования")

    if (done):
      key = security.hash_key(new_key)
  else:
    # В ином случае, генерируем новый ключ шифрования.
    new_key, done = QtWidgets.QInputDialog.getText(None, "Ключ расшифрования", "Введите новый ключ расшифрования")

    if (done):
      security.generate_key(new_key)

# Проверка введённого ключа шифрования.
result, message = security.validate_hash_key(key)

if (not result):
  # Если проверка не пройдена, программа завершает работу.
  QtWidgets.QMessageBox.information(None, "Ошибка", message)
  sys.exit()
elif (not security.get_key()):
  # Сохранение введённого ключа в файл.
  security.save_key()

# Инициализация данных
security.init()

# Загрузка окна авторизации
win = uic.loadUi("login.ui")
win.setFixedSize(win.geometry().width(), win.geometry().height())

import mainwindow

# Обработка нажатия кнопки "Выход"
def close():
  win.close()

win.pushButtonExit.clicked.connect(close)

# Обработка кнопки "Войти"
def login():
  login = win.lineEditLogin.text()
  password = win.lineEditPassword.text()
  
  # Аутентификация пользователя
  result, message = security.auth(login, password)

  
  if (result == True):
    # Авторизация пользователя, переход на главное окно
    user = security.get_user(login)
    win.mainwindow = mainwindow.create(user)

    # Подключение обработки закрытия главного окна
    win.mainwindow.closeEvent = close_event
    win.close()
  else:
    QtWidgets.QMessageBox.information(win, "Ошибка", message)

    # Превышение допустимого количества ошибок при вводе пароля - программа завершает работу.
    if (result == -1):
      win.close()

win.pushButtonLogin.clicked.connect(login)

# Обработка закрытия главного окна
def close_event(event):
  # Отображение окна авторизации
  win.show()
  event.accept()

win.show()
sys.exit(app.exec())
