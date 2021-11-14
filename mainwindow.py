from PyQt5 import QtWidgets, uic, Qt
import security

win = uic.loadUi("mainwindow.ui")
user = None

def create(current_user):
  # Установка текущего пользователя
  global user
  user = current_user
  # Строка состояния выполнена в виде названия окна
  win.setWindowTitle("Основное окно | Вы вошли как " + user["login"])

  if (user["first_login"]):
    # При первой авторизации пользователю предлогается изменить пароль
    security.first_login(user)
    change_password_window()

  if (user["admin"]):
    # Добавление информации в строку состояния
    win.setWindowTitle(win.windowTitle() + " | Режим администратора")

    # Отображение списка пользователей и кнопки добавления нового пользователя
    win.tableWidgetUsers.show()
    win.pushButtonAddUser.show()

    # Загрузка списка пользователей
    load_users()
  else:
    # В режиме пользователя список пользователей и кнопка добавления нового пользователя скрыты
    win.tableWidgetUsers.hide()
    win.pushButtonAddUser.hide()

  win.show()
  return win

def load_users():
  table = win.tableWidgetUsers
  table.setRowCount(0)
  table.setColumnCount(3)
  table.setHorizontalHeaderLabels(["Логин", "Проверка пароля", "Блокировка"])

  row = 0

  for login in security.data:
    user = security.data[login]

    # В списке отображаются только пользователи
    if (user["admin"]):
      continue

    login_item = QtWidgets.QTableWidgetItem(user["login"])

    check_password_item = QtWidgets.QCheckBox("", table)
    check_password_item.setTristate(False)
    check_password_item.setCheckState(0 if not user["check_password"] else 2)
    check_password_item.setStyleSheet("margin-left:50%; margin-right:50%;")

    check_password_item.stateChanged.connect(check_password_changed)

    blocked_item = QtWidgets.QCheckBox("", table)
    blocked_item.setTristate(False)
    blocked_item.setCheckState(0 if not user["blocked"] else 2)
    blocked_item.setStyleSheet("margin-left:50%; margin-right:50%;")

    blocked_item.stateChanged.connect(blocked_changed)

    table.insertRow(row)
    table.setItem(row, 0, login_item)
    table.setCellWidget(row, 1, check_password_item)
    table.setCellWidget(row, 2, blocked_item)
    row += 1

  table.resizeColumnsToContents()

# Настройка проверки пароля пользователя с помощью CheckBox
def check_password_changed(state):
  table = win.tableWidgetUsers
  enabled = False if state == 0 else True
  login = table.item(table.currentRow(), 0).text()
  
  security.set_check_password(login, enabled)
  
# Настройка блокировки пользователя с помощью CheckBox
def blocked_changed(state):
  table = win.tableWidgetUsers
  enabled = False if state == 0 else True
  login = table.item(table.currentRow(), 0).text()

  security.set_blocked(login, enabled)

# Диалоговое окно для ввода имени нового пользователя
def add_user():
  name, done = QtWidgets.QInputDialog.getText(win, "Добавление пользователя", "Введите имя нового пользователя:")

  if (done):
    # Создание пользователя
    result, message = security.create_user({
      "login": name
      })
    
    if (not result):
      # Вывод сообщения об ошибке
      QtWidgets.QMessageBox.information(win, "Ошибка", message)
      add_user()
    else:
      # Перезагрузка списка пользователей
      load_users()
      QtWidgets.QMessageBox.information(win, "Успех", "Пользователь успешно добавлен")

win.pushButtonAddUser.clicked.connect(add_user)

# Открытие окна изменения пароля
def change_password_window():
  win.changepassword = uic.loadUi("changepassword.ui")

  if (win.changepassword.isHidden()):
    win.changepassword.show()
  
  win.changepassword.pushButtonChange.clicked.connect(change_password)

# Обработка логики она изменения пароля
def change_password():
  cur_pass = win.changepassword.lineEditCurrentPassword.text()
  new_pass = win.changepassword.lineEditNewPassword.text()
  new_pass_rep = win.changepassword.lineEditNewPasswordRepeat.text()

  result, message = security.change_password(user, cur_pass, new_pass, new_pass_rep)

  if (not result):
    QtWidgets.QMessageBox.information(win, "Ошибка", message)
  else:
    QtWidgets.QMessageBox.information(win, "Успех", message)
    win.changepassword.close()

win.actionChangePassword.triggered.connect(change_password_window)

# Содержание окна "О программе"
program_info = """Демонстрационная программа разграничения полномочий пользователей на основе парольной аутентификации c использованием встроенных криптопровайдеров.
Разработчик: Смирнов Александр Алексеевич, ИСЭбд-41, Вариант №16.
Ограничение на выбираемые пароли: Наличие букв, цифр и знаков арифметических операций.
Используемый режим шифрования алгоритма DES: OFB.
Добавление к ключу случайного значения: Нет
Используемый алгоритм хеширования: MD4"""

def show_help():
  QtWidgets.QMessageBox.information(win, "О программе", program_info)

win.actionHelp.triggered.connect(show_help)
