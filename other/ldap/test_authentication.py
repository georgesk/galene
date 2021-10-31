import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QPushButton, QLabel, QLineEdit, QGridLayout)
from PyQt5.QtCore import Qt
import requests
import jwt

class Loginpage(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Test de l\'authentification (localhost:1234)')
        self.resize(550,200)
        layout = QGridLayout()
        label1 = QLabel('<b> Nom d\'utilisateur </b>')
        self.user_obj = QLineEdit()
        layout.addWidget(label1, 0, 0)
        layout.addWidget(self.user_obj, 0, 1)
        label2 = QLabel('<b> Mot de passe </b>')
        self.user_pwd = QLineEdit()
        self.user_pwd.setEchoMode(QLineEdit.Password);
        self.user_pwd.setInputMethodHints(Qt.ImhHiddenText|
                                          Qt.ImhNoPredictiveText|
                                          Qt.ImhNoAutoUppercase);
        layout.addWidget(label2, 1, 0)
        layout.addWidget(self.user_pwd, 1, 1)
        button_login = QPushButton('Essayer')
        layout.addWidget(button_login, 2, 0, 2, 2)
        self.setLayout(layout)
        button_login.clicked.connect(self.testeAuth)
        return

    def testeAuth(self):
        response = requests.post(
            url="http://localhost:1234/", 
            json={"group": "", "username": self.user_obj.text(),
                  "password": self.user_pwd.text()},
            timeout=5)
        print(response.status_code)
        print(response.text)
        print(jwt.decode(response.text, key=b"\1\2\3\4", algorithms=["HS256"],))
        return



app = QApplication(sys.argv)
form = Loginpage()
form.show()
sys.exit(app.exec_())
