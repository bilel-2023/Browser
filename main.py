import os
import sys
import json
from cryptography.fernet import Fernet
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QMainWindow, QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QComboBox, QPlainTextEdit, QMessageBox, QCheckBox
)
import requests

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        # Encryption key (this should be stored securely, not hardcoded in production)
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)

        self.cache_file = "cache.json"
        self.cookies_file = "cookies.json"
        self.cache = self.load_cache()
        self.cookies = self.load_cookies()
        self.session = requests.Session()

        # Charger les cookies dans la session
        self.session.cookies.update(self.cookies)

        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.layout = QVBoxLayout(self.main_widget)
        self.layout.setAlignment(Qt.AlignCenter)
        self.layout.setSpacing(20)

        title_label = QLabel("HTTP Browser with Persistent Cache and Cookies")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        title_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(title_label)

        url_layout = QHBoxLayout()
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Enter URL")
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        url_layout.addWidget(QLabel("URL:"))
        url_layout.addWidget(self.url_bar)
        self.layout.addLayout(url_layout)

        method_layout = QHBoxLayout()
        self.method_box = QComboBox()
        self.method_box.addItems(["GET", "POST", "PUT", "DELETE"])
        method_layout.addWidget(QLabel("Method:"))
        method_layout.addWidget(self.method_box)
        self.layout.addLayout(method_layout)

        self.cache_checkbox = QCheckBox("Use Cache")
        self.cache_checkbox.setChecked(True)
        self.layout.addWidget(self.cache_checkbox)

        self.headers_input = QPlainTextEdit()
        self.headers_input.setPlaceholderText("Headers (JSON)")
        self.layout.addWidget(QLabel("Headers:"))
        self.layout.addWidget(self.headers_input)

        self.body_input = QPlainTextEdit()
        self.body_input.setPlaceholderText("Body (JSON)")
        self.layout.addWidget(QLabel("Body:"))
        self.layout.addWidget(self.body_input)

        submit_button = QPushButton("Send Request")
        submit_button.setStyleSheet("padding: 10px; font-size: 16px; background-color: #4CAF50; color: white;")
        submit_button.clicked.connect(self.navigate_to_url)
        self.layout.addWidget(submit_button)

        clear_cache_button = QPushButton("Clear Cache")
        clear_cache_button.setStyleSheet("padding: 10px; font-size: 16px; background-color: #f44336; color: white;")
        clear_cache_button.clicked.connect(self.clear_cache)
        self.layout.addWidget(clear_cache_button)

        clear_cookies_button = QPushButton("Clear Cookies")
        clear_cookies_button.setStyleSheet("padding: 10px; font-size: 16px; background-color: #f44336; color: white;")
        clear_cookies_button.clicked.connect(self.clear_cookies)
        self.layout.addWidget(clear_cookies_button)

        self.response_area = QPlainTextEdit()
        self.response_area.setReadOnly(True)
        self.layout.addWidget(QLabel("Response:"))
        self.layout.addWidget(self.response_area)

        self.setWindowTitle("HTTP Browser with Persistent Cache and Cookies")
        self.resize(800, 600)

    def navigate_to_url(self):
        url = self.url_bar.text().strip()
        method = self.method_box.currentText()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        try:
            headers = self.parse_json(self.headers_input.toPlainText(), "Headers")
            body = self.parse_json(self.body_input.toPlainText(), "Body") if method in ["POST", "PUT"] else None
            cache_key = json.dumps([url, method, headers, body], sort_keys=True)

            if self.cache_checkbox.isChecked():
                if cache_key in self.cache:
                    cached_response = self.cache[cache_key]
                    cached_response['status_code'] = 304
                    QMessageBox.information(self, "Cache Hit", "Response loaded from cache.")
                    self.display_response(cached_response)
                    return

            response = self.session.request(method, url, headers=headers, json=body)
            response.raise_for_status()

            self.save_cookies()

            response_data = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "text": response.text
            }

            if self.cache_checkbox.isChecked():
                self.cache[cache_key] = response_data
                self.save_cache()

            self.display_response(response_data)

        except requests.exceptions.HTTPError as e:
            error_message = f"HTTP Error: {e.response.status_code} - {e.response.reason}"
            QMessageBox.warning(self, "HTTP Error", error_message)
            self.display_response({
                "status_code": e.response.status_code,
                "headers": dict(e.response.headers) if e.response else {},
                "text": e.response.text if e.response else "No response body"
            })
        except requests.exceptions.ConnectionError:
            QMessageBox.critical(self, "Connection Error", "Failed to connect to the server. Please check the URL.")
        except requests.exceptions.InvalidURL:
            QMessageBox.critical(self, "Invalid URL", "The URL entered is invalid. Please check and try again.")
        except ValueError as e:
            QMessageBox.critical(self, "Input Error", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Unexpected Error", f"An unexpected error occurred: {str(e)}")

    def clear_cache(self):
        self.cache = {}
        if os.path.exists(self.cache_file):
            os.remove(self.cache_file)
        QMessageBox.information(self, "Cache Cleared", "The cache has been successfully cleared.")

    def clear_cookies(self):
        self.cookies = {}
        self.session.cookies.clear()
        if os.path.exists(self.cookies_file):
            os.remove(self.cookies_file)
        QMessageBox.information(self, "Cookies Cleared", "All cookies have been successfully cleared.")

    def parse_json(self, json_text, field_name):
        if not json_text.strip():
            return None
        try:
            return json.loads(json_text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {field_name}: {str(e)}")

    def display_response(self, response):
        response_text = (
            f"Status Code: {response['status_code']}\n\n"
            f"Headers:\n{json.dumps(response['headers'], indent=2)}\n\n"
            f"Body:\n{response['text']}"
        )
        self.response_area.setPlainText(response_text)

    def load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "rb") as file:
                    encrypted_data = file.read()
                    return self.decrypt_data(encrypted_data)
            except Exception as e:
                QMessageBox.warning(self, "Cache Error", f"Cache file is corrupted or encrypted data error. {str(e)}")
        return {}

    def save_cache(self):
        with open(self.cache_file, "wb") as file:
            encrypted_data = self.encrypt_data(self.cache)
            file.write(encrypted_data)

    def load_cookies(self):
        if os.path.exists(self.cookies_file):
            try:
                with open(self.cookies_file, "rb") as file:
                    encrypted_data = file.read()
                    return self.decrypt_data(encrypted_data)
            except Exception as e:
                QMessageBox.warning(self, "Cookies Error", f"Cookies file is corrupted or encrypted data error. {str(e)}")
        return {}

    def save_cookies(self):
        cookies_dict = requests.utils.dict_from_cookiejar(self.session.cookies)
        with open(self.cookies_file, "wb") as file:
            encrypted_data = self.encrypt_data(cookies_dict)
            file.write(encrypted_data)

    def encrypt_data(self, data):
        serialized_data = json.dumps(data).encode()
        return self.cipher_suite.encrypt(serialized_data)

    def decrypt_data(self, data):
        decrypted_data = self.cipher_suite.decrypt(data)
        return json.loads(decrypted_data)

app = QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec_()
