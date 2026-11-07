"""Settings View: Relay endpoint configuration, TLS pinning, and app preferences."""

import time
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)
import httpx

from deaddrop.client.api import DeadDropClient


class SettingsView(QWidget):
    """Settings tab screen for configuring server endpoint and security preferences."""

    def __init__(self, api_client: DeadDropClient, parent=None):
        super().__init__(parent)
        self.api = api_client
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel("DeadDrop Settings & Preferences")
        title.setObjectName("headerTitle")
        subtitle = QLabel("Configure relay server connection, TLS certificates, and default drop policies.")
        subtitle.setObjectName("subtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        # 1. Connection Box
        conn_box = QGroupBox("Relay Server Connection")
        conn_layout = QVBoxLayout(conn_box)

        url_row = QHBoxLayout()
        url_row.addWidget(QLabel("Server URL:"))
        self.server_url_input = QLineEdit(self.api.base_url)
        self.server_url_input.setObjectName("monoField")
        url_row.addWidget(self.server_url_input)

        test_btn = QPushButton("Test Connection")
        test_btn.clicked.connect(self._test_connection)
        url_row.addWidget(test_btn)
        conn_layout.addLayout(url_row)

        pin_row = QHBoxLayout()
        pin_row.addWidget(QLabel("Pinned TLS SHA-256:"))
        self.pin_input = QLineEdit()
        self.pin_input.setPlaceholderText("Optional: SHA-256 certificate fingerprint for TLS pinning")
        self.pin_input.setObjectName("monoField")
        pin_row.addWidget(self.pin_input)
        conn_layout.addLayout(pin_row)

        layout.addWidget(conn_box)

        # 2. Defaults Box
        defaults_box = QGroupBox("Default Drop Parameters")
        defaults_layout = QFormLayout(defaults_box)

        self.default_expiry = QComboBox()
        self.default_expiry.addItem("1 hour", 1)
        self.default_expiry.addItem("6 hours", 6)
        self.default_expiry.addItem("24 hours (Recommended)", 24)
        self.default_expiry.addItem("3 days", 72)
        self.default_expiry.addItem("7 days", 168)
        self.default_expiry.setCurrentIndex(2)
        defaults_layout.addRow("Default Expiry:", self.default_expiry)

        self.default_downloads = QSpinBox()
        self.default_downloads.setRange(1, 10)
        self.default_downloads.setValue(1)
        self.default_downloads.setSuffix(" (Burn-after-read)")
        defaults_layout.addRow("Default Downloads:", self.default_downloads)

        layout.addWidget(defaults_box)

        # 3. About & Course Information
        about_box = QGroupBox("About DeadDrop")
        about_layout = QVBoxLayout(about_box)
        about_text = QLabel(
            "DeadDrop - Zero-Knowledge 2FA-Protected Secure File Exchange\n"
            "Project: Information Security Lab Mid-Term\n"
            "Target Environment: Kali Linux (Debian) / Cross-Platform Desktop\n"
            "Cryptographic Stack: AES-256-GCM, Argon2id, HKDF-SHA256, RFC 6238 TOTP (Google Authenticator)"
        )
        about_text.setStyleSheet("color: #8b949e; line-height: 1.4;")
        about_layout.addWidget(about_text)
        layout.addWidget(about_box)

        # Save Button
        action_row = QHBoxLayout()
        action_row.addStretch()
        save_btn = QPushButton("Save Settings")
        save_btn.setObjectName("primaryAction")
        save_btn.clicked.connect(self._save_settings)
        action_row.addWidget(save_btn)
        layout.addLayout(action_row)

        layout.addStretch()

    def _test_connection(self):
        url = self.server_url_input.text().strip().rstrip("/")
        start = time.perf_counter()
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(f"{url}/health")
                elapsed = (time.perf_counter() - start) * 1000
                if res.status_code == 200:
                    info = res.json()
                    QMessageBox.information(
                        self,
                        "Connection Succeeded",
                        f"Connected to relay successfully in {elapsed:.1f} ms!\n\n"
                        f"Service: {info.get('service')}\nVersion: {info.get('version')}",
                    )
                else:
                    QMessageBox.warning(self, "Unexpected Response", f"Server returned HTTP {res.status_code}: {res.text}")
        except Exception as e:
            QMessageBox.critical(self, "Connection Failed", f"Could not reach server at {url}:\n\n{e}")

    def _save_settings(self):
        new_url = self.server_url_input.text().strip().rstrip("/")
        self.api.base_url = new_url
        QMessageBox.information(self, "Settings Saved", f"Relay server URL updated to:\n{new_url}")
