"""PySide6 Desktop Application Entry Point for DeadDrop."""

import os
import sys
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from deaddrop.client.api import DeadDropClient
from deaddrop.client.ui.drops_view import DropsView
from deaddrop.client.ui.lab_view import LabView
from deaddrop.client.ui.receive_view import ReceiveView
from deaddrop.client.ui.send_view import SendView
from deaddrop.client.ui.settings_view import SettingsView
from deaddrop.client.ui.styles import KALI_DARK_THEME


class DeadDropMainWindow(QMainWindow):
    """Main window hosting tab navigation for Send, Receive, My Drops, Lab, and Settings."""

    def __init__(self, relay_url: str = "http://127.0.0.1:8000"):
        super().__init__()
        self.setWindowTitle("DeadDrop - Zero-Knowledge 2FA File Exchange [Kali Linux]")
        self.resize(920, 760)
        self.setMinimumSize(800, 650)

        self.api_client = DeadDropClient(base_url=relay_url)
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(16, 16, 16, 16)
        root_layout.setSpacing(10)

        # Header bar
        header_bar = QHBoxLayout()
        app_title = QLabel("✦ DEADDROP")
        app_title.setStyleSheet("font-size: 22px; font-weight: 900; color: #58a6ff; letter-spacing: 2px;")
        header_bar.addWidget(app_title)

        badge = QLabel("AES-256-GCM | ARGON2ID | GOOGLE AUTH 2FA | ZERO-KNOWLEDGE")
        badge.setStyleSheet(
            "background-color: #21262d; color: #2ea043; font-family: monospace; font-size: 11px; "
            "padding: 4px 10px; border: 1px solid #30363d; border-radius: 4px; font-weight: bold;"
        )
        header_bar.addWidget(badge)
        header_bar.addStretch()

        env_label = QLabel("ENV: Kali Linux / Desktop")
        env_label.setStyleSheet("color: #8b949e; font-size: 11px;")
        header_bar.addWidget(env_label)

        root_layout.addLayout(header_bar)

        # Tabs
        self.tabs = QTabWidget()

        self.send_tab = SendView(self.api_client)
        self.receive_tab = ReceiveView(self.api_client)
        self.drops_tab = DropsView(self.api_client)
        self.lab_tab = LabView(self.api_client)
        self.settings_tab = SettingsView(self.api_client)

        self.tabs.addTab(self.send_tab, "📤 Send Drop")
        self.tabs.addTab(self.receive_tab, "📥 Receive Drop")
        self.tabs.addTab(self.drops_tab, "📋 My Drops")
        self.tabs.addTab(self.lab_tab, "🔬 Security Lab")
        self.tabs.addTab(self.settings_tab, "⚙ Settings")

        self.tabs.currentChanged.connect(self._on_tab_changed)

        root_layout.addWidget(self.tabs)

    def _on_tab_changed(self, index: int):
        # Auto-refresh My Drops when switching to tab
        if self.tabs.widget(index) == self.drops_tab:
            self.drops_tab.load_drops()


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(KALI_DARK_THEME)

    server_url = os.getenv("DEADDROP_SERVER_URL", "http://127.0.0.1:8000")
    window = DeadDropMainWindow(relay_url=server_url)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
