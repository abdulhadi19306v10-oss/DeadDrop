"""Receive View: Drop code, password, 2FA verification, download, and decryption."""

import os
import subprocess
import sys
from pathlib import Path
from typing import Optional
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from deaddrop.client.api import DeadDropClient
from deaddrop.client.ui.widgets import SixBoxTotpInput
from deaddrop.client.workers import UnlockDownloadWorker


class ReceiveView(QWidget):
    """Receive tab screen for entering drop code, 2FA credentials, and downloading."""

    def __init__(self, api_client: DeadDropClient, parent=None):
        super().__init__(parent)
        self.api = api_client
        self.worker: Optional[UnlockDownloadWorker] = None
        self.output_dir: str = str(Path.home() / "Downloads")
        self.lockout_seconds_remaining = 0
        self.lockout_timer = QTimer(self)
        self.lockout_timer.timeout.connect(self._update_lockout_timer)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Receive & Unlock DeadDrop")
        title.setObjectName("headerTitle")
        subtitle = QLabel("Provide the Drop Code, Password, and current 6-digit Google Authenticator TOTP code.")
        subtitle.setObjectName("subtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        # 1. Drop Code Box
        code_box = QGroupBox("1. Drop Code")
        code_layout = QVBoxLayout(code_box)
        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("DD1-<drop_id>-<link_secret>")
        self.code_input.setObjectName("monoField")
        code_layout.addWidget(self.code_input)
        layout.addWidget(code_box)

        # 2. Password Box
        pwd_box = QGroupBox("2. Drop Password")
        pwd_layout = QHBoxLayout(pwd_box)
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.setPlaceholderText("Enter the decryption password")
        self.pwd_input.setObjectName("monoField")
        pwd_layout.addWidget(self.pwd_input)

        self.toggle_pwd_btn = QPushButton("Show")
        self.toggle_pwd_btn.setFixedWidth(60)
        self.toggle_pwd_btn.clicked.connect(self._toggle_pwd)
        pwd_layout.addWidget(self.toggle_pwd_btn)
        layout.addWidget(pwd_box)

        # 3. Two-Factor Authentication Box
        self.twofa_box = QGroupBox("3. Two-Factor Authentication")
        twofa_layout = QVBoxLayout(self.twofa_box)

        totp_row = QHBoxLayout()
        self.totp_label = QLabel("6-Digit TOTP:")
        self.totp_label.setStyleSheet("font-weight: bold; color: #58a6ff;")
        totp_row.addWidget(self.totp_label)

        self.totp_input = SixBoxTotpInput()
        totp_row.addWidget(self.totp_input)
        totp_row.addStretch()
        twofa_layout.addLayout(totp_row)

        backup_row = QHBoxLayout()
        self.toggle_mode_btn = QPushButton("Use single-use backup code instead")
        self.toggle_mode_btn.setStyleSheet("border: none; color: #58a6ff; text-align: left; text-decoration: underline;")
        self.toggle_mode_btn.setCursor(Qt.PointingHandCursor)
        self.toggle_mode_btn.clicked.connect(self._toggle_auth_mode)
        backup_row.addWidget(self.toggle_mode_btn)
        backup_row.addStretch()
        twofa_layout.addLayout(backup_row)

        # Hidden by default backup code input
        self.backup_input = QLineEdit()
        self.backup_input.setPlaceholderText("Enter 8-character backup code (e.g. ABCD-1234)")
        self.backup_input.setObjectName("monoField")
        self.backup_input.setVisible(False)
        twofa_layout.addWidget(self.backup_input)

        layout.addWidget(self.twofa_box)

        # 4. Save Location Box
        dest_box = QGroupBox("4. Destination Folder")
        dest_layout = QHBoxLayout(dest_box)
        self.dest_label = QLabel(self.output_dir)
        self.dest_label.setStyleSheet("color: #8b949e;")
        dest_layout.addWidget(self.dest_label)

        change_dest_btn = QPushButton("Change Folder...")
        change_dest_btn.clicked.connect(self._choose_dest)
        dest_layout.addWidget(change_dest_btn)
        layout.addWidget(dest_box)

        # Progress & Status
        self.prog_bar = QProgressBar()
        self.prog_bar.setRange(0, 100)
        self.prog_bar.setValue(0)
        self.prog_bar.setVisible(False)
        layout.addWidget(self.prog_bar)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #58a6ff; font-weight: bold;")
        self.status_label.setVisible(False)
        layout.addWidget(self.status_label)

        action_row = QHBoxLayout()
        action_row.addStretch()
        self.unlock_btn = QPushButton("Unlock & Decrypt File")
        self.unlock_btn.setObjectName("primaryAction")
        self.unlock_btn.clicked.connect(self._start_download)
        action_row.addWidget(self.unlock_btn)
        layout.addLayout(action_row)

        layout.addStretch()

    def _toggle_pwd(self):
        if self.pwd_input.echoMode() == QLineEdit.Password:
            self.pwd_input.setEchoMode(QLineEdit.Normal)
            self.toggle_pwd_btn.setText("Hide")
        else:
            self.pwd_input.setEchoMode(QLineEdit.Password)
            self.toggle_pwd_btn.setText("Show")

    def _toggle_auth_mode(self):
        if self.totp_input.isVisible():
            self.totp_input.setVisible(False)
            self.totp_label.setVisible(False)
            self.backup_input.setVisible(True)
            self.toggle_mode_btn.setText("Use Google Authenticator TOTP instead")
        else:
            self.totp_input.setVisible(True)
            self.totp_label.setVisible(True)
            self.backup_input.setVisible(False)
            self.toggle_mode_btn.setText("Use single-use backup code instead")

    def _choose_dest(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Destination Folder", self.output_dir)
        if folder:
            self.output_dir = folder
            self.dest_label.setText(folder)

    def _start_download(self):
        drop_code = self.code_input.text().strip()
        if not drop_code or not drop_code.startswith("DD1-"):
            QMessageBox.warning(self, "Invalid Drop Code", "Please enter a valid drop code starting with 'DD1-'.")
            return

        password = self.pwd_input.text().strip()
        if not password:
            QMessageBox.warning(self, "Missing Password", "Please enter the drop decryption password.")
            return

        totp_code = None
        backup_code = None
        if self.totp_input.isVisible():
            totp_code = self.totp_input.get_code()
            if len(totp_code) != 6 or not totp_code.isdigit():
                QMessageBox.warning(self, "Invalid TOTP", "Please enter a 6-digit Google Authenticator code in the boxes.")
                return
        else:
            backup_code = self.backup_input.text().strip()
            if not backup_code:
                QMessageBox.warning(self, "Missing Backup Code", "Please enter a backup code.")
                return

        self.unlock_btn.setEnabled(False)
        self.prog_bar.setVisible(True)
        self.prog_bar.setValue(0)
        self.status_label.setVisible(True)
        self.status_label.setText("Connecting to relay...")

        self.worker = UnlockDownloadWorker(
            api_client=self.api,
            drop_code=drop_code,
            password=password,
            totp_code=totp_code,
            backup_code=backup_code,
            output_directory=self.output_dir,
        )
        self.worker.progress.connect(self._on_progress)
        self.worker.success.connect(self._on_success)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def _on_progress(self, curr: int, tot: int, msg: str):
        self.prog_bar.setValue(curr)
        self.status_label.setText(msg)

    def _on_success(self, final_path: str, metadata: dict):
        self.unlock_btn.setEnabled(True)
        self.prog_bar.setVisible(False)
        self.status_label.setText("Decryption succeeded!")

        # Wipe secrets from UI fields
        self.pwd_input.clear()
        self.totp_input.clear()
        self.backup_input.clear()

        dest_file = Path(final_path)
        reply = QMessageBox.information(
            self,
            "Success: File Decrypted",
            f"Successfully decrypted:\n\nFile: {dest_file.name}\nSize: {metadata.get('size')} bytes\nSaved to: {dest_file.parent}\n\nWould you like to open the destination folder?",
            QMessageBox.Open | QMessageBox.Ok,
            QMessageBox.Ok,
        )
        if reply == QMessageBox.Open:
            try:
                if sys.platform == "win32":
                    os.startfile(dest_file.parent)
                elif sys.platform == "darwin":
                    subprocess.run(["open", str(dest_file.parent)])
                else:
                    subprocess.run(["xdg-open", str(dest_file.parent)])
            except Exception:
                pass

    def _on_error(self, err_msg: str):
        self.unlock_btn.setEnabled(True)
        self.prog_bar.setVisible(False)
        self.status_label.setText("Failed.")

        # Check if lockout was triggered
        if "locked" in err_msg.lower():
            # Parse seconds if present or set standard lockout
            self.lockout_seconds_remaining = 900
            self.lockout_timer.start(1000)
            self._update_lockout_timer()

        QMessageBox.critical(self, "Decryption Failed", f"Could not unlock or decrypt file:\n\n{err_msg}")

    def _update_lockout_timer(self):
        if self.lockout_seconds_remaining > 0:
            self.lockout_seconds_remaining -= 1
            mins = self.lockout_seconds_remaining // 60
            secs = self.lockout_seconds_remaining % 60
            self.status_label.setText(f"Drop is locked due to failed attempts. Try again in {mins:02d}:{secs:02d}")
            self.status_label.setStyleSheet("color: #da3633; font-weight: bold;")
            self.unlock_btn.setEnabled(False)
        else:
            self.lockout_timer.stop()
            self.status_label.setText("")
            self.unlock_btn.setEnabled(True)
