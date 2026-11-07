"""Reusable UI widgets for DeadDrop desktop application."""

import io
import os
import secrets
from typing import Dict, List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont, QImage, QPainter, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
import qrcode
import zxcvbn


DICEWARE_WORDS = [
    "alpha", "bravo", "cipher", "delta", "echo", "falcon", "galaxy", "hazard",
    "iron", "jupiter", "kilo", "laser", "matrix", "nexus", "orbit", "phantom",
    "quantum", "radar", "stealth", "titan", "ultra", "vector", "whisper", "xenon",
    "yonder", "zenith", "aurora", "beacon", "crypto", "dragon", "entropy", "fusion"
]


def generate_passphrase(num_words: int = 4) -> str:
    """Generates a high-entropy Diceware-style passphrase."""
    chosen = [secrets.choice(DICEWARE_WORDS) for _ in range(num_words)]
    num = secrets.randbelow(90) + 10
    symbols = "!@#$%^&*"
    sym = secrets.choice(symbols)
    return f"{'-'.join(chosen)}-{num}{sym}"


class PasswordStrengthBar(QWidget):
    """Visual password strength meter with zxcvbn evaluation."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.score = 0
        self.feedback_text = "Enter a password"
        self.crack_time = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(4)

        self.bar = QProgressBar()
        self.bar.setRange(0, 4)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(8)

        self.label = QLabel(self.feedback_text)
        self.label.setStyleSheet("color: #8b949e; font-size: 11px;")

        layout.addWidget(self.bar)
        layout.addWidget(self.label)

    def evaluate(self, password: str) -> int:
        if not password:
            self.score = 0
            self.bar.setValue(0)
            self.label.setText("Enter a password")
            self.bar.setStyleSheet("QProgressBar::chunk { background-color: #30363d; }")
            return 0

        res = zxcvbn.zxcvbn(password)
        self.score = res["score"]  # 0 to 4
        self.bar.setValue(self.score)

        crack_time = res["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
        levels = [
            ("Very Weak", "#f85149"),
            ("Weak", "#da3633"),
            ("Fair", "#d29922"),
            ("Strong", "#238636"),
            ("Very Strong", "#2ea043"),
        ]

        text, color = levels[self.score]
        self.label.setText(f"Strength: {text} (Crack time: ~{crack_time})")
        self.label.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: bold;")
        self.bar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; border-radius: 4px; }}")
        return self.score


class QRCodeWidget(QLabel):
    """Displays a QR code for Google Authenticator TOTP scanning."""

    def __init__(self, size: int = 190, parent=None):
        super().__init__(parent)
        self.qr_size = size
        self.setFixedSize(size, size)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet("background-color: white; border: 2px solid #58a6ff; border-radius: 8px;")

    def set_data(self, data: str):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=6,
            border=2,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        # Convert PIL to QPixmap
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qimg = QImage.fromData(buf.getvalue())
        pixmap = QPixmap.fromImage(qimg).scaled(
            self.qr_size - 8,
            self.qr_size - 8,
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation,
        )
        self.setPixmap(pixmap)


class SharePackageDialog(QDialog):
    """Modal dialog displaying the Share Package once a drop is active."""

    def __init__(self, share_data: Dict[str, any], parent=None):
        super().__init__(parent)
        self.share_data = share_data
        self.setWindowTitle("DeadDrop Share Package (Save Securely)")
        self.setMinimumSize(560, 680)
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(14)
        main_layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("Drop Created & Encrypted Successfully")
        title.setObjectName("headerTitle")
        main_layout.addWidget(title)

        notice = QLabel(
            "IMPORTANT: Share the Drop Code and Password over SEPARATE communication channels!\n"
            "The recipient needs the Drop Code, Password, and TOTP code to decrypt the file."
        )
        notice.setObjectName("securityNotice")
        notice.setWordWrap(True)
        main_layout.addWidget(notice)

        # 1. Drop Code Field
        code_box = QGroupBox("1. Drop Code (Send via chat or email)")
        code_layout = QHBoxLayout(code_box)
        self.code_edit = QLineEdit(self.share_data["drop_code"])
        self.code_edit.setReadOnly(True)
        self.code_edit.setObjectName("monoField")
        copy_code_btn = QPushButton("Copy")
        copy_code_btn.clicked.connect(lambda: self._copy(self.code_edit.text(), "Drop Code"))
        code_layout.addWidget(self.code_edit)
        code_layout.addWidget(copy_code_btn)
        main_layout.addWidget(code_box)

        # 2. Password Field
        pwd_box = QGroupBox("2. Drop Password (Send via a DIFFERENT channel)")
        pwd_layout = QHBoxLayout(pwd_box)
        self.pwd_edit = QLineEdit(self.share_data["password"])
        self.pwd_edit.setReadOnly(True)
        self.pwd_edit.setObjectName("monoField")
        copy_pwd_btn = QPushButton("Copy")
        copy_pwd_btn.clicked.connect(lambda: self._copy(self.pwd_edit.text(), "Password"))
        pwd_layout.addWidget(self.pwd_edit)
        pwd_layout.addWidget(copy_pwd_btn)
        main_layout.addWidget(pwd_box)

        # 3. TOTP QR & Manual Secret
        totp_box = QGroupBox("3. Two-Factor Authentication (Google Authenticator)")
        totp_layout = QHBoxLayout(totp_box)

        qr_widget = QRCodeWidget(size=180)
        qr_widget.set_data(self.share_data["totp_uri"])
        totp_layout.addWidget(qr_widget)

        secret_info_layout = QVBoxLayout()
        desc = QLabel("Scan QR code into Google Authenticator\nor enter manual base32 secret:")
        desc.setWordWrap(True)
        secret_info_layout.addWidget(desc)

        self.secret_edit = QLineEdit(self.share_data["totp_secret"])
        self.secret_edit.setReadOnly(True)
        self.secret_edit.setObjectName("monoField")
        copy_secret_btn = QPushButton("Copy Secret")
        copy_secret_btn.clicked.connect(lambda: self._copy(self.secret_edit.text(), "TOTP Secret"))
        secret_info_layout.addWidget(self.secret_edit)
        secret_info_layout.addWidget(copy_secret_btn)
        secret_info_layout.addStretch()

        totp_layout.addLayout(secret_info_layout)
        main_layout.addWidget(totp_box)

        # 4. Backup Codes
        backup_box = QGroupBox("4. Single-Use Backup Codes (In case TOTP is unavailable)")
        backup_layout = QVBoxLayout(backup_box)
        codes_text = "\n".join(self.share_data["backup_codes"])
        self.backup_edit = QTextEdit(codes_text)
        self.backup_edit.setReadOnly(True)
        self.backup_edit.setFixedHeight(70)
        self.backup_edit.setObjectName("monoField")
        copy_backup_btn = QPushButton("Copy Backup Codes")
        copy_backup_btn.clicked.connect(lambda: self._copy(codes_text, "Backup Codes"))
        backup_layout.addWidget(self.backup_edit)
        backup_layout.addWidget(copy_backup_btn)
        main_layout.addWidget(backup_box)

        # Action Buttons
        btn_layout = QHBoxLayout()
        save_file_btn = QPushButton("Save All to File...")
        save_file_btn.clicked.connect(self._save_to_file)
        btn_layout.addWidget(save_file_btn)
        btn_layout.addStretch()

        self.confirm_check = QCheckBox("I have recorded all credentials safely")
        self.confirm_check.stateChanged.connect(self._on_check_changed)
        btn_layout.addWidget(self.confirm_check)

        self.close_btn = QPushButton("Done")
        self.close_btn.setObjectName("primaryAction")
        self.close_btn.setEnabled(False)
        self.close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(self.close_btn)

        main_layout.addLayout(btn_layout)

    def _copy(self, text: str, name: str):
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Copied", f"{name} copied to clipboard.")

    def _on_check_changed(self, state):
        self.close_btn.setEnabled(self.confirm_check.isChecked())

    def _save_to_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Share Package", "deaddrop_credentials.txt", "Text Files (*.txt)")
        if path:
            content = (
                "============================================================\n"
                "           DEADDROP CREDENTIALS & SHARE PACKAGE             \n"
                "============================================================\n\n"
                f"Drop Code   : {self.share_data['drop_code']}\n"
                f"Password    : {self.share_data['password']}\n"
                f"TOTP Secret : {self.share_data['totp_secret']}\n"
                f"TOTP URI    : {self.share_data['totp_uri']}\n\n"
                "Single-Use Backup Codes:\n" + "\n".join(f"  - {c}" for c in self.share_data['backup_codes']) + "\n\n"
                "NOTE: Share Drop Code and Password over SEPARATE communication channels!\n"
            )
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            QMessageBox.information(self, "Saved", f"Credentials saved to:\n{path}")
