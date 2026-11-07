"""Send View: Drag-and-drop file selection, password generator, encryption, and upload."""

from pathlib import Path
from typing import Optional
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from deaddrop.client.api import DeadDropClient
from deaddrop.client.ui.widgets import PasswordStrengthBar, SharePackageDialog, generate_passphrase
from deaddrop.client.workers import EncryptUploadWorker


class SendView(QWidget):
    """Send tab screen for selecting, encrypting, and uploading drops."""

    def __init__(self, api_client: DeadDropClient, parent=None):
        super().__init__(parent)
        self.api = api_client
        self.selected_file_path: Optional[str] = None
        self.worker: Optional[EncryptUploadWorker] = None
        self.setAcceptDrops(True)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel("Send Secure DeadDrop")
        title.setObjectName("headerTitle")
        subtitle = QLabel("Files are encrypted client-side in RAM with AES-256-GCM before uploading to the cloud relay.")
        subtitle.setObjectName("subtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        # 1. File Selection Box
        file_box = QGroupBox("1. File Selection (Drag & Drop supported)")
        file_layout = QVBoxLayout(file_box)

        self.file_label = QLabel("No file selected. Click 'Browse' or drag a file here.")
        self.file_label.setStyleSheet("padding: 16px; border: 2px dashed #30363d; border-radius: 6px; color: #8b949e;")
        self.file_label.setAlignment(Qt.AlignCenter)
        file_layout.addWidget(self.file_label)

        btn_row = QHBoxLayout()
        browse_btn = QPushButton("Browse File...")
        browse_btn.clicked.connect(self._browse_file)
        btn_row.addWidget(browse_btn)
        btn_row.addStretch()
        file_layout.addLayout(btn_row)

        layout.addWidget(file_box)

        # 2. Password & Key Derivation Box
        pwd_box = QGroupBox("2. Access Password (KDF Argon2id)")
        pwd_layout = QVBoxLayout(pwd_box)

        input_row = QHBoxLayout()
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.setPlaceholderText("Enter or generate a strong password")
        self.pwd_input.textChanged.connect(self._on_password_changed)
        input_row.addWidget(self.pwd_input)

        self.toggle_pwd_btn = QPushButton("Show")
        self.toggle_pwd_btn.setFixedWidth(60)
        self.toggle_pwd_btn.clicked.connect(self._toggle_password)
        input_row.addWidget(self.toggle_pwd_btn)

        gen_btn = QPushButton("Generate Diceware")
        gen_btn.clicked.connect(self._generate_password)
        input_row.addWidget(gen_btn)

        pwd_layout.addLayout(input_row)

        self.strength_meter = PasswordStrengthBar()
        pwd_layout.addWidget(self.strength_meter)

        layout.addWidget(pwd_box)

        # 3. Policy Settings Box
        policy_box = QGroupBox("3. Expiration and Download Limits")
        policy_layout = QHBoxLayout(policy_box)

        policy_layout.addWidget(QLabel("Expires in:"))
        self.expiry_combo = QComboBox()
        self.expiry_combo.addItem("1 hour", 1)
        self.expiry_combo.addItem("6 hours", 6)
        self.expiry_combo.addItem("24 hours (Default)", 24)
        self.expiry_combo.addItem("3 days", 72)
        self.expiry_combo.addItem("7 days", 168)
        self.expiry_combo.setCurrentIndex(2)
        policy_layout.addWidget(self.expiry_combo)

        policy_layout.addSpacing(20)

        policy_layout.addWidget(QLabel("Max downloads:"))
        self.downloads_spin = QSpinBox()
        self.downloads_spin.setRange(1, 10)
        self.downloads_spin.setValue(1)
        self.downloads_spin.setSuffix(" (Burn after read)")
        policy_layout.addWidget(self.downloads_spin)

        policy_layout.addStretch()
        layout.addWidget(policy_box)

        # 4. Progress and Action
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
        self.send_btn = QPushButton("Encrypt & Upload to Relay")
        self.send_btn.setObjectName("primaryAction")
        self.send_btn.clicked.connect(self._start_upload)
        action_row.addWidget(self.send_btn)
        layout.addLayout(action_row)

        layout.addStretch()

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            self._set_selected_file(path)

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt & Send")
        if path:
            self._set_selected_file(path)

    def _set_selected_file(self, path_str: str):
        path = Path(path_str)
        if path.is_file():
            self.selected_file_path = str(path)
            size_kb = path.stat().st_size / 1024
            size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{(size_kb/1024):.2f} MB"
            self.file_label.setText(f"Selected: {path.name}  |  Size: {size_str}")
            self.file_label.setStyleSheet("padding: 16px; border: 2px solid #238636; border-radius: 6px; color: #f0f6fc; font-weight: bold;")

    def _toggle_password(self):
        if self.pwd_input.echoMode() == QLineEdit.Password:
            self.pwd_input.setEchoMode(QLineEdit.Normal)
            self.toggle_pwd_btn.setText("Hide")
        else:
            self.pwd_input.setEchoMode(QLineEdit.Password)
            self.toggle_pwd_btn.setText("Show")

    def _generate_password(self):
        pwd = generate_passphrase(4)
        self.pwd_input.setText(pwd)
        self.pwd_input.setEchoMode(QLineEdit.Normal)
        self.toggle_pwd_btn.setText("Hide")

    def _on_password_changed(self, text: str):
        self.strength_meter.evaluate(text)

    def _start_upload(self):
        if not self.selected_file_path:
            QMessageBox.warning(self, "Missing File", "Please select a file to encrypt and send.")
            return

        pwd = self.pwd_input.text().strip()
        if not pwd or len(pwd) < 6:
            QMessageBox.warning(self, "Weak Password", "Please provide a password of at least 6 characters.")
            return

        expires_hours = self.expiry_combo.currentData()
        max_downloads = self.downloads_spin.value()

        self.send_btn.setEnabled(False)
        self.prog_bar.setVisible(True)
        self.prog_bar.setValue(0)
        self.status_label.setVisible(True)
        self.status_label.setText("Starting encryption...")

        self.worker = EncryptUploadWorker(
            api_client=self.api,
            file_path=self.selected_file_path,
            password=pwd,
            expires_hours=expires_hours,
            max_downloads=max_downloads,
        )
        self.worker.progress.connect(self._on_progress)
        self.worker.success.connect(self._on_success)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def _on_progress(self, current: int, total: int, msg: str):
        self.prog_bar.setValue(current)
        self.status_label.setText(msg)

    def _on_success(self, share_data: dict):
        self.send_btn.setEnabled(True)
        self.prog_bar.setVisible(False)
        self.status_label.setText("Upload complete!")

        # Wipe password input field
        self.pwd_input.clear()

        # Display Share Package Modal
        dlg = SharePackageDialog(share_data, parent=self)
        dlg.exec()

    def _on_error(self, err_msg: str):
        self.send_btn.setEnabled(True)
        self.prog_bar.setVisible(False)
        self.status_label.setText("Error occurred.")
        QMessageBox.critical(self, "Upload Failed", f"Operation failed: {err_msg}")
