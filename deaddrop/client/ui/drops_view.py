"""My Drops View: Drop tracking, manual burning, and immutable audit log viewer."""

import datetime
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from deaddrop.client.api import DeadDropClient, RelayAPIError


class AuditDialog(QDialog):
    """Dialog showing the cryptographic append-only audit trail for a drop."""

    def __init__(self, drop_id: str, audit_logs: list, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Audit Trail for Drop {drop_id[:8]}")
        self.setMinimumSize(620, 380)

        layout = QVBoxLayout(self)
        title = QLabel(f"Immutable Audit Trail (Drop: {drop_id})")
        title.setObjectName("headerTitle")
        subtitle = QLabel("All server events are permanently recorded with salted client IP hashes for privacy.")
        subtitle.setObjectName("subtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Timestamp (UTC)", "Event", "Outcome", "Salted IP Hash"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setRowCount(len(audit_logs))

        for row, entry in enumerate(audit_logs):
            dt = datetime.datetime.fromtimestamp(entry["timestamp"], tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            table.setItem(row, 0, QTableWidgetItem(dt))
            table.setItem(row, 1, QTableWidgetItem(entry["event"]))
            table.setItem(row, 2, QTableWidgetItem(entry["outcome"]))
            table.setItem(row, 3, QTableWidgetItem(entry["ip_hash"]))

        layout.addWidget(table)

        btn_box = QHBoxLayout()
        btn_box.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_box.addWidget(close_btn)
        layout.addLayout(btn_box)


class DropsView(QWidget):
    """My Drops screen displaying active drops, status, burn action, and audit trail."""

    def __init__(self, api_client: DeadDropClient, parent=None):
        super().__init__(parent)
        self.api = api_client
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(24, 24, 24, 24)

        title = QLabel("My Drops Dashboard")
        title.setObjectName("headerTitle")
        subtitle = QLabel("Manage your uploaded drops, monitor download counts, view audit trails, or trigger manual burns.")
        subtitle.setObjectName("subtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        # Action bar
        top_bar = QHBoxLayout()
        refresh_btn = QPushButton("Refresh List")
        refresh_btn.clicked.connect(self.load_drops)
        top_bar.addWidget(refresh_btn)
        top_bar.addStretch()

        self.burn_btn = QPushButton("Burn Selected Drop")
        self.burn_btn.setObjectName("dangerAction")
        self.burn_btn.clicked.connect(self._burn_selected)
        top_bar.addWidget(self.burn_btn)

        self.audit_btn = QPushButton("View Audit Trail")
        self.audit_btn.clicked.connect(self._view_audit)
        top_bar.addWidget(self.audit_btn)

        layout.addLayout(top_bar)

        # Drops Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Drop ID",
            "Status",
            "Size",
            "Downloads",
            "Expires At (UTC)",
            "Created At (UTC)",
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        layout.addWidget(self.table)

    def load_drops(self):
        """Fetches active drops from relay and populates the table."""
        try:
            drops = self.api.list_drops()
        except RelayAPIError as e:
            QMessageBox.warning(self, "Relay Error", f"Failed to fetch drops: {e.detail}")
            return

        self.table.setRowCount(len(drops))
        for row, d in enumerate(drops):
            drop_id = d["id"]
            status = d["status"]
            size_kb = (d.get("blob_size") or 0) / 1024
            size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{(size_kb/1024):.2f} MB"
            downloads_str = f"{d['downloads']} / {d['max_downloads']}"

            exp_dt = datetime.datetime.fromtimestamp(d["expires_at"], tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M")
            cre_dt = datetime.datetime.fromtimestamp(d["created_at"], tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M")

            id_item = QTableWidgetItem(f"{drop_id[:8]}...{drop_id[-4:]}")
            id_item.setData(Qt.UserRole, drop_id)
            self.table.setItem(row, 0, id_item)

            status_item = QTableWidgetItem(status.upper())
            if status == "active":
                status_item.setForeground(Qt.green)
            elif status == "burned":
                status_item.setForeground(Qt.red)
            else:
                status_item.setForeground(Qt.yellow)
            self.table.setItem(row, 1, status_item)

            self.table.setItem(row, 2, QTableWidgetItem(size_str))
            self.table.setItem(row, 3, QTableWidgetItem(downloads_str))
            self.table.setItem(row, 4, QTableWidgetItem(exp_dt))
            self.table.setItem(row, 5, QTableWidgetItem(cre_dt))

    def _get_selected_drop_id(self) -> str:
        selected_indexes = self.table.selectionModel().selectedRows()
        if not selected_indexes:
            QMessageBox.information(self, "Selection Required", "Please select a drop from the table.")
            return None
        row = selected_indexes[0].row()
        item = self.table.item(row, 0)
        return item.data(Qt.UserRole)

    def _burn_selected(self):
        drop_id = self._get_selected_drop_id()
        if not drop_id:
            return

        confirm = QMessageBox.warning(
            self,
            "Confirm Burn",
            f"Are you sure you want to burn drop {drop_id}?\n\nThis will permanently shred the ciphertext blob on the relay and destroy all key shares.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm == QMessageBox.Yes:
            try:
                self.api.burn_drop(drop_id)
                QMessageBox.information(self, "Burned", f"Drop {drop_id} was securely shredded.")
                self.load_drops()
            except RelayAPIError as e:
                QMessageBox.critical(self, "Burn Failed", f"Failed to burn drop: {e.detail}")

    def _view_audit(self):
        drop_id = self._get_selected_drop_id()
        if not drop_id:
            return

        try:
            audit_logs = self.api.get_audit(drop_id)
            dlg = AuditDialog(drop_id, audit_logs, parent=self)
            dlg.exec()
        except RelayAPIError as e:
            QMessageBox.critical(self, "Audit Failed", f"Failed to load audit logs: {e.detail}")
