"""Kali Linux / Cybersecurity Dark Theme Stylesheet for PySide6."""

KALI_DARK_THEME = """
QWidget {
    background-color: #0d1117;
    color: #c9d1d9;
    font-family: 'Segoe UI', 'Ubuntu', 'DejaVu Sans', sans-serif;
    font-size: 13px;
}

/* Tab Bar */
QTabWidget::pane {
    border: 1px solid #30363d;
    background-color: #161b22;
    border-radius: 6px;
    top: -1px;
}

QTabBar::tab {
    background: #0d1117;
    color: #8b949e;
    padding: 10px 20px;
    border: 1px solid #30363d;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 4px;
    font-weight: 600;
}

QTabBar::tab:selected {
    background: #161b22;
    color: #58a6ff;
    border-bottom: 2px solid #58a6ff;
}

QTabBar::tab:hover {
    color: #58a6ff;
    background: #1c2128;
}

/* Group Boxes and Panels */
QGroupBox {
    border: 1px solid #30363d;
    border-radius: 8px;
    margin-top: 18px;
    padding-top: 14px;
    font-weight: bold;
    color: #58a6ff;
    background-color: #161b22;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    left: 12px;
}

/* Buttons */
QPushButton {
    background-color: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #30363d;
    border-color: #8b949e;
    color: #ffffff;
}

QPushButton:pressed {
    background-color: #161b22;
}

QPushButton:disabled {
    background-color: #161b22;
    color: #484f58;
    border-color: #21262d;
}

/* Primary Cyan / Action Button */
QPushButton#primaryAction {
    background-color: #1f6feb;
    color: #ffffff;
    border: 1px solid #388bfd;
    font-size: 14px;
    padding: 10px 20px;
}

QPushButton#primaryAction:hover {
    background-color: #388bfd;
}

QPushButton#primaryAction:pressed {
    background-color: #1158c7;
}

/* Danger / Burn Button */
QPushButton#dangerAction {
    background-color: #b62324;
    color: #ffffff;
    border: 1px solid #da3633;
}

QPushButton#dangerAction:hover {
    background-color: #da3633;
}

/* Line Edits & Text Inputs */
QLineEdit, QTextEdit, QSpinBox, QComboBox {
    background-color: #0d1117;
    color: #f0f6fc;
    border: 1px solid #30363d;
    padding: 8px;
    border-radius: 6px;
    selection-background-color: #1f6feb;
}

QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QComboBox:focus {
    border: 1px solid #58a6ff;
    outline: none;
}

/* Monospace Fields */
QLineEdit#monoField, QTextEdit#monoField {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}

/* Tables */
QTableWidget {
    background-color: #0d1117;
    border: 1px solid #30363d;
    gridline-color: #21262d;
    border-radius: 6px;
}

QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    padding: 6px;
    border: 1px solid #30363d;
    font-weight: bold;
}

/* Progress Bars */
QProgressBar {
    border: 1px solid #30363d;
    border-radius: 6px;
    background-color: #0d1117;
    text-align: center;
    color: #ffffff;
    font-weight: bold;
    height: 18px;
}

QProgressBar::chunk {
    background-color: #238636;
    border-radius: 5px;
}

/* Labels */
QLabel#headerTitle {
    font-size: 20px;
    font-weight: bold;
    color: #58a6ff;
}

QLabel#subtitle {
    color: #8b949e;
    font-size: 12px;
}

QLabel#securityNotice {
    color: #e3b341;
    font-size: 12px;
}
"""
