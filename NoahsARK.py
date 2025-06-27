import sys
import ipaddress
import os
import shutil
import subprocess
from tempfile import NamedTemporaryFile
from collections import defaultdict
from io import BytesIO, StringIO
import re
import base64
import csv
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import socks
import socket
import fitz  # PyMuPDF

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
    QPushButton, QTreeWidget, QTreeWidgetItem, QTextEdit, QMessageBox,
    QSplitter, QLabel, QFileDialog, QHeaderView, QMenu, QProgressDialog,
    QCheckBox, QComboBox, QTabWidget, QFormLayout, QGroupBox
)
from PyQt5.QtGui import QPixmap, QImage, QIcon, QTextDocument, QTextCursor, QPainter, QFont
from PyQt5.QtCore import Qt, QObject, QThread, pyqtSignal, QEvent

from subprocess import Popen, PIPE
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SMB_DIALECT
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_LOGON_FAILURE, STATUS_BAD_NETWORK_NAME

# --- STYLESHEETS AND CONSTANTS ---
DARK_STYLESHEET = """
    QWidget {
        background-color: #2b2b2b;
        color: #f0f0f0;
        font-family: 'Segoe UI', 'Fira Code', 'Ubuntu Mono', Cantarell, sans-serif;
        font-size: 10pt;
    }
    QGroupBox {
        border: 1px solid #3c3c3c;
        border-radius: 6px;
        margin-top: 1ex;
        font-weight: bold;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 0 5px;
        color: #00aaff;
    }
    QTabWidget::pane {
        border: 1px solid #3c3c3c;
        border-top: none;
    }
    QTabBar::tab {
        background: #2b2b2b;
        border: 1px solid #3c3c3c;
        border-bottom: none;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
        padding: 8px 16px;
        margin-right: 2px;
    }
    QTabBar::tab:selected {
        background: #3c3c3c;
        border-color: #00aaff;
    }
    QTabBar::tab:!selected:hover {
        background: #383838;
    }
    QComboBox {
        background-color: #3c3c3c;
        border: 1px solid #555;
        border-radius: 4px;
        padding: 4px;
        min-width: 6em;
    }
    QComboBox::drop-down {
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 15px;
        border-left-width: 1px;
        border-left-color: #555;
        border-left-style: solid;
        border-top-right-radius: 3px;
        border-bottom-right-radius: 3px;
    }
    QComboBox QAbstractItemView {
        background-color: #3c3c3c;
        border: 1px solid #555;
        selection-background-color: #00aaff;
    }
    QTreeWidget { 
        background-color: #252525; 
        border: 1px solid #3c3c3c; 
        color: #f0f0f0; 
        alternate-background-color: #292929;
    }
    QTreeWidget::item { padding: 5px; }
    QTreeWidget::item:selected { background-color: #007acc; color: #ffffff; }
    QTreeWidget::item:hover { background-color: #383838; }
    QHeaderView::section { 
        background-color: #3A3A3A; 
        color: #f0f0f0; 
        padding: 4px; 
        border: 1px solid #4A4A4A; 
        font-weight: bold;
    }
    QLineEdit, QTextEdit { 
        background-color: #3c3c3c; 
        border: 1px solid #555; 
        border-radius: 4px; 
        padding: 5px; 
    }
    QTextEdit {
        selection-background-color: #00aaff;
    }
    QPushButton { 
        background-color: #007acc; 
        color: #FFFFFF; 
        border: none; 
        border-radius: 4px; 
        padding: 8px 16px;
        font-weight: bold;
    }
    QPushButton:hover { background-color: #0099ff; }
    QPushButton:pressed { background-color: #005c99; }
    QPushButton:disabled { background-color: #424242; color: #888888; }
    QScrollBar:vertical, QScrollBar:horizontal { 
        border: none; 
        background-color: #252525; 
        width: 12px; 
        height: 12px; 
        margin: 0px; 
    }
    QScrollBar::handle:vertical, QScrollBar::handle:horizontal { 
        background-color: #5A5A5A; 
        min-height: 20px; 
        min-width: 20px; 
        border-radius: 6px; 
    }
    QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover { 
        background-color: #00aaff; 
    }
    QScrollBar::add-line, QScrollBar::sub-line { 
        height: 0px; 
        width: 0px; 
        background: none; 
    }
    QSplitter::handle { background-color: #4A4A4A; }
    QSplitter::handle:horizontal { width: 1px; }
    QSplitter::handle:vertical { height: 1px; }
    QMenu { 
        background-color: #3A3A3A; 
        border: 1px solid #4A4A4A; 
    }
    QMenu::item:selected { background-color: #007acc; }
    QProgressDialog { background-color: #3A3A3A; }
    QLabel { padding: 2px; }
"""

PROXY_MAP = {
    "No Proxy": None, "jump": 9050, "db0": 9057, "db1": 9051, "db2": 9052,
    "db3": 9053, "db4": 9054, "db5": 9055, "db6": 9056, "hp-db1": 9061,
    "hp-db2": 9062, "hp-db3": 9063, "hp-db4": 9064,
}

SENSITIVE_DATA_REGEX = {
    "API Key": re.compile(r'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'),
    "Private Key": re.compile(r'(-----BEGIN (?:RSA|OPENSSH) PRIVATE KEY-----)'),
    "Password": re.compile(r'pass(?:word)?\s*[:=]\s*[\'"]?([^\s\'"]+)[\'"]?', re.IGNORECASE)
}

DIALECT_DISPLAY_MAP = {
    SMB_DIALECT: "1.0", 0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0",
    0x0302: "3.0.2", 0x0311: "3.1.1",
}

preview_handlers = defaultdict(lambda: "file")
for ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']: preview_handlers[ext] = "image"
for ext in ['.pdf']: preview_handlers[ext] = "pdf"
for ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']: preview_handlers[ext] = "office"
for ext in ['.iso', '.vhd', '.vmdk', '.vdi', '.img']: preview_handlers[ext] = "diskimage"
for ext in ['.zip', '.rar', '.7z', '.tar', '.gz']: preview_handlers[ext] = "archive"
for ext in ['.py', '.c', '.cpp', '.js', '.ts', '.java', '.cs', '.html', '.css', '.sh', '.bat', '.txt', '.log', '.ini', '.conf']: preview_handlers[ext] = "text"

ICON_DATA = {
    "folder": "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiMwMGFhZmYiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2EtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMjIgMTlhMiAyIDAgMCAxLTIgMkg0YTIgMiAwIDAgMS0yLTJWNWEyIDIgMCAwIDEgMi0yaDVsMiAzaDlhMiAyIDAgMCAxIDIgMnoiPjwvcGF0aD48L3N2Zz4=",
    "file": "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmMGYwZjAiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMTMgMkg2YTIgMiAwIDAgMC0yIDJ2MTZhMiAyIDAgMCAwIDIgMmgxMmEyIDIgMCAwIDAgMi0yVjl6Ij48L3BhdGg+PHBvbHlsaW5lIHBvaW50cz0iMTMgMiAxMyA5IDIwIDkiPjwvcG9seWxpbmU+PC9zdmc+",
    "text": "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmMGYwZjAiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMTQgMkg2YTIgMiAwIDAgMC0yIDJ2MTZhMiAyIDAgMCAwIDIgMmgxMmEyIDIgMCAwIDAgMi0yVjh6Ij48L3BhdGg+PHBvbHlsaW5lIHBvaW50cz0iMTQgMiAxNCA4IDIwIDgiPjwvcG9seWxpbmU+PGxpbmUgeDE9IjE2IiB5MT0iMTMiIHgyPSI4IiB5Mj0iMTMiPjwvbGluZT48bGluZSB4MT0iMTYiIHkxPSIxNyIgeDI9IjgiIHkyPSIxNyI+PC9saW5lPjxwb2x5bGluZSBwb2ludHM9IjEwIDkgOSA5IDggOSI+PC9wb2x5bGluZT48L3N2Zz4=",
    "image": "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmMGYwZjAiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cmVjdCB4PSIzIiB5PSIzIiB3aWR0aD0iMTgiIGhlaWdodD0iMTgiIHJ4PSIyIiByeT0iMiI+PC9yZWN0PjxjaXJjbGUgY3g9IjguNSIgY3k9IjguNSIgcj0iMS41Ij48L2NpcmNsZT48cG9seWxpbmUgcG9pbnRzPSIyMSAxNSAxNiAxMCA1IDIxIj48L3BvbHlsaW5lPjwvc3ZnPg==",
    "archive": "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmMGYwZjAiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cG9seWxpbmUgcG9pbnRzPSIyMSA4IDIxIDIxIDMgMjEgMyA4Ij48L3BvbHlsaW5lPjxyZWN0IHg9IjEiIHk9IjMiIHdpZHRoPSIyMiIgaGVpZ2h0PSI1IiByeD0iMiIgcnk9IjIiPjwvcmVjdD48bGluZSB4MT0iMTAiIHkxPSIxMiIgeDI9IjE0IiB5Mj0iMTIiPjwvbGluZT48L3N2Zz4=",
    "loot": "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNGRkQ3MDAiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2EtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMyA2aDE4TDE5IDJoLTQuNUwyMSA5SDEybC0yLjUtN0gtN0wyIDloMTlMNiAyMiA3IDloMTBsMyAxMyAyLTdIMTdabTEuNS00TDEyIDZsMi41LTQuNU0xMCA1TDcuNSA0Ii8+PC9zdmc+",
    "refresh": "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiMwMGZmZmYiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2EtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNMjMgNCBMMiAzLjM0QTEwIDEwIDAgMSA3IDJhMTAgMTAgMCAwIDAgMSA5LjM0Ii8+PHBhdGggZD0iTTEgMjBsMSAuNjZBMTAgMTAgMCAwIDEgMTcgMjJhMTAgMTAgMCAwIDEgMS05LjY2Ii8+PC9zdmc+"
}

def format_size(size):
    if size <= 0: return ""
    power = 1024; n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size >= power and n < len(power_labels) -1 :
        size /= power; n += 1
    return f"{size:.1f} {power_labels[n]}B"

# --- HELPER & WIDGET CLASSES ---

class TitleScreen(QWidget):
    start_app_signal = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Welcome")
        self.setFixedSize(600, 450)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(25)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title Label
        title_label = QLabel("Noah's ARK")
        title_font = QFont("Segoe UI", 36)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #00aaff;")

        # Image Label
        image_label = QLabel()
        image_path = "title_image.png"
        if os.path.exists(image_path):
            pixmap = QPixmap(image_path)
            # CHANGE 1: The image is now scaled to a larger size (500x300).
            # You can adjust these numbers to your liking.
            image_label.setPixmap(pixmap.scaled(500, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            image_label.setText("(Image not found: place 'title_image.png' here)")
            image_label.setStyleSheet("color: #888888;")
        image_label.setAlignment(Qt.AlignCenter)

        # Button
        self.button = QPushButton("Board the ARK")
        self.button.setMinimumHeight(45)
        button_font = self.font()
        button_font.setPointSize(12)
        self.button.setFont(button_font)
        self.button.clicked.connect(self.start_app_signal.emit)

        # CHANGE 2: Add stretchable space before and after the content to center it vertically.
        layout.addStretch()  # Pushes everything down from the top
        layout.addWidget(title_label)
        layout.addWidget(image_label)
        layout.addWidget(self.button)
        layout.addStretch()  # Pushes everything up from the bottom


class ImageLabel(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pixmap = QPixmap()
        self.setAlignment(Qt.AlignCenter)
        self.setText("Double-click a file to preview")

    def setPixmap(self, pixmap):
        if pixmap and not pixmap.isNull():
            self.pixmap = pixmap
        else:
            self.pixmap = QPixmap()
        self.update()

    def paintEvent(self, event):
        if self.pixmap.isNull():
            super().paintEvent(event)
            return
        painter = QPainter(self)
        scaled_pixmap = self.pixmap.scaled(self.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
        point = self.rect().center() - scaled_pixmap.rect().center()
        painter.drawPixmap(point, scaled_pixmap)

class OfficeConverterWorker(QObject):
    conversion_success = pyqtSignal(bytes); conversion_error = pyqtSignal(str); finished = pyqtSignal()
    def __init__(self, office_path, libreoffice_cmd):
        super().__init__(); self.office_path = office_path; self.libreoffice_cmd = libreoffice_cmd
    def run(self):
        out_dir = os.path.dirname(self.office_path); pdf_path = os.path.splitext(self.office_path)[0] + ".pdf"
        try:
            cmd = [self.libreoffice_cmd, "--headless", "--convert-to", "pdf", "--outdir", out_dir, self.office_path]
            p = Popen(cmd, stdout=PIPE, stderr=PIPE); p.communicate()
            if p.returncode != 0 or not os.path.exists(pdf_path): self.conversion_error.emit("[Failed to convert Office file]")
            else:
                with open(pdf_path, 'rb') as f: self.conversion_success.emit(f.read())
        except Exception as e: self.conversion_error.emit(f"[Conversion Error]\n\n{e}")
        finally:
            self.finished.emit()
            try: os.unlink(self.office_path)
            except Exception: pass
            try: os.unlink(pdf_path)
            except Exception: pass

# --- WORKER CLASSES ---
class ScanWorker(QObject):
    host_authenticated = pyqtSignal(str, object, list) 
    host_error = pyqtSignal(str, str)
    finished = pyqtSignal()
    progress_update = pyqtSignal(int, int)

    def __init__(self, hosts, user, passwd):
        super().__init__()
        self.hosts = hosts
        self.user = user
        self.passwd = passwd
        self._is_stopped = False
        self.MAX_SCAN_WORKERS = 50

    def stop(self): self._is_stopped = True

    def run(self):
        with ThreadPoolExecutor(max_workers=self.MAX_SCAN_WORKERS) as executor:
            futures = [executor.submit(self._check_and_login, host) for host in self.hosts]
            total = len(futures)
            for i, future in enumerate(as_completed(futures)):
                if self._is_stopped: future.cancel()
                self.progress_update.emit(i + 1, total)
        self.finished.emit()

    def _check_and_login(self, host):
        if self._is_stopped: return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((host, 445)) != 0:
                s.close()
                return
            s.close()
        except socket.error:
            return

        try:
            smb = SMBConnection(host, host, sess_port=445, timeout=10)
            smb.login(self.user, self.passwd)
            shares = smb.listShares()
            self.host_authenticated.emit(host, smb, shares)
        except Exception as e:
            error_message = NoahsARK.get_smb_error_string(e)
            self.host_error.emit(host, error_message)

class SearchWorker(QObject):
    match_found = pyqtSignal(dict)
    update_status = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, main_window, hosts, keywords, search_filenames, search_contents, case_sensitive, text_only, user, passwd, active_regex):
        super().__init__()
        self.main_window = main_window
        self.hosts = hosts
        self.keywords = keywords
        self.search_filenames = search_filenames
        self.search_contents = search_contents
        self.case_sensitive = case_sensitive
        self.text_only = text_only
        self.user = user
        self.passwd = passwd
        self.active_regex = active_regex
        self._is_stopped = False
        self.MAX_CONTENT_SEARCH_SIZE = 5 * 1024 * 1024
        self.MAX_WORKERS = 10

    def stop(self): self._is_stopped = True

    def run(self):
        custom_keyword_regex = None
        if self.keywords:
            try:
                flags = 0 if self.case_sensitive else re.IGNORECASE
                custom_keyword_regex = re.compile(self.keywords, flags)
            except re.error as e:
                self.update_status.emit(f"Invalid keyword regex: {e}")
                self.finished.emit()
                return

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            tasks_to_run = []
            for host in self.hosts:
                if self._is_stopped: break
                try:
                    smb_tmp, err = self.main_window.get_smb_connection(host)
                    if smb_tmp:
                        shares = smb_tmp.listShares()
                        for share in shares:
                            share_name = share['shi1_netname'].rstrip('\x00')
                            if share_name in ["IPC$", "ADMIN$"]: continue
                            tasks_to_run.append((host, share_name))
                except Exception as e:
                    self.update_status.emit(f"Error listing shares for {host}: {e}")

            futures = [executor.submit(self.search_share_task, host, share_name, custom_keyword_regex) for host, share_name in tasks_to_run]
            for future in as_completed(futures):
                if self._is_stopped: future.cancel()

        if not self._is_stopped: self.update_status.emit("Search finished.")
        else: self.update_status.emit("Search stopped.")
        self.finished.emit()

    def search_share_task(self, host, share_name, custom_keyword_regex):
        if self._is_stopped: return
        try:
            smb, err = self.main_window.get_smb_connection(host)
            if smb:
                self.walk(smb, share_name, "", host, custom_keyword_regex)
            elif err:
                self.update_status.emit(f"Search failed on {host}: {err}")
        except Exception as e:
            self.update_status.emit(f"Search task failed on //{host}/{share_name}: {e}")

    def walk(self, smb, share, path, host, custom_keyword_regex):
        if self._is_stopped: return
        self.update_status.emit(f"Searching: //{host}/{share}/{path}")
        current_path_query = os.path.join(path, "*").replace(os.sep, '\\')
        try:
            dir_listing = smb.listPath(share, current_path_query)
        except (SessionError, Exception): return

        for entry in dir_listing:
            if self._is_stopped: return
            filename = entry.get_longname()
            if filename in [".", ".."]: continue
            full_path = os.path.join(path, filename).replace(os.sep, '\\')
            if entry.is_directory():
                self.walk(smb, share, full_path, host, custom_keyword_regex)
            else:
                if self.search_filenames and custom_keyword_regex and custom_keyword_regex.search(filename):
                    self.match_found.emit({'smb_host': host, 'share': share, 'path': full_path, 'size': entry.get_filesize(), 'host': host, 'reason': f"Filename match: {filename}"}); continue
                if self.search_contents:
                    ext = os.path.splitext(filename)[-1].lower()
                    file_type = preview_handlers.get(ext, 'file')
                    if self.text_only and file_type != 'text': continue
                    file_size = entry.get_filesize()
                    if 0 < file_size < self.MAX_CONTENT_SEARCH_SIZE:
                        try:
                            file_obj = BytesIO()
                            smb.getFile(share, full_path, file_obj.write)
                            content = file_obj.getvalue(); file_obj.close()
                            try: text_content = content.decode('utf-8')
                            except UnicodeDecodeError: text_content = content.decode('latin-1', errors='ignore')
                            if custom_keyword_regex and custom_keyword_regex.search(text_content):
                                self.match_found.emit({'smb_host': host, 'share': share, 'path': full_path, 'size': file_size, 'host': host, 'reason': f"Content keyword match"})
                            for name, regex in self.active_regex.items():
                                if regex.search(text_content): self.match_found.emit({'smb_host': host, 'share': share, 'path': full_path, 'size': file_size, 'host': host, 'reason': f"Found {name} pattern"})
                        except Exception: pass

class PreviewPane(QWidget):
    MAX_PREVIEW_SIZE = 10 * 1024 * 1024

    def __init__(self, parent_main_window):
        super().__init__(parent_main_window)
        self.main_window = parent_main_window
        self.current_pdf_doc = None; self.current_pdf_page_num = 0
        self.total_pdf_pages = 0
        preview_layout = QVBoxLayout(self); preview_layout.setContentsMargins(0,0,0,0)
        self.image_label = ImageLabel(self)
        self.text_preview_widget = QWidget()
        text_preview_layout = QVBoxLayout(self.text_preview_widget)
        text_preview_layout.setContentsMargins(0, 0, 0, 0); text_preview_layout.setSpacing(4)
        self.text_edit = QTextEdit(readOnly=True)
        in_file_search_bar = QWidget(); in_file_search_layout = QHBoxLayout(in_file_search_bar)
        in_file_search_layout.setContentsMargins(0,0,0,0)
        self.in_file_search_input = QLineEdit(placeholderText="Search in open file...")
        self.in_file_prev_button = QPushButton("Previous"); self.in_file_next_button = QPushButton("Next")
        in_file_search_layout.addWidget(self.in_file_search_input); in_file_search_layout.addWidget(self.in_file_prev_button); in_file_search_layout.addWidget(self.in_file_next_button)
        text_preview_layout.addWidget(self.text_edit); text_preview_layout.addWidget(in_file_search_bar)
        self.preview_stack = QSplitter(Qt.Vertical)
        self.preview_stack.addWidget(self.image_label); self.preview_stack.addWidget(self.text_preview_widget)
        self.text_preview_widget.hide()
        pdf_nav_widget = QWidget(); pdf_nav_layout = QHBoxLayout(pdf_nav_widget)
        self.pdf_prev_button = QPushButton("<< Previous"); self.pdf_page_label = QLabel("Page: 0 / 0"); self.pdf_page_label.setAlignment(Qt.AlignCenter)
        self.pdf_next_button = QPushButton("Next >>")
        pdf_nav_layout.addWidget(self.pdf_prev_button); pdf_nav_layout.addWidget(self.pdf_page_label); pdf_nav_layout.addWidget(self.pdf_next_button)
        self.pdf_nav_widget = pdf_nav_widget
        preview_layout.addWidget(self.preview_stack); preview_layout.addWidget(self.pdf_nav_widget); self.pdf_nav_widget.hide()
        self.pdf_prev_button.clicked.connect(self.show_prev_pdf_page); self.pdf_next_button.clicked.connect(self.show_next_pdf_page)
        self.in_file_next_button.clicked.connect(self.find_next_in_text); self.in_file_prev_button.clicked.connect(self.find_prev_in_text)
        self.in_file_search_input.returnPressed.connect(self.find_next_in_text)

    def show_preview_widget(self, widget_type):
        self.current_pdf_doc = None
        self.image_label.setPixmap(None)
        self.image_label.setText("Double-click a file to preview")
        if widget_type == 'image' or widget_type == 'pdf':
            self.image_label.show(); self.text_preview_widget.hide(); self.pdf_nav_widget.setVisible(widget_type == 'pdf')
        elif widget_type == 'text':
            self.image_label.hide(); self.text_preview_widget.show(); self.pdf_nav_widget.hide()
        else:
            self.image_label.show(); self.text_preview_widget.hide(); self.image_label.setText("[No preview available]"); self.pdf_nav_widget.hide()

    def render_pdf_page(self, page_num):
        if not self.current_pdf_doc or not (0 <= page_num < self.total_pdf_pages): return
        self.current_pdf_page_num = page_num; page = self.current_pdf_doc.load_page(page_num); pix = page.get_pixmap(dpi=150)
        qimage = QImage(pix.samples, pix.width, pix.height, pix.stride, QImage.Format_RGB888)
        self.image_label.setPixmap(QPixmap.fromImage(qimage))
        self.pdf_page_label.setText(f"Page: {page_num + 1} / {self.total_pdf_pages}")
        self.pdf_prev_button.setEnabled(page_num > 0); self.pdf_next_button.setEnabled(page_num < self.total_pdf_pages - 1)

    def show_prev_pdf_page(self): self.render_pdf_page(self.current_pdf_page_num - 1)
    def show_next_pdf_page(self): self.render_pdf_page(self.current_pdf_page_num + 1)
    
    def display_pdf_bytes(self, pdf_bytes):
        self.show_preview_widget('pdf')
        try:
            self.current_pdf_doc = fitz.open(stream=pdf_bytes, filetype="pdf"); self.total_pdf_pages = len(self.current_pdf_doc); self.render_pdf_page(0)
        except Exception as e: self.show_text_preview(f"Error rendering PDF: {e}")

    def on_conversion_success(self, pdf_bytes):
        if self.main_window.progress_dialog: self.main_window.progress_dialog.close()
        self.display_pdf_bytes(pdf_bytes)

    def on_conversion_error(self, error_message):
        if self.main_window.progress_dialog: self.main_window.progress_dialog.close()
        self.show_text_preview(error_message)

    def show_text_preview(self, text):
        self.show_preview_widget('text'); self.text_edit.setText(text)

    def find_next_in_text(self):
        query = self.in_file_search_input.text()
        if not query: return
        if not self.text_edit.find(query):
            self.text_edit.moveCursor(QTextCursor.Start); self.text_edit.find(query)

    def find_prev_in_text(self):
        query = self.in_file_search_input.text()
        if not query: return
        if not self.text_edit.find(query, QTextDocument.FindBackward):
            self.text_edit.moveCursor(QTextCursor.End); self.text_edit.find(query, QTextDocument.FindBackward)
    
    def preview_file(self, meta, user, passwd):
        file_size = meta.get('size', 0)
        if file_size > self.MAX_PREVIEW_SIZE:
            self.show_text_preview(f"File is too large for preview ({format_size(file_size)}).\n\nThe preview limit is {format_size(self.MAX_PREVIEW_SIZE)}."); return

        host = meta.get('smb_host') or meta.get('host')
        share, path = meta.get('share', ''), meta.get('path', '')
        ext = os.path.splitext(path)[-1].lower()
        filetype = preview_handlers.get(ext, "file")
        
        smb, error_msg = self.main_window.get_smb_connection(host)
        if not smb:
            self.show_text_preview(f"[Connection Error]\n\nCould not get SMB connection for {host}:\n{error_msg}")
            return

        if filetype == "office":
            if not self.main_window.libreoffice_path: self.show_text_preview("[Feature Unavailable]\n\nLibreOffice not found."); return
            try:
                with NamedTemporaryFile(delete=False, suffix=ext, mode='wb') as temp_office_file:
                    self.main_window.add_temp_file_to_clean(temp_office_file.name)
                    smb.getFile(share, path, temp_office_file.write)
                self.thread = QThread(); self.worker = OfficeConverterWorker(temp_office_file.name, self.main_window.libreoffice_path)
                self.worker.moveToThread(self.thread); self.worker.conversion_success.connect(self.on_conversion_success)
                self.worker.conversion_error.connect(self.on_conversion_error); self.worker.finished.connect(self.thread.quit)
                self.worker.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self.thread.deleteLater)
                self.thread.started.connect(self.worker.run); self.thread.start()
                self.main_window.progress_dialog = QProgressDialog("Converting Office file...", None, 0, 0, self)
                self.main_window.progress_dialog.setWindowModality(Qt.WindowModal); self.main_window.progress_dialog.setCancelButton(None)
                self.main_window.progress_dialog.show()
            except Exception as e: self.show_text_preview(f"[Error Reading File]\n\n{NoahsARK.get_smb_error_string(e)}")
            return
        
        try:
            file_obj = BytesIO()
            smb.getFile(share, path, file_obj.write)
            file_bytes = file_obj.getvalue()
        except Exception as e:
            self.show_text_preview(f"[Error Reading File]\n\n{NoahsARK.get_smb_error_string(e)}"); return
        
        if filetype == "pdf": self.display_pdf_bytes(file_bytes); return
        if filetype == "image":
            pixmap = QPixmap()
            if pixmap.loadFromData(file_bytes):
                self.show_preview_widget('image'); self.image_label.setPixmap(pixmap)
                return
        try: content = file_bytes.decode("utf-8")
        except UnicodeDecodeError: content = file_bytes.decode("latin-1", errors="replace")
        self.show_text_preview(content)


class DetachedPreviewWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent=None) 
        self.main_window_ref = parent
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("Detached Preview")
        self.setMinimumSize(800, 600)
        layout = QVBoxLayout(self)
        self.preview_pane = PreviewPane(self.main_window_ref)
        layout.addWidget(self.preview_pane)

    def load_file(self, meta, user, passwd):
        if not meta: return
        file_name = os.path.basename(meta.get('path', ''))
        self.setWindowTitle(f"Preview - {file_name}")
        self.preview_pane.preview_file(meta, user, passwd)
    
    def closeEvent(self, event):
        if self.main_window_ref:
            self.main_window_ref.remove_detached_window(self)
        super().closeEvent(event)


class NoahsARK(QWidget):
    MAX_PREVIEW_SIZE = 10 * 1024 * 1024
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Noah's ARK"); self.setMinimumSize(1200, 700)
        self.libreoffice_path = shutil.which("libreoffice") or shutil.which("soffice")
        self._temp_files_to_clean = []; self.scan_thread = None; self.scan_worker = None
        self.search_thread = None; self.search_worker = None
        self.user = ""; self.passwd = ""
        self.loot_data = []; self.looted_paths = set()
        self.progress_dialog = None
        self.dir_cache = {}; self.file_cache = {}
        self.current_smb_sessions = {}
        self.host_item_map = {}
        self.detached_windows = set()

        layout = QVBoxLayout(self)
        input_row = QHBoxLayout()
        self.ip_input = QLineEdit(placeholderText="Target IP/Subnet"); self.username = QLineEdit(placeholderText="Username (can be blank)")
        self.password = QLineEdit(placeholderText="Password", echoMode=QLineEdit.Password); 
        
        scan_button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Scan && Browse")
        self.stop_scan_button = QPushButton("Stop Scan")
        self.stop_scan_button.hide()
        scan_button_layout.addWidget(self.scan_button)
        scan_button_layout.addWidget(self.stop_scan_button)

        self.proxy_combo = QComboBox(); self.proxy_combo.addItems(PROXY_MAP.keys())
        input_row.addWidget(QLabel("Target:")); input_row.addWidget(self.ip_input, 1); input_row.addWidget(QLabel("Username:"))
        input_row.addWidget(self.username, 1); input_row.addWidget(QLabel("Password:")); input_row.addWidget(self.password, 1)
        input_row.addLayout(scan_button_layout); input_row.addWidget(QLabel("Proxy:")); input_row.addWidget(self.proxy_combo)
        layout.addLayout(input_row)
        
        self.tabs = QTabWidget(); layout.addWidget(self.tabs)
        
        browser_widget = QWidget(); browser_layout = QVBoxLayout(browser_widget); browser_layout.setContentsMargins(0,0,0,0)
        browser_splitter = QSplitter(Qt.Horizontal)
        self.tree = QTreeWidget(); self.tree.setHeaderLabels(["Name", "Type", "Size", "Details"]); self.tree.setIndentation(10)
        header = self.tree.header(); header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents); header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        browser_splitter.addWidget(self.tree)
        self.browser_preview_pane = PreviewPane(self)
        browser_splitter.addWidget(self.browser_preview_pane)
        browser_splitter.setSizes([700, 500])
        browser_layout.addWidget(browser_splitter); self.tabs.addTab(browser_widget, "Browser")

        search_widget = QWidget(); search_layout = QVBoxLayout(search_widget)
        custom_search_group = QGroupBox("Custom Keyword Search"); custom_search_layout = QFormLayout(custom_search_group)
        self.search_keywords_input = QLineEdit(placeholderText="Enter keywords (regex supported)"); custom_search_layout.addRow("Keywords:", self.search_keywords_input)
        keyword_options_layout = QHBoxLayout(); self.search_filenames_checkbox = QCheckBox("In Filenames"); self.search_filenames_checkbox.setChecked(True)
        self.search_contents_checkbox = QCheckBox("In File Contents"); self.search_case_checkbox = QCheckBox("Case-sensitive")
        keyword_options_layout.addWidget(self.search_filenames_checkbox); keyword_options_layout.addWidget(self.search_contents_checkbox)
        keyword_options_layout.addWidget(self.search_case_checkbox); keyword_options_layout.addStretch(); custom_search_layout.addRow("Search:", keyword_options_layout)
        sensitive_data_group = QGroupBox("Sensitive Data Scanner (searches file contents)"); sensitive_data_layout = QVBoxLayout(sensitive_data_group)
        self.sensitive_data_checkboxes = {}
        for name in SENSITIVE_DATA_REGEX.keys():
            cb = QCheckBox(f"Search for {name}"); cb.stateChanged.connect(self.update_search_content_dependency); self.sensitive_data_checkboxes[name] = cb; sensitive_data_layout.addWidget(cb)
        options_group = QGroupBox("General Options"); options_layout = QVBoxLayout(options_group)
        self.search_text_only_checkbox = QCheckBox("For content searches, only scan text-based files"); self.search_text_only_checkbox.setChecked(True); options_layout.addWidget(self.search_text_only_checkbox)
        search_button_layout = QHBoxLayout(); self.start_search_button = QPushButton("Search"); self.stop_search_button = QPushButton("Stop"); self.stop_search_button.setEnabled(False)
        search_button_layout.addWidget(self.start_search_button); search_button_layout.addWidget(self.stop_search_button); search_button_layout.addStretch()
        self.search_status_label = QLabel("Status: Idle. Start a scan before searching.")
        self.search_results_tree = QTreeWidget(); self.search_results_tree.setHeaderLabels(["Path", "Size", "Host", "Reason"])
        search_header = self.search_results_tree.header(); search_header.setSectionResizeMode(0, QHeaderView.Stretch)
        search_header.setSectionResizeMode(1, QHeaderView.ResizeToContents); search_header.setSectionResizeMode(2, QHeaderView.ResizeToContents); search_header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        search_layout.addWidget(custom_search_group); search_layout.addWidget(sensitive_data_group); search_layout.addWidget(options_group); search_layout.addLayout(search_button_layout)
        search_layout.addWidget(self.search_status_label); search_layout.addWidget(self.search_results_tree); self.tabs.addTab(search_widget, "Search")
        
        loot_widget = QWidget(); loot_layout = QVBoxLayout(loot_widget)
        loot_splitter = QSplitter(Qt.Horizontal)
        self.loot_tree = QTreeWidget(); self.loot_tree.setHeaderLabels(["Path", "Size", "Host"])
        loot_header = self.loot_tree.header(); loot_header.setSectionResizeMode(0, QHeaderView.Stretch)
        loot_header.setSectionResizeMode(1, QHeaderView.ResizeToContents); loot_header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        loot_splitter.addWidget(self.loot_tree)
        self.loot_preview_pane = PreviewPane(self)
        loot_splitter.addWidget(self.loot_preview_pane)
        loot_splitter.setSizes([700, 500])
        loot_layout.addWidget(loot_splitter)
        loot_buttons_layout = QHBoxLayout()
        self.remove_loot_button = QPushButton("Remove Selected from Loot")
        self.export_loot_button = QPushButton("Export Loot to CSV")
        loot_buttons_layout.addStretch(); loot_buttons_layout.addWidget(self.remove_loot_button); loot_buttons_layout.addWidget(self.export_loot_button)
        loot_layout.addLayout(loot_buttons_layout)
        self.tabs.addTab(loot_widget, "Loot")
        
        self.load_icons()
        
        self.scan_button.clicked.connect(self.scan)
        self.stop_scan_button.clicked.connect(self.stop_scan)
        self.tree.itemExpanded.connect(self.on_item_expanded); self.tree.itemDoubleClicked.connect(self.on_item_double_click)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu); self.tree.customContextMenuRequested.connect(self.open_context_menu)
        self.start_search_button.clicked.connect(self.start_search); self.stop_search_button.clicked.connect(self.stop_search)
        self.search_results_tree.itemDoubleClicked.connect(self.on_item_double_click)
        self.search_results_tree.setContextMenuPolicy(Qt.CustomContextMenu); self.search_results_tree.customContextMenuRequested.connect(self.open_context_menu)
        self.loot_tree.setContextMenuPolicy(Qt.CustomContextMenu); self.loot_tree.customContextMenuRequested.connect(self.open_context_menu)
        self.loot_tree.itemDoubleClicked.connect(self.on_item_double_click)
        self.remove_loot_button.clicked.connect(self.remove_selected_loot)
        self.export_loot_button.clicked.connect(self.export_loot)
    
    @staticmethod
    def get_smb_error_string(e):
        if isinstance(e, SessionError):
            error_code = e.getErrorCode()
            error_map = {
                0xC0000001: "STATUS_UNSUCCESSFUL", 0xC000000D: "STATUS_INVALID_PARAMETER",
                0xC0000022: "STATUS_ACCESS_DENIED", 0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
                0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND", 0xC000006D: "STATUS_LOGON_FAILURE (Bad U/P)",
                0xC0000072: "STATUS_ACCOUNT_DISABLED", 0xC00000AC: "STATUS_PIPE_NOT_AVAILABLE",
                0xC00000B5: "STATUS_IO_TIMEOUT", 0xC00000CC: "STATUS_BAD_NETWORK_NAME (Share not found)",
                0xC0000193: "STATUS_ACCOUNT_EXPIRED",
            }
            error_string = error_map.get(error_code, f"Unknown SMB Error (0x{error_code:x})")
            return f"{error_string}"
        elif isinstance(e, socket.timeout): return "Connection timed out."
        elif isinstance(e, ConnectionRefusedError): return "Connection refused by host."
        elif isinstance(e, OSError) and e.strerror: return e.strerror
        else: return str(e)

    def add_temp_file_to_clean(self, filename): self._temp_files_to_clean.append(filename)
    def update_search_content_dependency(self):
        is_any_sensitive_checked = any(cb.isChecked() for cb in self.sensitive_data_checkboxes.values())
        if is_any_sensitive_checked:
            self.search_contents_checkbox.setChecked(True); self.search_contents_checkbox.setEnabled(False)
        else: self.search_contents_checkbox.setEnabled(True)

    def load_icons(self):
        self.icons = {}
        for key, b64_data in ICON_DATA.items():
            pixmap = QPixmap(); pixmap.loadFromData(base64.b64decode(b64_data)); self.icons[key] = QIcon(pixmap)
        self.tabs.setTabIcon(0, self.icons.get('folder')); self.tabs.setTabIcon(1, self.icons.get('text')); self.tabs.setTabIcon(2, self.icons.get('loot'))
    
    def get_smb_connection(self, host):
        smb = self.current_smb_sessions.get(host)
        if smb:
            try:
                smb.get_smb_connection().echo()
                return smb, None
            except Exception:
                pass
        try:
            new_smb = SMBConnection(host, host, sess_port=445, timeout=10)
            new_smb.login(self.user, self.passwd)
            self.current_smb_sessions[host] = new_smb
            return new_smb, None
        except Exception as e:
            err_msg = self.get_smb_error_string(e)
            self.current_smb_sessions[host] = None
            return None, err_msg

    def on_item_expanded(self, item):
        meta = item.data(0, Qt.UserRole)
        if not meta or meta.get('expanded', False): return
        item_type = meta.get('type')
        if item_type not in ['share', 'folder']: return
        host = meta.get('host')
        if not host: return
        item.takeChildren()
        smb, error_msg = self.get_smb_connection(host)
        if error_msg:
            error_item = QTreeWidgetItem(item, [f"Error: {error_msg}"])
            error_item.setForeground(0, Qt.red)
            return
        try:
            share = meta.get('share', '')
            path = meta.get('path', '')
            self.populate_directory(smb, share, path, item)
            if item.childCount() == 0:
                empty_item = QTreeWidgetItem(item, ["[Empty or Access Denied]"])
                empty_item.setForeground(0, Qt.gray)
            meta['expanded'] = True
            item.setData(0, Qt.UserRole, meta)
        except Exception as e:
            error_text = self.get_smb_error_string(e)
            error_item = QTreeWidgetItem(item, [f"Error: {error_text}"])
            error_item.setForeground(0, Qt.red)

    def on_item_double_click(self, item, column):
        meta = item.data(0, Qt.UserRole)
        if not meta: return
        tree_widget = item.treeWidget()
        is_file = meta.get('type') == 'file' or tree_widget in [self.search_results_tree, self.loot_tree]
        if not is_file: return
        
        if tree_widget in [self.search_results_tree, self.loot_tree]:
            self.open_in_detached_window(meta)
        else:
            self.tabs.setCurrentIndex(0)
            self.browser_preview_pane.preview_file(meta, self.user, self.passwd)

    def open_in_detached_window(self, meta):
        if not meta: return
        win = DetachedPreviewWindow(self)
        win.load_file(meta, self.user, self.passwd)
        win.show()
        self.detached_windows.add(win)

    def remove_detached_window(self, window):
        self.detached_windows.discard(window)
        
    def scan(self):
        self.setWindowTitle("Noah's ARK")
        self.tree.clear(); self.close_all_smb_sessions()
        self.dir_cache.clear(); self.file_cache.clear(); self.host_item_map.clear()
        for win in list(self.detached_windows):
            win.close()
        self.search_status_label.setText("Status: Idle. Start a scan before searching.")
        
        selected_proxy_name = self.proxy_combo.currentText(); port = PROXY_MAP.get(selected_proxy_name)
        if port is not None:
            try: socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", port); socket.socket = socks.socksocket
            except Exception as e: QMessageBox.critical(self, "Proxy Error", f"Failed to set proxy: {e}"); return
        else:
            socks.set_default_proxy(None)
            if hasattr(socket, '_original_socket'): socket.socket = socket._original_socket
        
        target = self.ip_input.text().strip()
        if not target: QMessageBox.warning(self, "Missing Info", "Target is required."); return
        self.user, self.passwd = self.username.text().strip(), self.password.text().strip()
        
        try: hosts = self.expand_targets(target)
        except ValueError: QMessageBox.critical(self, "Invalid IP", "Invalid IP/subnet."); return
        
        self.scan_button.hide(); self.stop_scan_button.show()
        self.progress_dialog = QProgressDialog(f"Scanning {len(hosts)} hosts...", "Cancel", 0, len(hosts), self)
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.canceled.connect(self.stop_scan)
        self.progress_dialog.show()

        self.scan_thread = QThread()
        self.scan_worker = ScanWorker(hosts, self.user, self.passwd)
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_worker.host_authenticated.connect(self.on_host_authenticated)
        self.scan_worker.host_error.connect(self.on_host_error)
        self.scan_worker.progress_update.connect(self.on_scan_progress_update)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_thread.start()

    def stop_scan(self):
        if self.scan_worker: self.scan_worker.stop()
        if self.progress_dialog: self.progress_dialog.setLabelText("Stopping scan...")

    def on_scan_progress_update(self, value, total):
        if self.progress_dialog: self.progress_dialog.setValue(value)

    def on_host_authenticated(self, host, smb, shares):
        self.current_smb_sessions[host] = smb
        dialect_str = DIALECT_DISPLAY_MAP.get(smb.getDialect(), f"Unknown ({smb.getDialect()})")
        details = f"SMBv{dialect_str}, Signing: {smb.isSigningRequired()}"
        host_item = QTreeWidgetItem(self.tree, [host, "Host", "", details])
        host_item.setData(0, Qt.UserRole, {'host': host, 'type': 'host'})
        host_item.setIcon(0, self.icons.get('folder'))
        self.host_item_map[host] = host_item
        for share in shares:
            share_name = share['shi1_netname'].rstrip('\x00')
            if not share_name or share_name in ["IPC$", "ADMIN$"]: continue
            share_item = QTreeWidgetItem(host_item, [share_name, "Share"])
            share_item.setData(0, Qt.UserRole, {'host': host, 'share': share_name, 'path': '', 'expanded': False, 'type': 'share'})
            share_item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
            share_item.setIcon(0, self.icons.get('folder'))

    def on_host_error(self, host, error_message):
        host_item = QTreeWidgetItem(self.tree, [host, "Host", "", f"Error: {error_message}"])
        host_item.setData(0, Qt.UserRole, {'host': host, 'type': 'host', 'error': True})
        host_item.setForeground(0, Qt.red)
        host_item.setForeground(3, Qt.red)
        self.host_item_map[host] = host_item

    def on_scan_finished(self):
        if self.progress_dialog: self.progress_dialog.close()
        self.scan_thread.quit(); self.scan_thread.wait()
        self.scan_thread, self.scan_worker = None, None
        self.scan_button.show(); self.stop_scan_button.hide()
        self.setWindowTitle("Noah's ARK - Scan Complete")
        if self.current_smb_sessions: self.search_status_label.setText("Status: Ready to search.")
    
    def _populate_tree_from_listing(self, listing, parent_item, host, share, path):
        for entry in listing:
            if entry.get_longname() in [".", ".."]: continue
            is_dir = entry.is_directory(); new_path = os.path.join(path, entry.get_longname()).replace(os.sep, '\\')
            size = entry.get_filesize() if not is_dir else 0; size_str = format_size(size)
            item = QTreeWidgetItem(parent_item, [entry.get_longname(), "Folder" if is_dir else "File", size_str])
            ext = os.path.splitext(entry.get_longname())[-1].lower(); file_type = preview_handlers.get(ext, 'file')
            item_type = "folder" if is_dir else "file"
            if is_dir: item.setIcon(0, self.icons.get('folder')); item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
            else: item.setIcon(0, self.icons.get(file_type, self.icons.get('file')))
            item.setData(0, Qt.UserRole, {'host': host, 'share': share, 'path': new_path, 'expanded': False, 'size': size, 'type': item_type})

    def populate_directory(self, smb, share, path, parent_item):
        host = smb.getRemoteHost()
        cache_key = f"//{host}/{share}/{path}"
        cached_listing = self.dir_cache.get(cache_key)
        if cached_listing:
            self._populate_tree_from_listing(cached_listing, parent_item, host, share, path); return
        query = os.path.join(path, "*").replace(os.sep, '\\')
        dir_listing = smb.listPath(share, query)
        self.dir_cache[cache_key] = dir_listing
        self._populate_tree_from_listing(dir_listing, parent_item, host, share, path)
    
    def open_context_menu(self, position):
        tree_widget = self.sender(); item = tree_widget.itemAt(position)
        if not item: return
        menu = QMenu(); meta = item.data(0, Qt.UserRole)
        if not meta or meta.get('error'): return
        is_file = meta.get('type') == 'file' or tree_widget in [self.search_results_tree, self.loot_tree]
        is_folder = meta.get('type') in ['folder', 'share']
        add_to_loot_action, refresh_action, download_action, view_detached_action = None, None, None, None
        if is_file:
            if tree_widget in [self.tree, self.search_results_tree]: add_to_loot_action = menu.addAction(self.icons.get('loot'), "Add to Loot")
            download_action = menu.addAction("Download File")
            if tree_widget is self.tree:
                view_detached_action = menu.addAction("View in Detached Window")
        if is_folder and tree_widget is self.tree: 
            refresh_action = menu.addAction(self.icons.get('refresh'), "Refresh Folder")
        if not menu.actions(): return
        action = menu.exec_(tree_widget.viewport().mapToGlobal(position))
        if action == download_action: self.download_file(meta)
        elif action == add_to_loot_action: self.add_to_loot(meta)
        elif action == refresh_action: self.refresh_directory(item)
        elif action == view_detached_action: self.open_in_detached_window(meta)
    
    def refresh_directory(self, item):
        meta = item.data(0, Qt.UserRole)
        if not meta: return
        host = meta.get('host')
        share = meta.get('share', ''); path = meta.get('path', '')
        cache_key = f"//{host}/{share}/{path}"
        self.dir_cache.pop(cache_key, None)
        is_expanded = item.isExpanded()
        item.takeChildren()
        if meta.get('type') in ['folder', 'share', 'host']:
            item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
        if is_expanded:
            self.on_item_expanded(item)

    def download_file(self, meta):
        save_path, _ = QFileDialog.getSaveFileName(self, "Save File As", os.path.basename(meta['path']))
        if not save_path: return
        host = meta.get('smb_host') or meta.get('host')
        smb, error_msg = self.get_smb_connection(host)
        if error_msg:
            QMessageBox.critical(self, "Download Failed", f"Could not get SMB connection for {host}:\n{error_msg}")
            return
        try:
            with open(save_path, "wb") as f: smb.getFile(meta['share'], meta['path'], f.write)
            QMessageBox.information(self, "Download Complete", f"File saved to {save_path}")
        except Exception as e: 
            QMessageBox.critical(self, "Download Failed", self.get_smb_error_string(e))
    
    def add_to_loot(self, meta):
        host = meta.get('smb_host') or meta.get('host')
        full_path = f"//{host}/{meta['share']}/{meta['path']}"
        if full_path in self.looted_paths:
            QMessageBox.information(self, "Duplicate", "This item is already in your loot."); return
        self.looted_paths.add(full_path); self.loot_data.append(meta)
        self.populate_loot_tree(); self.tabs.setCurrentIndex(2)

    def remove_selected_loot(self):
        selected_items = self.loot_tree.selectedItems()
        if not selected_items: return
        reply = QMessageBox.question(self, "Confirm Removal", f"Are you sure you want to remove {len(selected_items)} item(s) from loot?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            items_to_remove_meta = [item.data(0, Qt.UserRole) for item in selected_items]
            for meta_to_remove in items_to_remove_meta:
                host = meta_to_remove.get('smb_host') or meta_to_remove.get('host')
                full_path = f"//{host}/{meta_to_remove['share']}/{meta_to_remove['path']}"
                self.looted_paths.discard(full_path)
            self.loot_data = [meta for meta in self.loot_data if meta not in items_to_remove_meta]
            self.populate_loot_tree()

    def export_loot(self):
        if not self.loot_data: QMessageBox.warning(self, "Empty Loot", "There is nothing to export."); return
        save_path, _ = QFileDialog.getSaveFileName(self, "Export Loot as CSV", "loot.csv", "CSV Files (*.csv)")
        if not save_path: return
        try:
            with open(save_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f); writer.writerow(['FullPath', 'Size', 'Host'])
                for meta in self.loot_data:
                    host = meta.get('smb_host') or meta.get('host')
                    full_path = f"//{host}/{meta['share']}/{meta['path']}"; size_str = format_size(meta.get('size', 0))
                    writer.writerow([full_path, size_str, host])
            QMessageBox.information(self, "Export Complete", f"Loot exported to {save_path}")
        except Exception as e: QMessageBox.critical(self, "Export Failed", f"Could not write to file: {e}")

    def populate_loot_tree(self):
        self.loot_tree.clear()
        for meta in self.loot_data:
            host = meta.get('smb_host') or meta.get('host')
            full_path = f"//{host}/{meta['share']}/{meta['path']}"; size_str = format_size(meta.get('size', 0))
            item = QTreeWidgetItem(self.loot_tree, [full_path, size_str, host])
            ext = os.path.splitext(meta['path'])[-1].lower(); file_type = preview_handlers.get(ext, 'file')
            item.setIcon(0, self.icons.get(file_type, self.icons.get('file'))); item.setData(0, Qt.UserRole, meta)
            
    def start_search(self):
        live_hosts = [host for host, conn in self.current_smb_sessions.items() if conn is not None]
        if not live_hosts:
            QMessageBox.warning(self, "Not Connected", "Please perform a scan and find authenticated hosts before searching.")
            return
        keywords = self.search_keywords_input.text()
        active_regex = {name: SENSITIVE_DATA_REGEX[name] for name, cb in self.sensitive_data_checkboxes.items() if cb.isChecked()}
        search_filenames = self.search_filenames_checkbox.isChecked()
        search_contents = self.search_contents_checkbox.isChecked()
        if not keywords and not active_regex:
            QMessageBox.warning(self, "Input Error", "Please enter keywords or select a sensitive data type.")
            return
        if keywords and not search_filenames and not search_contents:
            QMessageBox.warning(self, "Input Error", "Please select to search in 'Filenames' or 'File Contents'.")
            return
        self.search_results_tree.clear()
        self.start_search_button.setEnabled(False)
        self.stop_search_button.setEnabled(True)
        case_sensitive = self.search_case_checkbox.isChecked()
        text_only = self.search_text_only_checkbox.isChecked()
        self.search_thread = QThread()
        self.search_worker = SearchWorker(
            self, live_hosts, keywords, search_filenames, search_contents, 
            case_sensitive, text_only, self.user, self.passwd, active_regex
        )
        self.search_worker.moveToThread(self.search_thread)
        self.search_worker.match_found.connect(self.on_search_match_found)
        self.search_worker.update_status.connect(self.on_search_status_update)
        self.search_worker.finished.connect(self.on_search_finished)
        self.search_thread.started.connect(self.search_worker.run)
        self.search_thread.start()

    def stop_search(self):
        if self.search_worker: self.search_worker.stop(); self.search_status_label.setText("Status: Stopping..."); self.stop_search_button.setEnabled(False)

    def on_search_match_found(self, meta):
        host = meta['host']; path = meta['path']; size_str = format_size(meta['size']); reason = meta['reason']
        item = QTreeWidgetItem(self.search_results_tree, [f"//{host}/{meta['share']}/{path}", size_str, host, reason])
        item.setData(0, Qt.UserRole, meta); ext = os.path.splitext(path)[-1].lower(); file_type = preview_handlers.get(ext, 'file')
        item.setIcon(0, self.icons.get(file_type, self.icons.get('file')))

    def on_search_status_update(self, status): self.search_status_label.setText(f"Status: {status}")

    def on_search_finished(self):
        if self.search_thread: self.search_thread.quit(); self.search_thread.wait()
        self.search_thread = None; self.search_worker = None; self.start_search_button.setEnabled(True); self.stop_search_button.setEnabled(False)
        current_status = self.search_status_label.text()
        if "Stopping" in current_status or "Searching" in current_status:
             self.search_status_label.setText("Status: Search finished.")

    def expand_targets(self, t): return [str(ip) for ip in ipaddress.IPv4Network(t, strict=False)] if '/' in t else [t]

    def close_all_smb_sessions(self):
        for smb in self.current_smb_sessions.values():
            if smb:
                try: smb.close()
                except: pass
        self.current_smb_sessions.clear()

    def closeEvent(self, event):
        if self.scan_worker: self.scan_worker.stop()
        if self.search_worker: self.search_worker.stop()
        for win in list(self.detached_windows):
            win.close()
        self.cleanup_temp_files(); self.close_all_smb_sessions(); event.accept()

    def cleanup_temp_files(self):
        print("Cleaning up temporary files...")
        for f in self._temp_files_to_clean:
            try:
                if os.path.exists(f): os.remove(f)
            except Exception as e: print(f"Error removing temp file {f}: {e}")


if __name__ == "__main__":
    if hasattr(socks, '_original_socket'):
        socket.socket = socks._original_socket
    else:
        socks._original_socket = socket.socket
        
    app = QApplication(sys.argv)
    app.setStyleSheet(DARK_STYLESHEET)

    # --- New startup logic for Title Screen ---
    title_screen = TitleScreen()
    main_window = None  # Keep a reference

    def start_main_app():
        global main_window
        # Create the main window instance only when it's needed
        main_window = NoahsARK()
        main_window.show()
        title_screen.close()

    title_screen.start_app_signal.connect(start_main_app)
    title_screen.show()
    
    sys.exit(app.exec_())