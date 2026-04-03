from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from src.desktop_services import (
    PROVIDER_ORDER,
    analyze_soc_log,
    collect_iocs,
    export_ioc_csv,
    export_json,
    export_soc_csv,
    load_soc_log_inputs,
    load_persisted_settings,
    sanitize_api_keys,
    scan_iocs,
    save_persisted_settings,
    summarize_ioc_rows,
)

# ── design tokens ────────────────────────────────────────────────────────────
_BG = "#0B1220"
_SURFACE = "#111827"
_CARD = "#1F2937"
_BORDER = "#2D3748"
_PRIMARY = "#3B82F6"
_ACCENT = "#22C55E"
_WARNING = "#F59E0B"
_DANGER = "#EF4444"
_TEXT = "#E5E7EB"
_TEXT2 = "#9CA3AF"
_SIDEBAR = "#0F1629"


# ── helpers ──────────────────────────────────────────────────────────────────

def _status_item(value: str) -> QTableWidgetItem:
    item = QTableWidgetItem(value)
    low = value.lower()
    _colors = {
        "malicious": _DANGER,
        "suspicious": _WARNING,
        "clean": _ACCENT,
        "not_found": _TEXT2,
        "not_supported": _TEXT2,
    }
    if low in _colors:
        item.setForeground(QColor(_colors[low]))
    elif low in {"error", "invalid"}:
        item.setForeground(QColor("#B91C1C"))
    return item


def _card(title: str = "") -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setProperty("class", "card")
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(12, 10, 12, 10)
    lay.setSpacing(6)
    if title:
        lbl = QLabel(title.upper())
        lbl.setProperty("class", "cardTitle")
        lay.addWidget(lbl)
    return frame, lay


def _table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    header = t.horizontalHeader()
    header.setStretchLastSection(False)
    header.setMinimumSectionSize(88)
    header.setDefaultSectionSize(106)
    t.setAlternatingRowColors(True)
    t.setShowGrid(False)
    t.verticalHeader().setVisible(False)
    t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    return t


def _hrow() -> tuple[QWidget, QHBoxLayout]:
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    return w, lay


def _scrollpage() -> tuple[QScrollArea, QVBoxLayout]:
    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setFrameShape(QFrame.Shape.NoFrame)
    inner = QWidget()
    lay = QVBoxLayout(inner)
    lay.setContentsMargins(24, 16, 24, 16)
    lay.setSpacing(10)
    sa.setWidget(inner)
    sa.viewport().setAutoFillBackground(False)
    return sa, lay


def _btn(text: str, cls: str = "primary") -> QPushButton:
    b = QPushButton(text)
    b.setProperty("class", cls)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


class _Collapsible(QFrame):
    """Card with a clickable header that toggles body visibility."""

    def __init__(self, title: str, expanded: bool = False) -> None:
        super().__init__()
        self.setProperty("class", "card")
        self._title = title
        self._expanded = expanded

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self._header = QPushButton(self._label_text())
        self._header.setProperty("class", "collapseBtn")
        self._header.setCursor(Qt.CursorShape.PointingHandCursor)
        self._header.clicked.connect(self._toggle)
        outer.addWidget(self._header)

        self._body = QWidget()
        self._body_lay = QVBoxLayout(self._body)
        self._body_lay.setContentsMargins(12, 2, 12, 10)
        self._body_lay.setSpacing(4)
        self._body.setVisible(expanded)
        outer.addWidget(self._body)

    def _label_text(self) -> str:
        arrow = "\u25BE" if self._expanded else "\u25B8"
        return f"  {arrow}   {self._title}"

    def _toggle(self) -> None:
        self._expanded = not self._expanded
        self._body.setVisible(self._expanded)
        self._header.setText(self._label_text())

    def body(self) -> QVBoxLayout:
        return self._body_lay


# ── stylesheet ───────────────────────────────────────────────────────────────

_QSS = f"""
/* ── base ── */
QMainWindow {{
    background: {_BG};
    color: {_TEXT};
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
}}
QLabel, QCheckBox {{
    background: transparent;
}}
QStackedWidget {{
    background: transparent;
    border: none;
}}

/* ── sidebar ── */
QWidget#sidebar {{
    background: {_SIDEBAR};
    border-right: 1px solid {_BORDER};
}}
QLabel#brand {{
    font-size: 15px;
    font-weight: 700;
    color: {_TEXT};
    padding: 0 18px;
}}
QLabel#brandSub {{
    font-size: 10px;
    color: {_TEXT2};
    padding: 0 18px;
}}
QLabel#sidebarFooter {{
    font-size: 10px;
    color: {_TEXT2};
    padding: 10px 18px;
}}
QFrame#sidebarRule {{
    background: {_BORDER};
    max-height: 1px;
    border: none;
}}

QPushButton[class="nav"] {{
    text-align: left;
    padding: 0 16px;
    border: none;
    border-left: 3px solid transparent;
    border-radius: 0;
    background: transparent;
    color: {_TEXT2};
    font-size: 12.5px;
    font-weight: 500;
    margin: 1px 0;
}}
QPushButton[class="nav"]:hover {{
    background: rgba(59, 130, 246, 0.07);
    color: {_TEXT};
}}
QPushButton[class="nav"]:checked {{
    background: rgba(59, 130, 246, 0.13);
    border-left: 3px solid {_PRIMARY};
    color: {_PRIMARY};
    font-weight: 600;
}}

/* ── cards ── */
QFrame[class="card"] {{
    background: {_CARD};
    border: 1px solid {_BORDER};
    border-radius: 7px;
}}
QLabel[class="cardTitle"] {{
    font-size: 11px;
    font-weight: 700;
    color: {_TEXT2};
}}

/* ── collapse toggle ── */
QPushButton[class="collapseBtn"] {{
    text-align: left;
    padding: 9px 14px;
    background: transparent;
    color: {_TEXT};
    font-size: 12px;
    font-weight: 600;
    border: none;
    border-radius: 0;
}}
QPushButton[class="collapseBtn"]:hover {{
    background: rgba(255, 255, 255, 0.03);
}}

/* ── headings ── */
QLabel[class="pageTitle"] {{
    font-size: 20px;
    font-weight: 700;
    color: {_TEXT};
}}
QLabel[class="pageSubtitle"] {{
    font-size: 12px;
    color: {_TEXT2};
    padding-bottom: 2px;
}}

/* ── metric cards ── */
QFrame[class="metricCard"] {{
    background: {_CARD};
    border: 1px solid {_BORDER};
    border-radius: 8px;
}}
QLabel[class="metricValue"] {{
    font-size: 32px;
    font-weight: 700;
}}
QLabel[class="metricLabel"] {{
    font-size: 10px;
    font-weight: 600;
    color: {_TEXT2};
}}

/* ── buttons ── */
QPushButton[class="primary"] {{
    background: {_PRIMARY};
    color: #fff;
    border: none;
    border-radius: 6px;
    padding: 7px 22px;
    font-weight: 600;
    font-size: 13px;
}}
QPushButton[class="primary"]:hover {{
    background: #2563EB;
}}
QPushButton[class="primary"]:pressed {{
    background: #1D4ED8;
}}

QPushButton[class="secondary"] {{
    background: transparent;
    color: {_TEXT2};
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 7px 18px;
    font-weight: 500;
    font-size: 12px;
}}
QPushButton[class="secondary"]:hover {{
    background: rgba(255, 255, 255, 0.04);
    border-color: {_TEXT2};
    color: {_TEXT};
}}
QPushButton[class="secondary"]:pressed {{
    background: rgba(255, 255, 255, 0.07);
}}

QPushButton[class="accent"] {{
    background: {_ACCENT};
    color: #fff;
    border: none;
    border-radius: 6px;
    padding: 8px 28px;
    font-weight: 700;
    font-size: 13px;
}}
QPushButton[class="accent"]:hover {{
    background: #16A34A;
}}
QPushButton[class="accent"]:pressed {{
    background: #15803D;
}}

QPushButton[class="danger"] {{
    background: {_DANGER};
    color: #fff;
    border: none;
    border-radius: 6px;
    padding: 7px 22px;
    font-weight: 600;
    font-size: 13px;
}}
QPushButton[class="danger"]:hover {{
    background: #DC2626;
}}
QPushButton[class="danger"]:pressed {{
    background: #B91C1C;
}}

QPushButton[class="ghost"] {{
    background: transparent;
    color: {_TEXT2};
    border: none;
    border-radius: 5px;
    padding: 5px 12px;
    font-size: 11px;
}}
QPushButton[class="ghost"]:hover {{
    color: {_TEXT};
    background: rgba(255, 255, 255, 0.04);
}}
QPushButton[class="ghost"]:pressed {{
    background: rgba(255, 255, 255, 0.07);
}}

/* ── inputs ── */
QLineEdit {{
    background: {_SURFACE};
    color: {_TEXT};
    border: 1px solid {_BORDER};
    border-radius: 5px;
    padding: 4px 10px;
    font-size: 12.5px;
    min-height: 12px;
    max-height: 26px;
}}
QLineEdit:focus {{
    border-color: {_PRIMARY};
}}
QTextEdit {{
    background: {_SURFACE};
    color: {_TEXT};
    border: 1px solid {_BORDER};
    border-radius: 5px;
    padding: 4px 10px;
    font-size: 12.5px;
}}
QTextEdit:focus {{
    border-color: {_PRIMARY};
}}
QComboBox {{
    background: {_SURFACE};
    color: {_TEXT};
    border: 1px solid {_BORDER};
    border-radius: 5px;
    padding: 4px 10px;
    font-size: 12.5px;
    min-height: 12px;
}}
QComboBox:focus {{
    border-color: {_PRIMARY};
}}
QComboBox::drop-down {{
    border: none;
    width: 22px;
}}
QComboBox::down-arrow {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {_TEXT2};
    margin-right: 6px;
}}
QComboBox QAbstractItemView {{
    background: {_CARD};
    color: {_TEXT};
    border: 1px solid {_BORDER};
    selection-background-color: {_PRIMARY};
    padding: 2px;
}}

/* ── checkboxes ── */
QCheckBox {{
    spacing: 7px;
    color: {_TEXT};
    font-size: 12px;
}}
QCheckBox::indicator {{
    width: 15px;
    height: 15px;
    border: 1px solid {_BORDER};
    border-radius: 3px;
    background: {_SURFACE};
}}
QCheckBox::indicator:checked {{
    background: {_PRIMARY};
    border-color: {_PRIMARY};
}}

/* ── tables ── */
QTableWidget {{
    background: {_SURFACE};
    alternate-background-color: #131C2B;
    border: 1px solid {_BORDER};
    border-radius: 5px;
    gridline-color: transparent;
    font-size: 11.5px;
    color: {_TEXT};
}}
QTableWidget::item {{
    padding: 4px 8px;
    border: none;
    border-bottom: 1px solid rgba(45, 55, 72, 0.3);
}}
QTableWidget::item:hover {{
    background: rgba(59, 130, 246, 0.08);
}}
QTableWidget::item:selected {{
    background: rgba(59, 130, 246, 0.18);
}}
QHeaderView::section {{
    background: #151D2C;
    color: {_TEXT2};
    font-weight: 700;
    font-size: 10px;
    border: none;
    border-bottom: 2px solid {_BORDER};
    padding: 6px 8px;
}}

/* ── scrollbars ── */
QScrollArea {{
    background: transparent;
    border: none;
}}
QScrollBar:vertical {{
    background: transparent;
    width: 6px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {_BORDER};
    border-radius: 3px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {_TEXT2};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 6px;
    border: none;
}}
QScrollBar::handle:horizontal {{
    background: {_BORDER};
    border-radius: 3px;
    min-width: 30px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}

/* ── list widget ── */
QListWidget {{
    background: {_SURFACE};
    border: 1px solid {_BORDER};
    border-radius: 5px;
    font-size: 11.5px;
    color: {_TEXT};
}}
QListWidget::item {{
    padding: 6px 10px;
    border-bottom: 1px solid rgba(45, 55, 72, 0.5);
}}
QListWidget::item:hover {{
    background: rgba(59, 130, 246, 0.07);
}}
QListWidget::item:selected {{
    background: rgba(59, 130, 246, 0.16);
    color: {_TEXT};
}}

/* ── misc labels ── */
QLabel[class="summary"] {{
    font-size: 12px;
    color: {_TEXT2};
}}
QLabel[class="fileLabel"] {{
    font-size: 11px;
    color: {_TEXT2};
}}

/* ── dialogs ── */
QToolTip {{
    background: {_CARD};
    color: {_TEXT};
    border: 1px solid {_BORDER};
    padding: 5px 8px;
    border-radius: 4px;
    font-size: 11px;
}}
QMessageBox {{
    background: {_CARD};
}}
QMessageBox QLabel {{
    color: {_TEXT};
}}
QMessageBox QPushButton {{
    background: {_PRIMARY};
    color: #fff;
    border: none;
    border-radius: 5px;
    padding: 5px 16px;
    font-weight: 600;
}}
"""


# ── main window ──────────────────────────────────────────────────────────────

class DesktopSecurityApp(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SOC Security Workstation")
        self.resize(1360, 860)
        self.setStyleSheet(_QSS)

        self.settings_state = load_persisted_settings()
        self.history_entries: list[dict[str, Any]] = []
        self.last_ioc_rows: list[dict[str, Any]] = []
        self.last_soc_payload: dict[str, Any] | None = None
        self.ioc_file_path: str | None = None
        self.soc_file_path: str | None = None

        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._stack = QStackedWidget()

        self.tab_index_home = self._stack.addWidget(self._build_home_page())
        self.tab_index_ioc = self._stack.addWidget(self._build_ioc_page())
        self.tab_index_soc = self._stack.addWidget(self._build_soc_page())
        self.tab_index_settings = self._stack.addWidget(self._build_settings_page())
        self.tab_index_history = self._stack.addWidget(self._build_history_page())

        root.addWidget(self._build_sidebar())
        root.addWidget(self._stack, 1)

        self._sync_settings_to_ui()
        self._navigate_to(self.tab_index_home)
        self._update_home_metrics()

    # ── sidebar ──────────────────────────────────────────────────────────

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        col = QVBoxLayout(sidebar)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(0)

        brand = QLabel("SOC Workstation")
        brand.setObjectName("brand")
        brand.setFixedHeight(44)
        brand.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        col.addWidget(brand)

        rule = QFrame()
        rule.setObjectName("sidebarRule")
        rule.setFixedHeight(1)
        col.addWidget(rule)
        col.addSpacing(6)

        self._nav_buttons: list[QPushButton] = []
        nav_items = [
            ("\u229E  Home", self.tab_index_home),
            ("\u25CE  IOC Checker", self.tab_index_ioc),
            ("\u25C6  SOC Analysis", self.tab_index_soc),
            ("\u2699  Settings", self.tab_index_settings),
        ]
        for label, idx in nav_items:
            btn = QPushButton(f"   {label}")
            btn.setProperty("class", "nav")
            btn.setCheckable(True)
            btn.setFixedHeight(36)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _ch, i=idx: self._navigate_to(i))
            col.addWidget(btn)
            self._nav_buttons.append(btn)

        self._history_nav_btn = QPushButton("   \u25D4  History")
        self._history_nav_btn.setProperty("class", "nav")
        self._history_nav_btn.setCheckable(True)
        self._history_nav_btn.setFixedHeight(36)
        self._history_nav_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._history_nav_btn.setVisible(False)
        self._history_nav_btn.clicked.connect(
            lambda: self._navigate_to(self.tab_index_history),
        )
        col.addWidget(self._history_nav_btn)
        self._nav_buttons.append(self._history_nav_btn)

        col.addStretch(1)

        footer = QLabel("v1.0.0")
        footer.setObjectName("sidebarFooter")
        col.addWidget(footer)
        return sidebar

    # ── navigation ───────────────────────────────────────────────────────

    def _navigate_to(self, index: int) -> None:
        self._stack.setCurrentIndex(index)
        for i, btn in enumerate(self._nav_buttons):
            btn.setChecked(i == index)

    def _set_ioc_loading(self, loading: bool, message: str = "") -> None:
        controls = [
            self.ioc_scan_btn,
            self.ioc_export_json_btn,
            self.ioc_export_csv_btn,
            self.ioc_single_input,
            self.ioc_bulk_input,
            self.ioc_type_combo,
            self.ioc_use_providers,
        ]
        for control in controls:
            control.setEnabled(not loading)
        if loading:
            self.ioc_summary_label.setText(message or "Scanning IOCs...")
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            QApplication.processEvents()
        else:
            if QApplication.overrideCursor() is not None:
                QApplication.restoreOverrideCursor()

    def _set_soc_loading(self, loading: bool, message: str = "") -> None:
        controls = [
            self.soc_analyze_btn,
            self.soc_export_json_btn,
            self.soc_export_csv_btn,
            self.soc_raw_log_input,
            self.soc_model_path_input,
            self.soc_enrich_toggle,
        ]
        for control in controls:
            control.setEnabled(not loading)
        if loading:
            self.soc_summary_label.setText(message or "Running SOC analysis...")
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            QApplication.processEvents()
        else:
            if QApplication.overrideCursor() is not None:
                QApplication.restoreOverrideCursor()

    def _provider_lookup_url(self, provider: str, ioc: str, ioc_type: str) -> str | None:
        value = ioc.strip()
        if not value:
            return None
        if provider == "virustotal":
            return f"https://www.virustotal.com/gui/search/{quote_plus(value)}"
        if provider == "abuseipdb":
            if ioc_type != "ip":
                return None
            return f"https://www.abuseipdb.com/check/{quote_plus(value)}"
        if provider == "otx":
            type_map = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}
            otx_type = type_map.get(ioc_type)
            if not otx_type:
                return None
            return f"https://otx.alienvault.com/indicator/{otx_type}/{quote_plus(value)}"
        if provider == "threatfox":
            return f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{quote_plus(value)}"
        return None

    def _on_ioc_table_cell_clicked(self, row: int, column: int) -> None:
        provider_by_column = {5: "virustotal", 6: "abuseipdb", 7: "otx", 8: "threatfox"}
        provider = provider_by_column.get(column)
        if provider is None:
            return
        item = self.ioc_table.item(row, column)
        if item is None:
            return
        url = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(url, str) and url:
            QDesktopServices.openUrl(QUrl(url))

    # ── page: home ───────────────────────────────────────────────────────

    def _build_home_page(self) -> QWidget:
        page, lay = _scrollpage()

        title = QLabel("SOC Security Workstation")
        title.setProperty("class", "pageTitle")
        sub = QLabel(
            "Unified desktop workflow for IOC checking and SOC log analysis.\n"
            "Use the sidebar or quick-actions below to get started.",
        )
        sub.setProperty("class", "pageSubtitle")
        sub.setWordWrap(True)
        lay.addWidget(title)
        lay.addWidget(sub)
        lay.addSpacing(4)

        metrics_row, mlay = _hrow()
        mlay.setSpacing(12)

        def _metric(value_lbl: QLabel, label_text: str, color: str) -> QFrame:
            f = QFrame()
            f.setProperty("class", "metricCard")
            ml = QVBoxLayout(f)
            ml.setContentsMargins(14, 10, 14, 10)
            ml.setSpacing(2)
            bar = QFrame()
            bar.setFixedHeight(2)
            bar.setStyleSheet(f"background: {color}; border: none; border-radius: 1px;")
            ml.addWidget(bar)
            value_lbl.setProperty("class", "metricValue")
            value_lbl.setStyleSheet(f"color: {color};")
            ml.addWidget(value_lbl)
            lbl = QLabel(label_text)
            lbl.setProperty("class", "metricLabel")
            ml.addWidget(lbl)
            return f

        self.home_history_metric = QLabel("0")
        self.home_ioc_metric = QLabel("0")
        self.home_soc_metric = QLabel("No")

        mlay.addWidget(_metric(self.home_history_metric, "HISTORY ENTRIES", _PRIMARY))
        mlay.addWidget(_metric(self.home_ioc_metric, "IOC SCAN ROWS", _ACCENT))
        mlay.addWidget(_metric(self.home_soc_metric, "SOC ANALYSIS", _WARNING))
        mlay.addStretch(1)
        lay.addWidget(metrics_row)
        lay.addSpacing(4)

        actions_card, alay = _card("Quick Actions")
        row, rlay = _hrow()
        rlay.setSpacing(12)
        ioc_btn = _btn("Open IOC Checker")
        ioc_btn.setFixedHeight(34)
        ioc_btn.clicked.connect(lambda: self._navigate_to(self.tab_index_ioc))
        soc_btn = _btn("Open SOC Analysis")
        soc_btn.setFixedHeight(34)
        soc_btn.clicked.connect(lambda: self._navigate_to(self.tab_index_soc))
        settings_btn = _btn("Open Settings", "secondary")
        settings_btn.setFixedHeight(34)
        settings_btn.clicked.connect(lambda: self._navigate_to(self.tab_index_settings))
        rlay.addWidget(ioc_btn)
        rlay.addWidget(soc_btn)
        rlay.addWidget(settings_btn)
        rlay.addStretch(1)
        alay.addWidget(row)
        lay.addWidget(actions_card)
        lay.addStretch(1)
        return page

    # ── page: IOC checker ────────────────────────────────────────────────

    def _build_ioc_page(self) -> QWidget:
        page, lay = _scrollpage()

        title = QLabel("IOC Checker")
        title.setProperty("class", "pageTitle")
        sub = QLabel(
            "Submit and scan Indicators of Compromise against threat-intelligence providers.",
        )
        sub.setProperty("class", "pageSubtitle")
        sub.setWordWrap(True)
        lay.addWidget(title)
        lay.addWidget(sub)

        # -- input card --
        inp_card, inp = _card("Input")
        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self.ioc_single_input = QLineEdit()
        self.ioc_single_input.setPlaceholderText("e.g. 8.8.8.8 or evil.com")
        self.ioc_single_input.setMaximumWidth(480)
        form.addRow("Single IOC:", self.ioc_single_input)

        self.ioc_bulk_input = QTextEdit()
        self.ioc_bulk_input.setPlaceholderText(
            "Paste one IOC per line or comma-separated IOC list.",
        )
        self.ioc_bulk_input.setFixedHeight(72)
        form.addRow("Bulk paste:", self.ioc_bulk_input)

        file_row, flay = _hrow()
        self.ioc_file_label = QLabel("No file selected")
        self.ioc_file_label.setProperty("class", "fileLabel")
        browse = _btn("Upload File", "secondary")
        browse.clicked.connect(self._browse_ioc_file)
        clear = _btn("Clear", "ghost")
        clear.clicked.connect(self._clear_ioc_file)
        flay.addWidget(self.ioc_file_label, 1)
        flay.addWidget(browse)
        flay.addWidget(clear)
        form.addRow("File import:", file_row)

        inp.addLayout(form)
        lay.addWidget(inp_card)

        # -- options card --
        opt_card, opt = _card("Options")
        opt_form = QFormLayout()
        opt_form.setSpacing(10)

        self.ioc_type_combo = QComboBox()
        self.ioc_type_combo.addItem("Auto-detect", "auto")
        self.ioc_type_combo.addItem("IP", "ip")
        self.ioc_type_combo.addItem("Domain", "domain")
        self.ioc_type_combo.addItem("URL", "url")
        self.ioc_type_combo.addItem("Hash", "hash")
        self.ioc_type_combo.setMaximumWidth(200)
        opt_form.addRow("Type override:", self.ioc_type_combo)

        self.ioc_use_providers = QCheckBox("Use provider lookups")
        self.ioc_use_providers.setChecked(True)
        opt_form.addRow("", self.ioc_use_providers)

        opt.addLayout(opt_form)
        lay.addWidget(opt_card)

        # -- action row --
        actions_row, alay = _hrow()
        alay.setSpacing(10)
        scan_btn = _btn("Scan IOCs", "accent")
        scan_btn.clicked.connect(self._run_ioc_scan)
        export_json_btn = _btn("Export JSON", "secondary")
        export_json_btn.clicked.connect(self._export_ioc_json)
        export_csv_btn = _btn("Export CSV", "secondary")
        export_csv_btn.clicked.connect(self._export_ioc_csv)
        self.ioc_scan_btn = scan_btn
        self.ioc_export_json_btn = export_json_btn
        self.ioc_export_csv_btn = export_csv_btn
        alay.addWidget(scan_btn)
        alay.addWidget(export_json_btn)
        alay.addWidget(export_csv_btn)
        alay.addStretch(1)
        lay.addWidget(actions_row)

        # -- results card --
        res_card, res = _card("Results")
        self.ioc_summary_label = QLabel("No IOC scan has been run in this session.")
        self.ioc_summary_label.setProperty("class", "summary")
        self.ioc_summary_label.setWordWrap(True)
        res.addWidget(self.ioc_summary_label)

        self.ioc_table = _table([
            "IOC", "Detected Type", "Effective Type", "Status", "Score",
            "VirusTotal", "AbuseIPDB", "OTX", "ThreatFox",
            "Provider Summary", "Errors",
        ])
        for col, width in (
            (0, 120),
            (1, 110),
            (2, 110),
            (3, 90),
            (4, 70),
            (5, 95),
            (6, 95),
            (7, 80),
            (8, 90),
            (9, 170),
            (10, 70),
        ):
            self.ioc_table.setColumnWidth(col, width)
        self.ioc_table.cellClicked.connect(self._on_ioc_table_cell_clicked)
        res.addWidget(self.ioc_table)
        lay.addWidget(res_card, 1)
        return page

    # ── page: SOC analysis ───────────────────────────────────────────────

    def _build_soc_page(self) -> QWidget:
        page, lay = _scrollpage()

        title = QLabel("SOC Analysis")
        title.setProperty("class", "pageTitle")
        sub = QLabel(
            "Analyze raw security logs for entities, ATT&CK mappings, and response guidance.",
        )
        sub.setProperty("class", "pageSubtitle")
        sub.setWordWrap(True)
        lay.addWidget(title)
        lay.addWidget(sub)

        # -- input card --
        inp_card, inp = _card("Input")
        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self.soc_raw_log_input = QTextEdit()
        self.soc_raw_log_input.setPlaceholderText(
            "Paste raw log content here (JSON or plain text).",
        )
        self.soc_raw_log_input.setFixedHeight(78)
        form.addRow("Raw log:", self.soc_raw_log_input)

        file_row, flay = _hrow()
        self.soc_file_label = QLabel("No file selected")
        self.soc_file_label.setProperty("class", "fileLabel")
        browse = _btn("Upload File", "secondary")
        browse.clicked.connect(self._browse_soc_file)
        clear = _btn("Clear", "ghost")
        clear.clicked.connect(self._clear_soc_file)
        flay.addWidget(self.soc_file_label, 1)
        flay.addWidget(browse)
        flay.addWidget(clear)
        form.addRow("Log file:", file_row)

        inp.addLayout(form)
        lay.addWidget(inp_card)

        # -- options card --
        opt_card, opt = _card("Options")
        opt_form = QFormLayout()
        opt_form.setSpacing(10)

        self.soc_model_path_input = QLineEdit()
        self.soc_model_path_input.setPlaceholderText(
            "Optional .pkl model for ML fallback",
        )
        self.soc_model_path_input.setMaximumWidth(480)
        opt_form.addRow("Model path:", self.soc_model_path_input)

        self.soc_enrich_toggle = QCheckBox("Enable IOC enrichment in SOC analysis")
        self.soc_enrich_toggle.setChecked(False)
        opt_form.addRow("", self.soc_enrich_toggle)

        opt.addLayout(opt_form)
        lay.addWidget(opt_card)

        # -- action row --
        actions_row, alay = _hrow()
        alay.setSpacing(10)
        analyze_btn = _btn("Analyze Log", "accent")
        analyze_btn.clicked.connect(self._run_soc_analysis)
        export_json_btn = _btn("Export JSON", "secondary")
        export_json_btn.clicked.connect(self._export_soc_json)
        export_csv_btn = _btn("Export CSV", "secondary")
        export_csv_btn.clicked.connect(self._export_soc_csv)
        self.soc_analyze_btn = analyze_btn
        self.soc_export_json_btn = export_json_btn
        self.soc_export_csv_btn = export_csv_btn
        alay.addWidget(analyze_btn)
        alay.addWidget(export_json_btn)
        alay.addWidget(export_csv_btn)
        alay.addStretch(1)
        lay.addWidget(actions_row)

        # -- summary --
        self.soc_summary_label = QLabel("No SOC analysis result available.")
        self.soc_summary_label.setProperty("class", "summary")
        self.soc_summary_label.setWordWrap(True)
        lay.addWidget(self.soc_summary_label)

        # -- collapsible result sections --
        sec_entities = _Collapsible("Extracted Entities", expanded=True)
        self.soc_entities_table = _table(
            ["Type", "Value", "Evidence", "Start", "End"],
        )
        sec_entities.body().addWidget(self.soc_entities_table)
        lay.addWidget(sec_entities)

        sec_mitre = _Collapsible("MITRE ATT&CK Mapping")
        self.soc_mitre_table = _table([
            "Technique ID", "Technique Name", "Confidence", "Rationale", "Evidence",
        ])
        sec_mitre.body().addWidget(self.soc_mitre_table)
        lay.addWidget(sec_mitre)

        sec_epc = _Collapsible("EPC \u2014 Explain / Plan / Checklist")
        self.soc_epc_text = QTextEdit()
        self.soc_epc_text.setReadOnly(True)
        self.soc_epc_text.setMinimumHeight(120)
        sec_epc.body().addWidget(self.soc_epc_text)
        lay.addWidget(sec_epc)

        sec_enrich = _Collapsible("IOC Enrichment")
        self.soc_enrichment_table = _table(
            ["IOC", "Type", "Status", "Score", "Provider Summary"],
        )
        sec_enrich.body().addWidget(self.soc_enrichment_table)
        lay.addWidget(sec_enrich)

        return page

    # ── page: settings ───────────────────────────────────────────────────

    def _build_settings_page(self) -> QWidget:
        page, lay = _scrollpage()

        title = QLabel("Settings")
        title.setProperty("class", "pageTitle")
        sub = QLabel("Configure providers, API keys, and session options.")
        sub.setProperty("class", "pageSubtitle")
        lay.addWidget(title)
        lay.addWidget(sub)

        # -- providers card --
        prov_card, prov = _card("Providers")
        self.provider_checkboxes: dict[str, QCheckBox] = {}
        for provider in PROVIDER_ORDER:
            cb = QCheckBox(f"Enable {provider}")
            cb.setChecked(True)
            self.provider_checkboxes[provider] = cb
            prov.addWidget(cb)
        lay.addWidget(prov_card)

        # -- api keys card --
        api_card, api_lay = _card("API Keys")
        api_form = QFormLayout()
        api_form.setSpacing(10)
        self.api_key_inputs: dict[str, QLineEdit] = {}
        for provider in PROVIDER_ORDER:
            le = QLineEdit()
            le.setEchoMode(QLineEdit.EchoMode.Password)
            le.setPlaceholderText(f"Enter {provider} API key")
            le.setMaximumWidth(400)
            self.api_key_inputs[provider] = le
            api_form.addRow(f"{provider}:", le)
        api_lay.addLayout(api_form)
        lay.addWidget(api_card)

        # -- session options card --
        opt_card, opt_lay = _card("Session Options")
        self.history_toggle = QCheckBox("Enable in-session history")
        self.history_toggle.setChecked(False)
        opt_lay.addWidget(self.history_toggle)
        lay.addWidget(opt_card)

        # -- apply button --
        actions_row, alay = _hrow()
        alay.setSpacing(12)
        apply_btn = _btn("Apply Session Settings")
        apply_btn.setFixedHeight(34)
        apply_btn.clicked.connect(self._apply_settings)
        alay.addWidget(apply_btn)
        alay.addStretch(1)
        lay.addWidget(actions_row)

        self.settings_status_label = QLabel(
            "Settings are applied only when you click 'Apply Session Settings'.",
        )
        self.settings_status_label.setProperty("class", "summary")
        self.settings_status_label.setWordWrap(True)
        lay.addWidget(self.settings_status_label)
        lay.addStretch(1)
        return page

    # ── page: history ────────────────────────────────────────────────────

    def _build_history_page(self) -> QWidget:
        page, lay = _scrollpage()

        title = QLabel("History")
        title.setProperty("class", "pageTitle")
        sub = QLabel("In-session history of scans and analyses.")
        sub.setProperty("class", "pageSubtitle")
        lay.addWidget(title)
        lay.addWidget(sub)

        self.history_list = QListWidget()
        self.history_list.itemClicked.connect(self._show_history_detail)
        lay.addWidget(self.history_list, 1)

        self.history_details = QTextEdit()
        self.history_details.setReadOnly(True)
        self.history_details.setMinimumHeight(150)
        lay.addWidget(self.history_details, 1)

        row, rlay = _hrow()
        clear_btn = _btn("Clear Session History", "danger")
        clear_btn.clicked.connect(self._clear_history)
        rlay.addWidget(clear_btn)
        rlay.addStretch(1)
        lay.addWidget(row)
        return page

    # ── file dialogs ─────────────────────────────────────────────────────

    def _browse_ioc_file(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(
            self,
            "Select IOC file",
            "",
            "IOC Files (*.csv *.txt *.log);;All Files (*.*)",
        )
        if selected:
            self.ioc_file_path = selected
            self.ioc_file_label.setText(Path(selected).name)

    def _clear_ioc_file(self) -> None:
        self.ioc_file_path = None
        self.ioc_file_label.setText("No file selected")

    def _browse_soc_file(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(
            self,
            "Select log file",
            "",
            "Log Files (*.txt *.log *.json);;All Files (*.*)",
        )
        if selected:
            self.soc_file_path = selected
            self.soc_file_label.setText(Path(selected).name)

    def _clear_soc_file(self) -> None:
        self.soc_file_path = None
        self.soc_file_label.setText("No file selected")

    # ── IOC scan ─────────────────────────────────────────────────────────

    def _run_ioc_scan(self) -> None:
        self._set_ioc_loading(True, "Scanning IOCs and querying providers...")
        try:
            iocs = collect_iocs(
                single_ioc=self.ioc_single_input.text(),
                bulk_text=self.ioc_bulk_input.toPlainText(),
                file_path=self.ioc_file_path,
            )
            if not iocs:
                QMessageBox.warning(
                    self, "No IOC Input",
                    "Enter an IOC, paste bulk data, or upload an IOC file.",
                )
                return

            providers = dict(self.settings_state.providers)
            if not self.ioc_use_providers.isChecked():
                providers = {name: False for name in PROVIDER_ORDER}
            manual_type = str(self.ioc_type_combo.currentData())
            manual_override = None if manual_type == "auto" else manual_type

            rows = scan_iocs(
                iocs,
                manual_ioc_type=manual_override,
                providers=providers,
                api_keys=dict(self.settings_state.api_keys),
            )
            self.last_ioc_rows = rows
            self._populate_ioc_table(rows)
            summary = summarize_ioc_rows(rows)
            summary_text = (
                "Total: {total}  |  Malicious: {malicious}  |  Suspicious: {suspicious}  |  "
                "Clean: {clean}  |  Unknown: {unknown}  |  Errors: {error_rows}".format(
                    **summary,
                )
            )
            if summary["error_rows"] > 0:
                all_errors = []
                for r in rows:
                    all_errors.extend(str(e) for e in (r.get("errors") or []))
                if all_errors:
                    summary_text += "\n\u26A0  " + "  |  ".join(all_errors)
            self.ioc_summary_label.setText(summary_text)
            self._append_history(
                "IOC scan", f"Scanned {len(rows)} IOC(s).",
                {"summary": summary, "rows": rows},
            )
            self._update_home_metrics()
        finally:
            self._set_ioc_loading(False)

    def _populate_ioc_table(self, rows: list[dict[str, Any]]) -> None:
        self.ioc_table.setRowCount(0)
        for row in rows:
            idx = self.ioc_table.rowCount()
            self.ioc_table.insertRow(idx)
            self.ioc_table.setItem(idx, 0, QTableWidgetItem(str(row.get("ioc", ""))))
            self.ioc_table.setItem(idx, 1, QTableWidgetItem(str(row.get("detected_type", ""))))
            self.ioc_table.setItem(idx, 2, QTableWidgetItem(str(row.get("effective_type", ""))))
            self.ioc_table.setItem(idx, 3, _status_item(str(row.get("status", "unknown"))))

            score = QTableWidgetItem(str(row.get("score", 0)))
            score.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.ioc_table.setItem(idx, 4, score)

            effective_type = str(row.get("effective_type", "unknown"))
            ioc_value = str(row.get("ioc", ""))
            for col, provider_key in ((5, "virustotal"), (6, "abuseipdb"), (7, "otx"), (8, "threatfox")):
                status_text = str(row.get(provider_key, "n/a"))
                status_item = _status_item(status_text)
                link = self._provider_lookup_url(provider_key, ioc_value, effective_type)
                if link:
                    status_item.setData(Qt.ItemDataRole.UserRole, link)
                    status_item.setToolTip(f"Open in {provider_key}")
                self.ioc_table.setItem(idx, col, status_item)

            prov_summary = str(row.get("provider_summary", ""))
            prov_item = QTableWidgetItem(prov_summary)
            prov_item.setToolTip(prov_summary)
            self.ioc_table.setItem(idx, 9, prov_item)

            error_list = row.get("errors") or []
            error_count = int(row.get("error_count", 0) or 0)
            error_text = "\n".join(str(e) for e in error_list) if error_list else ""
            errors = QTableWidgetItem(str(error_count))
            errors.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if error_text:
                errors.setToolTip(error_text)
                errors.setForeground(QColor(_DANGER))
            self.ioc_table.setItem(idx, 10, errors)

    # ── SOC analysis ─────────────────────────────────────────────────────

    def _run_soc_analysis(self) -> None:
        self._set_soc_loading(True, "Analyzing SOC log and generating response...")
        try:
            selected_log = load_soc_log_inputs(
                self.soc_raw_log_input.toPlainText(), self.soc_file_path,
            )
            if not selected_log:
                QMessageBox.warning(
                    self, "No Log Input",
                    "Paste raw log text or upload a log file.",
                )
                return

            payload = analyze_soc_log(
                selected_log,
                model_path=self.soc_model_path_input.text().strip(),
                enrich_iocs=self.soc_enrich_toggle.isChecked(),
                ioc_providers=dict(self.settings_state.providers),
                ioc_api_keys=dict(self.settings_state.api_keys),
            )
            if not payload.get("ok"):
                message = str(payload.get("error", "SOC analysis failed"))
                QMessageBox.warning(self, "Analysis Failed", message)
                self.soc_summary_label.setText(message)
                return

            self.last_soc_payload = payload
            self._populate_soc_sections(payload)
            summary = payload.get("summary", {})
            self.soc_summary_label.setText(
                "Technique: {technique_id} ({technique_name})  |  "
                "Confidence: {confidence:.3f}  |  "
                "Source: {mapping_source}  |  Entities: {entity_count}".format(
                    technique_id=summary.get("technique_id", "N/A"),
                    technique_name=summary.get("technique_name", "N/A"),
                    confidence=float(summary.get("confidence", 0.0) or 0.0),
                    mapping_source=summary.get("mapping_source", "unknown"),
                    entity_count=int(summary.get("entity_count", 0) or 0),
                ),
            )
            self._append_history("SOC analysis", "Analyzed one log event.", payload)
            self._update_home_metrics()
        finally:
            self._set_soc_loading(False)

    def _populate_soc_sections(self, payload: dict[str, Any]) -> None:
        result = payload.get("result", {})
        entities = result.get("entities", [])
        mappings = result.get("attack_mapping", [])
        epc = result.get("epc", {})
        enrichment = result.get("audit", {}).get("ioc_enrichment", [])

        self.soc_entities_table.setRowCount(0)
        for entity in entities:
            r = self.soc_entities_table.rowCount()
            self.soc_entities_table.insertRow(r)
            self.soc_entities_table.setItem(r, 0, QTableWidgetItem(str(entity.get("type", ""))))
            self.soc_entities_table.setItem(r, 1, QTableWidgetItem(str(entity.get("value", ""))))
            self.soc_entities_table.setItem(r, 2, QTableWidgetItem(str(entity.get("evidence_ref", ""))))
            self.soc_entities_table.setItem(r, 3, QTableWidgetItem(str(entity.get("start", ""))))
            self.soc_entities_table.setItem(r, 4, QTableWidgetItem(str(entity.get("end", ""))))

        self.soc_mitre_table.setRowCount(0)
        for mapping in mappings:
            r = self.soc_mitre_table.rowCount()
            self.soc_mitre_table.insertRow(r)
            self.soc_mitre_table.setItem(r, 0, QTableWidgetItem(str(mapping.get("technique_id", ""))))
            self.soc_mitre_table.setItem(r, 1, QTableWidgetItem(str(mapping.get("technique_name", ""))))
            conf = QTableWidgetItem(str(mapping.get("confidence", "")))
            conf.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.soc_mitre_table.setItem(r, 2, conf)
            self.soc_mitre_table.setItem(r, 3, QTableWidgetItem(str(mapping.get("rationale", ""))))
            evidence = ", ".join(str(item) for item in mapping.get("evidence_refs", []))
            self.soc_mitre_table.setItem(r, 4, QTableWidgetItem(evidence))

        epc_text = (
            f"Explain:\n{epc.get('explain', '')}\n\n"
            f"Plan:\n- "
            + "\n- ".join(str(item) for item in epc.get("plan", []))
            + "\n\n"
            f"Checklist:\n- "
            + "\n- ".join(str(item) for item in epc.get("checklist", []))
            + "\n\n"
            f"Confidence: {epc.get('confidence', '')}"
        )
        self.soc_epc_text.setText(epc_text)

        self.soc_enrichment_table.setRowCount(0)
        for item in enrichment:
            provider_results = item.get("providers", {})
            provider_summary = ", ".join(
                f"{provider}:{(provider_results.get(provider) or {}).get('status', 'n/a')}"
                for provider in PROVIDER_ORDER
            )
            r = self.soc_enrichment_table.rowCount()
            self.soc_enrichment_table.insertRow(r)
            self.soc_enrichment_table.setItem(r, 0, QTableWidgetItem(str(item.get("ioc", ""))))
            self.soc_enrichment_table.setItem(r, 1, QTableWidgetItem(str(item.get("type", ""))))
            self.soc_enrichment_table.setItem(r, 2, _status_item(str(item.get("status", "unknown"))))
            score_item = QTableWidgetItem(str(item.get("score", 0)))
            score_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.soc_enrichment_table.setItem(r, 3, score_item)
            self.soc_enrichment_table.setItem(r, 4, QTableWidgetItem(provider_summary))

    # ── settings ─────────────────────────────────────────────────────────

    def _sync_settings_to_ui(self) -> None:
        for provider in PROVIDER_ORDER:
            if provider in self.provider_checkboxes:
                self.provider_checkboxes[provider].setChecked(
                    bool(self.settings_state.providers.get(provider, True)),
                )
            if provider in self.api_key_inputs:
                self.api_key_inputs[provider].setText(
                    str(self.settings_state.api_keys.get(provider, "")),
                )
        self.history_toggle.setChecked(bool(self.settings_state.history_enabled))
        self._history_nav_btn.setVisible(self.settings_state.history_enabled)

    def _apply_settings(self) -> None:
        providers = {
            name: checkbox.isChecked()
            for name, checkbox in self.provider_checkboxes.items()
        }
        api_keys = {
            name: line_edit.text()
            for name, line_edit in self.api_key_inputs.items()
        }
        self.settings_state.providers = providers
        self.settings_state.api_keys = sanitize_api_keys(api_keys)
        self.settings_state.history_enabled = self.history_toggle.isChecked()

        self._history_nav_btn.setVisible(self.settings_state.history_enabled)
        if not self.settings_state.history_enabled:
            self._navigate_to(self.tab_index_home)

        if save_persisted_settings(self.settings_state):
            self.settings_status_label.setText("Settings saved and applied.")
        else:
            self.settings_status_label.setText("Settings applied, but could not be saved to disk.")
        self._update_home_metrics()

    # ── history ──────────────────────────────────────────────────────────

    def _append_history(
        self, action: str, summary: str, payload: dict[str, Any],
    ) -> None:
        if not self.settings_state.history_enabled:
            return
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "summary": summary,
            "payload": payload,
        }
        self.history_entries.append(entry)
        item_text = f"{entry['timestamp']}  |  {entry['action']}  |  {entry['summary']}"
        item = QListWidgetItem(item_text)
        item.setData(Qt.ItemDataRole.UserRole, entry)
        self.history_list.addItem(item)

    def _show_history_detail(self, item: QListWidgetItem) -> None:
        entry = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(entry, dict):
            return
        self.history_details.setText(json.dumps(entry, indent=2, sort_keys=True))

    def _clear_history(self) -> None:
        self.history_entries.clear()
        self.history_list.clear()
        self.history_details.clear()
        self._update_home_metrics()

    # ── exports ──────────────────────────────────────────────────────────

    def _export_ioc_json(self) -> None:
        if not self.last_ioc_rows:
            QMessageBox.information(
                self, "No IOC Results", "Run an IOC scan before exporting.",
            )
            return
        selected, _ = QFileDialog.getSaveFileName(
            self, "Export IOC JSON", "", "JSON Files (*.json)",
        )
        if not selected:
            return
        payload = [
            {"row": {k: v for k, v in row.items() if k != "raw"}, "raw": row.get("raw")}
            for row in self.last_ioc_rows
        ]
        export_json(selected, payload)
        QMessageBox.information(
            self, "Export Complete", f"IOC results exported to:\n{selected}",
        )

    def _export_ioc_csv(self) -> None:
        if not self.last_ioc_rows:
            QMessageBox.information(
                self, "No IOC Results", "Run an IOC scan before exporting.",
            )
            return
        selected, _ = QFileDialog.getSaveFileName(
            self, "Export IOC CSV", "", "CSV Files (*.csv)",
        )
        if not selected:
            return
        export_ioc_csv(selected, self.last_ioc_rows)
        QMessageBox.information(
            self, "Export Complete", f"IOC results exported to:\n{selected}",
        )

    def _export_soc_json(self) -> None:
        if not self.last_soc_payload:
            QMessageBox.information(
                self, "No SOC Result", "Run SOC analysis before exporting.",
            )
            return
        selected, _ = QFileDialog.getSaveFileName(
            self, "Export SOC JSON", "", "JSON Files (*.json)",
        )
        if not selected:
            return
        export_json(selected, self.last_soc_payload)
        QMessageBox.information(
            self, "Export Complete", f"SOC result exported to:\n{selected}",
        )

    def _export_soc_csv(self) -> None:
        if not self.last_soc_payload:
            QMessageBox.information(
                self, "No SOC Result", "Run SOC analysis before exporting.",
            )
            return
        selected, _ = QFileDialog.getSaveFileName(
            self, "Export SOC CSV", "", "CSV Files (*.csv)",
        )
        if not selected:
            return
        export_soc_csv(selected, self.last_soc_payload)
        QMessageBox.information(
            self, "Export Complete", f"SOC result exported to:\n{selected}",
        )

    # ── home metrics ─────────────────────────────────────────────────────

    def _update_home_metrics(self) -> None:
        self.home_history_metric.setText(str(len(self.history_entries)))
        self.home_ioc_metric.setText(str(len(self.last_ioc_rows)))
        self.home_soc_metric.setText("Yes" if self.last_soc_payload else "No")


def main() -> int:
    app = QApplication([])
    window = DesktopSecurityApp()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
