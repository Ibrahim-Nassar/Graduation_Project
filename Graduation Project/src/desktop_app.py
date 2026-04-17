from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote_plus

from PySide6.QtCore import QObject, QThread, Qt, QUrl, Signal, Slot
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
    QProgressBar,
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
    assess_severity,
    collect_iocs,
    correlation_store,
    export_ioc_csv,
    export_json,
    export_soc_csv,
    generate_analyst_brief,
    generate_investigation_summary,
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


_SEVERITY_COLORS = {
    "critical": _DANGER,
    "high": _WARNING,
    "medium": _PRIMARY,
    "low": _ACCENT,
    "info": _TEXT2,
}


def _severity_label(severity: str) -> tuple[str, str]:
    s = severity.lower().strip()
    color = _SEVERITY_COLORS.get(s, _TEXT2)
    return s.upper(), color


# ── helpers ──────────────────────────────────────────────────────────────────

def _status_tone(value: str) -> tuple[str, str]:
    low = value.lower().strip()
    if low in {"malicious"}:
        return "MALICIOUS", _DANGER
    if low in {"suspicious"}:
        return "SUSPICIOUS", _WARNING
    if low in {"clean"}:
        return "CLEAN", _ACCENT
    if low in {"auth_error"}:
        return "BAD API KEY", "#F97316"
    if low in {"not_found", "not_supported", "unknown", "n/a"}:
        label = low.replace("_", " ").upper()
        return label, _TEXT2
    if low in {"error", "invalid"}:
        return low.upper(), "#B91C1C"
    return low.upper() if low else "UNKNOWN", _TEXT2


def _status_item(value: str, *, badge: bool = True) -> QTableWidgetItem:
    label, color = _status_tone(value)
    text = f" {label} " if badge else label
    item = QTableWidgetItem(text)
    if badge:
        item.setBackground(QColor(color))
        item.setForeground(QColor("#FFFFFF"))
        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    else:
        item.setForeground(QColor(color))
    item.setToolTip(f"Status: {label.title()}")
    item.setData(Qt.ItemDataRole.UserRole + 1, value)
    return item


def _score_item(score_value: Any) -> QTableWidgetItem:
    score = int(score_value or 0)
    item = QTableWidgetItem(f"{score:>3d}")
    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    if score >= 75:
        color = _DANGER
    elif score >= 35:
        color = _WARNING
    elif score <= 5:
        color = _ACCENT
    else:
        color = _PRIMARY
    item.setBackground(QColor(color))
    item.setForeground(QColor("#FFFFFF"))
    item.setToolTip(f"Risk score: {score}")
    return item


def _format_provider_summary(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "No provider summary available."
    return text.replace(",", " |")


def _verdict_tone(verdict: str) -> tuple[str, str]:
    low = verdict.lower().strip()
    if low == "malicious":
        return "MALICIOUS", _DANGER
    if low == "suspicious":
        return "SUSPICIOUS", _WARNING
    if low == "clean":
        return "CLEAN", _ACCENT
    return "UNKNOWN", _TEXT2


def _format_ioc_detail_text(row: dict[str, Any]) -> str:
    status = str(row.get("status", "unknown"))
    verdict = str(row.get("verdict", "Unknown"))
    verdict_confidence = int(row.get("verdict_confidence", 0) or 0)
    verdict_reasoning = str(row.get("verdict_reasoning", ""))
    providers = []
    for provider in PROVIDER_ORDER:
        providers.append(f"- {provider}: {row.get(provider, 'n/a')}")
    provider_summary = str(row.get("provider_summary", "")).strip() or "N/A"
    errors = row.get("errors") or []
    raw_section = row.get("raw")
    raw_text = json.dumps(raw_section, indent=2, sort_keys=True) if raw_section else "N/A"
    return (
        f"IOC: {row.get('ioc', '')}\n"
        f"\n=== VERDICT ===\n"
        f"Verdict: {verdict}\n"
        f"Confidence: {verdict_confidence}%\n"
        f"Reasoning: {verdict_reasoning}\n"
        f"===============\n\n"
        f"Detected Type: {row.get('detected_type', 'unknown')}\n"
        f"Effective Type: {row.get('effective_type', 'unknown')}\n"
        f"Aggregate Status: {status}\n"
        f"Score: {row.get('score', 0)}\n\n"
        "Provider Statuses:\n"
        f"{chr(10).join(providers)}\n\n"
        f"Provider Summary:\n{provider_summary}\n\n"
        "Errors:\n"
        f"{chr(10).join(f'- {err}' for err in errors) if errors else '- None'}\n\n"
        f"Raw Details:\n{raw_text}"
    )


def _soc_enrichment_label(enrich_used: bool, enrichment_count: int) -> str:
    if not enrich_used:
        return "IOC Enrichment: Not requested"
    if enrichment_count > 0:
        return f"IOC Enrichment: Used ({enrichment_count} IOCs)"
    return "IOC Enrichment: Enabled, but no IOC enrichment data was produced"


def _soc_summary_and_banner(payload: dict[str, Any], enrich_used: bool) -> tuple[str, str, str]:
    summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    technique_id = str(summary.get("technique_id", "N/A"))
    technique_name = str(summary.get("technique_name", "N/A"))
    mapping_source = str(summary.get("mapping_source", "unknown"))
    entity_count = int(summary.get("entity_count", 0) or 0)
    confidence_value = float(summary.get("confidence", 0.0) or 0.0)
    enrichment = payload.get("result", {}).get("audit", {}).get("ioc_enrichment", [])
    enrichment_count = len(enrichment) if isinstance(enrichment, list) else 0
    enrichment_label = _soc_enrichment_label(enrich_used, enrichment_count)

    if technique_id == "N/A":
        summary_text = (
            f"No ATT&CK mapping was produced. {enrichment_label}. "
            f"Mapping source: {mapping_source}. Extracted entities: {entity_count}."
        )
        banner_text = "SOC analysis completed without an ATT&CK mapping."
        return summary_text, banner_text, "info"

    if confidence_value < 0.6:
        summary_text = (
            f"Mapped {technique_id} ({technique_name}) with low confidence ({confidence_value:.0%}). "
            f"Review rationale and evidence before response actions. Source: {mapping_source}. "
            f"Extracted entities: {entity_count}. {enrichment_label}."
        )
        banner_text = f"SOC analysis complete: {technique_id} mapped with low confidence."
        return summary_text, banner_text, "info"

    summary_text = (
        f"Mapped {technique_id} ({technique_name}) at {confidence_value:.0%} confidence. "
        f"Source: {mapping_source}. Extracted entities: {entity_count}. {enrichment_label}."
    )
    banner_text = f"SOC analysis complete: {technique_id} mapped at {confidence_value:.0%} confidence."
    return summary_text, banner_text, "success"


def _card(title: str = "") -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setProperty("class", "card")
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(14, 12, 14, 12)
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
    header.setStretchLastSection(True)
    header.setMinimumSectionSize(70)
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
    lay.setContentsMargins(28, 20, 28, 20)
    lay.setSpacing(12)
    sa.setWidget(inner)
    sa.viewport().setAutoFillBackground(False)
    return sa, lay


def _btn(text: str, cls: str = "primary") -> QPushButton:
    b = QPushButton(text)
    b.setProperty("class", cls)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


class _BackgroundTaskWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(
        self,
        task: Callable[..., Any],
        *,
        task_kwargs: dict[str, Any],
    ) -> None:
        super().__init__()
        self._task = task
        self._task_kwargs = task_kwargs

    @Slot()
    def run(self) -> None:
        try:
            result = self._task(progress=self.progress.emit, **self._task_kwargs)
        except Exception as exc:
            self.failed.emit(str(exc))
            return
        self.finished.emit(result)


def _scan_iocs_background(
    *,
    iocs: list[str],
    manual_ioc_type: str | None,
    providers: dict[str, bool],
    api_keys: dict[str, str],
    progress: Callable[[str], None],
) -> list[dict[str, Any]]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    total = len(iocs)

    def _scan_one(ioc: str) -> list[dict[str, Any]]:
        return scan_iocs(
            [ioc], manual_ioc_type=manual_ioc_type,
            providers=providers, api_keys=api_keys,
        )

    if total <= 1:
        progress(f"Scanning IOC 1 of {total}...")
        return scan_iocs(iocs, manual_ioc_type=manual_ioc_type,
                         providers=providers, api_keys=api_keys)

    max_workers = min(4, total)
    ordered: dict[int, list[dict[str, Any]]] = {}
    done = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_one, ioc): idx for idx, ioc in enumerate(iocs)}
        for future in as_completed(futures):
            idx = futures[future]
            done += 1
            progress(f"Scanned {done} of {total} IOCs...")
            try:
                ordered[idx] = future.result()
            except Exception:
                ordered[idx] = [{
                    "ioc": iocs[idx], "detected_type": "unknown",
                    "effective_type": "unknown", "status": "error", "score": 0,
                    "verdict": "Unknown", "verdict_confidence": 0, "verdict_reasoning": "",
                    "virustotal": "error", "abuseipdb": "error",
                    "otx": "error", "threatfox": "error",
                    "provider_summary": "scan failed", "error_count": 1,
                    "errors": ["IOC scan failed"], "raw": {},
                }]
    rows: list[dict[str, Any]] = []
    for idx in range(total):
        rows.extend(ordered.get(idx, []))
    return rows


def _analyze_soc_background(
    *,
    selected_log: str,
    enrich_iocs: bool,
    ioc_providers: dict[str, bool],
    ioc_api_keys: dict[str, str],
    progress: Callable[[str], None],
) -> dict[str, Any]:
    progress("Analyzing log with enrichment..." if enrich_iocs else "Analyzing log...")
    return analyze_soc_log(
        selected_log,
        enrich_iocs=enrich_iocs,
        ioc_providers=ioc_providers,
        ioc_api_keys=ioc_api_keys,
    )


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
        self._body_lay.setContentsMargins(14, 4, 14, 12)
        self._body_lay.setSpacing(6)
        self._body.setVisible(expanded)
        outer.addWidget(self._body)

    def _label_text(self) -> str:
        arrow = "\u25BE" if self._expanded else "\u25B8"
        return f"  {arrow}   {self._title}"

    def _toggle(self) -> None:
        self._expanded = not self._expanded
        self._body.setVisible(self._expanded)
        self._header.setText(self._label_text())

    def set_expanded(self, expanded: bool) -> None:
        self._expanded = expanded
        self._body.setVisible(expanded)
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
    font-size: 16px;
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
    border-radius: 8px;
}}
QLabel[class="cardTitle"] {{
    font-size: 10px;
    font-weight: 700;
    color: {_TEXT2};
    letter-spacing: 0.5px;
}}

/* ── collapse toggle ── */
QPushButton[class="collapseBtn"] {{
    text-align: left;
    padding: 10px 14px;
    background: transparent;
    color: {_TEXT};
    font-size: 12.5px;
    font-weight: 600;
    border: none;
    border-radius: 0;
}}
QPushButton[class="collapseBtn"]:hover {{
    background: rgba(255, 255, 255, 0.03);
}}

/* ── headings ── */
QLabel[class="pageTitle"] {{
    font-size: 22px;
    font-weight: 700;
    color: {_TEXT};
}}
QLabel[class="pageSubtitle"] {{
    font-size: 12px;
    color: {_TEXT2};
    padding-bottom: 4px;
}}

/* ── metric cards ── */
QFrame[class="metricCard"] {{
    background: {_CARD};
    border: 1px solid {_BORDER};
    border-radius: 8px;
}}
QLabel[class="metricValue"] {{
    font-size: 30px;
    font-weight: 700;
}}
QLabel[class="metricLabel"] {{
    font-size: 10px;
    font-weight: 600;
    color: {_TEXT2};
    letter-spacing: 0.4px;
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
    padding: 5px 10px;
    font-size: 12.5px;
    min-height: 14px;
    max-height: 28px;
}}
QLineEdit:focus {{
    border-color: {_PRIMARY};
}}
QTextEdit {{
    background: {_SURFACE};
    color: {_TEXT};
    border: 1px solid {_BORDER};
    border-radius: 5px;
    padding: 5px 10px;
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
    padding: 5px 10px;
    font-size: 12.5px;
    min-height: 14px;
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
    border-radius: 6px;
    gridline-color: transparent;
    font-size: 11.5px;
    color: {_TEXT};
}}
QTableWidget::item {{
    padding: 5px 8px;
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
    padding: 7px 8px;
    text-transform: uppercase;
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
QLabel[class="inlineStatus"] {{
    font-size: 11px;
    color: {_TEXT2};
    padding: 2px 0;
}}
QLabel[class="statusBanner"] {{
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 11.5px;
    font-weight: 600;
}}
QLabel[class="statusInfo"] {{
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 11.5px;
    font-weight: 600;
    background: rgba(59, 130, 246, 0.10);
    color: {_PRIMARY};
}}
QLabel[class="statusSuccess"] {{
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 11.5px;
    font-weight: 600;
    background: rgba(34, 197, 94, 0.10);
    color: {_ACCENT};
}}
QLabel[class="statusDanger"] {{
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 11.5px;
    font-weight: 600;
    background: rgba(239, 68, 68, 0.12);
    color: {_DANGER};
}}
QTextEdit[class="detailBox"] {{
    font-size: 11.5px;
    line-height: 1.4;
}}
QLabel[class="analystBrief"] {{
    font-size: 12.5px;
    font-weight: 500;
    color: {_TEXT};
    line-height: 1.5;
    padding: 6px 4px;
}}
QProgressBar {{
    border: 1px solid {_BORDER};
    border-radius: 5px;
    text-align: center;
    height: 14px;
    background: {_SURFACE};
    color: {_TEXT2};
}}
QProgressBar::chunk {{
    background-color: {_PRIMARY};
    border-radius: 4px;
}}

/* ── severity badges ── */
QLabel[class="severityCritical"] {{
    background: rgba(239, 68, 68, 0.15);
    color: {_DANGER};
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 4px;
    padding: 4px 14px;
    font-weight: 700;
    font-size: 13px;
}}
QLabel[class="severityHigh"] {{
    background: rgba(245, 158, 11, 0.15);
    color: {_WARNING};
    border: 1px solid rgba(245, 158, 11, 0.3);
    border-radius: 4px;
    padding: 4px 14px;
    font-weight: 700;
    font-size: 13px;
}}
QLabel[class="severityMedium"] {{
    background: rgba(59, 130, 246, 0.15);
    color: {_PRIMARY};
    border: 1px solid rgba(59, 130, 246, 0.3);
    border-radius: 4px;
    padding: 4px 14px;
    font-weight: 700;
    font-size: 13px;
}}
QLabel[class="severityLow"] {{
    background: rgba(34, 197, 94, 0.15);
    color: {_ACCENT};
    border: 1px solid rgba(34, 197, 94, 0.3);
    border-radius: 4px;
    padding: 4px 14px;
    font-weight: 700;
    font-size: 13px;
}}
QLabel[class="severityInfo"] {{
    background: rgba(156, 163, 175, 0.15);
    color: {_TEXT2};
    border: 1px solid rgba(156, 163, 175, 0.3);
    border-radius: 4px;
    padding: 4px 14px;
    font-weight: 700;
    font-size: 13px;
}}

/* ── verdict badges ── */
QLabel[class="verdictMalicious"] {{
    background: rgba(239, 68, 68, 0.18);
    color: {_DANGER};
    border: 1px solid rgba(239, 68, 68, 0.35);
    border-radius: 4px;
    padding: 3px 12px;
    font-weight: 700;
    font-size: 12px;
}}
QLabel[class="verdictSuspicious"] {{
    background: rgba(245, 158, 11, 0.18);
    color: {_WARNING};
    border: 1px solid rgba(245, 158, 11, 0.35);
    border-radius: 4px;
    padding: 3px 12px;
    font-weight: 700;
    font-size: 12px;
}}
QLabel[class="verdictClean"] {{
    background: rgba(34, 197, 94, 0.18);
    color: {_ACCENT};
    border: 1px solid rgba(34, 197, 94, 0.35);
    border-radius: 4px;
    padding: 3px 12px;
    font-weight: 700;
    font-size: 12px;
}}
QLabel[class="verdictUnknown"] {{
    background: rgba(156, 163, 175, 0.15);
    color: {_TEXT2};
    border: 1px solid rgba(156, 163, 175, 0.3);
    border-radius: 4px;
    padding: 3px 12px;
    font-weight: 700;
    font-size: 12px;
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
        self._soc_analysis_count: int = 0
        self.ioc_file_path: str | None = None
        self.soc_file_path: str | None = None
        self._ioc_thread: QThread | None = None
        self._ioc_worker: _BackgroundTaskWorker | None = None
        self._soc_thread: QThread | None = None
        self._soc_worker: _BackgroundTaskWorker | None = None

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
        brand.setFixedHeight(48)
        brand.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        col.addWidget(brand)

        rule = QFrame()
        rule.setObjectName("sidebarRule")
        rule.setFixedHeight(1)
        col.addWidget(rule)
        col.addSpacing(8)

        self._nav_buttons: list[QPushButton] = []
        nav_items = [
            ("\u229E  Dashboard", self.tab_index_home),
            ("\u25CE  IOC Scanner", self.tab_index_ioc),
            ("\u25C6  SOC Analysis", self.tab_index_soc),
            ("\u2699  Settings", self.tab_index_settings),
        ]
        for label, idx in nav_items:
            btn = QPushButton(f"   {label}")
            btn.setProperty("class", "nav")
            btn.setCheckable(True)
            btn.setFixedHeight(38)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _ch, i=idx: self._navigate_to(i))
            col.addWidget(btn)
            self._nav_buttons.append(btn)

        self._history_nav_btn = QPushButton("   \u25D4  History")
        self._history_nav_btn.setProperty("class", "nav")
        self._history_nav_btn.setCheckable(True)
        self._history_nav_btn.setFixedHeight(38)
        self._history_nav_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._history_nav_btn.setVisible(False)
        self._history_nav_btn.clicked.connect(
            lambda: self._navigate_to(self.tab_index_history),
        )
        col.addWidget(self._history_nav_btn)
        self._nav_buttons.append(self._history_nav_btn)

        col.addStretch(1)

        footer = QLabel("v3.1.0")
        footer.setObjectName("sidebarFooter")
        col.addWidget(footer)
        return sidebar

    # ── navigation ───────────────────────────────────────────────────────

    def _navigate_to(self, index: int) -> None:
        self._stack.setCurrentIndex(index)
        for i, btn in enumerate(self._nav_buttons):
            btn.setChecked(i == index)

    def _set_banner(self, label: QLabel, message: str, tone: str = "info") -> None:
        label.setText(message)
        label.setProperty("class", f"status{tone.capitalize()}")
        label.style().unpolish(label)
        label.style().polish(label)

    def _set_ioc_loading(self, loading: bool, message: str = "") -> None:
        controls = [
            self.ioc_scan_btn,
            self.ioc_export_json_btn,
            self.ioc_export_csv_btn,
            self.ioc_single_input,
            self.ioc_bulk_input,
            self.ioc_type_combo,
            self.ioc_use_providers,
            self.ioc_browse_btn,
            self.ioc_clear_file_btn,
        ]
        for control in controls:
            control.setEnabled(not loading)
        if loading:
            self.ioc_summary_label.setText(message or "Scanning IOCs...")
            self.ioc_progress.setVisible(True)
            self.ioc_progress.setRange(0, 0)
            self._set_banner(self.ioc_run_status, message or "Scanning IOCs...", "info")
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            QApplication.processEvents()
        else:
            self.ioc_progress.setVisible(False)
            self.ioc_progress.setRange(0, 1)
            if QApplication.overrideCursor() is not None:
                QApplication.restoreOverrideCursor()

    def _set_soc_loading(self, loading: bool, message: str = "") -> None:
        controls = [
            self.soc_analyze_btn,
            self.soc_export_json_btn,
            self.soc_export_csv_btn,
            self.soc_raw_log_input,
            self.soc_enrich_toggle,
            self.soc_browse_btn,
            self.soc_clear_file_btn,
        ]
        for control in controls:
            control.setEnabled(not loading)
        if loading:
            self.soc_summary_label.setText(message or "Running SOC analysis...")
            self.soc_progress.setVisible(True)
            self.soc_progress.setRange(0, 0)
            self._set_banner(self.soc_run_status, message or "Running SOC analysis...", "info")
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            QApplication.processEvents()
        else:
            self.soc_progress.setVisible(False)
            self.soc_progress.setRange(0, 1)
            if QApplication.overrideCursor() is not None:
                QApplication.restoreOverrideCursor()

    def _on_ioc_progress(self, message: str) -> None:
        self.ioc_summary_label.setText(message)
        self._set_banner(self.ioc_run_status, message, "info")

    def _on_soc_progress(self, message: str) -> None:
        self.soc_summary_label.setText(message)
        self._set_banner(self.soc_run_status, message, "info")

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
        provider_by_column = {7: "virustotal", 8: "abuseipdb", 9: "otx", 10: "threatfox"}
        provider = provider_by_column.get(column)
        if provider is None:
            return
        item = self.ioc_table.item(row, column)
        if item is None:
            return
        url = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(url, str) and url:
            QDesktopServices.openUrl(QUrl(url))

    # ── page: home / dashboard ───────────────────────────────────────────

    def _build_home_page(self) -> QWidget:
        page, lay = _scrollpage()

        title = QLabel("SOC Security Workstation")
        title.setProperty("class", "pageTitle")
        sub = QLabel(
            "Unified desktop tool for IOC scanning, SOC log analysis, ATT&CK mapping, and correlation insights.",
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
            ml.setContentsMargins(16, 12, 16, 12)
            ml.setSpacing(2)
            bar = QFrame()
            bar.setFixedHeight(3)
            bar.setStyleSheet(f"background: {color}; border: none; border-radius: 1px;")
            ml.addWidget(bar)
            value_lbl.setProperty("class", "metricValue")
            value_lbl.setStyleSheet(f"color: {color};")
            ml.addWidget(value_lbl)
            lbl = QLabel(label_text)
            lbl.setProperty("class", "metricLabel")
            ml.addWidget(lbl)
            return f

        self.home_ioc_metric = QLabel("0")
        self.home_malicious_metric = QLabel("0")
        self.home_soc_metric = QLabel("0")
        self.home_severity_metric = QLabel("\u2014")
        self.home_history_metric = QLabel("0")

        mlay.addWidget(_metric(self.home_ioc_metric, "IOCS SCANNED", _PRIMARY))
        mlay.addWidget(_metric(self.home_malicious_metric, "MALICIOUS / SUSPICIOUS", _DANGER))
        mlay.addWidget(_metric(self.home_soc_metric, "SOC ANALYSES", _ACCENT))
        mlay.addWidget(_metric(self.home_severity_metric, "HIGHEST SEVERITY", _WARNING))
        mlay.addStretch(1)
        lay.addWidget(metrics_row)
        lay.addSpacing(4)

        actions_card, alay = _card("Quick Actions")
        row, rlay = _hrow()
        rlay.setSpacing(12)
        ioc_btn = _btn("Scan IOCs")
        ioc_btn.setFixedHeight(36)
        ioc_btn.clicked.connect(lambda: self._navigate_to(self.tab_index_ioc))
        soc_btn = _btn("Analyze Logs")
        soc_btn.setFixedHeight(36)
        soc_btn.clicked.connect(lambda: self._navigate_to(self.tab_index_soc))
        settings_btn = _btn("Settings", "secondary")
        settings_btn.setFixedHeight(36)
        settings_btn.clicked.connect(lambda: self._navigate_to(self.tab_index_settings))
        rlay.addWidget(ioc_btn)
        rlay.addWidget(soc_btn)
        rlay.addWidget(settings_btn)
        rlay.addStretch(1)
        alay.addWidget(row)
        lay.addWidget(actions_card)
        lay.addSpacing(4)

        activity_card, activity_lay = _card("Session Activity")
        self.home_recent_activity = QLabel("No activity yet. Run an IOC scan or SOC analysis to get started.")
        self.home_recent_activity.setProperty("class", "summary")
        self.home_recent_activity.setWordWrap(True)
        activity_lay.addWidget(self.home_recent_activity)
        lay.addWidget(activity_card)

        summary_row, srow_lay = _hrow()
        srow_lay.setSpacing(12)

        ioc_summary_card, ioc_summary_lay = _card("Last IOC Scan")
        self.home_ioc_summary = QLabel("No IOC scan results yet.")
        self.home_ioc_summary.setWordWrap(True)
        self.home_ioc_summary.setProperty("class", "summary")
        ioc_summary_lay.addWidget(self.home_ioc_summary)
        self.home_ioc_findings = QVBoxLayout()
        self.home_ioc_findings.setSpacing(3)
        ioc_summary_lay.addLayout(self.home_ioc_findings)

        soc_summary_card, soc_summary_lay = _card("Last SOC Analysis")
        self.home_soc_summary = QLabel("No SOC analysis results yet.")
        self.home_soc_summary.setWordWrap(True)
        self.home_soc_summary.setProperty("class", "summary")
        soc_summary_lay.addWidget(self.home_soc_summary)

        srow_lay.addWidget(ioc_summary_card, 1)
        srow_lay.addWidget(soc_summary_card, 1)
        lay.addWidget(summary_row)

        technique_card, tech_lay = _card("Observed ATT&CK Techniques")
        self.home_techniques_label = QLabel("No techniques observed yet.")
        self.home_techniques_label.setProperty("class", "summary")
        self.home_techniques_label.setWordWrap(True)
        tech_lay.addWidget(self.home_techniques_label)
        self.home_techniques_list = QVBoxLayout()
        self.home_techniques_list.setSpacing(3)
        tech_lay.addLayout(self.home_techniques_list)
        lay.addWidget(technique_card)

        lay.addStretch(1)
        return page

    # ── page: IOC scanner ────────────────────────────────────────────────

    def _build_ioc_page(self) -> QWidget:
        page, lay = _scrollpage()

        title = QLabel("IOC Scanner")
        title.setProperty("class", "pageTitle")
        sub = QLabel(
            "Scan Indicators of Compromise against multiple threat-intelligence providers and get unified verdicts.",
        )
        sub.setProperty("class", "pageSubtitle")
        sub.setWordWrap(True)
        lay.addWidget(title)
        lay.addWidget(sub)

        inp_card, inp = _card("Input")
        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self.ioc_single_input = QLineEdit()
        self.ioc_single_input.setPlaceholderText("e.g. 8.8.8.8, evil.com, or a file hash")
        self.ioc_single_input.setMaximumWidth(520)
        form.addRow("Single IOC:", self.ioc_single_input)

        self.ioc_bulk_input = QTextEdit()
        self.ioc_bulk_input.setPlaceholderText(
            "Paste one IOC per line, or comma-separated values.",
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
        self.ioc_browse_btn = browse
        self.ioc_clear_file_btn = clear
        flay.addWidget(self.ioc_file_label, 1)
        flay.addWidget(browse)
        flay.addWidget(clear)
        form.addRow("File import:", file_row)

        inp.addLayout(form)
        lay.addWidget(inp_card)

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

        self.ioc_run_status = QLabel("Ready to scan.")
        self._set_banner(self.ioc_run_status, "Ready to scan.", "info")
        self.ioc_progress = QProgressBar()
        self.ioc_progress.setVisible(False)
        self.ioc_progress.setTextVisible(False)
        lay.addWidget(self.ioc_run_status)
        lay.addWidget(self.ioc_progress)

        res_card, res = _card("Results")
        self.ioc_summary_label = QLabel("Submit IOCs above to start scanning.")
        self.ioc_summary_label.setProperty("class", "summary")
        self.ioc_summary_label.setWordWrap(True)
        res.addWidget(self.ioc_summary_label)

        self.ioc_table = _table([
            "IOC", "Verdict", "Confidence", "Detected Type", "Effective Type",
            "Status", "Score",
            "VirusTotal", "AbuseIPDB", "OTX", "ThreatFox",
            "Provider Summary", "Errors",
        ])
        for col, width in (
            (0, 190),
            (1, 100),
            (2, 80),
            (3, 100),
            (4, 100),
            (5, 90),
            (6, 55),
            (7, 90),
            (8, 90),
            (9, 75),
            (10, 85),
            (11, 200),
            (12, 55),
        ):
            self.ioc_table.setColumnWidth(col, width)
        self.ioc_table.cellClicked.connect(self._on_ioc_table_cell_clicked)
        self.ioc_table.itemSelectionChanged.connect(self._update_ioc_detail_panel)
        res.addWidget(self.ioc_table)

        self.ioc_detail_label = QLabel("Row Details")
        self.ioc_detail_label.setProperty("class", "cardTitle")
        self.ioc_detail_text = QTextEdit()
        self.ioc_detail_text.setReadOnly(True)
        self.ioc_detail_text.setProperty("class", "detailBox")
        self.ioc_detail_text.setMinimumHeight(180)
        self.ioc_detail_text.setText("Select a result row to view full details.")
        res.addWidget(self.ioc_detail_label)
        res.addWidget(self.ioc_detail_text)
        lay.addWidget(res_card, 1)
        return page

    # ── page: SOC analysis ───────────────────────────────────────────────

    def _build_soc_page(self) -> QWidget:
        page, lay = _scrollpage()

        title = QLabel("SOC Analysis")
        title.setProperty("class", "pageTitle")
        sub = QLabel(
            "Analyze raw security logs to extract entities, map ATT&CK techniques, and generate response guidance.",
        )
        sub.setProperty("class", "pageSubtitle")
        sub.setWordWrap(True)
        lay.addWidget(title)
        lay.addWidget(sub)

        inp_card, inp = _card("Input")
        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self.soc_raw_log_input = QTextEdit()
        self.soc_raw_log_input.setPlaceholderText(
            "Paste raw log content here (JSON, syslog, or plain text).",
        )
        self.soc_raw_log_input.setFixedHeight(82)
        form.addRow("Raw log:", self.soc_raw_log_input)

        file_row, flay = _hrow()
        self.soc_file_label = QLabel("No file selected")
        self.soc_file_label.setProperty("class", "fileLabel")
        browse = _btn("Upload File", "secondary")
        browse.clicked.connect(self._browse_soc_file)
        clear = _btn("Clear", "ghost")
        clear.clicked.connect(self._clear_soc_file)
        self.soc_browse_btn = browse
        self.soc_clear_file_btn = clear
        flay.addWidget(self.soc_file_label, 1)
        flay.addWidget(browse)
        flay.addWidget(clear)
        form.addRow("Log file:", file_row)

        inp.addLayout(form)
        lay.addWidget(inp_card)

        opt_card, opt = _card("Options")
        opt_form = QFormLayout()
        opt_form.setSpacing(10)

        self.soc_enrich_toggle = QCheckBox("Enable IOC enrichment in SOC analysis")
        self.soc_enrich_toggle.setChecked(False)
        opt_form.addRow("", self.soc_enrich_toggle)

        opt.addLayout(opt_form)
        lay.addWidget(opt_card)

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

        self.soc_run_status = QLabel("Ready to analyze.")
        self._set_banner(self.soc_run_status, "Ready to analyze.", "info")
        self.soc_progress = QProgressBar()
        self.soc_progress.setVisible(False)
        self.soc_progress.setTextVisible(False)
        lay.addWidget(self.soc_run_status)
        lay.addWidget(self.soc_progress)

        sev_row, sev_lay = _hrow()
        sev_lay.setSpacing(10)
        self.soc_severity_label = QLabel("")
        self.soc_severity_label.setFixedWidth(0)
        self.soc_severity_label.setVisible(False)
        sev_lay.addWidget(self.soc_severity_label)
        self.soc_summary_label = QLabel("Submit a log above to start analysis.")
        self.soc_summary_label.setProperty("class", "summary")
        self.soc_summary_label.setWordWrap(True)
        sev_lay.addWidget(self.soc_summary_label, 1)
        lay.addWidget(sev_row)

        brief_card, brief_lay = _card("What Happened \u2014 Analyst Brief")
        self.soc_analyst_brief_label = QLabel(
            "Run an analysis to generate the analyst brief."
        )
        self.soc_analyst_brief_label.setProperty("class", "analystBrief")
        self.soc_analyst_brief_label.setWordWrap(True)
        brief_lay.addWidget(self.soc_analyst_brief_label)
        lay.addWidget(brief_card)

        soc_top_card, soc_top_lay = _card("Analysis Summary")
        self.soc_top_technique = QLabel("Technique: N/A")
        self.soc_top_confidence = QLabel("Confidence: N/A")
        self.soc_top_source = QLabel("Mapping Source: N/A")
        self.soc_top_enrichment = QLabel("IOC Enrichment: Not used")
        for label in (
            self.soc_top_technique,
            self.soc_top_confidence,
            self.soc_top_source,
            self.soc_top_enrichment,
        ):
            label.setProperty("class", "summary")
            soc_top_lay.addWidget(label)
        lay.addWidget(soc_top_card)

        sec_entities = _Collapsible("Extracted Entities", expanded=False)
        self.soc_section_entities = sec_entities
        self.soc_entities_table = _table(
            ["Type", "Value", "Evidence", "Start", "End"],
        )
        sec_entities.body().addWidget(self.soc_entities_table)
        lay.addWidget(sec_entities)

        sec_mitre = _Collapsible("MITRE ATT&CK Mapping")
        self.soc_section_mitre = sec_mitre
        self.soc_mitre_table = _table([
            "Technique ID", "Technique Name", "Confidence", "Rationale", "Evidence",
        ])
        sec_mitre.body().addWidget(self.soc_mitre_table)
        lay.addWidget(sec_mitre)

        sec_epc = _Collapsible("EPC \u2014 Explain / Plan / Checklist")
        self.soc_section_epc = sec_epc
        self.soc_epc_text = QTextEdit()
        self.soc_epc_text.setReadOnly(True)
        self.soc_epc_text.setMinimumHeight(120)
        sec_epc.body().addWidget(self.soc_epc_text)
        lay.addWidget(sec_epc)

        sec_enrich = _Collapsible("IOC Enrichment")
        self.soc_section_enrichment = sec_enrich
        self.soc_enrichment_table = _table(
            ["IOC", "Type", "Status", "Score", "Provider Summary"],
        )
        sec_enrich.body().addWidget(self.soc_enrichment_table)
        lay.addWidget(sec_enrich)

        sec_summary = _Collapsible("Investigation Summary")
        self.soc_section_investigation = sec_summary
        self.soc_investigation_text = QTextEdit()
        self.soc_investigation_text.setReadOnly(True)
        self.soc_investigation_text.setMinimumHeight(100)
        self.soc_investigation_text.setText("Run an analysis to generate the investigation summary.")
        sec_summary.body().addWidget(self.soc_investigation_text)
        lay.addWidget(sec_summary)

        sec_correlation = _Collapsible("Correlation Insights")
        self.soc_section_correlation = sec_correlation
        self.soc_correlation_list = QVBoxLayout()
        self.soc_correlation_list.setSpacing(4)
        self.soc_correlation_empty = QLabel("No correlation insights yet. Run multiple analyses to detect patterns.")
        self.soc_correlation_empty.setProperty("class", "summary")
        self.soc_correlation_empty.setWordWrap(True)
        sec_correlation.body().addLayout(self.soc_correlation_list)
        sec_correlation.body().addWidget(self.soc_correlation_empty)
        lay.addWidget(sec_correlation)

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

        prov_card, prov = _card("Providers & API Keys")
        self.provider_checkboxes: dict[str, QCheckBox] = {}
        self.api_key_inputs: dict[str, QLineEdit] = {}
        self.provider_key_status_labels: dict[str, QLabel] = {}
        for provider in PROVIDER_ORDER:
            row = QWidget()
            row_lay = QVBoxLayout(row)
            row_lay.setContentsMargins(0, 2, 0, 6)
            row_lay.setSpacing(4)

            top_row, top_lay = _hrow()
            le = QLineEdit()
            le.setEchoMode(QLineEdit.EchoMode.Password)
            le.setPlaceholderText(f"Enter {provider} API key")
            le.setMaximumWidth(400)
            le.textChanged.connect(self._update_provider_key_statuses)

            cb = QCheckBox(f"Enable {provider}")
            cb.setChecked(True)
            self.provider_checkboxes[provider] = cb
            self.api_key_inputs[provider] = le
            status = QLabel("")
            status.setProperty("class", "inlineStatus")
            self.provider_key_status_labels[provider] = status

            top_lay.addWidget(cb)
            top_lay.addWidget(status, 1)
            row_lay.addWidget(top_row)
            row_lay.addWidget(le)
            prov.addWidget(row)
        lay.addWidget(prov_card)

        opt_card, opt_lay = _card("Session Options")
        self.history_toggle = QCheckBox("Enable in-session history")
        self.history_toggle.setChecked(False)
        opt_lay.addWidget(self.history_toggle)
        lay.addWidget(opt_card)

        actions_row, alay = _hrow()
        alay.setSpacing(12)
        apply_btn = _btn("Apply Session Settings")
        apply_btn.setFixedHeight(36)
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
        self.settings_info_label = QLabel(
            "Saved settings are loaded at startup. Applied keys are used in this session.",
        )
        self.settings_info_label.setProperty("class", "inlineStatus")
        self.settings_info_label.setWordWrap(True)
        lay.addWidget(self.settings_info_label)
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
        if self._ioc_thread is not None and self._ioc_thread.isRunning():
            return

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

        self._set_ioc_loading(True, f"Scanning IOC 1 of {len(iocs)}...")
        self._ioc_thread = QThread(self)
        self._ioc_worker = _BackgroundTaskWorker(
            _scan_iocs_background,
            task_kwargs={
                "iocs": iocs,
                "manual_ioc_type": manual_override,
                "providers": providers,
                "api_keys": dict(self.settings_state.api_keys),
            },
        )
        self._ioc_worker.moveToThread(self._ioc_thread)
        self._ioc_thread.started.connect(self._ioc_worker.run)
        self._ioc_worker.progress.connect(self._on_ioc_progress)
        self._ioc_worker.finished.connect(self._on_ioc_scan_finished)
        self._ioc_worker.failed.connect(self._on_ioc_scan_failed)
        self._ioc_worker.finished.connect(self._ioc_thread.quit)
        self._ioc_worker.failed.connect(self._ioc_thread.quit)
        self._ioc_thread.finished.connect(self._ioc_worker.deleteLater)
        self._ioc_thread.finished.connect(self._on_ioc_worker_thread_finished)
        self._ioc_thread.finished.connect(self._ioc_thread.deleteLater)
        self._ioc_thread.start()

    def _on_ioc_scan_finished(self, rows: list[dict[str, Any]]) -> None:
        self.last_ioc_rows = rows
        for row in rows:
            correlation_store.record_ioc(
                str(row.get("ioc", "")),
                str(row.get("status", "unknown")),
                "ioc_scan",
            )
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
            for row in rows:
                all_errors.extend(str(err) for err in (row.get("errors") or []))
            if all_errors:
                summary_text += "\n\u26A0  " + "  |  ".join(all_errors)
        self.ioc_summary_label.setText(summary_text)
        self._set_banner(
            self.ioc_run_status,
            f"IOC scan complete: {summary['total']} scanned, {summary['malicious']} malicious, {summary['suspicious']} suspicious.",
            "success",
        )
        self._append_history(
            "IOC scan", f"Scanned {len(rows)} IOC(s).",
            {"summary": summary, "rows": rows},
        )
        self._update_home_metrics()
        self._set_ioc_loading(False)

    def _on_ioc_scan_failed(self, message: str) -> None:
        error = message or "IOC scan failed."
        QMessageBox.warning(self, "IOC Scan Failed", error)
        self.ioc_summary_label.setText(error)
        self._set_banner(self.ioc_run_status, f"IOC scan failed: {error}", "danger")
        self._set_ioc_loading(False)

    def _on_ioc_worker_thread_finished(self) -> None:
        self._ioc_worker = None
        self._ioc_thread = None

    def _populate_ioc_table(self, rows: list[dict[str, Any]]) -> None:
        self.ioc_table.setRowCount(0)
        for row in rows:
            idx = self.ioc_table.rowCount()
            self.ioc_table.insertRow(idx)
            ioc_item = QTableWidgetItem(str(row.get("ioc", "")))
            ioc_item.setData(Qt.ItemDataRole.UserRole, row)
            self.ioc_table.setItem(idx, 0, ioc_item)

            verdict_text = str(row.get("verdict", "Unknown"))
            verdict_label, verdict_color = _verdict_tone(verdict_text)
            verdict_item = QTableWidgetItem(f" {verdict_label} ")
            verdict_item.setBackground(QColor(verdict_color))
            verdict_item.setForeground(QColor("#FFFFFF"))
            verdict_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            verdict_item.setToolTip(str(row.get("verdict_reasoning", "")))
            self.ioc_table.setItem(idx, 1, verdict_item)

            conf_val = int(row.get("verdict_confidence", 0) or 0)
            conf_item = QTableWidgetItem(f"{conf_val}%")
            conf_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if conf_val >= 70:
                conf_item.setForeground(QColor(_ACCENT))
            elif conf_val >= 40:
                conf_item.setForeground(QColor(_WARNING))
            else:
                conf_item.setForeground(QColor(_TEXT2))
            self.ioc_table.setItem(idx, 2, conf_item)

            self.ioc_table.setItem(idx, 3, QTableWidgetItem(str(row.get("detected_type", ""))))
            self.ioc_table.setItem(idx, 4, QTableWidgetItem(str(row.get("effective_type", ""))))
            self.ioc_table.setItem(idx, 5, _status_item(str(row.get("status", "unknown"))))
            self.ioc_table.setItem(idx, 6, _score_item(row.get("score", 0)))

            effective_type = str(row.get("effective_type", "unknown"))
            ioc_value = str(row.get("ioc", ""))
            for col, provider_key in ((7, "virustotal"), (8, "abuseipdb"), (9, "otx"), (10, "threatfox")):
                status_text = str(row.get(provider_key, "n/a"))
                status_item = _status_item(status_text)
                link = self._provider_lookup_url(provider_key, ioc_value, effective_type)
                if link:
                    status_item.setData(Qt.ItemDataRole.UserRole, link)
                    status_item.setToolTip(f"Click to open in {provider_key}")
                self.ioc_table.setItem(idx, col, status_item)

            prov_summary = _format_provider_summary(str(row.get("provider_summary", "")))
            prov_item = QTableWidgetItem(prov_summary)
            prov_item.setToolTip(str(row.get("provider_summary", "")))
            self.ioc_table.setItem(idx, 11, prov_item)

            error_list = row.get("errors") or []
            error_count = int(row.get("error_count", 0) or 0)
            error_text = "\n".join(str(e) for e in error_list) if error_list else ""
            errors = QTableWidgetItem(str(error_count))
            errors.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if error_text:
                errors.setToolTip(error_text)
                errors.setForeground(QColor(_DANGER))
            else:
                errors.setForeground(QColor(_TEXT2))
            self.ioc_table.setItem(idx, 12, errors)

            _, accent_color = _verdict_tone(str(row.get("verdict", "Unknown")))
            for col in range(self.ioc_table.columnCount()):
                table_item = self.ioc_table.item(idx, col)
                if table_item is None:
                    continue
                if col == 0:
                    table_item.setBackground(QColor(accent_color).lighter(160))
                table_item.setTextAlignment(
                    Qt.AlignmentFlag.AlignCenter if col in {1, 2, 5, 6, 7, 8, 9, 10, 12}
                    else Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                )
        self._update_ioc_detail_panel()

    def _update_ioc_detail_panel(self) -> None:
        selected = self.ioc_table.selectedItems()
        if not selected:
            self.ioc_detail_text.setText("Select a result row to view full details.")
            return
        row_index = selected[0].row()
        row_item = self.ioc_table.item(row_index, 0)
        if row_item is None:
            self.ioc_detail_text.setText("Select a result row to view full details.")
            return
        row_data = row_item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(row_data, dict):
            self.ioc_detail_text.setText("No structured detail available for this row.")
            return
        self.ioc_detail_text.setText(_format_ioc_detail_text(row_data))

    # ── SOC analysis ─────────────────────────────────────────────────────

    def _run_soc_analysis(self) -> None:
        if self._soc_thread is not None and self._soc_thread.isRunning():
            return

        selected_log = load_soc_log_inputs(
            self.soc_raw_log_input.toPlainText(), self.soc_file_path,
        )
        if not selected_log:
            QMessageBox.warning(
                self, "No Log Input",
                "Paste raw log text or upload a log file.",
            )
            return

        enrich_iocs = self.soc_enrich_toggle.isChecked()
        status_message = "Analyzing log with enrichment..." if enrich_iocs else "Analyzing log..."
        self._set_soc_loading(True, status_message)
        self._soc_thread = QThread(self)
        self._soc_worker = _BackgroundTaskWorker(
            _analyze_soc_background,
            task_kwargs={
                "selected_log": selected_log,
                "enrich_iocs": enrich_iocs,
                "ioc_providers": dict(self.settings_state.providers),
                "ioc_api_keys": dict(self.settings_state.api_keys),
            },
        )
        self._soc_worker.moveToThread(self._soc_thread)
        self._soc_thread.started.connect(self._soc_worker.run)
        self._soc_worker.progress.connect(self._on_soc_progress)
        self._soc_worker.finished.connect(self._on_soc_analysis_finished)
        self._soc_worker.failed.connect(self._on_soc_analysis_failed)
        self._soc_worker.finished.connect(self._soc_thread.quit)
        self._soc_worker.failed.connect(self._soc_thread.quit)
        self._soc_thread.finished.connect(self._soc_worker.deleteLater)
        self._soc_thread.finished.connect(self._on_soc_worker_thread_finished)
        self._soc_thread.finished.connect(self._soc_thread.deleteLater)
        self._soc_thread.start()

    def _on_soc_analysis_finished(self, payload: dict[str, Any]) -> None:
        self._soc_analysis_count += 1

        if not payload.get("ok"):
            message = str(payload.get("error", "SOC analysis failed"))
            reason = str(payload.get("reason", "")).strip().lower()
            partial_result = payload.get("partial_result", {})
            if reason == "no_mapping" and isinstance(partial_result, dict):
                self.last_soc_payload = payload
                entity_count = int(partial_result.get("audit", {}).get("entity_count", 0) or 0)
                self._populate_soc_sections(payload)
                brief = str(payload.get("analyst_brief", ""))
                if not brief:
                    brief = generate_analyst_brief(payload)
                self.soc_analyst_brief_label.setText(brief)
                self.soc_severity_label.setText("  INFO  ")
                self.soc_severity_label.setProperty("class", "severityInfo")
                self.soc_severity_label.style().unpolish(self.soc_severity_label)
                self.soc_severity_label.style().polish(self.soc_severity_label)
                self.soc_severity_label.setFixedWidth(100)
                self.soc_severity_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                self.soc_severity_label.setVisible(True)
                self.soc_top_technique.setText("Technique: Not mapped")
                self.soc_top_confidence.setText("Confidence: N/A (no mapping)")
                self.soc_top_source.setText("Mapping Source: none")
                self.soc_top_enrichment.setText(_soc_enrichment_label(self.soc_enrich_toggle.isChecked(), 0))
                if entity_count > 0:
                    self.soc_summary_label.setText(
                        "No ATT&CK mapping was produced for this log. "
                        f"Extraction still succeeded ({entity_count} entities found), but no deterministic ATT&CK mapping rule matched. "
                        "Review the extracted entities and normalized fields, then add more correlated context and retry.",
                    )
                else:
                    self.soc_summary_label.setText(
                        "No ATT&CK mapping was produced and no extractable entities were found. "
                        "Check log completeness/format and try again.",
                    )
                self.soc_section_entities.set_expanded(True)
                self.soc_section_mitre.set_expanded(False)
                self.soc_section_epc.set_expanded(False)
                self.soc_section_enrichment.set_expanded(False)
                self._populate_investigation_summary(payload)
                self._populate_correlation_insights(payload)
                self._set_banner(
                    self.soc_run_status,
                    "SOC analysis completed: no ATT&CK mapping was produced.",
                    "info",
                )
                self._append_history(
                    "SOC analysis",
                    "Analyzed one log event (no ATT&CK mapping).",
                    payload,
                )
                self._update_home_metrics()
            else:
                QMessageBox.warning(self, "Analysis Failed", message)
                self.soc_summary_label.setText(message)
                self._set_banner(self.soc_run_status, f"SOC analysis failed: {message}", "danger")
            self._set_soc_loading(False)
            return

        self.last_soc_payload = payload
        self._populate_soc_sections(payload)
        brief = str(payload.get("analyst_brief", ""))
        if not brief:
            brief = generate_analyst_brief(payload)
        self.soc_analyst_brief_label.setText(brief)
        summary = payload.get("summary", {})
        enrich_used = bool(self.soc_enrich_toggle.isChecked())
        confidence_value = float(summary.get("confidence", 0.0) or 0.0)
        enrichment = payload.get("result", {}).get("audit", {}).get("ioc_enrichment", [])
        enrichment_count = len(enrichment) if isinstance(enrichment, list) else 0
        summary_text, banner_text, banner_tone = _soc_summary_and_banner(payload, enrich_used)
        self.soc_summary_label.setText(summary_text)

        severity = assess_severity(payload)
        sev_text, sev_color = _severity_label(severity)
        self.soc_severity_label.setText(f"  {sev_text}  ")
        self.soc_severity_label.setProperty("class", f"severity{severity.capitalize()}")
        self.soc_severity_label.style().unpolish(self.soc_severity_label)
        self.soc_severity_label.style().polish(self.soc_severity_label)
        self.soc_severity_label.setFixedWidth(100)
        self.soc_severity_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.soc_severity_label.setVisible(True)

        self.soc_top_technique.setText(
            f"Technique: {summary.get('technique_id', 'N/A')} ({summary.get('technique_name', 'N/A')})",
        )
        if confidence_value < 0.6:
            self.soc_top_confidence.setText(f"Confidence: {confidence_value:.0%} (low)")
        else:
            self.soc_top_confidence.setText(f"Confidence: {confidence_value:.0%}")
        self.soc_top_source.setText(f"Mapping Source: {summary.get('mapping_source', 'unknown')}")
        self.soc_top_enrichment.setText(_soc_enrichment_label(enrich_used, enrichment_count))
        self.soc_section_mitre.set_expanded(True)
        self.soc_section_entities.set_expanded(True)
        self.soc_section_epc.set_expanded(True)
        self.soc_section_enrichment.set_expanded(enrich_used and enrichment_count > 0)

        self._populate_investigation_summary(payload)
        self._populate_correlation_insights(payload)

        self._set_banner(self.soc_run_status, banner_text, banner_tone)
        self._append_history("SOC analysis", "Analyzed one log event.", payload)
        self._update_home_metrics()
        self._set_soc_loading(False)

    def _on_soc_analysis_failed(self, message: str) -> None:
        error = message or "SOC analysis failed."
        QMessageBox.warning(self, "Analysis Failed", error)
        self.soc_summary_label.setText(error)
        self._set_banner(self.soc_run_status, f"SOC analysis failed: {error}", "danger")
        self._set_soc_loading(False)

    def _on_soc_worker_thread_finished(self) -> None:
        self._soc_worker = None
        self._soc_thread = None

    def _populate_soc_sections(self, payload: dict[str, Any]) -> None:
        result = payload.get("result", {})
        if not isinstance(result, dict):
            result = {}
        if not result and isinstance(payload.get("partial_result"), dict):
            result = payload.get("partial_result", {})
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
            self.soc_mitre_table.setItem(r, 2, _score_item(int(float(mapping.get("confidence", 0)) * 100)))
            self.soc_mitre_table.setItem(r, 3, QTableWidgetItem(str(mapping.get("rationale", ""))))
            evidence = ", ".join(str(item) for item in mapping.get("evidence_refs", []))
            self.soc_mitre_table.setItem(r, 4, QTableWidgetItem(evidence))

        if isinstance(epc, dict) and epc.get("explain"):
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
        else:
            epc_text = (
                "EPC guidance is unavailable because no ATT&CK mapping was produced.\n\n"
                "Suggested next steps:\n"
                "- Review extracted entities and normalized fields for missing context.\n"
                "- Provide additional correlated log lines."
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
            self.soc_enrichment_table.setItem(r, 3, _score_item(item.get("score", 0)))
            summary_item = QTableWidgetItem(_format_provider_summary(provider_summary))
            summary_item.setToolTip(provider_summary)
            self.soc_enrichment_table.setItem(r, 4, summary_item)

    def _populate_investigation_summary(self, payload: dict[str, Any]) -> None:
        inv = payload.get("investigation_summary", {})
        if not isinstance(inv, dict) or not inv:
            inv = generate_investigation_summary(payload)
        text = (
            f"WHAT HAPPENED\n{inv.get('what_happened', 'N/A')}\n\n"
            f"SEVERITY ASSESSMENT\n{inv.get('severity_assessment', 'N/A')}\n\n"
            f"RECOMMENDED NEXT STEPS\n{inv.get('next_steps', 'N/A')}"
        )
        self.soc_investigation_text.setText(text)
        self.soc_section_investigation.set_expanded(True)

    def _populate_correlation_insights(self, payload: dict[str, Any]) -> None:
        while self.soc_correlation_list.count():
            child = self.soc_correlation_list.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        insights = payload.get("correlation_insights", [])
        if not isinstance(insights, list):
            insights = []
        self.soc_correlation_empty.setVisible(len(insights) == 0)

        type_icons = {
            "repeated_ioc": "\u26A0",
            "repeated_technique": "\u21BB",
            "multi_stage": "\u26D4",
        }
        type_colors = {
            "repeated_ioc": _WARNING,
            "repeated_technique": _PRIMARY,
            "multi_stage": _DANGER,
        }
        for insight in insights:
            icon = type_icons.get(insight.get("type", ""), "\u2022")
            color = type_colors.get(insight.get("type", ""), _TEXT2)
            label = QLabel(f"{icon}  {insight.get('summary', '')}")
            label.setWordWrap(True)
            label.setStyleSheet(
                f"color: {color}; font-size: 12px; font-weight: 500; "
                f"padding: 6px 10px; background: rgba(255,255,255,0.03); "
                f"border-left: 3px solid {color}; border-radius: 3px;"
            )
            self.soc_correlation_list.addWidget(label)

        if insights:
            self.soc_section_correlation.set_expanded(True)

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
        self._update_provider_key_statuses()

    def _update_provider_key_statuses(self) -> None:
        for provider in PROVIDER_ORDER:
            status_label = self.provider_key_status_labels.get(provider)
            line_edit = self.api_key_inputs.get(provider)
            if status_label is None or line_edit is None:
                continue
            has_key = bool(line_edit.text().strip())
            status_label.setText("Key entered" if has_key else "Key missing")
            status_label.setStyleSheet(
                f"color: {(_ACCENT if has_key else _WARNING)}; font-weight: 600;",
            )

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
        self._update_provider_key_statuses()
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
        self.home_soc_metric.setText(str(self._soc_analysis_count))

        ioc_summary = summarize_ioc_rows(self.last_ioc_rows)
        malicious_count = ioc_summary["malicious"]
        suspicious_count = ioc_summary["suspicious"]
        self.home_malicious_metric.setText(f"{malicious_count + suspicious_count}")

        if self.last_soc_payload:
            severity = assess_severity(self.last_soc_payload)
            self.home_severity_metric.setText(severity.upper())
        else:
            self.home_severity_metric.setText("\u2014")

        if self.history_entries:
            latest = self.history_entries[-1]
            self.home_recent_activity.setText(
                f"{latest.get('timestamp', '')}  |  {latest.get('action', '')}  |  {latest.get('summary', '')}",
            )
        else:
            self.home_recent_activity.setText(
                "No activity yet. Run an IOC scan or SOC analysis to get started.",
            )

        while self.home_ioc_findings.count():
            child = self.home_ioc_findings.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        if self.last_ioc_rows:
            self.home_ioc_summary.setText(
                "Total: {total} | Malicious: {malicious} | Suspicious: {suspicious} | "
                "Clean: {clean} | Unknown: {unknown}".format(**ioc_summary),
            )
            notable = [r for r in self.last_ioc_rows if str(r.get("verdict", "")).lower() in {"malicious", "suspicious"}]
            for r in notable[:5]:
                verdict = str(r.get("verdict", "Unknown"))
                _, color = _verdict_tone(verdict)
                lbl = QLabel(f"\u2022 {r.get('ioc', '?')} \u2014 {verdict.upper()} ({r.get('verdict_confidence', 0)}%)")
                lbl.setStyleSheet(f"color: {color}; font-size: 11.5px; font-weight: 500; padding: 1px 0;")
                lbl.setWordWrap(True)
                self.home_ioc_findings.addWidget(lbl)
        else:
            self.home_ioc_summary.setText("No IOC scan results yet.")

        if self.last_soc_payload:
            summary = self.last_soc_payload.get("summary", {})
            if not isinstance(summary, dict) or not summary:
                partial_result = self.last_soc_payload.get("partial_result", {})
                if isinstance(partial_result, dict):
                    audit = partial_result.get("audit", {})
                    if not isinstance(audit, dict):
                        audit = {}
                    summary = {
                        "technique_id": "N/A",
                        "technique_name": "Not mapped",
                        "confidence": 0.0,
                        "mapping_source": str(audit.get("mapping_source", "none")),
                        "entity_count": int(audit.get("entity_count", len(partial_result.get("entities", []) or [])) or 0),
                    }
            if isinstance(summary, dict) and summary:
                sev = assess_severity(self.last_soc_payload)
                self.home_soc_summary.setText(
                    "Severity: {severity} | Technique: {technique_id} ({technique_name}) | "
                    "Confidence: {confidence:.0%} | Source: {mapping_source}".format(
                        severity=sev.upper(),
                        technique_id=summary.get("technique_id", "N/A"),
                        technique_name=summary.get("technique_name", "N/A"),
                        confidence=float(summary.get("confidence", 0.0) or 0.0),
                        mapping_source=summary.get("mapping_source", "unknown"),
                    ),
                )
            else:
                self.home_soc_summary.setText("SOC analysis was run, but no summary is available.")
        else:
            self.home_soc_summary.setText("No SOC analysis results yet.")

        while self.home_techniques_list.count():
            child = self.home_techniques_list.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        techniques = correlation_store._technique_history
        if techniques:
            self.home_techniques_label.setVisible(False)
            seen: set[str] = set()
            for entry in reversed(techniques):
                tid = entry.get("technique_id", "")
                if tid in seen:
                    continue
                seen.add(tid)
                conf = float(entry.get("confidence", 0))
                lbl = QLabel(f"\u2022 {tid} ({entry.get('technique_name', '')}) \u2014 {conf:.0%} confidence")
                lbl.setStyleSheet(f"color: {_TEXT}; font-size: 11.5px; padding: 1px 0;")
                lbl.setWordWrap(True)
                self.home_techniques_list.addWidget(lbl)
                if len(seen) >= 8:
                    break
        else:
            self.home_techniques_label.setVisible(True)


def main() -> int:
    app = QApplication([])
    window = DesktopSecurityApp()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
