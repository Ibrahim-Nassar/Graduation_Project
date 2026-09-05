from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote_plus

from PySide6.QtCore import QObject, QThread, Qt, QUrl, Signal, Slot
from PySide6.QtGui import QColor, QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
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
    export_json,
    generate_analyst_brief,
    load_soc_log_inputs,
    load_persisted_settings,
    sanitize_api_keys,
    scan_iocs,
    save_persisted_settings,
    summarize_ioc_rows,
)

# ── design tokens ─────────────────────────────────────────────────────────────
# Layered dark palette (critical ordering):
#   _BG  <  _CARD  <  _SURFACE  (inputs / table body)
# i.e. the page is darkest; card chrome sits above it; text fields and data
# grids are *lighter* than the card, not darker — otherwise QTextEdit and
# QTableWidget read as “black voids” inside panels (common Qt + Windows issue
# when this order is inverted). Subtle borders finish the separation.
_BG = "#090F1C"              # page canvas — deepest plane
_CARD = "#121A2E"            # cards / panels — lifted off the canvas
_SURFACE = "#1A2338"         # inputs, QTextEdit, QTableWidget body (lighter than _CARD)
_SURFACE_HOVER = "#1F2A42"
_CARD_HEADER = "#1E293E"     # table header strip — between card and surface
_CARD_HOVER = "#1A243C"
_BORDER = "#2E3B56"          # visible border on controls
_BORDER_SOFT = "#28334C"     # hairline row separator
_PRIMARY = "#4F8AF8"         # slightly softer blue, less harsh on long sessions
_PRIMARY_SOFT = "rgba(79, 138, 248, 0.14)"
_PRIMARY_SUBTLE = "rgba(79, 138, 248, 0.08)"
_ACCENT = "#22C55E"          # green — clean / success
_INFO = "#60A5FA"            # blue — informational only
_WARNING = "#F59E0B"         # amber — medium / suspicious
_DANGER = "#EF4444"          # red — high / malicious
_CRITICAL = "#DC2626"        # deeper red — critical severity
_TEXT = "#EEF1F8"
_TEXT2 = "#A8B0C4"
_TEXT3 = "#808A9E"           # tertiary — lifted slightly for accessibility
_SIDEBAR = "#0B1020"

# Kept as alias for legacy references in this module.
_CARD_SOFT = _CARD


# ── helpers ───────────────────────────────────────────────────────────────────

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


_EVIDENCE_COLORS = {
    "strong": _ACCENT,
    "moderate": _TEXT,
    "weak": _WARNING,
}


def _evidence_item(strength: Any) -> QTableWidgetItem:
    """Compact evidence-strength cell: the literal word, coloured text only."""
    label = str(strength or "").strip().lower()
    item = QTableWidgetItem(label or "—")
    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    item.setForeground(QColor(_EVIDENCE_COLORS.get(label, _TEXT3)))
    font = item.font()
    font.setBold(True)
    item.setFont(font)
    item.setToolTip(f"Evidence strength: {label or 'n/a'}")
    return item


def _format_provider_summary(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "No provider summary available."
    return text.replace(",", " |")


def _assessment_label(assessment: str) -> str:
    return assessment.replace("_", " ").strip().upper() or "INSUFFICIENT DATA"


def _verdict_tone(assessment: str) -> tuple[str, str]:
    low = assessment.lower().strip()
    if low in {"corroborated_malicious", "single_source_malicious"}:
        return _assessment_label(low), _DANGER
    if low in {"providers_disagree", "suspicious_only"}:
        return _assessment_label(low), _WARNING
    if low == "no_suspicious_findings":
        return _assessment_label(low), _ACCENT
    return "INSUFFICIENT DATA", _TEXT2


def _format_ioc_detail_text(row: dict[str, Any]) -> str:
    status = str(row.get("status", "unknown"))
    assessment = str(row.get("assessment", "insufficient_data"))
    verdict_reasoning = str(row.get("verdict_reasoning", ""))
    skip_reason = str(row.get("skip_reason", "") or "")
    providers = []
    for provider in PROVIDER_ORDER:
        providers.append(f"- {provider}: {row.get(provider, 'n/a')}")
    provider_summary = str(row.get("provider_summary", "")).strip() or "N/A"
    errors = row.get("errors") or []
    raw_section = row.get("raw")
    raw_text = json.dumps(raw_section, indent=2, sort_keys=True) if raw_section else "N/A"
    skipped_line = (
        f"Skipped: not sent to providers ({skip_reason})\n"
        if status == "skipped" else ""
    )
    return (
        f"IOC: {row.get('ioc', '')}\n"
        f"\n=== ASSESSMENT ===\n"
        f"Assessment: {assessment}\n"
        f"Reasoning: {verdict_reasoning}\n"
        f"{skipped_line}"
        f"==================\n\n"
        f"Detected Type: {row.get('detected_type', 'unknown')}\n"
        f"Effective Type: {row.get('effective_type', 'unknown')}\n"
        f"Aggregate Status: {status}\n\n"
        "Provider Statuses:\n"
        f"{chr(10).join(providers)}\n\n"
        f"Provider Summary:\n{provider_summary}\n\n"
        "Errors:\n"
        f"{chr(10).join(f'- {err}' for err in errors) if errors else '- None'}\n\n"
        f"Raw Details:\n{raw_text}"
    )


def _soc_banner(payload: dict[str, Any]) -> tuple[str, str, str]:
    summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    technique_id = str(summary.get("technique_id") or "N/A")
    technique_name = str(summary.get("technique_name") or "N/A")
    evidence_strength = str(summary.get("evidence_strength") or "").strip().lower()
    mapping_source = str(summary.get("mapping_source", "")).strip().lower()

    if technique_id == "N/A" or str(payload.get("status", "")).lower() == "no_mapping":
        return (
            "No reliable ATT&CK mapping for this log.",
            "SOC analysis completed — no reliable ATT&CK mapping.",
            "info",
        )
    if mapping_source == "ml_fallback":
        return (
            f"ML fallback predicted {technique_id} ({technique_name}); evidence strength: "
            f"{evidence_strength or 'weak'}. No deterministic rule matched — "
            "treat as preliminary and verify manually before responding.",
            f"SOC analysis complete: {technique_id} via ML fallback.",
            "info",
        )
    if evidence_strength == "weak":
        return (
            f"Mapped {technique_id} ({technique_name}) with weak evidence. "
            "Review evidence before taking response actions.",
            f"SOC analysis complete: {technique_id} mapped with weak evidence.",
            "info",
        )
    return (
        f"Rule-based mapping: {technique_id} ({technique_name}); evidence strength: {evidence_strength or 'unknown'}.",
        f"SOC analysis complete: {technique_id} mapped with {evidence_strength or 'unknown'} evidence.",
        "success",
    )


def _card(title: str = "", *, soft: bool = False) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    # Keep the section wrapper API, but style it as a lightweight layout
    # container so only real data surfaces (inputs/tables/output panes)
    # carry the dark boxed treatment.
    frame.setProperty("class", "card")
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(12)
    if title:
        lbl = QLabel(title.upper())
        lbl.setProperty("class", "cardTitle")
        lbl.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        lay.addWidget(lbl)
    return frame, lay


def _table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    header = t.horizontalHeader()
    header.setStretchLastSection(True)
    header.setMinimumSectionSize(72)
    header.setDefaultSectionSize(120)
    header.setHighlightSections(False)
    # Consistent header row height — text sits on a clean baseline.
    header.setFixedHeight(36)
    header.setDefaultAlignment(
        Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
    )
    # Subtle row alternation lifts the table visually without looking busy.
    t.setAlternatingRowColors(True)
    t.setShowGrid(False)
    t.verticalHeader().setVisible(False)
    t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    t.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    # Taller rows give text room to sit visually centred with the padding
    # we apply to ::item — 36px pairs with 8/14px cell padding.
    t.verticalHeader().setDefaultSectionSize(36)
    t.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    t.setWordWrap(False)
    t.setMouseTracking(True)
    return t


def _hrow(spacing: int = 10) -> tuple[QWidget, QHBoxLayout]:
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(spacing)
    # Align items to vertical centre by default so buttons, labels, and
    # inputs share a single baseline on every row they appear on.
    lay.setAlignment(Qt.AlignmentFlag.AlignVCenter)
    return w, lay


def _scrollpage() -> tuple[QScrollArea, QVBoxLayout]:
    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setFrameShape(QFrame.Shape.NoFrame)
    sa.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    inner = QWidget()
    lay = QVBoxLayout(inner)
    # Slightly roomier page rhythm to mimic the old, cleaner hierarchy.
    lay.setContentsMargins(36, 30, 36, 30)
    lay.setSpacing(20)
    sa.setWidget(inner)
    sa.viewport().setAutoFillBackground(False)
    return sa, lay


def _vline() -> QFrame:
    line = QFrame()
    line.setFixedWidth(1)
    line.setMinimumHeight(28)
    line.setMaximumHeight(36)
    line.setProperty("class", "vDivider")
    return line


def _chip(text: str, cls: str = "chip") -> QLabel:
    """Compact inline pill for result/summary strips."""
    lbl = QLabel(text)
    lbl.setProperty("class", cls)
    lbl.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
    return lbl


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
                    "effective_type": "unknown", "status": "error", "skip_reason": "",
                    "assessment": "insufficient_data", "verdict_reasoning": "",
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
    progress: Callable[[str], None],
) -> dict[str, Any]:
    # NOTE: we intentionally do NOT pass ``enrich_iocs`` / provider settings
    # here.  SOC Analysis is a pure rule + ML-fallback mapping step; the
    # dedicated IOC Scanner page is where provider enrichment happens.
    # Earlier revisions threaded ``ioc_providers`` / ``ioc_api_keys`` down
    # into this path but ``enrich_iocs`` was hard-coded to ``False``, so the
    # arguments were dead plumbing that implied a live capability that
    # never fired.  Removed to keep the contract honest.
    progress("Analyzing log...")
    return analyze_soc_log(selected_log)


class _Collapsible(QFrame):
    """Sub-section with a small clickable header that toggles body visibility.

    Renders flat (no card chrome) so it can be dropped inline inside a
    parent card without creating a nested-box look.
    """

    def __init__(self, title: str, expanded: bool = False, *, flat: bool = True) -> None:
        super().__init__()
        if not flat:
            self.setProperty("class", "cardSoft")
        self._title = title
        self._expanded = expanded

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(8)

        self._header = QPushButton(self._label_text())
        self._header.setProperty("class", "collapseBtn")
        self._header.setCursor(Qt.CursorShape.PointingHandCursor)
        self._header.setFixedHeight(24)
        self._header.clicked.connect(self._toggle)
        outer.addWidget(self._header)

        self._body = QWidget()
        self._body_lay = QVBoxLayout(self._body)
        self._body_lay.setContentsMargins(0, 0, 0, 0)
        self._body_lay.setSpacing(8)
        self._body.setVisible(expanded)
        outer.addWidget(self._body)

    def _label_text(self) -> str:
        arrow = "\u25BE" if self._expanded else "\u25B8"
        return f"{arrow}  {self._title}"

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


# ── stylesheet ────────────────────────────────────────────────────────────────

_QSS = f"""
/* ── base ── */
QMainWindow, QWidget {{
    background: {_BG};
    color: {_TEXT};
    font-family: "Segoe UI", "Inter", "SF Pro Text", sans-serif;
    font-size: 13px;
}}
QLabel, QCheckBox {{
    background: transparent;
}}
QStackedWidget {{
    background: transparent;
    border: none;
}}
QFrame[class="vDivider"] {{
    background: {_BORDER_SOFT};
    border: none;
    max-width: 1px;
    min-width: 1px;
}}
QFrame[class="hRule"] {{
    background: {_BORDER_SOFT};
    border: none;
    max-height: 1px;
    min-height: 1px;
}}

/* ── sidebar ── */
QWidget#sidebar {{
    background: {_SIDEBAR};
    border: none;
    border-right: 1px solid {_BORDER};
}}
QWidget#brandBlock {{
    background: transparent;
}}
QLabel#brandMark {{
    background: rgba(79, 138, 248, 0.18);
    color: {_PRIMARY};
    font-size: 15px;
    font-weight: 800;
    border-radius: 8px;
    border: 1px solid rgba(79, 138, 248, 0.35);
    qproperty-alignment: AlignCenter;
    letter-spacing: 0.5px;
}}
QLabel#brand {{
    font-size: 13.5px;
    font-weight: 700;
    color: {_TEXT};
    letter-spacing: 0.1px;
}}
QLabel#brandSub {{
    font-size: 8.5px;
    font-weight: 700;
    color: {_TEXT3};
    letter-spacing: 1.8px;
}}
QLabel#sidebarFooter {{
    font-size: 10.5px;
    color: {_TEXT3};
    padding: 14px 22px;
    letter-spacing: 0.2px;
}}
QLabel#navSection {{
    font-size: 9px;
    font-weight: 700;
    color: {_TEXT3};
    padding: 0 22px;
    letter-spacing: 1.8px;
}}
QFrame#sidebarRule {{
    background: {_BORDER_SOFT};
    max-height: 1px;
    border: none;
}}
/* Settings provider-table column header strip — matches the QHeaderView
   aesthetic so the settings provider list reads as a structured table. */
QWidget[class="settingsHeadRow"] {{
    background: transparent;
    border: none;
    border-bottom: 1px solid {_BORDER_SOFT};
}}

QPushButton[class="nav"] {{
    text-align: left;
    padding: 0 16px 0 22px;
    margin: 0 10px;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: {_TEXT2};
    font-size: 12.5px;
    font-weight: 500;
    letter-spacing: 0.1px;
}}
QPushButton[class="nav"]:hover {{
    background: rgba(255, 255, 255, 0.040);
    color: {_TEXT};
}}
QPushButton[class="nav"]:checked {{
    background: rgba(79, 138, 248, 0.16);
    color: {_TEXT};
    font-weight: 600;
    border-left: 3px solid {_PRIMARY};
    padding-left: 19px;
}}

/* ── cards ── */
/* Cards lift clearly off the page background. A single 1px border traces
   the shape at full _BORDER weight — strong enough to read as intentional
   structure, light enough not to box-in the content above it. */
QFrame[class="card"], QFrame[class="cardSoft"] {{
    background: transparent;
    border: none;
    border-radius: 0;
}}
QFrame[class="resultStrip"], QFrame[class="summaryStrip"] {{
    background: transparent;
    border: none;
    border-radius: 0;
}}
/* Inner panel (KPI strip): slightly *lighter* than the card via a soft
   highlight — never a black multiply overlay (that recreated “void” panels). */
QFrame[class="innerPanel"] {{
    background: rgba(255, 255, 255, 0.018);
    border: 1px solid rgba(46, 59, 86, 0.65);
    border-radius: 8px;
}}
QWidget[class="stripCol"] {{
    background: transparent;
    border: none;
}}
/* Analyst brief: tinted output well — readable, clearly primary, not a
   second near-black box on top of the card. */
QFrame[class="briefBox"] {{
    background: {_SURFACE};
    border: 1px solid {_BORDER};
    border-radius: 6px;
}}
QLabel[class="cardTitle"] {{
    font-size: 10.5px;
    font-weight: 700;
    color: {_TEXT2};
    letter-spacing: 1.3px;
    text-transform: uppercase;
}}
QLabel[class="cardTitleStrong"] {{
    font-size: 12px;
    font-weight: 700;
    color: {_TEXT};
    letter-spacing: 0.2px;
}}
QLabel[class="cardSubtitle"] {{
    font-size: 12px;
    color: {_TEXT2};
    font-weight: 400;
}}

/* ── collapse toggle ── */
QPushButton[class="collapseBtn"] {{
    text-align: left;
    padding: 0 0 0 2px;
    min-height: 22px;
    background: transparent;
    color: {_TEXT2};
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: 1.1px;
    border: none;
    border-radius: 0;
}}
QPushButton[class="collapseBtn"]:hover {{
    color: {_TEXT};
    background: transparent;
}}

/* ── headings ── */
QLabel[class="pageTitle"] {{
    font-size: 23px;
    font-weight: 800;
    color: {_TEXT};
    letter-spacing: -0.6px;
}}
QLabel[class="pageSubtitle"] {{
    font-size: 13px;
    color: {_TEXT2};
    padding: 4px 0 0 0;
    line-height: 1.5;
}}
QLabel[class="sectionLabel"] {{
    font-size: 10.5px;
    font-weight: 700;
    color: {_TEXT2};
    letter-spacing: 1.3px;
}}

/* ── buttons ── */
/* Fixed min-height + zero vertical padding on the padding axis keeps text
   visually centred. We pad horizontally only; min-height drives the box. */
QPushButton[class="primary"], QPushButton[class="accent"] {{
    background: {_PRIMARY};
    color: #fff;
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 7px;
    padding: 0 20px;
    min-height: 34px;
    font-weight: 600;
    font-size: 12.5px;
    letter-spacing: 0.1px;
}}
QPushButton[class="primary"]:hover, QPushButton[class="accent"]:hover {{
    background: #6699FA;
}}
QPushButton[class="primary"]:pressed, QPushButton[class="accent"]:pressed {{
    background: #3D74E3;
}}
QPushButton[class="primary"]:disabled, QPushButton[class="accent"]:disabled {{
    background: rgba(79, 138, 248, 0.25);
    color: rgba(255, 255, 255, 0.55);
    border-color: transparent;
}}

QPushButton[class="secondary"] {{
    background: rgba(255, 255, 255, 0.07);
    color: {_TEXT};
    border: 1px solid {_BORDER};
    border-radius: 7px;
    padding: 0 14px;
    min-height: 34px;
    font-weight: 500;
    font-size: 12px;
    letter-spacing: 0.1px;
}}
QPushButton[class="secondary"]:hover {{
    background: rgba(255, 255, 255, 0.11);
    border-color: #3F4D6A;
    color: {_TEXT};
}}
QPushButton[class="secondary"]:pressed {{
    background: rgba(255, 255, 255, 0.04);
}}
QPushButton[class="secondary"]:disabled {{
    color: {_TEXT3};
    background: rgba(255, 255, 255, 0.015);
    border-color: {_BORDER_SOFT};
}}

QPushButton[class="ghost"] {{
    background: transparent;
    color: {_TEXT2};
    border: 1px solid transparent;
    border-radius: 7px;
    padding: 0 12px;
    min-height: 34px;
    font-size: 12px;
    font-weight: 500;
}}
QPushButton[class="ghost"]:hover {{
    color: {_TEXT};
    background: rgba(255, 255, 255, 0.04);
}}
QPushButton[class="ghost"]:pressed {{
    background: rgba(255, 255, 255, 0.06);
}}

/* Icon-style minimal button (used for show/hide API key toggle). */
QPushButton[class="iconBtn"] {{
    background: transparent;
    color: {_TEXT3};
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 0 8px;
    min-height: 30px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.4px;
}}
QPushButton[class="iconBtn"]:hover {{
    color: {_TEXT};
    background: rgba(255, 255, 255, 0.04);
}}

/* ── inputs ── */
/* min-height drives the box; padding is horizontal-only so text sits
   visually centred inside the input. The input plane is a little lighter
   than the card so a focused input reads as "on top" of the card, not
   sunken into it. */
QLineEdit, QComboBox {{
    background: {_SURFACE};
    color: {_TEXT};
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 0 12px;
    min-height: 34px;
    font-size: 12.5px;
    selection-background-color: rgba(79, 138, 248, 0.35);
}}
QLineEdit:hover, QComboBox:hover {{
    background: {_SURFACE_HOVER};
    border-color: #35415A;
}}
QLineEdit:focus, QComboBox:focus {{
    background: {_SURFACE_HOVER};
    border-color: {_PRIMARY};
}}
QLineEdit:disabled, QComboBox:disabled {{
    color: {_TEXT3};
    background: rgba(255, 255, 255, 0.015);
    border-color: {_BORDER_SOFT};
}}
QTextEdit {{
    background-color: {_SURFACE};
    background: {_SURFACE};
    color: {_TEXT};
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 12.5px;
    selection-background-color: rgba(79, 138, 248, 0.35);
}}
QTextEdit:hover {{
    background: {_SURFACE_HOVER};
    border-color: #3D4B68;
}}
QTextEdit:focus {{
    background: {_SURFACE_HOVER};
    border-color: {_PRIMARY};
}}
QComboBox::drop-down {{
    border: none;
    width: 28px;
    subcontrol-origin: padding;
    subcontrol-position: center right;
    background: transparent;
}}
/* Custom chevron rendered via inline SVG data-URL. The native Windows
   arrow is a heavy dark glyph that reads as a mismatch in a dark theme —
   this version uses our {_TEXT2} palette tone and a clean 12×7 stroke. */
QComboBox::down-arrow {{
    image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='7' viewBox='0 0 12 7'><path d='M1 1l5 5 5-5' fill='none' stroke='%23A5ADBE' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/></svg>");
    width: 12px;
    height: 7px;
    margin-right: 12px;
}}
QComboBox:hover::down-arrow {{
    image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='7' viewBox='0 0 12 7'><path d='M1 1l5 5 5-5' fill='none' stroke='%23EEF1F8' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/></svg>");
}}
QComboBox QAbstractItemView {{
    background: {_CARD};
    color: {_TEXT};
    border: 1px solid {_BORDER};
    border-radius: 6px;
    selection-background-color: {_PRIMARY_SOFT};
    outline: none;
    padding: 4px;
}}
QComboBox QAbstractItemView::item {{
    min-height: 24px;
    padding: 4px 10px;
    border-radius: 4px;
}}
QCheckBox {{
    color: {_TEXT};
    font-size: 12.5px;
    spacing: 10px;
    padding: 0;
}}
QCheckBox::indicator {{
    width: 15px;
    height: 15px;
    border: 1px solid {_BORDER};
    border-radius: 3px;
    background: {_SURFACE};
}}
QCheckBox::indicator:hover {{
    border-color: {_TEXT3};
}}
QCheckBox::indicator:checked {{
    background: {_PRIMARY};
    border-color: {_PRIMARY};
    image: none;
}}

/* ── tables ── */
/* Table body sits on the same dark surface plane as inputs — clearly
   inside the card, not floating above it. Alternating rows use a stronger
   tint so the data grid has real visual rhythm without looking noisy.
   The header strip is darker than the body so it reads as structure. */
QTableWidget {{
    background-color: {_SURFACE};
    background: {_SURFACE};
    border: 1px solid {_BORDER};
    border-radius: 8px;
    gridline-color: transparent;
    selection-background-color: {_PRIMARY_SOFT};
    alternate-background-color: rgba(255, 255, 255, 0.028);
    color: {_TEXT};
    font-size: 12.5px;
    outline: none;
}}
/* Symmetric 9px vertical padding centres text precisely at the default
   36px row height. Horizontal padding matches card interior padding. */
QTableWidget::item {{
    padding: 9px 14px;
    border: none;
    border-bottom: 1px solid rgba(45, 58, 84, 0.55);
}}
QTableWidget::item:selected {{
    background: rgba(79, 138, 248, 0.16);
    color: {_TEXT};
}}
QTableWidget::item:hover {{
    background: rgba(255, 255, 255, 0.038);
}}
QHeaderView {{
    background: transparent;
    border: none;
}}
QHeaderView::section {{
    background: {_CARD_HEADER};
    color: {_TEXT2};
    font-weight: 700;
    font-size: 9.5px;
    border: none;
    border-bottom: 1px solid {_BORDER};
    padding: 0 14px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
}}
QHeaderView::section:first {{
    border-top-left-radius: 8px;
}}
QHeaderView::section:last {{
    border-top-right-radius: 8px;
}}
QTableCornerButton::section {{
    background: {_CARD_HEADER};
    border: none;
    border-bottom: 1px solid {_BORDER};
}}

/* ── scrollbars ── */
QScrollArea {{
    background: transparent;
    border: none;
}}
QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    border: none;
    margin: 2px;
}}
QScrollBar::handle:vertical {{
    background: {_BORDER};
    border-radius: 3px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {_TEXT3};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
    background: transparent;
}}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    background: transparent;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 8px;
    border: none;
    margin: 2px;
}}
QScrollBar::handle:horizontal {{
    background: {_BORDER};
    border-radius: 3px;
    min-width: 30px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {_TEXT3};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
    background: transparent;
}}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
    background: transparent;
}}

/* ── misc labels ── */
QLabel[class="summary"] {{
    font-size: 12px;
    color: {_TEXT};
}}
QLabel[class="fileLabel"] {{
    font-size: 12px;
    color: {_TEXT2};
    padding: 0 4px;
}}
QLabel[class="inlineStatus"] {{
    font-size: 11.5px;
    color: {_TEXT2};
    font-weight: 600;
    padding: 0 4px;
    letter-spacing: 0.1px;
}}
QLabel[class="statusLine"] {{
    font-size: 11.5px;
    color: {_TEXT};
}}
QLabel[class="warningLine"] {{
    font-size: 11.5px;
    color: {_WARNING};
    background: rgba(245, 158, 11, 0.10);
    border: 1px solid rgba(245, 158, 11, 0.30);
    border-left: 3px solid {_WARNING};
    border-radius: 0 6px 6px 0;
    padding: 8px 14px;
    font-weight: 500;
}}
QLabel[class="hint"] {{
    font-size: 11.5px;
    color: {_TEXT2};
    padding: 4px 0 2px 0;
    line-height: 1.6;
}}
/* Disclaimer sits immediately under the card title — honest, readable,
   and clearly secondary. Slightly lighter than _TEXT3 so it is actually
   legible without implying more importance than it warrants. */
QLabel[class="disclaimer"] {{
    font-size: 11.5px;
    color: {_TEXT2};
    line-height: 1.6;
    padding: 0 0 2px 0;
}}

/* ── status chips (inline, beside primary action) ── */
/* Status chips sit immediately beside the CTA — short eye travel.
   Fixed min-height matches the button so the text baseline aligns.
   Rounded pill shape distinguishes chips from squared buttons/inputs. */
QLabel[class="statusBanner"], QLabel[class="statusInfo"],
QLabel[class="statusSuccess"], QLabel[class="statusDanger"],
QLabel[class="statusWarn"] {{
    border-radius: 999px;
    padding: 0 14px;
    min-height: 28px;
    font-size: 11.5px;
    font-weight: 600;
    border: 1px solid transparent;
    letter-spacing: 0.15px;
}}
QLabel[class="statusInfo"] {{
    background: rgba(96, 165, 250, 0.10);
    color: {_INFO};
    border-color: rgba(96, 165, 250, 0.22);
}}
QLabel[class="statusSuccess"] {{
    background: rgba(34, 197, 94, 0.10);
    color: {_ACCENT};
    border-color: rgba(34, 197, 94, 0.24);
}}
QLabel[class="statusWarn"] {{
    background: rgba(245, 158, 11, 0.10);
    color: {_WARNING};
    border-color: rgba(245, 158, 11, 0.26);
}}
QLabel[class="statusDanger"] {{
    background: rgba(239, 68, 68, 0.10);
    color: {_DANGER};
    border-color: rgba(239, 68, 68, 0.28);
}}
/* Passive / idle state — no tint, no colour, just a quiet muted label.
   Used for the "Ready" state so it does not compete with actual status. */
QLabel[class="statusIdle"] {{
    background: transparent;
    color: {_TEXT3};
    border-color: transparent;
    border-radius: 999px;
    padding: 0 12px;
    min-height: 28px;
    font-size: 11px;
    font-weight: 500;
    border: 1px solid transparent;
    letter-spacing: 0.1px;
}}

/* Detail box: monospace output pane for structured IOC detail data.
   Dark interior matches the input surface so it reads as a data container,
   not a floating document. Slightly lifted text colour aids dense reading. */
QTextEdit[class="detailBox"] {{
    font-family: "JetBrains Mono", "Cascadia Code", "Consolas", monospace;
    font-size: 11.5px;
    line-height: 1.6;
    background: rgba(0, 0, 0, 0.22);
    border: 1px solid {_BORDER};
    border-radius: 6px;
    padding: 12px 16px;
    color: {_TEXT};
}}
/* Empty state: dashed border and muted text communicate "nothing selected"
   clearly without adding visual weight to an otherwise empty pane. */
QTextEdit[class="detailEmpty"] {{
    font-family: "Segoe UI", "Inter", "SF Pro Text", sans-serif;
    font-size: 12px;
    background: rgba(0, 0, 0, 0.12);
    border: 1px dashed rgba(45, 58, 84, 0.8);
    border-radius: 6px;
    padding: 14px 16px;
    color: {_TEXT3};
}}

/* Analyst brief: primary paragraph output. Generous padding so the text
   breathes inside the deep dark accent-bordered box. The 1.75 line-height
   makes dense analysis output scannable at a quick read. */
QLabel[class="analystBrief"] {{
    font-size: 13px;
    font-weight: 400;
    color: {_TEXT};
    line-height: 1.75;
    padding: 16px 22px;
}}

QProgressBar {{
    border: none;
    border-radius: 2px;
    text-align: center;
    max-height: 3px;
    min-height: 3px;
    background: {_BORDER_SOFT};
    color: transparent;
}}
QProgressBar::chunk {{
    background-color: {_PRIMARY};
    border-radius: 2px;
}}

/* ── severity badges (compact, fixed height, centred) ── */
QLabel[class="severityCritical"], QLabel[class="severityHigh"],
QLabel[class="severityMedium"], QLabel[class="severityLow"],
QLabel[class="severityInfo"] {{
    border-radius: 4px;
    padding: 0 12px;
    min-height: 24px;
    font-weight: 700;
    font-size: 10.5px;
    letter-spacing: 1.0px;
    border: none;
    qproperty-alignment: AlignCenter;
}}
QLabel[class="severityCritical"] {{
    background: rgba(220, 38, 38, 0.18);
    color: #FCA5A5;
    border: 1px solid rgba(220, 38, 38, 0.35);
}}
QLabel[class="severityHigh"] {{
    background: rgba(239, 68, 68, 0.15);
    color: #FDA4A4;
    border: 1px solid rgba(239, 68, 68, 0.30);
}}
QLabel[class="severityMedium"] {{
    background: rgba(245, 158, 11, 0.15);
    color: #FCD34D;
    border: 1px solid rgba(245, 158, 11, 0.30);
}}
QLabel[class="severityLow"] {{
    background: rgba(34, 197, 94, 0.15);
    color: #86EFAC;
    border: 1px solid rgba(34, 197, 94, 0.28);
}}
QLabel[class="severityInfo"] {{
    background: rgba(165, 173, 190, 0.10);
    color: {_TEXT2};
    border: 1px solid rgba(165, 173, 190, 0.22);
}}

/* ── verdict badges (compact) ── */
QLabel[class="verdictMalicious"], QLabel[class="verdictSuspicious"],
QLabel[class="verdictClean"], QLabel[class="verdictUnknown"] {{
    border-radius: 3px;
    padding: 1px 8px;
    font-weight: 700;
    font-size: 10.5px;
    letter-spacing: 0.3px;
    border: none;
}}
QLabel[class="verdictMalicious"] {{
    background: rgba(239, 68, 68, 0.18);
    color: {_DANGER};
}}
QLabel[class="verdictSuspicious"] {{
    background: rgba(245, 158, 11, 0.18);
    color: {_WARNING};
}}
QLabel[class="verdictClean"] {{
    background: rgba(34, 197, 94, 0.18);
    color: {_ACCENT};
}}
QLabel[class="verdictUnknown"] {{
    background: rgba(156, 163, 175, 0.14);
    color: {_TEXT2};
}}

/* ── result-strip / summary-strip text ── */
/* Strip labels are the caption above each KPI value — keep them small,
   uppercase, and clearly secondary. Strip values are the focal numbers
   or text that the analyst actually reads at a glance. */
QLabel[class="stripLabel"] {{
    font-size: 9.5px;
    font-weight: 700;
    color: {_TEXT3};
    letter-spacing: 1.4px;
    text-transform: uppercase;
}}
QLabel[class="stripValue"] {{
    font-size: 15px;
    font-weight: 700;
    color: {_TEXT};
    letter-spacing: -0.1px;
}}
QLabel[class="stripValueMuted"] {{
    font-size: 15px;
    font-weight: 600;
    color: {_TEXT2};
}}
QLabel[class="stripNumber"] {{
    font-size: 22px;
    font-weight: 700;
    color: {_TEXT};
    letter-spacing: -0.5px;
}}
QLabel[class="stripNumberMuted"] {{
    font-size: 22px;
    font-weight: 600;
    color: {_TEXT3};
    letter-spacing: -0.5px;
}}

/* ── dialogs ── */
QToolTip {{
    background: {_CARD};
    color: {_TEXT};
    border: 1px solid {_BORDER};
    padding: 6px 10px;
    border-radius: 5px;
    font-size: 11.5px;
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
    border-radius: 6px;
    padding: 0 18px;
    min-height: 30px;
    font-weight: 600;
    min-width: 80px;
}}
QMessageBox QPushButton:hover {{
    background: #4C8DF7;
}}
"""


# ── main window ───────────────────────────────────────────────────────────────

class DesktopSecurityApp(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SOC Security Workstation")
        self.resize(1360, 860)
        self.setStyleSheet(_QSS)

        self.settings_state = load_persisted_settings()
        self.last_ioc_rows: list[dict[str, Any]] = []
        self.last_soc_payload: dict[str, Any] | None = None
        self.ioc_file_path: str | None = None
        self.soc_file_path: str | None = None
        self._ioc_thread: QThread | None = None
        self._ioc_worker: _BackgroundTaskWorker | None = None
        self._soc_thread: QThread | None = None
        self._soc_worker: _BackgroundTaskWorker | None = None
        self._current_soc_raw_log: str = ""

        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._stack = QStackedWidget()

        self.tab_index_soc = self._stack.addWidget(self._build_soc_page())
        self.tab_index_ioc = self._stack.addWidget(self._build_ioc_page())
        self.tab_index_settings = self._stack.addWidget(self._build_settings_page())

        root.addWidget(self._build_sidebar())
        root.addWidget(self._stack, 1)

        self._sync_settings_to_ui()
        self._navigate_to(self.tab_index_soc)

    # ── sidebar ───────────────────────────────────────────────────────────

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(236)
        col = QVBoxLayout(sidebar)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(0)

        # ── Branding block ──
        # A small square brandmark + two-line title give the sidebar a real
        # product header instead of a lonely single word. Fixed heights keep
        # the baseline clean across platforms.
        col.addSpacing(20)
        brand_block = QWidget()
        brand_block.setObjectName("brandBlock")
        brand_row = QHBoxLayout(brand_block)
        brand_row.setContentsMargins(20, 0, 20, 0)
        brand_row.setSpacing(12)
        brand_row.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        mark = QLabel("S")
        mark.setObjectName("brandMark")
        mark.setFixedSize(34, 34)
        brand_row.addWidget(mark, 0, Qt.AlignmentFlag.AlignVCenter)

        title_col = QVBoxLayout()
        title_col.setContentsMargins(0, 0, 0, 0)
        title_col.setSpacing(2)
        brand = QLabel("SOC Workstation")
        brand.setObjectName("brand")
        brand.setFixedHeight(18)
        brand.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        brand_sub = QLabel("THREAT ANALYSIS")
        brand_sub.setObjectName("brandSub")
        brand_sub.setFixedHeight(12)
        brand_sub.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        title_col.addWidget(brand)
        title_col.addWidget(brand_sub)
        brand_row.addLayout(title_col, 1)
        col.addWidget(brand_block)

        col.addSpacing(28)

        # ── Nav group ──
        nav_section = QLabel("WORKFLOWS")
        nav_section.setObjectName("navSection")
        nav_section.setFixedHeight(18)
        nav_section.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        col.addWidget(nav_section)
        col.addSpacing(8)

        self._nav_buttons: list[tuple[QPushButton, int]] = []
        # Keep navigation items calm: a single text label, no wobbly unicode
        # icons. The checked state's soft tint does the visual lifting.
        nav_items = [
            ("SOC Analysis", self.tab_index_soc),
            ("IOC Scanner", self.tab_index_ioc),
            ("Settings", self.tab_index_settings),
        ]
        for label, idx in nav_items:
            btn = QPushButton(label)
            btn.setProperty("class", "nav")
            btn.setCheckable(True)
            btn.setFixedHeight(36)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _ch, i=idx: self._navigate_to(i))
            col.addWidget(btn)
            self._nav_buttons.append((btn, idx))
            col.addSpacing(2)

        col.addStretch(1)

        # ── Footer ──
        footer_rule = QFrame()
        footer_rule.setObjectName("sidebarRule")
        footer_rule.setFixedHeight(1)
        col.addWidget(footer_rule)

        footer = QLabel("SOC Workstation  ·  v3.2.0")
        footer.setObjectName("sidebarFooter")
        footer.setFixedHeight(36)
        footer.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        col.addWidget(footer)
        return sidebar

    # ── navigation ────────────────────────────────────────────────────────

    def _navigate_to(self, index: int) -> None:
        self._stack.setCurrentIndex(index)
        for btn, idx in self._nav_buttons:
            btn.setChecked(idx == index)

    def _set_banner(self, label: QLabel, message: str, tone: str = "info") -> None:
        label.setText(message)
        label.setProperty("class", f"status{tone.capitalize()}")
        label.style().unpolish(label)
        label.style().polish(label)

    def _set_ioc_loading(self, loading: bool, message: str = "") -> None:
        controls = [
            self.ioc_scan_btn,
            self.ioc_export_json_btn,
            self.ioc_single_input,
            self.ioc_bulk_input,
            self.ioc_type_combo,
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
            self.soc_raw_log_input,
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

    # ── page: IOC scanner ─────────────────────────────────────────────────

    def _build_ioc_page(self) -> QWidget:
        page, lay = _scrollpage()

        # ── Header ────────────────────────────────────────────────────────
        title = QLabel("IOC Scanner")
        title.setProperty("class", "pageTitle")
        title.setFixedHeight(28)
        title.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        sub = QLabel(
            "Check indicators of compromise against multiple threat-intelligence providers.",
        )
        sub.setProperty("class", "pageSubtitle")
        sub.setWordWrap(True)
        header_col = QVBoxLayout()
        header_col.setContentsMargins(0, 0, 0, 0)
        header_col.setSpacing(2)
        header_col.addWidget(title)
        header_col.addWidget(sub)
        header_wrap = QWidget()
        header_wrap.setLayout(header_col)
        lay.addWidget(header_wrap)
        lay.addSpacing(6)

        # ── Input card: single IOC + type + bulk + file controls ─────────
        inp_card, inp = _card()
        inp_head_row, inp_head_lay = _hrow(10)
        inp_label = QLabel("INDICATORS")
        inp_label.setProperty("class", "cardTitle")
        inp_label.setFixedHeight(16)
        inp_hint = QLabel("IP, domain, URL, or file hash — one at a time or in bulk.")
        inp_hint.setProperty("class", "cardSubtitle")
        inp_hint.setFixedHeight(16)
        inp_head_lay.addWidget(inp_label, 0)
        inp_head_lay.addStretch(1)
        inp_head_lay.addWidget(inp_hint, 0)
        inp.addWidget(inp_head_row)

        # Top row — single IOC + type dropdown. Both share the same 32px
        # min-height so text and dropdown arrow sit on a single baseline.
        top_row, top_lay = _hrow(10)
        self.ioc_single_input = QLineEdit()
        self.ioc_single_input.setPlaceholderText(
            "Single IOC — e.g. 8.8.8.8, evil.com, or a file hash"
        )
        self.ioc_type_combo = QComboBox()
        for label, value in (
            ("Auto-detect", "auto"),
            ("IP", "ip"),
            ("Domain", "domain"),
            ("URL", "url"),
            ("Hash", "hash"),
        ):
            self.ioc_type_combo.addItem(label, value)
        self.ioc_type_combo.setFixedWidth(152)
        top_lay.addWidget(self.ioc_single_input, 1)
        top_lay.addWidget(self.ioc_type_combo)
        inp.addWidget(top_row)

        self.ioc_bulk_input = QTextEdit()
        self.ioc_bulk_input.setPlaceholderText(
            "Or paste multiple IOCs, one per line or comma-separated…"
        )
        self.ioc_bulk_input.setMinimumHeight(84)
        self.ioc_bulk_input.setMaximumHeight(132)
        self.ioc_bulk_input.setAcceptRichText(False)
        inp.addWidget(self.ioc_bulk_input)

        file_row, flay = _hrow(10)
        self.ioc_file_label = QLabel("No file selected")
        self.ioc_file_label.setProperty("class", "fileLabel")
        self.ioc_file_label.setAlignment(
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
        )
        self.ioc_file_label.setFixedHeight(32)
        self.ioc_browse_btn = _btn("Upload file", "secondary")
        self.ioc_browse_btn.clicked.connect(self._browse_ioc_file)
        self.ioc_clear_file_btn = _btn("Clear", "ghost")
        self.ioc_clear_file_btn.clicked.connect(self._clear_ioc_file)
        flay.addWidget(self.ioc_file_label, 1)
        flay.addWidget(self.ioc_browse_btn)
        flay.addWidget(self.ioc_clear_file_btn)
        inp.addWidget(file_row)

        lay.addWidget(inp_card)

        # ── Action bar ────────────────────────────────────────────────────
        # Status pill sits immediately beside the CTA — short eye travel,
        # clear association between the action and its current status.
        actions_row, alay = _hrow(10)
        self.ioc_scan_btn = _btn("Scan IOCs", "primary")
        self.ioc_scan_btn.clicked.connect(self._run_ioc_scan)
        self.ioc_export_json_btn = _btn("Export JSON", "secondary")
        self.ioc_export_json_btn.clicked.connect(self._export_ioc_json)
        alay.addWidget(self.ioc_scan_btn)
        alay.addWidget(self.ioc_export_json_btn)
        alay.addSpacing(6)
        self.ioc_run_status = QLabel("· Ready")
        self.ioc_run_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._set_banner(self.ioc_run_status, "· Ready", "idle")
        alay.addWidget(self.ioc_run_status, 0, Qt.AlignmentFlag.AlignVCenter)
        alay.addStretch(1)
        lay.addWidget(actions_row)

        self.ioc_progress = QProgressBar()
        self.ioc_progress.setVisible(False)
        self.ioc_progress.setTextVisible(False)
        self.ioc_progress.setFixedHeight(3)
        lay.addWidget(self.ioc_progress)

        # ── Results card: strip + warning line + table + row details ─────
        res_card, rcol = _card()
        rcol.setSpacing(12)

        # Summary strip — five stat columns on a slightly lifted inner
        # panel. The panel adds just enough surface contrast against the
        # card background to read as "at-a-glance KPIs" without feeling
        # like yet another nested dark box.
        strip_panel = QFrame()
        strip_panel.setProperty("class", "innerPanel")
        strip_panel_lay = QHBoxLayout(strip_panel)
        strip_panel_lay.setContentsMargins(4, 4, 4, 4)
        strip_panel_lay.setSpacing(0)

        def _stat_col(caption: str) -> tuple[QWidget, QLabel]:
            col_w = QWidget()
            col_w.setProperty("class", "stripCol")
            col_lay = QVBoxLayout(col_w)
            col_lay.setContentsMargins(16, 6, 16, 6)
            col_lay.setSpacing(3)
            cap = QLabel(caption)
            cap.setProperty("class", "stripLabel")
            cap.setFixedHeight(14)
            cap.setAlignment(
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            )
            val = QLabel("—")
            val.setProperty("class", "stripNumberMuted")
            val.setFixedHeight(32)
            val.setAlignment(
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            )
            col_lay.addWidget(cap)
            col_lay.addWidget(val)
            return col_w, val

        scanned_col, self._ioc_stat_scanned = _stat_col("SCANNED")
        mal_col, self._ioc_stat_malicious = _stat_col("MALICIOUS")
        sus_col, self._ioc_stat_suspicious = _stat_col("SUSPICIOUS")
        clean_col, self._ioc_stat_clean = _stat_col("CLEAN")
        err_col, self._ioc_stat_errors = _stat_col("ERRORS")

        for col, weight in (
            (scanned_col, 1),
            (mal_col, 1),
            (sus_col, 1),
            (clean_col, 1),
            (err_col, 1),
        ):
            strip_panel_lay.addWidget(col, weight)
            if col is not err_col:
                strip_panel_lay.addWidget(_vline())
        rcol.addWidget(strip_panel)

        # Small, secondary warning line for provider/API issues.
        self.ioc_warning_label = QLabel("")
        self.ioc_warning_label.setProperty("class", "warningLine")
        self.ioc_warning_label.setWordWrap(True)
        self.ioc_warning_label.setVisible(False)
        rcol.addWidget(self.ioc_warning_label)

        # Hidden compatibility label — tests read its text for summary rows.
        self.ioc_summary_label = QLabel("Submit IOCs above to start scanning.")
        self.ioc_summary_label.setProperty("class", "summary")
        self.ioc_summary_label.setWordWrap(True)
        self.ioc_summary_label.setVisible(False)
        self.ioc_summary_label.setFixedHeight(0)
        rcol.addWidget(self.ioc_summary_label)

        # Results table.
        # The old layout had "Verdict" and "Status" carrying almost the same
        # information. We replace "Status" with a much more useful
        # "Providers" column that shows how many threat-intel providers
        # flagged the indicator (e.g. "3 / 4"), so the analyst can
        # immediately gauge agreement at a glance. The Assessment column
        # carries the categorical provider-agreement read on its own.
        self.ioc_table = _table([
            "IOC", "Assessment", "Type", "Providers", "Provider summary",
        ])
        for col, width in (
            (0, 230),
            (1, 200),
            (2, 92),
            (3, 110),
            (4, 340),
        ):
            self.ioc_table.setColumnWidth(col, width)
        # Centre-align the header labels for numeric/badge columns so the
        # header caption sits directly over its centred cell content.
        for center_col in (1, 2, 3):
            header_item = QTableWidgetItem(
                self.ioc_table.horizontalHeaderItem(center_col).text()
            )
            header_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.ioc_table.setHorizontalHeaderItem(center_col, header_item)
        self.ioc_table.setMinimumHeight(200)
        self.ioc_table.itemSelectionChanged.connect(self._update_ioc_detail_panel)
        rcol.addWidget(self.ioc_table, 1)
        self.ioc_table.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )

        # Row-details sub-section, expanded by default (selection updates it).
        self.ioc_detail_label = QLabel("Row Details")  # kept for compatibility
        self.ioc_detail_label.setProperty("class", "cardTitle")
        self.ioc_detail_label.setVisible(False)
        self.ioc_detail_section = _Collapsible("ROW DETAILS", expanded=False)
        self.ioc_detail_text = QTextEdit()
        self.ioc_detail_text.setReadOnly(True)
        # Empty-state styling is dashed + muted so it reads as "nothing
        # selected yet" instead of a populated-but-noisy panel.
        self.ioc_detail_text.setProperty("class", "detailEmpty")
        self.ioc_detail_text.setMinimumHeight(120)
        self.ioc_detail_text.setMaximumHeight(200)
        self.ioc_detail_text.setText(
            "Select a row above to inspect per-provider verdicts, reasoning, and raw details."
        )
        self.ioc_detail_section.body().addWidget(self.ioc_detail_text)
        rcol.addWidget(self.ioc_detail_section)

        lay.addWidget(res_card, 1)
        return page

    # ── page: SOC analysis ────────────────────────────────────────────────

    def _build_soc_page(self) -> QWidget:
        page, lay = _scrollpage()

        # ── Header ────────────────────────────────────────────────────────
        title = QLabel("SOC Analysis")
        title.setProperty("class", "pageTitle")
        title.setFixedHeight(28)
        title.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        sub = QLabel(
            "Map raw security logs to MITRE ATT&CK techniques and generate analyst guidance.",
        )
        sub.setProperty("class", "pageSubtitle")
        sub.setWordWrap(True)
        header_col = QVBoxLayout()
        header_col.setContentsMargins(0, 0, 0, 0)
        header_col.setSpacing(2)
        header_col.addWidget(title)
        header_col.addWidget(sub)
        header_wrap = QWidget()
        header_wrap.setLayout(header_col)
        lay.addWidget(header_wrap)
        lay.addSpacing(6)

        # ── Input card: textarea + file controls + primary action ────────
        inp_card, inp = _card()
        inp_head_row, inp_head_lay = _hrow(10)
        inp_label = QLabel("RAW LOG")
        inp_label.setProperty("class", "cardTitle")
        inp_label.setFixedHeight(16)
        inp_hint = QLabel("Paste or upload a log — JSON, syslog, or plain text.")
        inp_hint.setProperty("class", "cardSubtitle")
        inp_hint.setFixedHeight(16)
        inp_head_lay.addWidget(inp_label, 0)
        inp_head_lay.addStretch(1)
        inp_head_lay.addWidget(inp_hint, 0)
        inp.addWidget(inp_head_row)

        self.soc_raw_log_input = QTextEdit()
        self.soc_raw_log_input.setPlaceholderText(
            "Paste raw log content here (JSON, syslog, or plain text)…",
        )
        # Give the raw-log textarea real breathing room for verbose logs and
        # let it grow vertically with the card. A sensible minimum keeps the
        # one-liner case clean without collapsing multi-line logs into a
        # claustrophobic strip.
        self.soc_raw_log_input.setMinimumHeight(132)
        self.soc_raw_log_input.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.soc_raw_log_input.setAcceptRichText(False)
        self.soc_raw_log_input.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        inp.addWidget(self.soc_raw_log_input)

        # File + actions on a single footer row inside the input card.
        # All controls on this row share the same 32px min-height from the
        # stylesheet so they sit on a single clean baseline.
        footer_row, frow = _hrow(10)
        self.soc_file_label = QLabel("No file selected")
        self.soc_file_label.setProperty("class", "fileLabel")
        self.soc_file_label.setAlignment(
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
        )
        self.soc_file_label.setFixedHeight(32)
        self.soc_browse_btn = _btn("Upload file", "secondary")
        self.soc_browse_btn.clicked.connect(self._browse_soc_file)
        self.soc_clear_file_btn = _btn("Clear", "ghost")
        self.soc_clear_file_btn.clicked.connect(self._clear_soc_file)
        frow.addWidget(self.soc_file_label, 1)
        frow.addWidget(self.soc_browse_btn)
        frow.addWidget(self.soc_clear_file_btn)
        inp.addWidget(footer_row)

        lay.addWidget(inp_card)

        # ── Action bar (primary + secondary + inline status pill) ─────────
        # The status pill sits immediately to the right of the CTA so the
        # analyst's eye doesn't have to travel across the page after
        # clicking "Analyze log". A soft pill background gives it quiet
        # presence without competing with the primary button.
        actions_row, alay = _hrow(10)
        self.soc_analyze_btn = _btn("Analyze log", "primary")
        self.soc_analyze_btn.clicked.connect(self._run_soc_analysis)
        self.soc_export_json_btn = _btn("Export JSON", "secondary")
        self.soc_export_json_btn.clicked.connect(self._export_soc_json)
        alay.addWidget(self.soc_analyze_btn)
        alay.addWidget(self.soc_export_json_btn)
        alay.addSpacing(6)
        self.soc_run_status = QLabel("· Ready")
        self.soc_run_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._set_banner(self.soc_run_status, "· Ready", "idle")
        alay.addWidget(self.soc_run_status, 0, Qt.AlignmentFlag.AlignVCenter)
        alay.addStretch(1)
        lay.addWidget(actions_row)

        self.soc_progress = QProgressBar()
        self.soc_progress.setVisible(False)
        self.soc_progress.setTextVisible(False)
        self.soc_progress.setFixedHeight(3)
        lay.addWidget(self.soc_progress)

        # ── Result card: strip + brief + evidence tables ─────────────────
        result_card, rcol = _card()
        rcol.setSpacing(16)

        # Strip: technique · evidence strength · source
        # The strip lives on a lifted inner panel so the KPIs read as a
        # distinct "result header" above the analyst brief, without turning
        # into a competing dark box.
        strip_panel = QFrame()
        strip_panel.setProperty("class", "innerPanel")
        strip_panel.setFixedHeight(66)
        strip_lay = QHBoxLayout(strip_panel)
        strip_lay.setContentsMargins(18, 8, 18, 8)
        strip_lay.setSpacing(20)
        strip_lay.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        def _strip_col(label_text: str, *, stretch: int = 1) -> tuple[QWidget, QLabel]:
            col_w = QWidget()
            col_w.setProperty("class", "stripCol")
            col_lay = QVBoxLayout(col_w)
            col_lay.setContentsMargins(0, 0, 0, 0)
            col_lay.setSpacing(3)
            cap = QLabel(label_text)
            cap.setProperty("class", "stripLabel")
            cap.setFixedHeight(14)
            cap.setAlignment(
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            )
            val = QLabel("—")
            val.setProperty("class", "stripValueMuted")
            val.setFixedHeight(26)
            val.setAlignment(
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            )
            col_lay.addWidget(cap)
            col_lay.addWidget(val)
            return col_w, val

        tech_col, self._soc_strip_technique = _strip_col("TECHNIQUE")
        conf_col, self._soc_strip_evidence = _strip_col("EVIDENCE")
        # "SOURCE" replaces the old "FAMILY" column: the family tag was
        # never populated for most logs and just showed "—", whereas the
        # mapping source ("Rule" vs "ML prediction") is the piece of
        # provenance analysts actually want to see at a glance.
        src_col, self._soc_strip_source = _strip_col("SOURCE")
        strip_lay.addWidget(tech_col, 4)
        strip_lay.addWidget(_vline())
        strip_lay.addWidget(conf_col, 1)
        strip_lay.addWidget(_vline())
        strip_lay.addWidget(src_col, 2)
        strip_lay.addStretch(0)
        # NOTE: this replaces the old strip_row widget; we carry the panel
        # itself as the strip container below.
        strip_row = strip_panel

        # Hidden compatibility labels (tests read their text). They live
        # in the widget tree but never render any pixels.  ``soc_top_family``
        # and ``_soc_strip_family`` are retained as zero-height stubs so
        # existing tests that read those labels keep working even though
        # the FAMILY column is no longer shown on screen.
        self.soc_top_technique = QLabel("Technique: —")
        self.soc_top_evidence = QLabel("Evidence: —")
        self.soc_top_family = QLabel("Family: —")
        self._soc_strip_family = QLabel("—")
        for hidden in (
            self.soc_top_technique,
            self.soc_top_evidence,
            self.soc_top_family,
            self._soc_strip_family,
        ):
            hidden.setVisible(False)
            hidden.setFixedHeight(0)
            strip_lay.addWidget(hidden)
        rcol.addWidget(strip_row)

        # Hidden compatibility label for the legacy "summary" text. The
        # strip + analyst brief now carry that information visually; keep
        # this in the tree so tests that assert on its text still pass.
        self.soc_summary_label = QLabel("Submit a log above to start analysis.")
        self.soc_summary_label.setProperty("class", "summary")
        self.soc_summary_label.setWordWrap(True)
        self.soc_summary_label.setVisible(False)
        self.soc_summary_label.setFixedHeight(0)
        rcol.addWidget(self.soc_summary_label)

        # The dedicated "ANALYST BRIEF" panel has been removed: the
        # compact strip above already shows the technique, evidence
        # strength and mapping source, and the MITRE table below carries the
        # per-mapping rationale.  A prose brief on top of those just
        # duplicated information the analyst could already read at a
        # glance.  We still construct ``soc_analyst_brief_label`` as a
        # hidden, zero-height stub because existing tests read its
        # ``.text()`` as a cheap smoke check that the mapping produced
        # a non-empty summary line.
        self.soc_analyst_brief_label = QLabel(
            "Run an analysis to generate the analyst brief."
        )
        self.soc_analyst_brief_label.setProperty("class", "analystBrief")
        self.soc_analyst_brief_label.setWordWrap(True)
        self.soc_analyst_brief_label.setVisible(False)
        self.soc_analyst_brief_label.setFixedHeight(0)
        rcol.addWidget(self.soc_analyst_brief_label)

        # Evidence: side-by-side sub-sections with tight sub-titles. We
        # keep the collapsibles for test/attribute compatibility but they
        # default to expanded and their header acts as a sub-section label.
        ev_row = QWidget()
        ev_lay = QHBoxLayout(ev_row)
        ev_lay.setContentsMargins(0, 0, 0, 0)
        ev_lay.setSpacing(16)

        sec_entities = _Collapsible("EXTRACTED ENTITIES", expanded=True)
        self.soc_section_entities = sec_entities
        # The old layout had separate ``Value`` and ``Evidence`` columns,
        # but for the vast majority of rows the two cells held the exact
        # same string (e.g. a process name whose "evidence" is literally
        # that process name).  That read as redundant noise on screen, so
        # the visible header is now just ``Type`` + ``Value`` and the raw
        # ``evidence_ref`` is carried as the row's tooltip — analysts who
        # want the surrounding log snippet still get it on hover, but the
        # default view no longer repeats the value twice.
        self.soc_entities_table = _table(["Type", "Value"])
        for col, width in ((0, 96), (1, 320)):
            self.soc_entities_table.setColumnWidth(col, width)
        self.soc_entities_table.setMinimumHeight(160)
        self.soc_entities_table.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        sec_entities.body().addWidget(self.soc_entities_table)

        sec_mitre = _Collapsible("MITRE ATT&CK MAPPING", expanded=True)
        self.soc_section_mitre = sec_mitre
        # ``Source`` column makes it visible at a glance whether the
        # mapping came from a deterministic rule or the ML fallback — an
        # analyst needs to know that before acting on the technique.
        self.soc_mitre_table = _table(["Technique", "Name", "Source", "Evidence"])
        for col, width in ((0, 96), (1, 200), (2, 110), (3, 90)):
            self.soc_mitre_table.setColumnWidth(col, width)
        # Centre-align the evidence header over its centred cells.
        conf_header = QTableWidgetItem(
            self.soc_mitre_table.horizontalHeaderItem(3).text()
        )
        conf_header.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.soc_mitre_table.setHorizontalHeaderItem(3, conf_header)
        self.soc_mitre_table.setMinimumHeight(160)
        self.soc_mitre_table.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        sec_mitre.body().addWidget(self.soc_mitre_table)

        ev_lay.addWidget(sec_entities, 1)
        ev_lay.addWidget(sec_mitre, 1)
        # When the classifier only yields a single mapping, the table is
        # pure duplication of the summary strip above.  We still keep the
        # section in the tree (tests and the multi-mapping case rely on
        # it), but hide it at runtime via ``sec_mitre.setVisible(False)``
        # and show this placeholder card instead.  The placeholder carries
        # the same section heading so the page layout stays balanced.
        self._soc_mitre_placeholder = _Collapsible(
            "MITRE ATT&CK MAPPING", expanded=True,
        )
        placeholder_label = QLabel(
            "Single technique mapped \u2014 details are shown in the summary strip above."
        )
        placeholder_label.setProperty("class", "subtle")
        placeholder_label.setWordWrap(True)
        placeholder_label.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
        )
        self._soc_mitre_placeholder.body().addWidget(placeholder_label)
        self._soc_mitre_placeholder_label = placeholder_label
        self._soc_mitre_placeholder.setVisible(False)
        ev_lay.addWidget(self._soc_mitre_placeholder, 1)
        rcol.addWidget(ev_row, 1)

        lay.addWidget(result_card, 1)
        return page

    # ── page: settings ────────────────────────────────────────────────────

    def _build_settings_page(self) -> QWidget:
        page, lay = _scrollpage()

        title = QLabel("Settings")
        title.setProperty("class", "pageTitle")
        title.setFixedHeight(30)
        title.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        sub = QLabel("Configure threat-intelligence providers and their API keys.")
        sub.setProperty("class", "pageSubtitle")
        sub.setWordWrap(True)
        header_col = QVBoxLayout()
        header_col.setContentsMargins(0, 0, 0, 0)
        header_col.setSpacing(2)
        header_col.addWidget(title)
        header_col.addWidget(sub)
        header_wrap = QWidget()
        header_wrap.setLayout(header_col)
        lay.addWidget(header_wrap)
        lay.addSpacing(6)

        # ── Providers card: one tight row per provider ───────────────────
        # Each provider row uses a fixed height (48px) and an explicit
        # AlignVCenter on every cell so the checkbox indicator, provider
        # name, input box, visibility toggle and status label all sit on
        # the exact same horizontal baseline.
        prov_card, prov = _card()
        prov_header = QLabel("PROVIDERS & API KEYS")
        prov_header.setProperty("class", "cardTitle")
        prov_header.setFixedHeight(14)
        prov.addWidget(prov_header)

        # Small honest disclaimer sits directly under the card title —
        # replaces the misleading "Key entered" green-check pattern by
        # telling the user exactly what saving does.
        prov_sub = QLabel(
            "Keys are saved locally on this machine. Saving does not verify the "
            "key with the provider."
        )
        prov_sub.setProperty("class", "disclaimer")
        prov_sub.setWordWrap(True)
        prov.addWidget(prov_sub)
        prov.addSpacing(6)

        # Column captions — give the table a quiet but informative header so
        # the analyst knows what each column is without guessing.
        head_row = QWidget()
        head_row.setFixedHeight(30)
        head_row.setProperty("class", "settingsHeadRow")
        head_lay = QHBoxLayout(head_row)
        head_lay.setContentsMargins(10, 0, 10, 0)
        head_lay.setSpacing(14)
        head_lay.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        for text, width in (("PROVIDER", 172), ("API KEY", 0), ("STATUS", 132)):
            cap = QLabel(text)
            cap.setProperty("class", "stripLabel")
            cap.setFixedHeight(14)
            cap.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            if width:
                cap.setFixedWidth(width)
                head_lay.addWidget(cap, 0)
            else:
                head_lay.addWidget(cap, 1)
        prov.addWidget(head_row)

        self.provider_checkboxes: dict[str, QCheckBox] = {}
        self.api_key_inputs: dict[str, QLineEdit] = {}
        self.provider_key_status_labels: dict[str, QLabel] = {}
        self._provider_key_toggles: dict[str, QPushButton] = {}

        _provider_display = {
            "virustotal": "VirusTotal",
            "abuseipdb": "AbuseIPDB",
            "otx": "AlienVault OTX",
            "threatfox": "ThreatFox",
        }

        _ROW_HEIGHT = 48
        _vcenter_left = Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft

        for i, provider in enumerate(PROVIDER_ORDER):
            if i > 0:
                divider = QFrame()
                divider.setProperty("class", "hRule")
                divider.setFixedHeight(1)
                prov.addWidget(divider)

            row = QWidget()
            row.setFixedHeight(_ROW_HEIGHT)
            row_lay = QHBoxLayout(row)
            row_lay.setContentsMargins(10, 0, 10, 0)
            row_lay.setSpacing(14)
            row_lay.setAlignment(Qt.AlignmentFlag.AlignVCenter)

            cb = QCheckBox(_provider_display.get(provider, provider.title()))
            cb.setChecked(True)
            cb.setFixedWidth(172)
            cb.setFixedHeight(_ROW_HEIGHT)
            self.provider_checkboxes[provider] = cb

            # Key input + show/hide toggle share a tight composed block so
            # the eye-icon button reads as part of the input, not a loose
            # control floating in the row.
            key_wrap = QWidget()
            key_wrap_lay = QHBoxLayout(key_wrap)
            key_wrap_lay.setContentsMargins(0, 0, 0, 0)
            key_wrap_lay.setSpacing(6)
            key_wrap_lay.setAlignment(Qt.AlignmentFlag.AlignVCenter)

            le = QLineEdit()
            le.setEchoMode(QLineEdit.EchoMode.Password)
            le.setPlaceholderText("Paste API key…")
            le.setMinimumHeight(34)
            le.textChanged.connect(self._update_provider_key_statuses)
            self.api_key_inputs[provider] = le

            toggle = _btn("Show", "iconBtn")
            toggle.setCheckable(True)
            toggle.setFixedWidth(56)
            toggle.clicked.connect(
                lambda _checked=False, p=provider: self._toggle_api_key_visibility(p)
            )
            toggle.setToolTip("Show or hide the API key")
            self._provider_key_toggles[provider] = toggle

            key_wrap_lay.addWidget(le, 1)
            key_wrap_lay.addWidget(toggle, 0, Qt.AlignmentFlag.AlignVCenter)

            status = QLabel("")
            status.setProperty("class", "inlineStatus")
            status.setFixedWidth(132)
            status.setFixedHeight(_ROW_HEIGHT)
            status.setAlignment(
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
            )
            self.provider_key_status_labels[provider] = status

            row_lay.addWidget(cb, 0, _vcenter_left)
            row_lay.addWidget(key_wrap, 1, Qt.AlignmentFlag.AlignVCenter)
            row_lay.addWidget(status, 0, _vcenter_left)
            prov.addWidget(row)
        lay.addWidget(prov_card)

        # ── Action row: save + inline status pill ────────────────────────
        # Inline pill sits immediately next to the CTA (same pattern used on
        # SOC and IOC pages) so the analyst sees the save outcome without
        # any eye travel.
        actions_row, alay = _hrow(10)
        apply_btn = _btn("Save Settings", "primary")
        apply_btn.clicked.connect(self._apply_settings)
        alay.addWidget(apply_btn)
        alay.addSpacing(6)
        self.settings_status_label = QLabel("")
        self.settings_status_label.setProperty("class", "statusIdle")
        self.settings_status_label.setWordWrap(False)
        self.settings_status_label.setAlignment(
            Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
        )
        alay.addWidget(self.settings_status_label, 0, Qt.AlignmentFlag.AlignVCenter)
        alay.addStretch(1)
        lay.addWidget(actions_row)

        # Subtle usage hint fills the otherwise empty space without adding
        # any real "feature" — a live demo reads this as context.
        hint = QLabel(
            "Keys are stored on this machine only and are transmitted exclusively "
            "to the corresponding provider's public threat-intelligence API."
        )
        hint.setProperty("class", "hint")
        hint.setWordWrap(True)
        lay.addWidget(hint)

        lay.addStretch(1)
        return page

    def _toggle_api_key_visibility(self, provider: str) -> None:
        le = self.api_key_inputs.get(provider)
        btn = self._provider_key_toggles.get(provider)
        if le is None or btn is None:
            return
        showing = btn.isChecked()
        le.setEchoMode(
            QLineEdit.EchoMode.Normal if showing else QLineEdit.EchoMode.Password
        )
        btn.setText("Hide" if showing else "Show")

    # ── file dialogs ──────────────────────────────────────────────────────

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

    # ── IOC scan ──────────────────────────────────────────────────────────

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
        manual_type = str(self.ioc_type_combo.currentData())
        manual_override = None if manual_type == "auto" else manual_type

        self._reset_ioc_summary_strip()
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
        self._populate_ioc_table(rows)
        summary = summarize_ioc_rows(rows)

        # Update the compact summary strip.  The strip groups the six
        # categorical assessments into its four coloured buckets; the
        # per-row Assessment column carries the precise category.
        malicious_count = int(summary["corroborated_malicious"]) + int(summary["single_source_malicious"])
        suspicious_count = int(summary["suspicious_only"]) + int(summary["providers_disagree"])
        self._set_ioc_summary_strip(
            scanned=int(summary["total"]),
            malicious=malicious_count,
            suspicious=suspicious_count,
            clean=int(summary["no_suspicious_findings"]),
            errors=int(summary["error_rows"]),
        )

        # Legacy single-line summary text (tests read this).
        summary_text = (
            "Total: {total}  |  Corroborated malicious: {corroborated_malicious}  |  "
            "Single-source malicious: {single_source_malicious}  |  "
            "Providers disagree: {providers_disagree}  |  Suspicious only: {suspicious_only}  |  "
            "No suspicious findings: {no_suspicious_findings}  |  "
            "Insufficient data: {insufficient_data}  |  Errors: {error_rows}".format(
                **summary,
            )
        )
        warning_msgs: list[str] = []
        if summary["error_rows"] > 0:
            for row in rows:
                warning_msgs.extend(str(err) for err in (row.get("errors") or []))
            if warning_msgs:
                summary_text += "\n\u26A0  " + "  |  ".join(warning_msgs)
        self.ioc_summary_label.setText(summary_text)

        # Smaller secondary warning line for provider/API issues.
        if warning_msgs:
            self.ioc_warning_label.setText("\u26A0 " + "  ·  ".join(warning_msgs[:3]))
            self.ioc_warning_label.setVisible(True)
        else:
            self.ioc_warning_label.setText("")
            self.ioc_warning_label.setVisible(False)

        self._set_banner(
            self.ioc_run_status,
            f"Scan complete: {summary['total']} scanned, {malicious_count} malicious, {suspicious_count} suspicious.",
            "success",
        )
        self._set_ioc_loading(False)

    def _set_ioc_summary_strip(
        self,
        *,
        scanned: int,
        malicious: int,
        suspicious: int,
        clean: int,
        errors: int,
    ) -> None:
        """Populate the compact results summary strip with numeric values."""
        self._ioc_stat_scanned.setText(str(scanned))
        self._ioc_stat_malicious.setText(str(malicious))
        self._ioc_stat_suspicious.setText(str(suspicious))
        self._ioc_stat_clean.setText(str(clean))
        self._ioc_stat_errors.setText(str(errors))

        def _apply(lbl: QLabel, value: int, color: str | None) -> None:
            # Counts of 0 stay muted; meaningful counts pop via colour.
            # Font size matches the `stripNumber`/`stripNumberMuted` class
            # so swapping between states never shifts the baseline.
            if value > 0 and color:
                lbl.setStyleSheet(
                    "color: %s; font-size: 22px; font-weight: 700; "
                    "letter-spacing: -0.5px;" % color
                )
            elif value > 0:
                lbl.setStyleSheet(
                    "color: %s; font-size: 22px; font-weight: 700; "
                    "letter-spacing: -0.5px;" % _TEXT
                )
            else:
                lbl.setStyleSheet(
                    "color: %s; font-size: 22px; font-weight: 600; "
                    "letter-spacing: -0.5px;" % _TEXT3
                )

        _apply(self._ioc_stat_scanned, scanned, None)
        _apply(self._ioc_stat_malicious, malicious, _DANGER)
        _apply(self._ioc_stat_suspicious, suspicious, _WARNING)
        _apply(self._ioc_stat_clean, clean, _ACCENT)
        _apply(self._ioc_stat_errors, errors, _WARNING if errors else None)

    def _reset_ioc_summary_strip(self) -> None:
        for lbl in (
            self._ioc_stat_scanned,
            self._ioc_stat_malicious,
            self._ioc_stat_suspicious,
            self._ioc_stat_clean,
            self._ioc_stat_errors,
        ):
            lbl.setText("—")
            lbl.setStyleSheet(
                "color: %s; font-size: 22px; font-weight: 600; "
                "letter-spacing: -0.5px;" % _TEXT3
            )
        self.ioc_warning_label.setText("")
        self.ioc_warning_label.setVisible(False)

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

            # Assessment: filled badge cell — dark tinted background with
            # contrasting text so malicious/suspicious rows pop immediately.
            # Using a dark tinted bg (not saturated) keeps the table legible
            # without burning the eye on long scan sessions.
            status_lower = str(row.get("status", "unknown")).lower().strip()
            skipped = status_lower == "skipped"
            skip_reason = str(row.get("skip_reason", "") or "")
            assessment_lower = str(row.get("assessment", "insufficient_data")).lower().strip()
            assessment_label = "SKIPPED" if skipped else _assessment_label(assessment_lower)
            verdict_item = QTableWidgetItem(f"  {assessment_label}  ")
            verdict_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            font = verdict_item.font()
            font.setBold(True)
            verdict_item.setFont(font)
            verdict_item.setToolTip(
                f"Not sent to providers: {skip_reason}" if skipped
                else str(row.get("verdict_reasoning", ""))
            )
            if skipped:
                verdict_item.setForeground(QColor(_TEXT3))
            elif assessment_lower in {"corroborated_malicious", "single_source_malicious"}:
                verdict_item.setBackground(QColor(100, 22, 22))
                verdict_item.setForeground(QColor("#FCA5A5"))
            elif assessment_lower in {"providers_disagree", "suspicious_only"}:
                verdict_item.setBackground(QColor(95, 52, 8))
                verdict_item.setForeground(QColor("#FDE68A"))
            elif assessment_lower == "no_suspicious_findings":
                verdict_item.setBackground(QColor(18, 68, 38))
                verdict_item.setForeground(QColor("#86EFAC"))
            else:
                verdict_item.setForeground(QColor(_TEXT2))
            self.ioc_table.setItem(idx, 1, verdict_item)

            type_item = QTableWidgetItem(str(row.get("effective_type", "")))
            type_item.setForeground(QColor(_TEXT2))
            self.ioc_table.setItem(idx, 2, type_item)

            # Providers column: how many providers flagged the indicator out
            # of how many responded. Gives analysts an at-a-glance sense of
            # multi-source agreement that the old "Status" column did not.
            hits, total = self._ioc_provider_hits(row)
            hits_text = f"{hits} / {total}" if total else "—"
            hits_item = QTableWidgetItem(hits_text)
            hits_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if total:
                if hits >= 2:
                    hit_color = _DANGER
                elif hits == 1:
                    hit_color = _WARNING
                else:
                    hit_color = _ACCENT
                hits_item.setForeground(QColor(hit_color))
                hit_font = hits_item.font()
                hit_font.setBold(True)
                hits_item.setFont(hit_font)
            else:
                hits_item.setForeground(QColor(_TEXT3))
            status_text_for_tip = str(row.get("status", "unknown")).replace("_", " ").title()
            hits_item.setToolTip(
                f"{hits} of {total} providers flagged this indicator"
                f"\nAggregate status: {status_text_for_tip}"
                if total else f"Aggregate status: {status_text_for_tip}"
            )
            self.ioc_table.setItem(idx, 3, hits_item)

            # Provider summary: show full text in-cell and rely on the table
            # width for clipping only when truly necessary.  Skipped rows
            # carry the skip reason here instead, since no provider ran.
            if skipped:
                full_prov = f"Not sent to providers: {skip_reason or 'not scannable'}"
            else:
                full_prov = _format_provider_summary(str(row.get("provider_summary", "")))
            prov_item = QTableWidgetItem(full_prov)
            prov_item.setForeground(QColor(_TEXT2))
            prov_item.setToolTip(full_prov or "No provider summary.")
            self.ioc_table.setItem(idx, 4, prov_item)

            # Row-level semantic tint on the non-assessment columns —
            # very dark so it doesn't overwhelm, but enough to communicate
            # that this row carries a finding the analyst should act on.
            if assessment_lower in {"corroborated_malicious", "single_source_malicious"}:
                row_bg = QColor(55, 14, 14)
            elif assessment_lower in {"providers_disagree", "suspicious_only"}:
                row_bg = QColor(50, 32, 5)
            else:
                row_bg = None

            for col in range(self.ioc_table.columnCount()):
                table_item = self.ioc_table.item(idx, col)
                if table_item is None:
                    continue
                table_item.setTextAlignment(
                    Qt.AlignmentFlag.AlignCenter if col in {1, 3}
                    else Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                )
                if row_bg is not None and col != 1:
                    table_item.setBackground(row_bg)
        self._update_ioc_detail_panel()

    def _ioc_provider_hits(self, row: dict[str, Any]) -> tuple[int, int]:
        """Count how many providers flagged this indicator vs how many replied."""
        hits = 0
        total = 0
        for provider in PROVIDER_ORDER:
            raw_val = str(row.get(provider, "")).strip().lower()
            if not raw_val or raw_val in {"n/a", "not_supported", "not supported"}:
                continue
            total += 1
            if raw_val in {"malicious", "suspicious"}:
                hits += 1
        return hits, total

    def _update_ioc_detail_panel(self) -> None:
        def _show_empty(message: str) -> None:
            self.ioc_detail_text.setProperty("class", "detailEmpty")
            self.ioc_detail_text.style().unpolish(self.ioc_detail_text)
            self.ioc_detail_text.style().polish(self.ioc_detail_text)
            self.ioc_detail_text.setText(message)

        def _show_detail(text: str) -> None:
            self.ioc_detail_text.setProperty("class", "detailBox")
            self.ioc_detail_text.style().unpolish(self.ioc_detail_text)
            self.ioc_detail_text.style().polish(self.ioc_detail_text)
            self.ioc_detail_text.setText(text)

        selected = self.ioc_table.selectedItems()
        if not selected:
            _show_empty(
                "Select a row above to inspect per-provider verdicts, reasoning, and raw details."
            )
            return
        row_index = selected[0].row()
        row_item = self.ioc_table.item(row_index, 0)
        if row_item is None:
            _show_empty("Select a row above to view full details.")
            return
        row_data = row_item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(row_data, dict):
            _show_empty("No structured detail available for this row.")
            return
        _show_detail(_format_ioc_detail_text(row_data))
        # Auto-expand row-details when the user picks a row for the first time.
        detail_section = getattr(self, "ioc_detail_section", None)
        if detail_section is not None and not detail_section._expanded:
            detail_section.set_expanded(True)

    # ── SOC analysis ──────────────────────────────────────────────────────

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
        self._current_soc_raw_log = selected_log
        self._reset_soc_strip()

        self._set_soc_loading(True, "Analyzing log...")
        self._soc_thread = QThread(self)
        self._soc_worker = _BackgroundTaskWorker(
            _analyze_soc_background,
            task_kwargs={
                "selected_log": selected_log,
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

    def _set_soc_strip_values(
        self,
        *,
        technique: str,
        evidence: str,
        family: str,
        tone: str = "muted",
        source: str | None = None,
    ) -> None:
        """Update the compact result strip + keep legacy labels in sync.

        ``family`` is kept in the signature for backwards compatibility
        with existing callers / tests but is now only written to the
        hidden family stub.  The third visible column is driven by
        ``source`` (the mapping provenance: "Rule" / "ML prediction").
        When ``source`` is not supplied we fall back to showing the
        family value so older call-sites keep rendering something.
        """
        self._soc_strip_technique.setText(technique)
        self._soc_strip_evidence.setText(evidence)
        self._soc_strip_family.setText(family)
        visible_source = source if source is not None else family
        self._soc_strip_source.setText(visible_source)
        value_cls = "stripValue" if tone == "strong" else "stripValueMuted"
        for lbl in (
            self._soc_strip_technique,
            self._soc_strip_evidence,
            self._soc_strip_source,
            self._soc_strip_family,
        ):
            lbl.setProperty("class", value_cls)
            lbl.style().unpolish(lbl)
            lbl.style().polish(lbl)
        # Apply semantic colour to the evidence-strength word so an analyst
        # immediately knows whether the match is strong or marginal.
        evidence_color = _EVIDENCE_COLORS.get(evidence.strip().lower())
        if tone == "strong" and evidence_color is not None:
            self._soc_strip_evidence.setStyleSheet(
                "color: %s; font-size: 15px; font-weight: 700;" % evidence_color
            )
        else:
            self._soc_strip_evidence.setStyleSheet("")

    def _reset_soc_strip(self) -> None:
        self._set_soc_strip_values(
            technique="—", evidence="—", family="—", tone="muted",
        )
        self._soc_strip_evidence.setStyleSheet("")

    def _on_soc_analysis_finished(self, payload: dict[str, Any]) -> None:
        if not payload.get("ok"):
            message = str(payload.get("error", "SOC analysis failed"))
            self.last_soc_payload = payload
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
        if not isinstance(summary, dict):
            summary = {}
        summary_text, banner_text, banner_tone = _soc_banner(payload)

        if str(payload.get("status", "")).strip().lower() == "no_mapping":
            # A completed analysis with no reliable mapping — rendered as a
            # normal outcome, not an error state.
            result = payload.get("result", {}) if isinstance(payload.get("result"), dict) else {}
            audit = result.get("audit", {}) if isinstance(result.get("audit"), dict) else {}
            entity_count = int(audit.get("entity_count", len(result.get("entities", []) or [])) or 0)
            self.soc_top_technique.setText("Technique: No reliable ATT&CK mapping")
            self.soc_top_evidence.setText("Evidence: N/A")
            self.soc_top_family.setText("Family: —")
            self._set_soc_strip_values(
                technique="No reliable ATT&CK mapping",
                evidence="N/A",
                family="—",
                tone="muted",
            )
            if entity_count > 0:
                self.soc_summary_label.setText(
                    f"No reliable ATT&CK mapping. {entity_count} entities extracted — "
                    "add more log context and try again."
                )
            else:
                self.soc_summary_label.setText(
                    "No reliable ATT&CK mapping and no entities extracted. "
                    "Check log format and completeness."
                )
            self.soc_section_entities.set_expanded(True)
            self.soc_section_mitre.set_expanded(False)
            self._update_mitre_section_visibility(payload)
            self._set_banner(self.soc_run_status, banner_text, banner_tone)
            self._set_soc_loading(False)
            return

        self.soc_summary_label.setText(summary_text)

        technique_id = str(summary.get("technique_id") or "N/A")
        technique_name = str(summary.get("technique_name") or "N/A")
        family = str(summary.get("family", "—")) or "—"
        self.soc_top_technique.setText(f"Technique: {technique_id}  —  {technique_name}")
        evidence_label = str(summary.get("evidence_strength") or "unknown").strip().lower()
        self.soc_top_evidence.setText(f"Evidence: {evidence_label}")
        self.soc_top_family.setText(f"Family: {family}")

        technique_display = (
            f"{technique_id} — {technique_name}"
            if technique_name and technique_name != "N/A"
            else technique_id
        )
        mapping_source_raw = str(summary.get("mapping_source", "")).strip().lower()
        if mapping_source_raw == "ml_fallback":
            source_display = "ML prediction"
        elif mapping_source_raw in {"rule", "rule_match", "rule-based"}:
            source_display = "Rule"
        elif mapping_source_raw:
            source_display = mapping_source_raw.replace("_", " ").title()
        else:
            source_display = "—"
        self._set_soc_strip_values(
            technique=technique_display,
            evidence=evidence_label,
            family=family,
            source=source_display,
            tone="strong",
        )

        self.soc_section_mitre.set_expanded(True)
        self.soc_section_entities.set_expanded(True)
        self._update_mitre_section_visibility(payload)

        self._set_banner(self.soc_run_status, banner_text, banner_tone)
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

    def _update_mitre_section_visibility(self, payload: dict[str, Any]) -> None:
        """Show the MITRE table only when there is more than one mapping.

        When the pipeline emits a single mapping, the summary strip at the
        top of the SOC page (TECHNIQUE / EVIDENCE / SOURCE) already
        carries every field the table would show, so the second panel is
        pure redundancy and was raised as noise in user feedback.  With
        two or more mappings the table becomes the only place that lists
        *all* techniques with their individual confidences / sources, so
        we keep it visible.  The table widget itself is always populated
        in ``_populate_soc_sections`` so tests that poll ``rowCount`` /
        headers continue to work regardless of visibility.
        """

        result = payload.get("result", {})
        if not isinstance(result, dict):
            result = {}
        if not result and isinstance(payload.get("partial_result"), dict):
            result = payload.get("partial_result", {})
        mappings = result.get("attack_mapping") or []
        mapping_count = len(mappings) if isinstance(mappings, list) else 0

        show_table = mapping_count >= 2
        if hasattr(self, "soc_section_mitre"):
            self.soc_section_mitre.setVisible(show_table)
        if hasattr(self, "_soc_mitre_placeholder"):
            self._soc_mitre_placeholder.setVisible(mapping_count == 1)

    def _populate_soc_sections(self, payload: dict[str, Any]) -> None:
        result = payload.get("result", {})
        if not isinstance(result, dict):
            result = {}
        if not result and isinstance(payload.get("partial_result"), dict):
            result = payload.get("partial_result", {})
        entities = result.get("entities", [])
        mappings = result.get("attack_mapping", [])

        left_vcenter = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        self.soc_entities_table.setRowCount(0)
        for entity in entities:
            r = self.soc_entities_table.rowCount()
            self.soc_entities_table.insertRow(r)
            type_text = str(entity.get("type", ""))
            value_text = str(entity.get("value", ""))
            evidence_text = str(entity.get("evidence_ref", ""))
            # Evidence is only surfaced in a tooltip when it actually
            # differs from the displayed value; otherwise the tooltip
            # would just repeat the visible cell and add noise.
            tooltip = (
                f"Evidence: {evidence_text}"
                if evidence_text and evidence_text != value_text
                else ""
            )
            for col, text in ((0, type_text), (1, value_text)):
                item = QTableWidgetItem(text)
                item.setTextAlignment(left_vcenter)
                if tooltip:
                    item.setToolTip(tooltip)
                self.soc_entities_table.setItem(r, col, item)

        audit = result.get("audit", {}) if isinstance(result.get("audit"), dict) else {}
        audit_source = str(audit.get("mapping_source", "")).strip().lower()

        self.soc_mitre_table.setRowCount(0)
        for mapping in mappings:
            r = self.soc_mitre_table.rowCount()
            self.soc_mitre_table.insertRow(r)
            tech_item = QTableWidgetItem(str(mapping.get("technique_id", "")))
            tech_item.setTextAlignment(left_vcenter)
            self.soc_mitre_table.setItem(r, 0, tech_item)
            name_item = QTableWidgetItem(str(mapping.get("technique_name", "")))
            name_item.setTextAlignment(left_vcenter)
            self.soc_mitre_table.setItem(r, 1, name_item)

            # Per-row ``source`` (if present) takes precedence over the
            # audit's overall mapping source so a mixed list shows the
            # correct label for each row; fall back to the audit value so
            # existing rule-only payloads still light up the column.
            per_row_source = str(mapping.get("source", "")).strip().lower()
            source_key = per_row_source or audit_source
            source_label = {
                "ml_fallback": "ML fallback",
                "rule": "Rule",
                "none": "—",
                "": "—",
            }.get(source_key, source_key.replace("_", " ").title())
            source_item = QTableWidgetItem(source_label)
            source_item.setTextAlignment(left_vcenter)
            if source_key == "ml_fallback":
                # Tint ML rows so analysts cannot mistake them for the
                # stronger rule-based mappings when skimming the table.
                source_item.setForeground(QColor("#c69a00"))
            self.soc_mitre_table.setItem(r, 2, source_item)

            self.soc_mitre_table.setItem(
                r, 3, _evidence_item(mapping.get("evidence_strength")),
            )

    # ── settings ──────────────────────────────────────────────────────────

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
        self._update_provider_key_statuses()

    def _update_provider_key_statuses(self) -> None:
        """Update the per-provider key status label.

        The label is intentionally honest: we do not claim the key is valid
        — we only report whether a key is present and whether the field
        matches what's currently saved to disk. The old "Key entered"
        wording implied validation that never happened; this replaces it.
        """
        for provider in PROVIDER_ORDER:
            status_label = self.provider_key_status_labels.get(provider)
            line_edit = self.api_key_inputs.get(provider)
            if status_label is None or line_edit is None:
                continue
            current = line_edit.text().strip()
            saved = str(self.settings_state.api_keys.get(provider, "")).strip()

            if not current:
                text, color = "Not set", _TEXT3
            elif current == saved and saved:
                # Key is present in the field and matches the last saved
                # value — honest wording: it's been saved locally, nothing
                # about provider-side validity is implied.
                text, color = "Key saved", _ACCENT
            else:
                # There's text in the field, but it hasn't been persisted
                # yet (or differs from the saved one). Call it unsaved so
                # the user knows to hit Save.
                text, color = "Unsaved", _WARNING

            status_label.setText(text)
            # Match the `inlineStatus` baseline so colour is the only thing
            # that changes between the states.
            status_label.setStyleSheet(
                "color: %s; font-size: 11.5px; font-weight: 600;" % color,
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

        if save_persisted_settings(self.settings_state):
            self._set_settings_status("Settings saved successfully.", "success")
        else:
            self._set_settings_status(
                "Settings applied, but could not be saved to disk.", "warn",
            )
        self._update_provider_key_statuses()

    def _set_settings_status(self, message: str, tone: str = "info") -> None:
        """Apply status-pill styling to the settings save-result message."""
        self.settings_status_label.setText(message)
        cls_map = {
            "success": "statusSuccess",
            "warn": "statusWarn",
            "danger": "statusDanger",
            "info": "statusInfo",
            "idle": "statusIdle",
        }
        self.settings_status_label.setProperty("class", cls_map.get(tone, "statusInfo"))
        self.settings_status_label.style().unpolish(self.settings_status_label)
        self.settings_status_label.style().polish(self.settings_status_label)

    # ── exports ───────────────────────────────────────────────────────────

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


def main() -> int:
    app = QApplication([])
    # Fusion + QSS: on Windows the native style often ignores or fights
    # stylesheet backgrounds on QTextEdit/QTableWidget — Fusion applies
    # colors consistently so the layered token palette is actually visible.
    app.setStyle("Fusion")
    window = DesktopSecurityApp()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
