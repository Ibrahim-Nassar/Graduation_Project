from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QCheckBox,
    QComboBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QToolBox,
    QVBoxLayout,
    QWidget,
)

from src.desktop_services import (
    PROVIDER_ORDER,
    analyze_soc_log,
    collect_iocs,
    default_session_settings,
    export_ioc_csv,
    export_json,
    export_soc_csv,
    load_soc_log_inputs,
    sanitize_api_keys,
    scan_iocs,
    summarize_ioc_rows,
)


def _status_item(value: str) -> QTableWidgetItem:
    item = QTableWidgetItem(value)
    lowered = value.lower()
    if lowered == "malicious":
        item.setForeground(Qt.GlobalColor.red)
    elif lowered == "suspicious":
        item.setForeground(Qt.GlobalColor.yellow)
    elif lowered == "clean":
        item.setForeground(Qt.GlobalColor.green)
    elif lowered in {"error", "invalid"}:
        item.setForeground(Qt.GlobalColor.darkRed)
    return item


class DesktopSecurityApp(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SOC Security Workstation")
        self.resize(1360, 860)

        self.settings_state = default_session_settings()
        self.history_entries: list[dict[str, Any]] = []
        self.last_ioc_rows: list[dict[str, Any]] = []
        self.last_soc_payload: dict[str, Any] | None = None
        self.ioc_file_path: str | None = None
        self.soc_file_path: str | None = None

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.home_tab = self._build_home_tab()
        self.ioc_tab = self._build_ioc_tab()
        self.soc_tab = self._build_soc_tab()
        self.settings_tab = self._build_settings_tab()
        self.history_tab = self._build_history_tab()

        self.tab_index_home = self.tabs.addTab(self.home_tab, "Home")
        self.tab_index_ioc = self.tabs.addTab(self.ioc_tab, "IOC Checker")
        self.tab_index_soc = self.tabs.addTab(self.soc_tab, "SOC Analysis")
        self.tab_index_settings = self.tabs.addTab(self.settings_tab, "Settings")
        self.tab_index_history = self.tabs.addTab(self.history_tab, "History")
        self.tabs.setCurrentIndex(self.tab_index_home)
        self.tabs.setTabVisible(self.tab_index_history, False)

        self._apply_dark_theme()
        self._update_home_metrics()

    def _apply_dark_theme(self) -> None:
        self.setStyleSheet(
            """
            QWidget {
                background-color: #0f172a;
                color: #d1d5db;
                font-size: 12px;
            }
            QGroupBox {
                border: 1px solid #1f2937;
                border-radius: 6px;
                margin-top: 8px;
                padding-top: 8px;
            }
            QGroupBox::title {
                color: #67e8f9;
                left: 8px;
                padding: 0 4px;
            }
            QPushButton {
                background-color: #1d4ed8;
                border: 1px solid #2563eb;
                padding: 6px 10px;
                border-radius: 5px;
                color: #f8fafc;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QLineEdit, QTextEdit, QComboBox, QTableWidget, QListWidget, QToolBox {
                background-color: #111827;
                border: 1px solid #374151;
                border-radius: 4px;
            }
            QHeaderView::section {
                background-color: #1f2937;
                color: #93c5fd;
                border: 0;
                padding: 4px;
            }
            QTabBar::tab {
                background: #111827;
                color: #93c5fd;
                padding: 8px 12px;
            }
            QTabBar::tab:selected {
                background: #1d4ed8;
                color: #f8fafc;
            }
            """
        )

    def _build_home_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        title = QLabel("SOC Security Workstation")
        title.setStyleSheet("font-size: 24px; font-weight: 700; color: #67e8f9;")
        subtitle = QLabel(
            "Unified desktop workflow for IOC checking and SOC log analysis.\n"
            "Use the tabs or quick actions to start."
        )
        subtitle.setWordWrap(True)

        quick_actions = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout(quick_actions)
        open_ioc_button = QPushButton("Open IOC Checker")
        open_soc_button = QPushButton("Open SOC Analysis")
        open_settings_button = QPushButton("Open Settings")
        open_ioc_button.clicked.connect(lambda: self.tabs.setCurrentIndex(self.tab_index_ioc))
        open_soc_button.clicked.connect(lambda: self.tabs.setCurrentIndex(self.tab_index_soc))
        open_settings_button.clicked.connect(lambda: self.tabs.setCurrentIndex(self.tab_index_settings))
        actions_layout.addWidget(open_ioc_button)
        actions_layout.addWidget(open_soc_button)
        actions_layout.addWidget(open_settings_button)

        metrics_group = QGroupBox("Session Overview")
        metrics_layout = QFormLayout(metrics_group)
        self.home_history_metric = QLabel("0")
        self.home_ioc_metric = QLabel("0")
        self.home_soc_metric = QLabel("0")
        metrics_layout.addRow("History entries:", self.home_history_metric)
        metrics_layout.addRow("Last IOC result rows:", self.home_ioc_metric)
        metrics_layout.addRow("SOC result loaded:", self.home_soc_metric)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(quick_actions)
        layout.addWidget(metrics_group)
        layout.addStretch(1)
        return tab

    def _build_ioc_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        input_group = QGroupBox("IOC Inputs")
        form = QFormLayout(input_group)
        self.ioc_single_input = QLineEdit()
        self.ioc_bulk_input = QTextEdit()
        self.ioc_bulk_input.setPlaceholderText("Paste one IOC per line or comma-separated IOC list.")
        self.ioc_bulk_input.setFixedHeight(120)
        self.ioc_type_combo = QComboBox()
        self.ioc_type_combo.addItem("Auto-detect", "auto")
        self.ioc_type_combo.addItem("IP", "ip")
        self.ioc_type_combo.addItem("Domain", "domain")
        self.ioc_type_combo.addItem("URL", "url")
        self.ioc_type_combo.addItem("Hash", "hash")
        self.ioc_use_providers = QCheckBox("Use provider lookups")
        self.ioc_use_providers.setChecked(True)

        file_box = QWidget()
        file_layout = QHBoxLayout(file_box)
        file_layout.setContentsMargins(0, 0, 0, 0)
        self.ioc_file_label = QLabel("No file selected")
        browse_button = QPushButton("Upload IOC File")
        clear_button = QPushButton("Clear")
        browse_button.clicked.connect(self._browse_ioc_file)
        clear_button.clicked.connect(self._clear_ioc_file)
        file_layout.addWidget(self.ioc_file_label, 1)
        file_layout.addWidget(browse_button)
        file_layout.addWidget(clear_button)

        form.addRow("Single IOC:", self.ioc_single_input)
        form.addRow("Bulk IOC paste:", self.ioc_bulk_input)
        form.addRow("IOC file import (.csv/.txt):", file_box)
        form.addRow("Type override:", self.ioc_type_combo)
        form.addRow("", self.ioc_use_providers)

        controls = QWidget()
        controls_layout = QHBoxLayout(controls)
        controls_layout.setContentsMargins(0, 0, 0, 0)
        scan_button = QPushButton("Scan IOCs")
        export_json_button = QPushButton("Export JSON")
        export_csv_button = QPushButton("Export CSV")
        scan_button.clicked.connect(self._run_ioc_scan)
        export_json_button.clicked.connect(self._export_ioc_json)
        export_csv_button.clicked.connect(self._export_ioc_csv)
        controls_layout.addWidget(scan_button)
        controls_layout.addWidget(export_json_button)
        controls_layout.addWidget(export_csv_button)
        controls_layout.addStretch(1)

        self.ioc_summary_label = QLabel("No IOC scan has been run in this session.")

        self.ioc_table = QTableWidget(0, 11)
        self.ioc_table.setHorizontalHeaderLabels(
            [
                "IOC",
                "Detected Type",
                "Effective Type",
                "Status",
                "Score",
                "VirusTotal",
                "AbuseIPDB",
                "OTX",
                "ThreatFox",
                "Provider Summary",
                "Errors",
            ]
        )
        self.ioc_table.horizontalHeader().setStretchLastSection(True)

        layout.addWidget(input_group)
        layout.addWidget(controls)
        layout.addWidget(self.ioc_summary_label)
        layout.addWidget(self.ioc_table, 1)
        return tab

    def _build_soc_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        input_group = QGroupBox("SOC Input")
        form = QFormLayout(input_group)
        self.soc_raw_log_input = QTextEdit()
        self.soc_raw_log_input.setPlaceholderText("Paste raw log content here.")
        self.soc_raw_log_input.setFixedHeight(150)
        self.soc_model_path_input = QLineEdit()
        self.soc_model_path_input.setPlaceholderText("Optional .pkl model for ML fallback")
        self.soc_enrich_toggle = QCheckBox("Enable IOC enrichment in SOC analysis")
        self.soc_enrich_toggle.setChecked(False)

        file_box = QWidget()
        file_layout = QHBoxLayout(file_box)
        file_layout.setContentsMargins(0, 0, 0, 0)
        self.soc_file_label = QLabel("No file selected")
        browse_button = QPushButton("Upload Log File")
        clear_button = QPushButton("Clear")
        browse_button.clicked.connect(self._browse_soc_file)
        clear_button.clicked.connect(self._clear_soc_file)
        file_layout.addWidget(self.soc_file_label, 1)
        file_layout.addWidget(browse_button)
        file_layout.addWidget(clear_button)

        form.addRow("Raw log paste:", self.soc_raw_log_input)
        form.addRow("Log file import (.txt/.log/.json):", file_box)
        form.addRow("Optional model path:", self.soc_model_path_input)
        form.addRow("", self.soc_enrich_toggle)

        controls = QWidget()
        controls_layout = QHBoxLayout(controls)
        controls_layout.setContentsMargins(0, 0, 0, 0)
        analyze_button = QPushButton("Analyze Log")
        export_json_button = QPushButton("Export JSON")
        export_csv_button = QPushButton("Export CSV")
        analyze_button.clicked.connect(self._run_soc_analysis)
        export_json_button.clicked.connect(self._export_soc_json)
        export_csv_button.clicked.connect(self._export_soc_csv)
        controls_layout.addWidget(analyze_button)
        controls_layout.addWidget(export_json_button)
        controls_layout.addWidget(export_csv_button)
        controls_layout.addStretch(1)

        self.soc_summary_label = QLabel("No SOC analysis result available.")

        self.soc_sections = QToolBox()
        self.soc_entities_table = QTableWidget(0, 5)
        self.soc_entities_table.setHorizontalHeaderLabels(["Type", "Value", "Evidence", "Start", "End"])
        self.soc_entities_table.horizontalHeader().setStretchLastSection(True)

        self.soc_mitre_table = QTableWidget(0, 5)
        self.soc_mitre_table.setHorizontalHeaderLabels(
            ["Technique ID", "Technique Name", "Confidence", "Rationale", "Evidence"]
        )
        self.soc_mitre_table.horizontalHeader().setStretchLastSection(True)

        self.soc_epc_text = QTextEdit()
        self.soc_epc_text.setReadOnly(True)

        self.soc_enrichment_table = QTableWidget(0, 5)
        self.soc_enrichment_table.setHorizontalHeaderLabels(
            ["IOC", "Type", "Status", "Score", "Provider Summary"]
        )
        self.soc_enrichment_table.horizontalHeader().setStretchLastSection(True)

        self.soc_sections.addItem(self.soc_entities_table, "Extracted Entities")
        self.soc_sections.addItem(self.soc_mitre_table, "MITRE ATT&CK Mapping")
        self.soc_sections.addItem(self.soc_epc_text, "EPC (Explain / Plan / Checklist)")
        self.soc_sections.addItem(self.soc_enrichment_table, "IOC Enrichment")

        layout.addWidget(input_group)
        layout.addWidget(controls)
        layout.addWidget(self.soc_summary_label)
        layout.addWidget(self.soc_sections, 1)
        return tab

    def _build_settings_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        providers_group = QGroupBox("Providers")
        provider_layout = QFormLayout(providers_group)
        self.provider_checkboxes: dict[str, QCheckBox] = {}
        for provider in PROVIDER_ORDER:
            checkbox = QCheckBox("Enabled")
            checkbox.setChecked(True)
            self.provider_checkboxes[provider] = checkbox
            provider_layout.addRow(provider, checkbox)

        api_group = QGroupBox("API Keys (Session Only)")
        api_layout = QFormLayout(api_group)
        self.api_key_inputs: dict[str, QLineEdit] = {}
        for provider in PROVIDER_ORDER:
            line_edit = QLineEdit()
            line_edit.setEchoMode(QLineEdit.EchoMode.Password)
            line_edit.setPlaceholderText(f"Enter {provider} API key")
            self.api_key_inputs[provider] = line_edit
            api_layout.addRow(provider, line_edit)

        options_group = QGroupBox("Session Options")
        options_layout = QFormLayout(options_group)
        self.history_toggle = QCheckBox("Enable in-session history")
        self.history_toggle.setChecked(False)
        options_layout.addRow("", self.history_toggle)

        controls = QWidget()
        controls_layout = QHBoxLayout(controls)
        controls_layout.setContentsMargins(0, 0, 0, 0)
        apply_button = QPushButton("Apply Session Settings")
        apply_button.clicked.connect(self._apply_settings)
        controls_layout.addWidget(apply_button)
        controls_layout.addStretch(1)

        self.settings_status_label = QLabel("Settings are applied only when you click 'Apply Session Settings'.")

        layout.addWidget(providers_group)
        layout.addWidget(api_group)
        layout.addWidget(options_group)
        layout.addWidget(controls)
        layout.addWidget(self.settings_status_label)
        layout.addStretch(1)
        return tab

    def _build_history_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.history_list = QListWidget()
        self.history_details = QTextEdit()
        self.history_details.setReadOnly(True)
        clear_button = QPushButton("Clear Session History")
        clear_button.clicked.connect(self._clear_history)

        self.history_list.itemClicked.connect(self._show_history_detail)

        layout.addWidget(self.history_list, 1)
        layout.addWidget(self.history_details, 1)
        layout.addWidget(clear_button)
        return tab

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

    def _run_ioc_scan(self) -> None:
        iocs = collect_iocs(
            single_ioc=self.ioc_single_input.text(),
            bulk_text=self.ioc_bulk_input.toPlainText(),
            file_path=self.ioc_file_path,
        )
        if not iocs:
            QMessageBox.warning(self, "No IOC Input", "Enter an IOC, paste bulk data, or upload an IOC file.")
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
        self.ioc_summary_label.setText(
            "Total: {total} | Malicious: {malicious} | Suspicious: {suspicious} | "
            "Clean: {clean} | Unknown: {unknown} | Rows with provider errors: {error_rows}".format(**summary)
        )
        self._append_history("IOC scan", f"Scanned {len(rows)} IOC(s).", {"summary": summary, "rows": rows})
        self._update_home_metrics()

    def _populate_ioc_table(self, rows: list[dict[str, Any]]) -> None:
        self.ioc_table.setRowCount(0)
        for row in rows:
            index = self.ioc_table.rowCount()
            self.ioc_table.insertRow(index)
            self.ioc_table.setItem(index, 0, QTableWidgetItem(str(row.get("ioc", ""))))
            self.ioc_table.setItem(index, 1, QTableWidgetItem(str(row.get("detected_type", ""))))
            self.ioc_table.setItem(index, 2, QTableWidgetItem(str(row.get("effective_type", ""))))
            self.ioc_table.setItem(index, 3, _status_item(str(row.get("status", "unknown"))))
            self.ioc_table.setItem(index, 4, QTableWidgetItem(str(row.get("score", 0))))
            self.ioc_table.setItem(index, 5, QTableWidgetItem(str(row.get("virustotal", "n/a"))))
            self.ioc_table.setItem(index, 6, QTableWidgetItem(str(row.get("abuseipdb", "n/a"))))
            self.ioc_table.setItem(index, 7, QTableWidgetItem(str(row.get("otx", "n/a"))))
            self.ioc_table.setItem(index, 8, QTableWidgetItem(str(row.get("threatfox", "n/a"))))
            self.ioc_table.setItem(index, 9, QTableWidgetItem(str(row.get("provider_summary", ""))))
            self.ioc_table.setItem(index, 10, QTableWidgetItem(str(row.get("error_count", 0))))

    def _run_soc_analysis(self) -> None:
        selected_log = load_soc_log_inputs(self.soc_raw_log_input.toPlainText(), self.soc_file_path)
        if not selected_log:
            QMessageBox.warning(self, "No Log Input", "Paste raw log text or upload a log file.")
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
            "Technique: {technique_id} ({technique_name}) | Confidence: {confidence:.3f} | "
            "Source: {mapping_source} | Entities: {entity_count}".format(
                technique_id=summary.get("technique_id", "N/A"),
                technique_name=summary.get("technique_name", "N/A"),
                confidence=float(summary.get("confidence", 0.0) or 0.0),
                mapping_source=summary.get("mapping_source", "unknown"),
                entity_count=int(summary.get("entity_count", 0) or 0),
            )
        )
        self._append_history("SOC analysis", "Analyzed one log event.", payload)
        self._update_home_metrics()

    def _populate_soc_sections(self, payload: dict[str, Any]) -> None:
        result = payload.get("result", {})
        entities = result.get("entities", [])
        mappings = result.get("attack_mapping", [])
        epc = result.get("epc", {})
        enrichment = result.get("audit", {}).get("ioc_enrichment", [])

        self.soc_entities_table.setRowCount(0)
        for entity in entities:
            row = self.soc_entities_table.rowCount()
            self.soc_entities_table.insertRow(row)
            self.soc_entities_table.setItem(row, 0, QTableWidgetItem(str(entity.get("type", ""))))
            self.soc_entities_table.setItem(row, 1, QTableWidgetItem(str(entity.get("value", ""))))
            self.soc_entities_table.setItem(row, 2, QTableWidgetItem(str(entity.get("evidence_ref", ""))))
            self.soc_entities_table.setItem(row, 3, QTableWidgetItem(str(entity.get("start", ""))))
            self.soc_entities_table.setItem(row, 4, QTableWidgetItem(str(entity.get("end", ""))))

        self.soc_mitre_table.setRowCount(0)
        for mapping in mappings:
            row = self.soc_mitre_table.rowCount()
            self.soc_mitre_table.insertRow(row)
            self.soc_mitre_table.setItem(row, 0, QTableWidgetItem(str(mapping.get("technique_id", ""))))
            self.soc_mitre_table.setItem(row, 1, QTableWidgetItem(str(mapping.get("technique_name", ""))))
            self.soc_mitre_table.setItem(row, 2, QTableWidgetItem(str(mapping.get("confidence", ""))))
            self.soc_mitre_table.setItem(row, 3, QTableWidgetItem(str(mapping.get("rationale", ""))))
            evidence = ", ".join(str(item) for item in mapping.get("evidence_refs", []))
            self.soc_mitre_table.setItem(row, 4, QTableWidgetItem(evidence))

        epc_text = (
            f"Explain:\n{epc.get('explain', '')}\n\n"
            f"Plan:\n- " + "\n- ".join(str(item) for item in epc.get("plan", [])) + "\n\n"
            f"Checklist:\n- " + "\n- ".join(str(item) for item in epc.get("checklist", [])) + "\n\n"
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
            row = self.soc_enrichment_table.rowCount()
            self.soc_enrichment_table.insertRow(row)
            self.soc_enrichment_table.setItem(row, 0, QTableWidgetItem(str(item.get("ioc", ""))))
            self.soc_enrichment_table.setItem(row, 1, QTableWidgetItem(str(item.get("type", ""))))
            self.soc_enrichment_table.setItem(row, 2, _status_item(str(item.get("status", "unknown"))))
            self.soc_enrichment_table.setItem(row, 3, QTableWidgetItem(str(item.get("score", 0))))
            self.soc_enrichment_table.setItem(row, 4, QTableWidgetItem(provider_summary))

    def _apply_settings(self) -> None:
        providers = {name: checkbox.isChecked() for name, checkbox in self.provider_checkboxes.items()}
        api_keys = {name: line_edit.text() for name, line_edit in self.api_key_inputs.items()}
        self.settings_state.providers = providers
        self.settings_state.api_keys = sanitize_api_keys(api_keys)
        self.settings_state.history_enabled = self.history_toggle.isChecked()

        self.tabs.setTabVisible(self.tab_index_history, self.settings_state.history_enabled)
        if not self.settings_state.history_enabled:
            self.tabs.setCurrentIndex(self.tab_index_home)

        self.settings_status_label.setText("Session settings applied.")
        self._update_home_metrics()

    def _append_history(self, action: str, summary: str, payload: dict[str, Any]) -> None:
        if not self.settings_state.history_enabled:
            return
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "summary": summary,
            "payload": payload,
        }
        self.history_entries.append(entry)
        item_text = f"{entry['timestamp']} | {entry['action']} | {entry['summary']}"
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

    def _export_ioc_json(self) -> None:
        if not self.last_ioc_rows:
            QMessageBox.information(self, "No IOC Results", "Run an IOC scan before exporting.")
            return
        selected, _ = QFileDialog.getSaveFileName(self, "Export IOC JSON", "", "JSON Files (*.json)")
        if not selected:
            return
        payload = [{"row": {k: v for k, v in row.items() if k != "raw"}, "raw": row.get("raw")} for row in self.last_ioc_rows]
        export_json(selected, payload)
        QMessageBox.information(self, "Export Complete", f"IOC results exported to:\n{selected}")

    def _export_ioc_csv(self) -> None:
        if not self.last_ioc_rows:
            QMessageBox.information(self, "No IOC Results", "Run an IOC scan before exporting.")
            return
        selected, _ = QFileDialog.getSaveFileName(self, "Export IOC CSV", "", "CSV Files (*.csv)")
        if not selected:
            return
        export_ioc_csv(selected, self.last_ioc_rows)
        QMessageBox.information(self, "Export Complete", f"IOC results exported to:\n{selected}")

    def _export_soc_json(self) -> None:
        if not self.last_soc_payload:
            QMessageBox.information(self, "No SOC Result", "Run SOC analysis before exporting.")
            return
        selected, _ = QFileDialog.getSaveFileName(self, "Export SOC JSON", "", "JSON Files (*.json)")
        if not selected:
            return
        export_json(selected, self.last_soc_payload)
        QMessageBox.information(self, "Export Complete", f"SOC result exported to:\n{selected}")

    def _export_soc_csv(self) -> None:
        if not self.last_soc_payload:
            QMessageBox.information(self, "No SOC Result", "Run SOC analysis before exporting.")
            return
        selected, _ = QFileDialog.getSaveFileName(self, "Export SOC CSV", "", "CSV Files (*.csv)")
        if not selected:
            return
        export_soc_csv(selected, self.last_soc_payload)
        QMessageBox.information(self, "Export Complete", f"SOC result exported to:\n{selected}")

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
