"""Findings window (FR-UI-02): run an audit on a snapshot file or a fixture folder, then filter the results.

Run from the repository root:  python -m kerbo_s.ui.main_window
(Install requirements first. Needs a desktop session.)
"""
from __future__ import annotations

import sys

from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QHBoxLayout, QLabel, QMainWindow, QMessageBox,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from kerbo_s.config import Config
from kerbo_s.engine import run_audit
from kerbo_s.parsers.kadmin import load_fixture_dir
from kerbo_s.snapshot.io import SnapshotError, load_snapshot
from kerbo_s.ui.findings_view import (
    CATEGORY_FILTER, HEADERS, SEVERITY_FILTER, counts_text, filter_findings, row_values,
)

RULES_CONFIG = "config/rules.yaml"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kerbo-S: Kerberos Security Auditor")
        self.resize(1100, 560)
        self.findings = []

        self.button = QPushButton("Run Audit (choose snapshot)")
        self.button.clicked.connect(self.run_audit)
        self.folder_button = QPushButton("Run Audit (choose fixture folder)")
        self.folder_button.clicked.connect(self.run_folder_audit)

        self.severity = QComboBox()
        self.severity.addItems(SEVERITY_FILTER)
        self.category = QComboBox()
        self.category.addItems(CATEGORY_FILTER)
        self.severity.currentTextChanged.connect(self.refresh)
        self.category.currentTextChanged.connect(self.refresh)
        self.counts = QLabel(counts_text([]))

        self.table = QTableWidget(0, len(HEADERS))
        self.table.setHorizontalHeaderLabels(HEADERS)

        buttons = QHBoxLayout()
        buttons.addWidget(self.button)
        buttons.addWidget(self.folder_button)
        filters = QHBoxLayout()
        filters.addWidget(QLabel("Severity:"))
        filters.addWidget(self.severity)
        filters.addWidget(QLabel("Category:"))
        filters.addWidget(self.category)
        filters.addStretch(1)
        filters.addWidget(self.counts)

        layout = QVBoxLayout()
        layout.addLayout(buttons)
        layout.addLayout(filters)
        layout.addWidget(self.table)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def run_audit(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose snapshot", "tests/fixtures", "JSON (*.json)")
        if not path:
            return
        try:
            snapshot = load_snapshot(path)
        except SnapshotError as exc:
            QMessageBox.critical(self, "Cannot load snapshot", str(exc))
            return
        self.show_findings(run_audit(snapshot, Config.load(RULES_CONFIG)))

    def run_folder_audit(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose fixture folder", "tests/fixtures")
        if not folder:
            return
        try:
            snapshot = load_fixture_dir(folder)
        except (FileNotFoundError, ValueError) as exc:
            QMessageBox.critical(self, "Cannot load fixture folder", str(exc))
            return
        self.show_findings(run_audit(snapshot, Config.load(RULES_CONFIG)))
        if snapshot.errors:
            QMessageBox.warning(self, "Some input could not be read",
                                "\n".join(f"{source}: {message}" for source, message in snapshot.errors[:10]))

    def show_findings(self, findings):
        self.findings = findings
        self.refresh()

    def refresh(self, *_):
        rows = filter_findings(self.findings, self.severity.currentText(), self.category.currentText())
        self.table.setRowCount(len(rows))
        for row, finding in enumerate(rows):
            for col, value in enumerate(row_values(finding)):
                self.table.setItem(row, col, QTableWidgetItem(str(value)))
        self.counts.setText(counts_text(self.findings))


def main() -> int:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
