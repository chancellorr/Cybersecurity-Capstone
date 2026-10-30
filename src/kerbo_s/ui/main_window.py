"""Walking-skeleton window: choose a snapshot, run the audit, show findings in a table.

Run from the repository root:  python -m kerbo_s.ui.main_window
(Install requirements first. Needs a desktop session.)
"""
from __future__ import annotations

import sys

from PyQt6.QtWidgets import (
    QApplication, QFileDialog, QMainWindow, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from kerbo_s.config import Config
from kerbo_s.engine import run_audit
from kerbo_s.snapshot.io import load_snapshot

HEADERS = ["Severity", "Score", "Rule", "Object", "Observed", "Threshold"]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kerbo-S: Kerberos Security Auditor")
        self.resize(900, 500)
        self.button = QPushButton("Run Audit (choose snapshot)")
        self.button.clicked.connect(self.run_audit)
        self.table = QTableWidget(0, len(HEADERS))
        self.table.setHorizontalHeaderLabels(HEADERS)
        layout = QVBoxLayout()
        layout.addWidget(self.button)
        layout.addWidget(self.table)
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def run_audit(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose snapshot", "tests/fixtures", "JSON (*.json)")
        if not path:
            return
        findings = run_audit(load_snapshot(path), Config.load("config/rules.yaml"))
        self.table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            values = [f.severity, f.score, f.rule_id, f.object_id, f.observed, f.threshold]
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(str(value)))


def main() -> int:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
