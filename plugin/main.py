#!/usr/bin/env python3
"""Standalone Qt application for testing the settings editor outside IDA Pro.

This application loads the settings editor UI components without requiring IDA Pro.
It uses the same MVC architecture as the IDA plugin but wraps it in a standalone
QApplication instead of ida_kernwin.PluginForm.

Usage:
    python plugin/main.py
"""

import sys

try:
    from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout
    from PyQt5.QtCore import Qt
except ImportError:
    from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout
    from PySide6.QtCore import Qt

from settings_editor.model import SettingsModel
from settings_editor.view import settings_manager_widget_t
from settings_editor.controller import SettingsController


class StandaloneSettingsWindow(QWidget):
    """Standalone window for settings editor."""

    def __init__(self):
        """Initialize standalone settings window."""
        super().__init__()
        self.setWindowTitle("Plugin Settings Manager (Standalone)")
        self.resize(900, 600)

        self.model = SettingsModel()
        self.view = settings_manager_widget_t(self)
        self.controller = SettingsController(self.model, self.view)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.view)
        self.setLayout(layout)


def main():
    """Main entry point for standalone application."""
    app = QApplication(sys.argv)

    window = StandaloneSettingsWindow()
    window.show()

    return app.exec() if hasattr(app, 'exec') else app.exec_()


if __name__ == "__main__":
    sys.exit(main())
