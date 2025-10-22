"""Settings view widgets."""

try:
    from PyQt5.QtWidgets import (
        QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
        QListWidget, QScrollArea, QSplitter, QFormLayout,
        QComboBox, QLineEdit
    )
    from PyQt5.QtCore import Qt, pyqtSignal as Signal
    from PyQt5.QtGui import QIcon
except ImportError:
    from PySide6.QtWidgets import (
        QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
        QListWidget, QScrollArea, QSplitter, QFormLayout,
        QComboBox, QLineEdit
    )
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtGui import QIcon

from hcli.lib.ida.plugin import PluginSettingDescriptor
from settings_editor.editors import create_editor_for_setting


class setting_editor_row_t(QWidget):
    """Widget for editing a single setting."""

    valueChanged = Signal(str, object)
    deleteRequested = Signal(str)

    def __init__(self, descriptor: PluginSettingDescriptor, parent=None):
        """Initialize setting editor row."""
        super().__init__(parent)
        self.descriptor = descriptor
        self._setup_ui()

    def _setup_ui(self):
        """Setup UI components."""
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 5, 0, 5)

        row_layout = QHBoxLayout()
        row_layout.setSpacing(10)

        self.name_label = QLabel(self.descriptor.name)
        self.name_label.setMinimumWidth(100)
        self.name_label.setMaximumWidth(100)
        self.name_label.setWordWrap(True)
        self.name_label.setAlignment(Qt.AlignTop)
        row_layout.addWidget(self.name_label)

        editor_container = QVBoxLayout()
        editor_container.setSpacing(3)

        self.editor_widget, self._get_value, self._set_value = create_editor_for_setting(self.descriptor)
        editor_container.addWidget(self.editor_widget)

        if self.descriptor.type == "boolean":
            self.editor_widget.stateChanged.connect(self._on_value_changed)
        elif isinstance(self.editor_widget, QLineEdit):
            self.editor_widget.textChanged.connect(self._on_value_changed)
        elif isinstance(self.editor_widget, QComboBox):
            self.editor_widget.currentTextChanged.connect(self._on_value_changed)

        if self.descriptor.documentation:
            self.doc_label = QLabel(self.descriptor.documentation)
            self.doc_label.setStyleSheet("color: gray; font-size: 10px;")
            self.doc_label.setWordWrap(True)
            editor_container.addWidget(self.doc_label)

        self.default_label = None
        if self.descriptor.default is not None:
            default_text = str(self.descriptor.default)
            if self.descriptor.type == "boolean":
                default_text = "true" if self.descriptor.default else "false"
            self.default_label = QLabel(f'<span style="color: gray; font-size: 10px;">default: {default_text}</span>')
            self.default_label.setVisible(False)
            editor_container.addWidget(self.default_label)

        self.error_label = QLabel()
        self.error_label.setStyleSheet("color: red; font-size: 10px;")
        self.error_label.setWordWrap(True)
        self.error_label.setVisible(False)
        editor_container.addWidget(self.error_label)

        row_layout.addLayout(editor_container, 1)

        self.delete_button = QPushButton("✖")
        self.delete_button.setMinimumWidth(40)
        self.delete_button.setMaximumWidth(40)
        self.delete_button.clicked.connect(lambda: self.deleteRequested.emit(self.descriptor.key))

        if self.descriptor.required and self.descriptor.default is None:
            self.delete_button.setEnabled(False)
            self.delete_button.setToolTip("Required settings cannot be deleted")

        row_layout.addWidget(self.delete_button, alignment=Qt.AlignTop)

        main_layout.addLayout(row_layout)
        self.setLayout(main_layout)

    def _on_value_changed(self):
        """Handle value change."""
        value = self._get_value()
        self.valueChanged.emit(self.descriptor.key, value)

    def get_value(self):
        """Get current editor value."""
        return self._get_value()

    def set_value(self, value):
        """Set editor value."""
        self._set_value(value)

    def show_error(self, message: str):
        """Show error message."""
        self.error_label.setText(f"⚠ {message}")
        self.error_label.setVisible(True)

    def hide_error(self):
        """Hide error message."""
        self.error_label.setVisible(False)

    def set_explicit(self, is_explicit: bool):
        """Enable/disable delete button and show/hide default label based on explicit setting."""
        if self.descriptor.required and self.descriptor.default is None:
            self.delete_button.setEnabled(False)
            self.delete_button.setToolTip("Required settings cannot be deleted")
        else:
            self.delete_button.setEnabled(is_explicit)
            if is_explicit:
                self.delete_button.setToolTip("Delete this setting to revert to default value")
            else:
                self.delete_button.setToolTip("")

        if self.default_label:
            self.default_label.setVisible(not is_explicit)


class settings_editor_view_t(QScrollArea):
    """Scrollable area for settings editors."""

    def __init__(self, parent=None):
        """Initialize settings editor view."""
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.editor_rows = {}

        self.content_widget = QWidget()
        self.layout = QVBoxLayout()
        self.layout.addStretch()
        self.content_widget.setLayout(self.layout)
        self.setWidget(self.content_widget)

    def clear_editors(self):
        """Clear all editor rows."""
        for row in self.editor_rows.values():
            row.deleteLater()
        self.editor_rows = {}

    def add_editor_row(self, key: str, row: setting_editor_row_t):
        """Add an editor row."""
        self.editor_rows[key] = row
        self.layout.insertWidget(self.layout.count() - 1, row)

    def get_editor_row(self, key: str) -> setting_editor_row_t:
        """Get editor row by key."""
        return self.editor_rows.get(key)

    def show_message(self, message: str):
        """Show a message in the editor area."""
        self.clear_editors()
        label = QLabel(message)
        label.setStyleSheet("color: gray; padding: 20px;")
        label.setAlignment(Qt.AlignCenter)
        self.layout.insertWidget(0, label)


class plugin_list_view_t(QListWidget):
    """List widget for displaying plugins."""

    def __init__(self, parent=None):
        """Initialize plugin list view."""
        super().__init__(parent)


class settings_manager_widget_t(QWidget):
    """Main settings manager widget."""

    def __init__(self, parent=None):
        """Initialize settings manager widget."""
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        """Setup UI components."""
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Horizontal)

        self.plugin_list = plugin_list_view_t()
        self.plugin_list.setMaximumWidth(250)
        splitter.addWidget(self.plugin_list)

        self.settings_editor = settings_editor_view_t()
        splitter.addWidget(self.settings_editor)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)

        layout.addWidget(splitter)
        self.setLayout(layout)
