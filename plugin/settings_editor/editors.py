"""Setting editor widget helpers."""

from typing import Callable, Tuple

try:
    from PyQt5.QtWidgets import QCheckBox, QLineEdit, QComboBox, QWidget
except ImportError:
    from PySide6.QtWidgets import QCheckBox, QLineEdit, QComboBox, QWidget

from hcli.lib.ida.plugin import PluginSettingDescriptor


def create_boolean_editor(descriptor: PluginSettingDescriptor) -> Tuple[QWidget, Callable, Callable]:
    """Create a checkbox editor for boolean settings.

    Returns:
        (widget, get_value_func, set_value_func)
    """
    checkbox = QCheckBox()

    def get_value():
        return checkbox.isChecked()

    def set_value(value):
        if value is None:
            checkbox.setChecked(bool(descriptor.default) if descriptor.default is not None else False)
        else:
            checkbox.setChecked(bool(value))

    return checkbox, get_value, set_value


def create_string_editor(descriptor: PluginSettingDescriptor) -> Tuple[QWidget, Callable, Callable]:
    """Create a text input or combobox editor for string settings.

    Returns:
        (widget, get_value_func, set_value_func)
    """
    if descriptor.choices:
        combobox = QComboBox()
        combobox.setEditable(False)
        combobox.addItem("")
        combobox.addItems(descriptor.choices)

        def get_value():
            text = combobox.currentText()
            return text if text else None

        def set_value(value):
            if value is None or value == "":
                combobox.setCurrentIndex(0)
            else:
                index = combobox.findText(str(value))
                if index >= 0:
                    combobox.setCurrentIndex(index)

        return combobox, get_value, set_value
    else:
        lineedit = QLineEdit()
        if descriptor.default is not None:
            lineedit.setPlaceholderText(str(descriptor.default))

        def get_value():
            text = lineedit.text()
            return text if text else None

        def set_value(value):
            if value is None or value == "":
                lineedit.clear()
            else:
                lineedit.setText(str(value))

        return lineedit, get_value, set_value


def create_editor_for_setting(descriptor: PluginSettingDescriptor) -> Tuple[QWidget, Callable, Callable]:
    """Create appropriate editor widget for setting type.

    Returns:
        (widget, get_value_func, set_value_func)
    """
    if descriptor.type == "boolean":
        return create_boolean_editor(descriptor)
    elif descriptor.type == "string":
        return create_string_editor(descriptor)
    else:
        raise ValueError(f"Unsupported setting type: {descriptor.type}")
