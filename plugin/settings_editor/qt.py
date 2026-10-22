"""Qt binding selection.

IDA 9.2+ ships PySide6. It answers a PyQt5 import with a compatibility shim
that, on first use, shows a modal dialog asking the user to enable the shim
(and blocks scripted GUI starts until someone clicks). So PySide6 must be
imported first, and PyQt5 only on IDA before 9.2, which ships PyQt5 alone.

On IDA before 9.2 we don't merely try PySide6 and fall back: a PySide6 that
the user pip-installed would bring its own Qt, distinct from IDA's.
"""


def _ida_kernel_version() -> tuple[int, ...] | None:
    try:
        import ida_kernwin
    except ImportError:
        return None

    return tuple(
        int(part)
        for part in ida_kernwin.get_kernel_version().split(".")
        if part.isdigit()
    ) or (0,)


def _use_pyqt5() -> bool:
    version = _ida_kernel_version()
    if version is not None:
        return version < (9, 2)

    # outside IDA (plugin/main.py): use whichever binding is installed, PySide6 first.
    try:
        import PySide6  # noqa: F401
    except ImportError:
        return True
    return False


if _use_pyqt5():
    from PyQt5.QtCore import QObject, Qt
    from PyQt5.QtCore import pyqtSignal as Signal
    from PyQt5.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QPushButton,
        QScrollArea,
        QSplitter,
        QVBoxLayout,
        QWidget,
    )
else:
    from PySide6.QtCore import QObject, Qt, Signal
    from PySide6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QPushButton,
        QScrollArea,
        QSplitter,
        QVBoxLayout,
        QWidget,
    )

__all__ = [
    "QApplication",
    "QCheckBox",
    "QComboBox",
    "QHBoxLayout",
    "QLabel",
    "QLineEdit",
    "QListWidget",
    "QListWidgetItem",
    "QObject",
    "QPushButton",
    "QScrollArea",
    "QSplitter",
    "QVBoxLayout",
    "QWidget",
    "Qt",
    "Signal",
]
