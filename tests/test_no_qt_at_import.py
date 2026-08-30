"""Importing ``ida_settings`` must not pull in a Qt binding.

The modern API (``get_current_plugin_setting`` and friends) comes from
``hcli.lib.ida.plugin.settings``, which touches no Qt at all. But
``__init__`` imports ``.legacy``, and ``legacy`` calls ``import_qtcore()``
at module scope -- so every consumer of the modern API loads Qt as a side
effect.

Inside a non-GUI IDA that is not merely wasteful, it is fatal. IDA answers a
PyQt5 import with its own compatibility shim, which constructs a QMessageBox
(<IDA>/python/PyQt5/utils.py:119 confirm_decision). A QWidget with no
QApplication calls qFatal(), so the process dies with SIGABRT -- and because
that is an abort() rather than an exception, the ``except (ImportError,
NotImplementedError)`` guard in ``__init__`` cannot catch it.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"

QT_MODULES = ("PyQt5", "PySide6", "PyQt5.QtCore", "PySide6.QtCore")


def _run(body: str) -> subprocess.CompletedProcess:
    """Run a snippet in a clean interpreter; import state is process-global."""
    script = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {str(SRC)!r})
        {textwrap.indent(textwrap.dedent(body), " " * 8).lstrip()}
        """
    )
    return subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=120
    )


def test_importing_the_package_loads_no_qt_binding() -> None:
    result = _run(
        """
        import ida_settings
        loaded = sorted(m for m in sys.modules if m.split(".")[0] in ("PyQt5", "PySide6"))
        print("LOADED:" + ",".join(loaded))
        """
    )

    assert result.returncode == 0, result.stderr
    loaded = result.stdout.split("LOADED:")[1].strip()
    assert loaded == "", f"importing ida_settings loaded Qt: {loaded}"


def test_the_modern_api_is_available_without_qt() -> None:
    result = _run(
        """
        import ida_settings
        assert callable(ida_settings.get_current_plugin_setting)
        assert callable(ida_settings.set_current_plugin_setting)
        print("OK")
        """
    )

    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout


def test_legacy_qtcore_still_resolves_on_access() -> None:
    """Deferring must not remove ``legacy.QtCore``; it resolves on first use."""
    result = _run(
        """
        from ida_settings import legacy
        before = [m for m in sys.modules if m.split(".")[0] in ("PyQt5", "PySide6")]
        qtcore = legacy.QtCore
        assert hasattr(qtcore, "QSettings"), qtcore
        print("BEFORE:" + str(bool(before)))
        print("OK")
        """
    )

    assert result.returncode == 0, result.stderr
    assert "BEFORE:False" in result.stdout, "importing legacy should not preload Qt"
    assert "OK" in result.stdout
