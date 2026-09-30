"""Selecting a plugin in the settings editor's list by plugin name."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "plugin"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

view = pytest.importorskip("settings_editor.view")


@pytest.fixture(scope="session")
def qapp():
    try:
        from PyQt5.QtWidgets import QApplication
    except ImportError:
        from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


@pytest.fixture
def suite_list(qapp):
    """A list laid out like the controller does for a suite with components."""
    plugin_list = view.plugin_list_view_t()
    plugin_list.add_plugin_item("standalone", "standalone")
    plugin_list.add_plugin_item("suite", "suite", selectable=False)
    plugin_list.add_plugin_item("component-a", "    component-a")
    plugin_list.add_plugin_item("component-b", "    component-b")
    plugin_list.select_first_selectable()
    return plugin_list


def test_select_indented_component_by_name(suite_list):
    assert suite_list.select_plugin_name("component-b")
    assert suite_list.get_selected_plugin_name() == "component-b"


def test_select_top_level_plugin_by_name(suite_list):
    suite_list.select_plugin_name("component-a")

    assert suite_list.select_plugin_name("standalone")
    assert suite_list.get_selected_plugin_name() == "standalone"


def test_select_unknown_name_keeps_selection(suite_list):
    assert not suite_list.select_plugin_name("missing")
    assert suite_list.get_selected_plugin_name() == "standalone"


def test_select_suite_header_keeps_selection(suite_list):
    assert not suite_list.select_plugin_name("suite")
    assert suite_list.get_selected_plugin_name() == "standalone"
