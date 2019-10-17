import json

from idaapi import PluginForm
from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5 import QtWidgets

import ida_settings 


class IdaSettingsEditor(PluginForm):
    def OnCreate(self, form):
        # 6.8 and below
        #self.parent = self.FormToPySideWidget(form)
        # 6.9 and above
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        """
        +-----------------------------------------------------------------------+
        | +--- splitter ------------------------------------------------------+ |
        | | +-- list widget--------------+  +- IdaSettingsView -------------+ | |
        | | |                            |  |                               | | |
        | | |  - plugin name             |  |                               | | |
        | | |  - plugin name             |  |                               | | |
        | | |  - plugin name             |  |                               | | |
        | | |                            |  |                               | | |
        | | |                            |  |                               | | |
        | | |                            |  |                               | | |
        | | |                            |  |                               | | |
        | | |                            |  |                               | | |
        | | |                            |  |                               | | |
        | | |                            |  |                               | | |
        | | |                            |  |                               | | |
        | | |                            |  |                               | | |
        | | |                            |  |                               | | |
        | | |                            |  |                               | | |
        | | |                            |  |                               | | |
        | | |                            |  |                               | | |
        | | +----------------------------+  +-------------------------------+ | |
        | +-------------------------------------------------------------------+ |
        +-----------------------------------------------------------------------+
        """
        hbox = QtWidgets.QHBoxLayout(self.parent)

        self._splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self._plugin_list = QtWidgets.QListWidget()

        plugin_names = set([])
        for scope, fn in (("idb", ida_settings.IDASettings.get_idb_plugin_names),
                ("directory", ida_settings.IDASettings.get_directory_plugin_names),
                ("user", ida_settings.IDASettings.get_user_plugin_names),
                ("system", ida_settings.IDASettings.get_system_plugin_names)):
            for plugin_name in fn():
                plugin_names.add(plugin_name)
        for plugin_name in plugin_names:
            self._plugin_list.addItem(plugin_name)
        self._splitter.addWidget(self._plugin_list)

        hbox.addWidget(self._splitter)
        self.parent.setLayout(hbox)
        
        self._plugin_list.currentItemChanged.connect(self._handle_plugin_changed)

    def _clear_settings_widgets(self):
        for i in range(1, self._splitter.count()):
            w = self._splitter.widget(i)
            if w is not None:
                w.deleteLater()

    def _set_settings_widget(self, settings):
        self._clear_settings_widgets()
        w = IdaSettingsView(settings, parent=self.parent)
        self._splitter.insertWidget(1, w)

    def _handle_plugin_changed(self, current, previous):
        plugin_name = str(current.text())
        settings = ida_settings.IDASettings(plugin_name)
        self._set_settings_widget(settings)


class IdaSettingsView(QtWidgets.QWidget):
    def __init__(self, settings, parent=None):
        """
        +-----------------------------------------------------------------------+
        | +--- hbox ----------------------------------------------------------+ |
        | | +-- list widget--------------+  +- vbox ------------------------+ | |
        | | |                            |  | +- QTextEdit ---------------+ | | |
        | | |  - key                     |  | |                           | | | |
        | | |  - key                     |  | |  value                    | | | |
        | | |  - key                     |  | |                           | | | |
        | | |                            |  | |                           | | | |
        | | |                            |  | |                           | | | |
        | | |                            |  | |                           | | | |
        | | |                            |  | |                           | | | |
        | | |                            |  | |                           | | | |
        | | |                            |  | +---------------------------+ | | |
        | | |                            |  |                               | | |
        | | |                            |  | +- QPushButton -------------+ | | |
        | | |                            |  | |                           | | | |
        | | |                            |  | |  save                     | | | |
        | | |                            |  | |                           | | | |
        | | |                            |  | +---------------------------+ | | |
        | | +----------------------------+  +-------------------------------+ | |
        | +-------------------------------------------------------------------+ |
        +-----------------------------------------------------------------------+
        """
        super(IdaSettingsView, self).__init__(parent=parent)
        self._settings = settings
        self._current_key = None
        self._current_scope = None

        hbox = QtWidgets.QHBoxLayout(self)
        self._key_list = QtWidgets.QListWidget()
        for scope, keys in (("idb", iter(self._settings.idb.keys())),
                            ("directory", iter(self._settings.directory.keys())),
                            ("user", iter(self._settings.user.keys())),
                            ("system", iter(self._settings.system.keys()))):
            for key in keys:
                self._key_list.addItem("({scope:s}) {key:s}".format(scope=scope, key=key))

        hbox.addWidget(self._key_list)

        vbox = QtWidgets.QVBoxLayout(self)
        self._value_view = QtWidgets.QTextEdit(self)
        self._save_button = QtWidgets.QPushButton("save")
        vbox.addWidget(self._value_view)
        vbox.addWidget(self._save_button)

        hbox.addLayout(vbox)
 
        self._key_list.currentItemChanged.connect(self._handle_key_changed)
        self._save_button.clicked.connect(self._handle_save_value)

        self.setLayout(hbox)

    def _handle_key_changed(self, current, previous):
        if current is None:
            return 

        self._value_view.clear()
        scope, _, key = str(current.text()).partition(" ")
        scope = scope.lstrip("(").rstrip(")")
        self._current_scope = scope
        self._current_key = key

        v = getattr(self._settings, scope)[key]
        self._value_view.setText(json.dumps(v))

    def _handle_save_value(self):
        v = str(self._value_view.toPlainText())
        s = getattr(self._settings, self._current_scope)
        s[self._current_key] = json.loads(v)
        

def main():
    v = IdaSettingsEditor()
    v.Show("Plugin Settings Editor")


if __name__ == "__main__":
    main()
