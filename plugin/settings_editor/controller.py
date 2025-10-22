"""Settings controller."""

from settings_editor.model import SettingsModel
from settings_editor.view import settings_manager_widget_t, setting_editor_row_t


class SettingsController:
    """Controller for settings manager."""

    def __init__(self, model: SettingsModel, view: settings_manager_widget_t):
        """Initialize controller."""
        self.model = model
        self.view = view
        self.current_plugin = None

        self._connect_signals()

        self.model.load_plugins()

    def _connect_signals(self):
        """Connect model and view signals."""
        self.model.pluginsLoaded.connect(self._on_plugins_loaded)

        self.view.plugin_list.currentTextChanged.connect(self._on_plugin_selected)

    def _on_plugins_loaded(self, plugins: list):
        """Handle plugins loaded."""
        self.view.plugin_list.clear()
        if plugins:
            self.view.plugin_list.addItems(plugins)
            self.view.plugin_list.setCurrentRow(0)
        else:
            self.view.settings_editor.show_message("No plugins with settings found")

    def _on_plugin_selected(self, plugin_name: str):
        """Handle plugin selection."""
        if not plugin_name:
            self.view.settings_editor.clear_editors()
            return

        self.current_plugin = plugin_name
        self.view.settings_editor.clear_editors()

        try:
            descriptors = self.model.get_plugin_settings(plugin_name)

            if not descriptors:
                self.view.settings_editor.show_message("No settings defined for this plugin")
                return

            for descriptor in descriptors:
                row = setting_editor_row_t(descriptor)

                is_explicit = self.model.is_setting_explicit(plugin_name, descriptor.key)

                if is_explicit:
                    try:
                        value = self.model.get_setting_value(plugin_name, descriptor.key)
                        row.set_value(value)
                    except KeyError:
                        pass
                else:
                    row.set_value(None)

                row.set_explicit(is_explicit)

                row.valueChanged.connect(
                    lambda k, v, p=plugin_name: self._on_setting_value_changed(p, k, v)
                )
                row.deleteRequested.connect(
                    lambda k, p=plugin_name: self._on_delete_requested(p, k)
                )

                self.view.settings_editor.add_editor_row(descriptor.key, row)

        except Exception as e:
            self.view.settings_editor.show_message(f"Error loading settings: {e}")

    def _on_setting_value_changed(self, plugin_name: str, key: str, value):
        """Handle setting value change."""
        row = self.view.settings_editor.get_editor_row(key)
        if not row:
            return

        try:
            if value is None or value == "":
                if row.descriptor.default is not None:
                    self.model.delete_setting(plugin_name, key)
                    row.hide_error()
                    row.set_explicit(False)
                    row.set_value(None)
                else:
                    row.show_error("Required setting cannot be empty")
            else:
                self.model.set_setting_value(plugin_name, key, value)
                row.hide_error()
                row.set_explicit(True)
        except ValueError as e:
            row.show_error(str(e))
        except Exception as e:
            row.show_error(f"Error: {e}")

    def _on_delete_requested(self, plugin_name: str, key: str):
        """Handle delete setting request."""
        row = self.view.settings_editor.get_editor_row(key)
        if not row:
            return

        try:
            self.model.delete_setting(plugin_name, key)
            row.hide_error()
            row.set_explicit(False)
            row.set_value(None)
        except ValueError as e:
            row.show_error(str(e))
        except Exception as e:
            row.show_error(f"Error: {e}")
