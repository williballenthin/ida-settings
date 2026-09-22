"""Settings data model."""

try:
    from PyQt5.QtCore import QObject
    from PyQt5.QtCore import pyqtSignal as Signal
except ImportError:
    from PySide6.QtCore import QObject, Signal

from hcli.lib.ida.plugin import ChoiceValueError, PluginSettingDescriptor
from hcli.lib.ida.plugin.components import walk_component_tree_from_directory
from hcli.lib.ida.plugin.install import get_metadata_from_plugin_directory
from hcli.lib.ida.plugin.settings import (
    del_plugin_setting,
    get_plugin_setting,
    has_plugin_setting,
    resolve_plugin_directory,
    set_plugin_setting,
)


class SettingsModel(QObject):
    """Model for plugin settings data."""

    pluginsLoaded = Signal(list)
    settingChanged = Signal(str, str, object)
    settingDeleted = Signal(str, str)
    validationError = Signal(str, str, str)

    def __init__(self):
        """Initialize settings model."""
        super().__init__()
        self._plugins = []
        self._plugin_metadata = {}
        self._component_of = {}

    def load_plugins(self):
        """Enumerate installed plugins with settings, including suite components."""
        self._plugins = []
        self._plugin_metadata = {}
        self._component_of = {}

        from pathlib import Path

        from hcli.lib.ida import get_ida_user_dir

        ida_user_dir = Path(get_ida_user_dir())
        plugins_dir = ida_user_dir / "plugins"

        if not plugins_dir.exists():
            self.pluginsLoaded.emit([])
            return

        groups = []

        for entry in sorted(plugins_dir.iterdir(), key=lambda e: e.name.lower()):
            if not entry.is_dir():
                continue

            metadata_file = entry / "ida-plugin.json"
            if not metadata_file.exists():
                continue

            try:
                metadata = get_metadata_from_plugin_directory(entry)
            except Exception:
                continue

            suite_name = entry.name
            suite_has_settings = bool(metadata.plugin.settings)
            components_with_settings = []

            if suite_has_settings:
                self._plugin_metadata[suite_name] = metadata

            if metadata.plugin.components:
                try:
                    tree = walk_component_tree_from_directory(entry)
                    for _comp_path, comp_meta in tree:
                        if comp_meta.plugin.settings:
                            comp_name = comp_meta.plugin.name
                            self._plugin_metadata[comp_name] = comp_meta
                            self._component_of[comp_name] = suite_name
                            components_with_settings.append(comp_name)
                except ValueError:
                    pass

            if suite_has_settings or components_with_settings:
                groups.append((suite_name, suite_has_settings, components_with_settings))

        for suite_name, suite_has_settings, components in groups:
            if suite_has_settings:
                self._plugins.append(suite_name)
            for comp_name in sorted(components, key=str.lower):
                self._plugins.append(comp_name)

        self.pluginsLoaded.emit(self._plugins)

    def parent_suite(self, plugin_name: str) -> str | None:
        return self._component_of.get(plugin_name)

    def get_plugin_settings(self, plugin_name: str) -> list[PluginSettingDescriptor]:
        """Get all setting descriptors for a plugin."""
        if plugin_name not in self._plugin_metadata:
            plugin_path = resolve_plugin_directory(plugin_name)
            metadata = get_metadata_from_plugin_directory(plugin_path)
            self._plugin_metadata[plugin_name] = metadata

        return self._plugin_metadata[plugin_name].plugin.settings

    def get_setting_value(self, plugin_name: str, key: str) -> str | bool:
        """Get current value (or default) for a setting."""
        try:
            return get_plugin_setting(plugin_name, key)
        except KeyError:
            descriptors = self.get_plugin_settings(plugin_name)
            for desc in descriptors:
                if desc.key == key:
                    return desc.default
            raise KeyError(f"Setting not found: {plugin_name}.{key}")

    def set_setting_value(self, plugin_name: str, key: str, value: str | bool):
        """Validate and set a setting value."""
        descriptors = self.get_plugin_settings(plugin_name)
        descriptor = None
        for desc in descriptors:
            if desc.key == key:
                descriptor = desc
                break

        if descriptor is None:
            raise KeyError(f"Setting not found: {plugin_name}.{key}")

        if descriptor.type == "string" and not isinstance(value, str):
            raise ValueError(f"Expected string, got {type(value).__name__}")
        elif descriptor.type == "boolean" and not isinstance(value, bool):
            raise ValueError(f"Expected boolean, got {type(value).__name__}")

        try:
            descriptor.validate_value(value)
        except ChoiceValueError as e:
            choices_str = ", ".join(e.choices)
            raise ValueError(f"Must be one of: {choices_str}") from e
        except ValueError as e:
            raise ValueError(str(e)) from e

        set_plugin_setting(plugin_name, key, value)
        self.settingChanged.emit(plugin_name, key, value)

    def delete_setting(self, plugin_name: str, key: str):
        """Remove explicit setting, revert to default."""
        descriptors = self.get_plugin_settings(plugin_name)
        descriptor = None
        for desc in descriptors:
            if desc.key == key:
                descriptor = desc
                break

        if descriptor is None:
            raise KeyError(f"Setting not found: {plugin_name}.{key}")

        if descriptor.required and descriptor.default is None:
            raise ValueError("Cannot delete required setting without default")

        del_plugin_setting(plugin_name, key)
        self.settingDeleted.emit(plugin_name, key)

    def is_setting_explicit(self, plugin_name: str, key: str) -> bool:
        """Check if setting is explicitly set vs using default."""
        return has_plugin_setting(plugin_name, key)
