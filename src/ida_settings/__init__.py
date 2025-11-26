from hcli.lib.ida.plugin.settings import (
    del_current_plugin_setting,
    del_plugin_setting,
    get_current_plugin,
    get_current_plugin_setting,
    get_plugin_setting,
    has_current_plugin_setting,
    has_plugin_setting,
    set_current_plugin_setting,
    set_plugin_setting,
)
from hcli.lib.ida.plugin.settings import (
    list_current_plugin_settings as _list_current_plugin_settings,
)

from .legacy import IDASettings, PermissionError

__all__ = [
    "del_current_plugin_setting",
    "get_current_plugin_setting",
    "has_current_plugin_setting",
    "set_current_plugin_setting",
    "list_current_plugin_settings",
    "IDASettings",
    "PermissionError",
    "PluginSettings",
    "get_current_plugin_settings",
]


def list_current_plugin_settings() -> list[dict]:
    descriptors = _list_current_plugin_settings()
    return [
        {
            "key": d.key,
            "type": d.type,
            "default": d.default,
            "required": d.required,
            "documentation": d.documentation,
            "choices": d.choices,
        }
        for d in descriptors
    ]


class PluginSettings:
    def __init__(self, plugin_name: str):
        self._plugin_name = plugin_name

    def get_setting(self, key: str) -> str | bool:
        return get_plugin_setting(self._plugin_name, key)

    def del_setting(self, key: str) -> None:
        return del_plugin_setting(self._plugin_name, key)

    def has_setting(self, key: str) -> bool:
        return has_plugin_setting(self._plugin_name, key)

    def set_setting(self, key: str, value: str | bool) -> None:
        return set_plugin_setting(self._plugin_name, key, value)


def get_current_plugin_settings() -> PluginSettings:
    return PluginSettings(get_current_plugin())
