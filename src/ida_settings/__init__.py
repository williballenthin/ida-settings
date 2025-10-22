from hcli.lib.ida.plugin.settings import (
    del_current_plugin_setting,
    get_current_plugin_setting,
    has_current_plugin_setting,
    set_current_plugin_setting,
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
