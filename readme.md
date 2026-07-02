# ida-settings

ida-settings is a Python library used by IDA Pro plugins to fetch configuration values from the shared settings infrastructure.

During plugin installation, [hcli](https://hcli.docs.hex-rays.com/) prompts users for the configuration values and stores them in `ida-config.json`.
Subsequently, users can invoke hcli (or later, the IDA Pro GUI) to update their configuration.
This is the library that plugins use to fetch the configuration values.

For example, within an IDA Pro plugin:

```py
import ida_settings

api_key = ida_settings.get_current_plugin_setting("openai_key")
```

### API reference

```
def get_current_plugin_setting(key: str) -> str | bool
```

Fetch the setting value identified by `key`, raising `KeyError` if its not found.
This setting should be declared in the current plugin's `ida-plugin.json` file.

Changing of configuration values should be done via hcli or the IDA Pro GUI.
However, there are also `set`/`del`/`has`/`list` routines for programmatic access.


### Notes

- this library relies on the IDA Pro's specific plugin environment to identify the current plugin; therefore, this library doesn't work outside of IDA Pro.
- plugins shouldn't try to reach into `ida-config.json` themselves, because in the future, we may introduce cascading settings, a la VS Code.

## IDA Settings Editor Plugin

This repository also includes a graphical settings manager plugin for IDA Pro.

Install it with:

```bash
hcli plugin install ida-settings-editor
```

### Features

- Browse all plugins with settings
- Edit settings with appropriate UI controls
- Immediate validation and feedback
- Revert to defaults
- Dockable/floating window

### Usage

Open via:
- Edit → Plugins → Plugin Settings Manager
- View → Open subviews → Plugin Settings Manager

Other plugins can open the settings UI focused on a specific plugin via IDC:

```py
import idc
idc.eval_idc('ida_settings_show_plugin_settings("my-plugin-name")')
```

### Integration with HCLI

HCLI-compatible IDA plugins can declare settings that are set/fetched with ida-settings. An `ida-plugin.json` file
may have a settings block like:

```json
    "settings": [
      {
        "key": "required_api_key",
        "type": "string",
        "required": true,
        "name": "Demo API Key",
        "documentation": "Required API key for authentication (cannot be deleted)"
      },
      {
        "key": "key1",
        "type": "string",
        "required": false,
        "default": "default-value",
        "name": "Demo String Setting",
        "documentation": "A demo string setting to test the settings editor"
      },
      {
        "key": "key2",
        "type": "boolean",
        "required": false,
        "default": false,
        "name": "Demo Boolean Setting",
        "documentation": "A demo boolean setting to test the settings editor"
      },
      {
        "key": "log_level",
        "type": "string",
        "required": false,
        "default": "info",
        "name": "Demo Log Level",
        "documentation": "Logging verbosity level",
        "choices": ["debug", "info", "warning", "error"]
      },
      {
        "key": "api_endpoint",
        "type": "string",
        "required": false,
        "default": "https://api.example.com",
        "name": "Demo API Endpoint",
        "documentation": "URL for the API endpoint (must start with https://)",
        "validation_pattern": "^https://.*$"
      },
      {
        "key": "enable_debug_mode",
        "type": "boolean",
        "required": false,
        "default": false,
        "name": "Demo Enable Debug Mode",
        "documentation": "Enable verbose debug logging and diagnostics"
      },
      {
        "key": "timeout",
        "type": "string",
        "required": true,
        "default": "30",
        "name": "Demo Timeout",
        "documentation": "Request timeout in seconds (must be a positive integer)",
        "validation_pattern": "^[1-9][0-9]*$"
      }
    ],
    ...
```

and HCLI will prompt for the settings during installation:

```
configure 5 settings:
? Demo String Setting default-value
? Demo Boolean Setting No
? Demo API Endpoint https://api.example.com
? Demo Enable Debug Mode No
? Demo Timeout 30
Installed plugin: demo-settings==1.0.0
```
