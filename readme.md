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

Changing of configuration values should be done via hcli (or later, the IDA Pro GUI).
Plugins shouldn't have to do this themselves - but open an issue for discussion if you think otherwise.


### Notes

- this library relies on the IDA Pro's specific plugin environment to identify the current plugin; therefore, this library doesn't work outside of IDA Pro.
- plugins shouldn't try to reach into `ida-config.json` themselves, because in the future, we may introduce cascading settings, a la VS Code.

## IDA Settings Editor Plugin

This repository also includes a graphical settings manager plugin for IDA Pro.

### Features

- Browse all plugins with settings
- Edit settings with appropriate UI controls
- Immediate validation and feedback
- Revert to defaults
- Dockable/floating window

### Installation

```bash
hcli plugin install /path/to/ida-settings
```

### Usage

Open via:
- Edit → Plugins → Plugin Settings Manager
- View → Open subviews → Plugin Settings Manager

See [Plugin Usage Guide](docs/plugin-usage.md) for details.

## Standalone Development Mode

For development and testing, you can run the settings editor outside of IDA Pro:

```bash
cd /path/to/ida-settings
python plugin/main.py
```

This standalone mode:
- Uses the same settings editor UI as the IDA plugin
- Reads/writes settings from your IDA user directory (`~/.idapro` on macOS/Linux)
- Requires HCLI library but not IDA Pro itself
- Useful for UI development and debugging

**Requirements:**
- Python 3.9+
- PyQt5 or PySide6
- HCLI library installed
