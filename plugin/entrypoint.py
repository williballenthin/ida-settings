
import ida_idaapi
import ida_kernwin

try:
    from PyQt5.QtWidgets import QVBoxLayout
except ImportError:
    from PySide6.QtWidgets import QVBoxLayout

# IDA adds the directory of the file pointed to by the `.plugin.entryPoint` field of `ida-plugin.json` to sys.path.
# and it does this for all plugins.
# so ideally plugins should avoid using common names like `model.py` and perhaps have a module structure

from settings_editor.model import SettingsModel
from settings_editor.view import settings_manager_widget_t
from settings_editor.controller import SettingsController


class settings_manager_form_t(ida_kernwin.PluginForm):
    """Form for settings manager UI."""

    def __init__(self, caption: str = "Plugin Settings Manager", form_registry: dict[str, "settings_manager_form_t"] | None = None):
        """Initialize form."""
        super().__init__()
        self.TITLE = caption
        self.form_registry = form_registry
        self.model = None
        self.view = None
        self.controller = None

    def OnCreate(self, form):
        """Called when form is created."""
        self.parent = self.FormToPyQtWidget(form)

        self.model = SettingsModel()
        self.view = settings_manager_widget_t(self.parent)
        self.controller = SettingsController(self.model, self.view)

        layout = self.parent.layout()
        if layout is None:
            layout = QVBoxLayout()
            self.parent.setLayout(layout)

        layout.addWidget(self.view)

        if self.form_registry is not None:
            self.form_registry[self.TITLE] = self

    def OnClose(self, form):
        """Called when form is closed."""
        if self.form_registry is not None:
            self.form_registry.pop(self.TITLE, None)


class open_settings_handler_t(ida_kernwin.action_handler_t):
    """Action handler for opening settings manager."""

    def __init__(self, plugmod: "settings_editor_plugmod_t"):
        """Initialize action handler."""
        super().__init__()
        self.plugmod = plugmod

    def activate(self, ctx):
        """Handle action activation."""
        self.plugmod.show_settings_manager()
        return 1

    def update(self, ctx):
        """Update action state."""
        return ida_kernwin.AST_ENABLE_ALWAYS


class settings_editor_plugmod_t(ida_idaapi.plugmod_t):
    """Plugin module for settings editor."""

    ACTION_NAME = "settings_editor:open"
    MENU_PATH_PLUGINS = "Edit/Plugins/"
    MENU_PATH_SUBVIEWS = "View/Open subviews/"

    def __init__(self):
        """Initialize plugin module."""
        super().__init__()
        self.form_registry: dict[str, settings_manager_form_t] = {}
        self.init()

    def init(self):
        """Initialize plugin module - called from __init__."""
        self._register_actions()

    def _register_actions(self):
        """Register menu actions."""
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_NAME,
            "Plugin Settings Manager",
            open_settings_handler_t(self),
            "",
            "Open plugin settings manager",
            -1
        )
        ida_kernwin.register_action(action_desc)

        ida_kernwin.attach_action_to_menu(
            self.MENU_PATH_PLUGINS,
            self.ACTION_NAME,
            ida_kernwin.SETMENU_APP
        )

        ida_kernwin.attach_action_to_menu(
            self.MENU_PATH_SUBVIEWS,
            self.ACTION_NAME,
            ida_kernwin.SETMENU_APP
        )

    def _unregister_actions(self):
        """Unregister actions and detach from menus."""
        ida_kernwin.detach_action_from_menu(self.MENU_PATH_PLUGINS, self.ACTION_NAME)
        ida_kernwin.detach_action_from_menu(self.MENU_PATH_SUBVIEWS, self.ACTION_NAME)
        ida_kernwin.unregister_action(self.ACTION_NAME)

    def show_settings_manager(self):
        """Show or focus settings manager form."""
        caption = "Plugin Settings Manager"

        if caption in self.form_registry:
            widget = ida_kernwin.find_widget(caption)
            if widget:
                ida_kernwin.activate_widget(widget, True)
                return

        form = settings_manager_form_t(caption, self.form_registry)
        form.Show(caption, options=(
            ida_kernwin.PluginForm.WOPN_TAB |
            ida_kernwin.PluginForm.WOPN_MENU |
            ida_kernwin.PluginForm.WOPN_RESTORE |
            ida_kernwin.PluginForm.WCLS_SAVE
        ))

    def run(self, arg):
        """Run plugin module."""
        self.show_settings_manager()
        return True

    def term(self):
        """Terminate plugin module."""
        self._unregister_actions()


class settings_editor_plugin_t(ida_idaapi.plugin_t):
    """Plugin entry point for IDA Settings Editor."""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Settings manager UI for IDA Pro plugins"
    help = "Open via Edit/Plugins or View/Open subviews"
    wanted_name = "Plugin Settings Manager"
    wanted_hotkey = ""

    def init(self):
        """Initialize plugin - return plugmod instance."""
        return settings_editor_plugmod_t()

    def run(self, arg):
        """Run plugin (should not be called for PLUGIN_KEEP)."""
        pass

    def term(self):
        """Terminate plugin."""
        pass


def PLUGIN_ENTRY():
    """IDA plugin entry point."""
    return settings_editor_plugin_t()
