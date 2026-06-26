import logging
import os

import ida_expr
import ida_idaapi
import ida_kernwin

logger = logging.getLogger(__name__)


def should_load():
    if not ida_kernwin.is_idaq():
        return False

    if os.environ.get("IDA_IS_INTERACTIVE") != "1":
        return False

    kernel_version: tuple[int, ...] = tuple(
        int(part) for part in ida_kernwin.get_kernel_version().split(".") if part.isdigit()
    ) or (0,)
    if kernel_version < (9, 0):
        logger.warning("IDA too old (must be 9.0+): %s", ida_kernwin.get_kernel_version())
        return False

    return True


if should_load():
    try:
        from PyQt5.QtCore import Qt
        from PyQt5.QtWidgets import QVBoxLayout
    except ImportError:
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QVBoxLayout

    from settings_editor.controller import SettingsController
    from settings_editor.model import SettingsModel
    from settings_editor.view import settings_manager_widget_t

    class settings_manager_form_t(ida_kernwin.PluginForm):
        def __init__(
            self,
            caption: str = "Plugin Settings Manager",
            form_registry: dict[str, "settings_manager_form_t"] | None = None,
        ):
            super().__init__()
            self.TITLE = caption
            self.form_registry = form_registry
            self.model = None
            self.view = None
            self.controller = None

        def OnCreate(self, form):
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

        def select_plugin(self, plugin_name: str) -> bool:
            if self.view is None:
                return False
            items = self.view.plugin_list.findItems(plugin_name, Qt.MatchExactly)
            if not items:
                return False
            self.view.plugin_list.setCurrentItem(items[0])
            return True

        def OnClose(self, form):
            if self.form_registry is not None:
                self.form_registry.pop(self.TITLE, None)

    class open_settings_handler_t(ida_kernwin.action_handler_t):
        def __init__(self, plugmod: "settings_editor_plugmod_t"):
            super().__init__()
            self.plugmod = plugmod

        def activate(self, ctx):
            self.plugmod.show_settings_manager()
            return 1

        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    class settings_editor_plugmod_t(ida_idaapi.plugmod_t):
        ACTION_NAME = "settings_editor:open"
        MENU_PATH_PLUGINS = "Edit/Plugins/"
        MENU_PATH_SUBVIEWS = "View/Open subviews/"

        def __init__(self):
            super().__init__()
            self.form_registry: dict[str, settings_manager_form_t] = {}
            self.init()

        IDC_FUNC_NAME = "ida_settings_show"

        def init(self):
            self._register_actions()
            self._register_idc_func()

        def _register_actions(self):
            action_desc = ida_kernwin.action_desc_t(
                self.ACTION_NAME,
                "Plugin Settings Manager",
                open_settings_handler_t(self),
                "",
                "Open plugin settings manager",
                -1,
            )
            ida_kernwin.register_action(action_desc)

            ida_kernwin.attach_action_to_menu(
                self.MENU_PATH_PLUGINS, self.ACTION_NAME, ida_kernwin.SETMENU_APP
            )

            ida_kernwin.attach_action_to_menu(
                self.MENU_PATH_SUBVIEWS, self.ACTION_NAME, ida_kernwin.SETMENU_APP
            )

        def _unregister_actions(self):
            ida_kernwin.detach_action_from_menu(self.MENU_PATH_PLUGINS, self.ACTION_NAME)
            ida_kernwin.detach_action_from_menu(self.MENU_PATH_SUBVIEWS, self.ACTION_NAME)
            ida_kernwin.unregister_action(self.ACTION_NAME)

        def _register_idc_func(self):
            def idc_show_settings(plugin_name: str) -> str:
                self.show_settings_manager(plugin_name)
                return plugin_name

            if ida_expr.add_idc_func(self.IDC_FUNC_NAME, idc_show_settings, (ida_expr.VT_STR,)):
                logger.debug("registered %s IDC function", self.IDC_FUNC_NAME)
            else:
                logger.warning("failed to register %s IDC function", self.IDC_FUNC_NAME)

        def _unregister_idc_func(self):
            ida_expr.del_idc_func(self.IDC_FUNC_NAME)

        def show_settings_manager(self, plugin_name: str = ""):
            caption = "Plugin Settings Manager"

            if caption in self.form_registry:
                widget = ida_kernwin.find_widget(caption)
                if widget:
                    ida_kernwin.activate_widget(widget, True)
                    if plugin_name:
                        self.form_registry[caption].select_plugin(plugin_name)
                    return

            form = settings_manager_form_t(caption, self.form_registry)
            form.Show(
                caption,
                options=(
                    ida_kernwin.PluginForm.WOPN_TAB
                    | ida_kernwin.PluginForm.WOPN_MENU
                    | ida_kernwin.PluginForm.WOPN_RESTORE
                    | ida_kernwin.PluginForm.WCLS_SAVE
                ),
            )

            if plugin_name:
                form.select_plugin(plugin_name)

        def run(self, arg):
            self.show_settings_manager()
            return True

        def term(self):
            self._unregister_idc_func()
            self._unregister_actions()

    class settings_editor_plugin_t(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_KEEP
        comment = "Settings manager UI for IDA Pro plugins"
        help = "Open via Edit/Plugins or View/Open subviews"
        wanted_name = "Plugin Settings Manager"
        wanted_hotkey = ""

        def init(self):
            return settings_editor_plugmod_t()

        def run(self, arg):
            pass

        def term(self):
            pass

    def PLUGIN_ENTRY():
        return settings_editor_plugin_t()

else:

    class settings_editor_nop_plugin_t(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_UNL
        wanted_name = "Plugin Settings Manager disabled"
        comment = "Plugin Settings Manager is disabled for this IDA environment"
        help = ""
        wanted_hotkey = ""

        def init(self):
            return ida_idaapi.PLUGIN_SKIP

    def PLUGIN_ENTRY():
        return settings_editor_nop_plugin_t()
