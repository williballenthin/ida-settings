ida_settings provides a mechanism for settings and fetching
configration values for IDAPython scripts and plugins.
Configurations are namespaced by plugin name,
and scoped to the global system, current user,
working directory, or current IDB file. Configurations
can be exported and imported using an .ini-style intermediate
representation.

Example fetching a configuration value:

    settings = IDASettings("MSDN-doc")
    if settings["verbosity"] == "high":
        ...

Example setting a global configuration value:

    settings = IDASettings("MSDN-doc")
    settings.system["verbosity"] = "high"

Example setting a working directory configuration value:

    settings = IDASettings("MSDN-doc")
    settings.directory["verbosity"] = "high"

Use the properties "system", "user", "directory" and "idb"
to scope configuration accesses and mutations to the global
system, current user, working directory, or current IDB file.

Treat a settings instance like a dictionary. For example:

    settings = IDASettings("MSDN-doc")
    "verbosity" in settings --> False
    settings["verbosity"] = "high"
    settings["verbosity"] --> "high"
    settings.keys()       --> ["verbosity"]
    settings.values()     --> ["high"]
    settings.items()      --> [("verbosity", "high')]

The value of a particular settings entry must be a small, JSON-encodable
value. For example, these are fine:

    settings = IDASettings("MSDN-doc")
    settings["verbosity"] = "high"
    settings["count"] = 1
    settings["percentage"] = 0.75
    settings["filenames"] = ["a.txt", "b.txt"]
    settings["aliases"] = {"bp": "breakpoint", "g": "go"}

and these are not:

    settings["object"] = hashlib.md5()      # this is not JSON-encodable
    settings["buf"] = "\x90" * 4096 * 1024  # this is not small

To export the current effective settings, use the `export_settings`
function. For example:

    settings = IDASettings("MSDN-doc")
    export_settings(settings, "/home/user/desktop/current.ini")

To import existing settings into a settings instance, such as
the open IDB, use the `import_settings` function. For example:

    settings = IDASettings("MSDN-doc")
    import_settings(settings.idb, "/home/user/desktop/current.ini")

Enumerate the plugin names for the various levels using the
IDASettings class properties:

    IDASettings.system_plugin_names     --> ["plugin-1", "plugin-2"]
    IDASettings.user_plugin_names       --> ["plugin-3", "plugin-4"]
    IDASettings.directory_plugin_names  --> ["plugin-5", "plugin-6"]
    IDASettings.idb_plugin_names        --> ["plugin-7", "plugin-8"]

This module is a single file that you can include in IDAPython
plugin module or scripts. It is licensed under the Apache 2.0
license.

Author: Willi Ballenthin <william.ballenthin@fireeye.com>

