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

Use the properties `system`, `user`, `directory` and `idb`
to scope configuration accesses and mutations to the global
system, current user, working directory, or current IDB file.

Treat a settings instance like a dictionary. For example:

    settings = IDASettings("MSDN-doc")
    "verbosity" in settings --> False
    settings["verbosity"] = "high"
    settings["verbosity"] --> "high"
    settings.keys() --> ["verbosity"]
    settings.values() --> ["high"]
    settings.items() --> [("verbosity", "high")]

To export the current effective settings, use the `export_settings`
function. For example:

    settings = IDASettings("MSDN-doc")
    export_settings(settings, "/home/user/desktop/current.ini")

To import existing settings into a settings instance, such as
the open IDB, use the `import_settings` function. For example:

    settings = IDASettings("MSDN-doc")
    import_settings(settings.idb, "/home/user/desktop/current.ini")

This module is a single file that you can include in IDAPython
plugin module or scripts. It is licensed under the Apache 2.0
license.

Author: Willi Ballenthin <william.ballenthin@fireeye.com>

