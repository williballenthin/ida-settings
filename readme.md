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

Plugins that write settings should pick the appropriate
scope for their settings. Plugins that read settings should
fetch them from the default scope. This allows for precedence
of scopes, such as the current IDB over system-wide configuration.
For example:

    settings = IDASettings("MSDN-doc")
    # when writing, use a scope:
    settings.user["verbosity"] = "high"
    
    # when reading, use the default scope:
    settings["verbosity"] --> "high"

Generally, treat a settings instance like a dictionary. For example:

    settings = IDASettings("MSDN-doc")
    "verbosity" in settings.user --> False
    settings.user["verbosity"] = "high"
    settings.user["verbosity"] --> "high"
    settings.user.keys()       --> ["verbosity"]
    settings.user.values()     --> ["high"]
    settings.user.items()      --> [("verbosity", "high')]

The value of a particular settings entry must be a small, JSON-encodable
value. For example, these are fine:

    settings = IDASettings("MSDN-doc")
    settings.user["verbosity"] = "high"
    settings.user["count"] = 1
    settings.user["percentage"] = 0.75
    settings.user["filenames"] = ["a.txt", "b.txt"]
    settings.user["aliases"] = {"bp": "breakpoint", "g": "go"}

and these are not:

    settings.user["object"] = hashlib.md5()      # this is not JSON-encodable
    settings.user["buf"] = "\x90" * 4096 * 1024  # this is not small

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
plugin module or scripts.

It depends on ida-netnode, which you can download here: 
https://github.com/williballenthin/ida-netnode

This project is licensed under the Apache 2.0 license.

Author: Willi Ballenthin <william.ballenthin@fireeye.com>
