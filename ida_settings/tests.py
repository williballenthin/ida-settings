#######################################################################################
#
# Test Cases
#  run this file as an IDAPython script to invoke the tests.
#
#######################################################################################
import logging
import unittest
import contextlib

from ida_settings import IDASettings, PermissionError

g_logger = logging.getLogger("ida-settings")

PLUGIN_1 = "plugin1"
PLUGIN_2 = "plugin2"
KEY_1 = "key_1"
KEY_2 = "key_2"
VALUE_1 = "hello"
VALUE_2 = "goodbye"
VALUE_STR = "foo"
VALUE_INT = 69
VALUE_FLOAT = 69.69
VALUE_LIST = ["a", "b", "c"]
VALUE_DICT = {"a": 1, "b": "2", "c": 3.0}
# bytes are not supported
VALUE_BYTES = b"foo"


class TestSync(unittest.TestCase):
    """
    Demonstrate that creating new instances of the settings objects shows the same data.
    """

    def test_system(self):
        try:
            # this may fail if the user is not running as admin
            IDASettings(PLUGIN_1).system.set_value(KEY_1, VALUE_1)
            self.assertEqual(IDASettings(PLUGIN_1).system.get_value(KEY_1), VALUE_1)
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")

    def test_user(self):
        try:
            IDASettings(PLUGIN_1).user.set_value(KEY_1, VALUE_1)
            self.assertEqual(IDASettings(PLUGIN_1).user.get_value(KEY_1), VALUE_1)
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")

    def test_directory(self):
        try:
            IDASettings(PLUGIN_1).directory.set_value(KEY_1, VALUE_1)
            self.assertEqual(IDASettings(PLUGIN_1).directory.get_value(KEY_1), VALUE_1)
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")

    def test_idb(self):
        try:
            IDASettings(PLUGIN_1).idb.set_value(KEY_1, VALUE_1)
            self.assertEqual(IDASettings(PLUGIN_1).idb.get_value(KEY_1), VALUE_1)
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")


@contextlib.contextmanager
def clearing(settings):
    settings.clear()
    try:
        yield
    finally:
        settings.clear()


class TestSettingsMixin(object):
    """
    A mixin that adds standard tests test cases with:
      - self.settings, an IDASettingsInterface implementor
    """

    def test_set(self):
        try:
            with clearing(self.settings):
                # simple set
                self.settings.set_value(KEY_1, VALUE_1)
                self.assertEqual(self.settings.get_value(KEY_1), VALUE_1)
                # overwrite
                self.settings.set_value(KEY_1, VALUE_2)
                self.assertEqual(self.settings.get_value(KEY_1), VALUE_2)
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")

    def test_del(self):
        try:
            with clearing(self.settings):
                self.settings.set_value(KEY_1, VALUE_1)
                self.settings.del_value(KEY_1)
                with self.assertRaises(KeyError):
                    self.settings.get_value(KEY_1)
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")

    def test_keys(self):
        try:
            with clearing(self.settings):
                self.settings.del_value(KEY_1)
                self.settings.del_value(KEY_2)
                self.settings.set_value(KEY_1, VALUE_1)
                self.assertEqual(list(self.settings.get_keys()), [KEY_1])
                self.settings.set_value(KEY_2, VALUE_2)
                self.assertEqual(list(self.settings.get_keys()), [KEY_1, KEY_2])
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")

    def test_dict(self):
        try:
            with clearing(self.settings):
                self.assertFalse(KEY_1 in self.settings)
                self.settings[KEY_1] = VALUE_1
                self.assertEqual(self.settings[KEY_1], VALUE_1)
                self.settings[KEY_2] = VALUE_2
                self.assertEqual(self.settings[KEY_2], VALUE_2)
                self.assertEqual(list(self.settings.keys()), [KEY_1, KEY_2])
                self.assertEqual(list(self.settings.values()), [VALUE_1, VALUE_2])
                del self.settings[KEY_1]
                self.assertEqual(list(self.settings.keys()), [KEY_2])
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")

    def test_types(self):
        try:
            with clearing(self.settings):
                for v in [VALUE_STR, VALUE_INT, VALUE_FLOAT, VALUE_LIST, VALUE_DICT]:
                    self.settings.set_value(KEY_1, v)
                    self.assertEqual(self.settings[KEY_1], v)

                self.assertRaises(TypeError, self.settings.set_value, KEY_1, VALUE_BYTES)

        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")

    def test_large_values(self):
        large_value_1 = "".join(VALUE_1 * 1000)
        large_value_2 = "".join(VALUE_2 * 1000)
        try:
            with clearing(self.settings):
                # simple set
                self.settings.set_value(KEY_1, large_value_1)
                self.assertEqual(self.settings.get_value(KEY_1), large_value_1)
                # overwrite
                self.settings.set_value(KEY_1, large_value_2)
                self.assertEqual(self.settings.get_value(KEY_1), large_value_2)
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")


class TestSystemSettings(unittest.TestCase, TestSettingsMixin):
    def setUp(self):
        self.settings = IDASettings(PLUGIN_1).system


class TestUserSettings(unittest.TestCase, TestSettingsMixin):
    def setUp(self):
        self.settings = IDASettings(PLUGIN_1).user


class TestDirectorySettings(unittest.TestCase, TestSettingsMixin):
    def setUp(self):
        self.settings = IDASettings(PLUGIN_1).directory


class TestIdbSettings(unittest.TestCase, TestSettingsMixin):
    def setUp(self):
        self.settings = IDASettings(PLUGIN_1).idb


class TestUserAndSystemSettings(unittest.TestCase):
    def setUp(self):
        self.system = IDASettings(PLUGIN_1).system
        self.user = IDASettings(PLUGIN_1).user

    def test_system_fallback(self):
        """
        QSettings instances with scope "user" automatically fall back to
         scope "system" if the key doesn't exist.
        """
        try:
            with clearing(self.system):
                with clearing(self.user):
                    self.system.set_value(KEY_1, VALUE_1)
                    self.assertEqual(self.user.get_value(KEY_1), VALUE_1)
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")


class TestSettingsPrecendence(unittest.TestCase):
    def setUp(self):
        self.system = IDASettings(PLUGIN_1).system
        self.user = IDASettings(PLUGIN_1).user
        self.directory = IDASettings(PLUGIN_1).directory
        self.idb = IDASettings(PLUGIN_1).idb
        self.mux = IDASettings(PLUGIN_1)

    def test_user_gt_system(self):
        try:
            with clearing(self.system):
                with clearing(self.user):
                    self.system.set_value(KEY_1, VALUE_1)
                    self.user.set_value(KEY_1, VALUE_2)
                    self.assertEqual(self.mux.get_value(KEY_1), VALUE_2)
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")

    def test_directory_gt_user(self):
        try:
            with clearing(self.user):
                with clearing(self.directory):
                    self.user.set_value(KEY_1, VALUE_1)
                    self.directory.set_value(KEY_1, VALUE_2)
                    self.assertEqual(self.mux.get_value(KEY_1), VALUE_2)
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")

    def test_idb_gt_directory(self):
        try:
            with clearing(self.directory):
                with clearing(self.idb):
                    self.directory.set_value(KEY_1, VALUE_1)
                    self.idb.set_value(KEY_1, VALUE_2)
                    self.assertEqual(self.mux.get_value(KEY_1), VALUE_2)
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")


class TestPluginNamesAccessors(unittest.TestCase):
    def test_system_plugin_names(self):
        try:
            self.assertEqual(set(IDASettings.get_system_plugin_names()), set([]))

            s1 = IDASettings(PLUGIN_1).system
            with clearing(s1):
                s1[KEY_1] = VALUE_1
                self.assertEqual(set(IDASettings.get_system_plugin_names()), set([PLUGIN_1]))

                s2 = IDASettings(PLUGIN_2).system
                with clearing(s2):
                    s2[KEY_1] = VALUE_1
                    self.assertEqual(set(IDASettings.get_system_plugin_names()), set([PLUGIN_1, PLUGIN_2]))

            self.assertEqual(set(IDASettings.get_system_plugin_names()), set([]))
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")

    def test_user_plugin_names(self):
        try:
            self.assertEqual(set(IDASettings.get_user_plugin_names()), set([]))

            s1 = IDASettings(PLUGIN_1).user
            with clearing(s1):
                s1[KEY_1] = VALUE_1
                self.assertEqual(set(IDASettings.get_user_plugin_names()), set([PLUGIN_1]))

                s2 = IDASettings(PLUGIN_2).user
                with clearing(s2):
                    s2[KEY_1] = VALUE_1
                    self.assertEqual(set(IDASettings.get_user_plugin_names()), set([PLUGIN_1, PLUGIN_2]))

            self.assertEqual(set(IDASettings.get_user_plugin_names()), set([]))
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")

    def test_directory_plugin_names(self):
        try:
            self.assertEqual(set(IDASettings.get_directory_plugin_names()), set([]))

            s1 = IDASettings(PLUGIN_1).directory
            with clearing(s1):
                s1[KEY_1] = VALUE_1
                self.assertEqual(set(IDASettings.get_directory_plugin_names()), set([PLUGIN_1]))

                s2 = IDASettings(PLUGIN_2).directory
                with clearing(s2):
                    s2[KEY_1] = VALUE_1
                    self.assertEqual(set(IDASettings.get_directory_plugin_names()), set([PLUGIN_1, PLUGIN_2]))

            self.assertEqual(set(IDASettings.get_directory_plugin_names()), set([]))
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")

    def test_idb_plugin_names(self):
        try:
            self.assertEqual(set(IDASettings.get_idb_plugin_names()), set([]))

            s1 = IDASettings(PLUGIN_1).idb
            with clearing(s1):
                s1[KEY_1] = VALUE_1
                self.assertEqual(set(IDASettings.get_idb_plugin_names()), set([PLUGIN_1]))

                s2 = IDASettings(PLUGIN_2).idb
                with clearing(s2):
                    s2[KEY_1] = VALUE_1
                    self.assertEqual(set(IDASettings.get_idb_plugin_names()), set([PLUGIN_1, PLUGIN_2]))

            self.assertEqual(set(IDASettings.get_idb_plugin_names()), set([]))
        except PermissionError:
            g_logger.warning("swallowing PermissionError during testing")


def main():
    try:
        unittest.main()
    except SystemExit:
        pass


if __name__ == "__main__":
    main()
