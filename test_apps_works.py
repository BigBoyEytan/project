import unittest
import subprocess
import sys
import os

# Add the parent directory to Python path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apps.apps_interact import AppsInterface
from apps.check_for_updates import get_updatable_apps, display_updatable_apps
from apps.list_installed_apps import get_installed_apps, display_installed_apps, run_winget_command
from apps.upgrade_apps import upgrade_apps, upgrade_app


class TestAppsManager(unittest.TestCase):
    def setUp(self):
        """Initialize AppsInterface for testing."""
        self.apps_interface = AppsInterface()

    def test_run_winget_command(self):
        """Test basic winget command execution."""
        # Note: This might actually call winget, so it's more of an integration test
        result = run_winget_command()
        self.assertIsNotNone(result)

    def test_get_installed_apps(self):
        """Test retrieving installed apps."""
        installed_apps = get_installed_apps()

        # Check that it returns a list
        self.assertIsInstance(installed_apps, list)

        # If apps are found, validate their structure
        if installed_apps:
            for app in installed_apps:
                self.assertIn('name', app)
                self.assertIn('id', app)
                self.assertIn('current_version', app)

    def test_get_updatable_apps(self):
        """Test retrieving updatable apps."""
        updatable_apps = get_updatable_apps()

        # Check that it returns a list
        self.assertIsInstance(updatable_apps, list)

        # If updates are found, validate their structure
        if updatable_apps:
            for app in updatable_apps:
                self.assertIn('name', app)
                self.assertIn('id', app)
                self.assertIn('current_version', app)
                self.assertIn('available_version', app)

    def test_apps_interface_methods(self):
        """Test AppsInterface methods."""
        # Check updates method
        updates = self.apps_interface.check_updates()
        self.assertIsInstance(updates, list)

        # Check installed apps method
        installed = self.apps_interface.list_installed()
        self.assertIsInstance(installed, list)

    def test_upgrade_app_empty_list(self):
        """Test upgrade method with empty list."""
        try:
            self.apps_interface.upgrade([])
        except Exception as e:
            self.fail(f"Upgrade with empty list raised an unexpected exception: {e}")

    def test_upgrade_method_with_sample_app(self):
        """
        Test upgrade method with a dummy app.
        Note: This is a mock test and won't actually upgrade anything.
        """
        sample_apps = [
            {'id': 'DummyApp1'},
            {'id': 'DummyApp2'}
        ]

        try:
            upgrade_apps(sample_apps)
        except Exception as e:
            self.fail(f"Upgrade method raised an unexpected exception: {e}")

    def test_display_methods(self):
        """
        Test display methods don't raise exceptions.
        Mainly checking for no crashes with empty and populated lists.
        """
        try:
            # Test with empty list
            display_installed_apps([])
            display_updatable_apps([])

            # Test with sample data
            sample_apps = [
                {
                    'name': 'TestApp',
                    'id': 'test.app',
                    'current_version': '1.0.0'
                }
            ]
            display_installed_apps(sample_apps)

            sample_updates = [
                {
                    'name': 'UpdateApp',
                    'id': 'update.app',
                    'current_version': '1.0.0',
                    'available_version': '1.1.0'
                }
            ]
            display_updatable_apps(sample_updates)

        except Exception as e:
            self.fail(f"Display methods raised an unexpected exception: {e}")

    def test_upgrade_app_error_handling(self):
        """
        Test error handling in upgrade_app method.
        Uses an impossible app ID to test error handling.
        """
        try:
            upgrade_app('non.existent.app.that.should.not.exist')
        except Exception as e:
            self.fail(f"Upgrade method raised an unexpected exception: {e}")

    def test_apps_interface_method_returns(self):
        """
        Verify that AppsInterface methods return expected types.
        """
        # Check updates returns a list
        updates = self.apps_interface.check_updates()
        self.assertIsInstance(updates, list)

        # Check installed apps returns a list
        installed = self.apps_interface.list_installed()
        self.assertIsInstance(installed, list)


def main():
    """Run tests with more detailed output."""
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAppsManager)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Exit with non-zero status if tests fail
    sys.exit(not result.wasSuccessful())


if __name__ == '__main__':
    main()