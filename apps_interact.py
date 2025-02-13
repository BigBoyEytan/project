from apps.check_for_updates import get_updatable_apps, display_updatable_apps, run_winget_command
from apps.list_installed_apps import get_installed_apps, display_installed_apps
from apps.upgrade_apps import upgrade_apps
import traceback  # Ensure traceback is imported at the top


class AppsInterface:

    def __init__(self):
        """Initialize the apps interface."""
        pass

    def check_updates(self):
        """Check for available updates and display them."""
        apps = get_updatable_apps()
        display_updatable_apps(apps)
        return apps

    def list_installed(self):
        """List all installed applications."""
        apps = get_installed_apps()
        display_installed_apps(apps)
        return apps

    def upgrade(self, updates):
        """
        Upgrade all provided apps.

        Parameters:
            updates (list): List of apps that need updates.

        Returns:
            None
        """
        if not updates:
            return

        upgrade_apps(updates)

