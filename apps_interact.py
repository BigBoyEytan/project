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
        """Upgrade a given list of apps, confirming before upgrading.

        Parameters:
            updates (list): List of apps that need updates.
        """
        if not updates:
            print("\n✅ All applications are up to date.")
            return

        print("\n⬆️ The following applications have updates available:")
        for i, app in enumerate(updates, 1):
            print(f"{i}. {app['name']} (Current: {app['current_version']}, New: {app['available_version']})")

        confirm = input("\nDo you want to proceed with upgrading all apps? (y/n): ").strip().lower()
        if confirm != "y":
            print("\n❌ Upgrade canceled.")
            return

        detailed_print = input("Would you like to see details for each update? (y/n): ").strip().lower()
        if detailed_print == "y":
            for app in updates:
                print(f"\n📦 {app['name']}\n   - ID: {app['id']}\n   - Current: {app['current_version']}\n   - Available: {app['available_version']}")

        upgrade_apps(updates)


