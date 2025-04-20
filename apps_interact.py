from apps.check_for_updates import get_updatable_apps, display_updatable_apps
from apps.list_installed_apps import get_installed_apps, display_installed_apps, run_winget_command
from apps.upgrade_apps import upgrade_app, upgrade_apps
import time


class AppsInterface:
    """Interface for interacting with Windows Package Manager (winget) functionality."""

    def __init__(self):
        """Initialize the apps interface."""
        # Check if winget is available
        output = run_winget_command(["winget", "--version"])
        if not output:
            print("WARNING: Winget may not be installed or accessible")
        else:
            print(f"Winget version: {output.strip()}")

    def check_updates(self):
        """Check for available updates and display them.

        Returns:
            list: List of apps that have updates available
        """
        print("Checking for app updates...")

        # First ensure source cache is up to date (this might fail but we continue)
        try:
            print("Resetting winget source cache...")
            run_winget_command(["winget", "source", "reset", "--force"])
            # Add a small delay after reset to ensure winget has time to update
            time.sleep(2)
        except Exception as e:
            print(f"Warning: Couldn't reset source cache: {e}")

        # Then check for updates
        print("Retrieving updatable apps...")
        apps = get_updatable_apps()

        # Display the results
        print("Displaying update results...")
        display_updatable_apps(apps)

        # If no apps found, try alternative method and display diagnostic info
        if not apps:
            print("\nNo updates detected through primary method. Trying alternative approach...")
            alt_output = run_winget_command(["winget", "upgrade", "--include-unknown"])

            print("\nRaw output from alternative approach:")
            print("-" * 50)
            print(alt_output)
            print("-" * 50)

            if "upgrades available" in alt_output and "0 upgrades available" not in alt_output:
                print("\nNOTE: Updates may be available but weren't properly detected by the parser.")
                print("Please check the raw output above for details.")

        return apps

    def list_installed(self):
        """List all installed applications.

        Returns:
            list: List of installed apps
        """
        print("Listing installed applications...")
        apps = get_installed_apps()
        display_installed_apps(apps)
        return apps

    def upgrade(self, updates):
        """Upgrade all provided apps.

        Args:
            updates (list): List of apps that need updates.
        """
        if not updates:
            print("No updates available to install.")
            return

        print(f"Upgrading {len(updates)} applications...")
        upgrade_apps(updates)
        print("Upgrade process completed.")

    def upgrade_specific(self, app_id):
        """Upgrade a specific app by ID.

        Args:
            app_id (str): The ID of the application to upgrade

        Returns:
            bool: True if successful, False otherwise
        """
        print(f"Upgrading specific application: {app_id}")
        return upgrade_app(app_id)


def main():
    """
    Main function to test the apps interface directly without client-server architecture.
    This allows for standalone testing of winget functionality.
    """
    print("\n===== Windows Package Manager (winget) Interface Tester =====\n")

    # Initialize the interface
    print("Initializing AppsInterface...")
    app_interface = AppsInterface()

    while True:
        print("\nAvailable Actions:")
        print("1. List Installed Applications")
        print("2. Check for Updates")
        print("3. Upgrade All Available Updates")
        print("4. Upgrade Specific Application")
        print("5. Debug: Raw Winget Command")
        print("6. Exit")

        choice = input("\nEnter your choice (1-6): ")

        if choice == '1':
            print("\nRetrieving installed applications...")
            apps = app_interface.list_installed()
            print(f"\nFound {len(apps)} installed applications")

        elif choice == '2':
            print("\nChecking for available updates...")
            updates = app_interface.check_updates()

            # Show detailed information about the updates
            if updates:
                print("\nDetailed update information:")
                for i, app in enumerate(updates, 1):
                    print(f"\n{i}. {app['name']}")
                    print(f"   ID: {app['id']}")
                    print(f"   Current Version: {app['current_version']}")
                    print(f"   Available Version: {app['available_version']}")
                    if 'source' in app:
                        print(f"   Source: {app['source']}")

        elif choice == '3':
            print("\nChecking for available updates first...")
            updates = app_interface.check_updates()

            if updates:
                confirm = input(f"\nDo you want to upgrade all {len(updates)} applications? (y/n): ")
                if confirm.lower() == 'y':
                    print("\nUpgrading all applications...")
                    app_interface.upgrade(updates)
            else:
                print("\nNo updates available to install.")

        elif choice == '4':
            app_id = input("\nEnter the application ID to upgrade: ")
            if app_id:
                print(f"\nAttempting to upgrade {app_id}...")
                result = app_interface.upgrade_specific(app_id)
                if result:
                    print(f"Successfully upgraded {app_id}")
                else:
                    print(f"Failed to upgrade {app_id}")
            else:
                print("No application ID provided.")

        elif choice == '5':
            cmd = input("\nEnter raw winget command to execute (e.g., 'winget list'): ")
            if cmd:
                print("\nExecuting command...")
                output = run_winget_command(cmd)
                print("\nCommand output:")
                print(output)
            else:
                print("No command provided.")

        elif choice == '6':
            print("\nExiting application...")
            break

        else:
            print("\nInvalid choice. Please try again.")


if __name__ == "__main__":
    main()