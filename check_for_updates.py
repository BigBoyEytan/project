from .list_installed_apps import run_winget_command, get_upgradable_apps


def get_updatable_apps():
    """Retrieve list of applications with available updates.

    This is a wrapper function that calls the improved get_upgradable_apps
    function from list_installed_apps.py.

    Returns:
        list: List of updatable app dictionaries
    """
    print("Retrieving list of updatable applications...")
    return get_upgradable_apps()


def display_updatable_apps(updatable_apps):
    """Display list of applications with available updates in table format."""
    if not updatable_apps:
        print("\nNo updatable applications found.")
        return

    print("\nUpdatable Applications:")
    print("-" * 70)
    print(f"{'Name':<30} {'ID':<25} {'Current':<10} {'Available':<10}")
    print("-" * 70)

    for app in updatable_apps:
        name = app['name'][:28] if len(app['name']) > 28 else app['name']
        app_id = app['id'][:23] if len(app['id']) > 23 else app['id']
        current = app['current_version'][:8] if len(app['current_version']) > 8 else app['current_version']
        available = app['available_version'][:8] if len(app['available_version']) > 8 else app['available_version']

        print(f"{name:<30} {app_id:<25} {current:<10} {available:<10}")

    print(f"\nTotal: {len(updatable_apps)} updatable applications")


# Test the function directly if run as a script
if __name__ == "__main__":
    print("Running updatable apps check directly...")
    apps = get_updatable_apps()
    display_updatable_apps(apps)