import re
from apps.list_installed_apps import run_winget_command

def get_updatable_apps():
    """Retrieve list of applications with available updates."""
    output = run_winget_command(['winget', 'upgrade'])
    if not output:
        return []

    updatable_apps = []
    lines = output.split('\n')
    for line in lines[2:]:  # Skip header lines
        if not line.strip():
            continue
        parts = re.split(r'\s{2,}', line.strip())
        if len(parts) >= 3:
            app = {
                'name': parts[0],
                'id': parts[1] if len(parts) > 1 else 'N/A',
                'current_version': parts[2] if len(parts) > 2 else 'N/A',
                'available_version': parts[3] if len(parts) > 3 else 'N/A'
            }
            updatable_apps.append(app)

    return updatable_apps

def display_updatable_apps(updatable_apps):
    """Display list of applications with available updates."""
    if not updatable_apps:
        print("\n🌟 No updatable applications found.")
        return
    print("\n🔍 Updatable Applications:")
    print("-" * 50)
    for app in updatable_apps:
        print(f"Application: {app['name']}")
        print(f"  ID:      {app['id']}")
        print(f"  Version: {app['current_version']}")
        print(f"  Update Available: {app['available_version']}")