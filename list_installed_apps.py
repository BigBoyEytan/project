import subprocess
import re


def run_winget_command():
    try:
        result = subprocess.run(
            ["powershell", "-Command", "winget list"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",  # Fix encoding issue
            timeout=30
        )
        print(f"Return: {result.returncode}, Error: {result.stderr}")
        return result.stdout if result.returncode == 0 else ""
    except Exception as e:
        print(f"Error: {e}")
        return ""


def get_installed_apps():
    output = run_winget_command()
    if not output:
        print("No output received from winget")
        return []

    installed_apps = []
    lines = output.split("\n")
    print(f"Processing {len(lines)} lines of output")

    for line in lines[2:]:  # Skip headers
        if not line.strip():
            continue

        parts = re.split(r'\s{2,}', line.strip())  # Split by multiple spaces
        if len(parts) < 2:
            continue  # Ignore malformed lines

        app = {
            "name": parts[0],
            "id": parts[1] if len(parts) > 1 else "N/A",
            "current_version": parts[2] if len(parts) > 2 else "N/A",
        }
        installed_apps.append(app)

    return installed_apps


def display_installed_apps(installed_apps):
    if not installed_apps:
        print("\n🌟 No installed applications found.")
        return

    print("\n🔍 Installed Applications:")
    print("-" * 50)
    for app in installed_apps:
        print(f"Application: {app['name']}")
        print(f"  ID:      {app['id']}")
        print(f"  Version: {app['current_version']}")


