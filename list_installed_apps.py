import subprocess
import re


def run_winget_command(command=None):
    """
    Run winget command with optional custom command.

    Args:
        command (list, optional): Custom winget command.
                                  Defaults to standard 'winget list' if not provided.

    Returns:
        str: Command output or empty string if error occurs
    """
    try:
        # Use provided command or default to 'winget list'
        if command is None:
            cmd = ["powershell", "-Command", "winget list"]
        else:
            # If command is a list, convert to powershell command
            cmd = ["powershell", "-Command"] + [" ".join(command)]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",  # Fix encoding issue
            timeout=30
        )

        # Only print error details in debug mode or if return code is non-zero
        if result.returncode != 0:
            print(f"Command failed. Return: {result.returncode}, Error: {result.stderr}")
            return ""

        return result.stdout
    except Exception as e:
        print(f"Error running winget command: {e}")
        return ""


def get_installed_apps():
    """Retrieve list of installed applications."""
    output = run_winget_command()
    if not output:
        print("No output received from winget")
        return []

    installed_apps = []
    lines = output.split("\n")

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
    """Display list of installed applications."""
    if not installed_apps:
        print("\n🌟 No installed applications found.")
        return

    print("\n🔍 Installed Applications:")
    print("-" * 50)
    for app in installed_apps:
        print(f"Application: {app['name']}")
        print(f"  ID:      {app['id']}")
        print(f"  Version: {app['current_version']}")