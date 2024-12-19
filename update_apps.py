import subprocess
import sys
import re


def run_winget_command(command):
    """
    Run winget command with robust encoding handling.

    Args:
    command (list): Winget command to run

    Returns:
    str: Command output
    """
    try:
        # Use UTF-8 encoding with error handling
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',  # Replace undecodable characters
            shell=True
        )

        # Check if command was successful
        if result.returncode != 0:
            print(f"Error running winget: {result.stderr}")
            return ""

        return result.stdout

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return ""


def get_installed_apps():
    """
    Retrieve a list of installed applications using winget.

    Returns:
    list: A list of dictionaries containing information about installed apps
    """
    # Run winget to list installed applications
    output = run_winget_command(['winget', 'list'])

    if not output:
        return []

    # Parse the output
    installed_apps = []
    lines = output.split('\n')

    # Skip header lines and process data lines
    for line in lines[2:]:  # Adjust index based on winget output format
        # Skip empty lines and lines that don't contain app information
        if not line.strip():
            continue

        # Split the line into columns
        parts = re.split(r'\s{2,}', line.strip())

        # Ensure we have enough parts to extract information
        if len(parts) >= 3:
            app = {
                'name': parts[0],
                'id': parts[1] if len(parts) > 1 else 'N/A',
                'current_version': parts[2] if len(parts) > 2 else 'N/A',
                'available_version': 'N/A'  # As specified, this will be empty for installed apps
            }
            installed_apps.append(app)

    return installed_apps


def get_updatable_apps():
    """
    Check for updatable applications using winget.

    Returns:
    list: A list of dictionaries containing update information for each app
    """
    # Run winget upgrade command
    output = run_winget_command(['winget', 'upgrade'])

    if not output:
        return []

    # Parse the output
    updatable_apps = []
    lines = output.split('\n')

    # Skip header lines and process data lines
    for line in lines[2:]:  # Adjust index based on winget output format
        # Skip empty lines and lines that don't contain app information
        if not line.strip():
            continue

        # Split the line into columns
        parts = re.split(r'\s{2,}', line.strip())

        # Ensure we have enough parts to extract information
        if len(parts) >= 3:
            app = {
                'name': parts[0],
                'id': parts[1] if len(parts) > 1 else 'N/A',
                'current_version': parts[2] if len(parts) > 2 else 'N/A',
                'available_version': parts[3] if len(parts) > 3 else 'N/A'
            }
            updatable_apps.append(app)

    return updatable_apps


def display_apps(apps, title="Installed Applications"):
    """
    Display the list of applications.

    Args:
    apps (list): List of applications
    title (str): Title to display before the list
    """
    if not apps:
        print(f"\n🌟 No {title.lower()} found.")
        return

    print(f"\n🔍 {title}:")
    print("-" * 50)
    for app in apps:
        print(f"Application: {app['name']}")
        print(f"  ID:      {app['id']}")
        print(f"  Version: {app['current_version']}")
        if 'available_version' in app and app['available_version'] != 'N/A':
            print(f"  Update Available: {app['available_version']}")
        print()


def upgrade_apps():
    """
    Perform upgrade for all available applications.
    """
    try:
        print("\n⬆️  Upgrading all applications...")
        result = subprocess.run(
            ['winget', 'upgrade', '--all'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            shell=True
        )

        if result.returncode == 0:
            print("✅ Upgrade process completed.")
        else:
            print("❌ Error during upgrade:")
            print(result.stderr)

    except Exception as e:
        print(f"An error occurred during upgrade: {e}")


def main():
    """
    Main function to run the Windows app management tool.
    """
    try:
        # Check for winget availability
        subprocess.run(
            ['winget', '--version'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=True
        )
    except FileNotFoundError:
        print("❌ Windows Package Manager (winget) is not installed.")
        print("Please install winget from the Microsoft Store or ensure it's in your system PATH.")
        sys.exit(1)
    except subprocess.CalledProcessError:
        print("❌ Error running winget. Please check your installation.")
        sys.exit(1)

    while True:
        # Display menu
        print("\n=== Windows App Management Tool ===")
        print("1. List Installed Applications")
        print("2. Check for Updates")
        print("3. Upgrade Applications")
        print("4. Exit")

        # Get user choice
        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            # List installed apps
            installed_apps = get_installed_apps()
            display_apps(installed_apps)

        elif choice == '2':
            # Check for updates
            updatable_apps = get_updatable_apps()
            display_apps(updatable_apps, "Updatable Applications")

        elif choice == '3':
            # Upgrade applications
            updatable_apps = get_updatable_apps()
            if updatable_apps:
                display_apps(updatable_apps, "Updatable Applications")
                confirm = input("Do you want to upgrade these applications? (y/n): ").lower()
                if confirm == 'y':
                    upgrade_apps()
            else:
                print("No updates available.")

        elif choice == '4':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()

