import subprocess
import re
import time


def run_winget_command(command=None, max_wait=120):
    """
    Run winget command with optional custom command and wait for complete output.

    Args:
        command (list or str, optional): Custom winget command.
        max_wait (int, optional): Maximum wait time in seconds. Default is 120.

    Returns:
        str: Command output or empty string if error occurs
    """
    try:
        # Use provided command or default to 'winget list'
        if command is None:
            cmd = "winget list"
        elif isinstance(command, list):
            cmd = " ".join(command)
        else:
            cmd = command

        print(f"Executing command: {cmd}")

        # Start the process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        # Wait for completion with timeout
        try:
            print(f"Waiting for command to complete (timeout: {max_wait} seconds)...")
            stdout, stderr = process.communicate(timeout=max_wait)

            if process.returncode != 0:
                print(f"Command returned non-zero exit code: {process.returncode}")
                print(f"Error output: {stderr}")
                return stdout  # Return stdout even if there's an error code, as there might be useful data

            print(f"Command completed successfully ({len(stdout)} bytes)")
            return stdout

        except subprocess.TimeoutExpired:
            print(f"Command timed out after {max_wait} seconds")
            process.kill()
            return ""

    except Exception as e:
        print(f"Error executing command: {e}")
        return ""


def get_installed_apps():
    """Retrieve list of installed applications.

    Returns:
        list: List of dictionaries with app data
    """
    # Get the raw output with extended timeout for slow systems
    print("Getting installed applications...")
    output = run_winget_command("winget list", max_wait=180)
    if not output:
        print("No output received from winget list command")
        return []

    installed_apps = []
    lines = output.split("\n")

    # Find where the actual app list starts - look for the line with Name and ID
    header_index = -1
    for i, line in enumerate(lines):
        # More robust header detection - case insensitive and trimmed
        if re.search(r'name.*id.*version', line.lower().strip()):
            header_index = i
            break

    if header_index == -1:
        print("Could not find header row in output")
        return []

    # Skip header and separator line
    start_index = header_index + 2

    # Process apps
    for line in lines[start_index:]:
        # Skip empty lines, separator lines, progress indicators, and short lines
        line = line.strip()
        if (not line or
                line.startswith('-') or
                any(char in line for char in ['█', '▒', '\\', '|', '/', '●']) or
                len(line) < 10):
            continue

        # Try to parse the line
        try:
            # Split by multiple spaces (2 or more)
            parts = re.split(r'\s{2,}', line)
            if len(parts) >= 2:
                app = {
                    "name": parts[0].strip(),
                    "id": parts[1].strip() if len(parts) > 1 else "N/A",
                    "current_version": parts[2].strip() if len(parts) > 2 else "N/A",
                }
                # Add available version if present
                if len(parts) > 3:
                    app["available_version"] = parts[3].strip()

                installed_apps.append(app)
        except Exception as e:
            print(f"Failed to parse line: {line} - {e}")
            continue  # Skip lines that can't be parsed

    print(f"Found {len(installed_apps)} installed applications")
    return installed_apps


def get_upgradable_apps():
    """Retrieve list of applications with available upgrades.

    Returns:
        list: List of dictionaries with upgradable app data
    """
    # Get the raw output from winget upgrade
    print("Checking for application updates...")

    # IMPORTANT: Adding --include-unknown to ensure we catch all possible updates
    output = run_winget_command("winget upgrade --include-unknown", max_wait=180)
    if not output:
        print("No output received from winget upgrade command")
        return []

    # Print the entire output for debugging
    print("\nRaw winget upgrade output:")
    print("-" * 50)
    print(output)
    print("-" * 50)

    # New direct parsing approach that better handles the specific format
    upgradable_apps = []
    lines = output.split("\n")

    # Find the line containing "upgrades available"
    upgrades_count_line = None
    for line in reversed(lines):  # Search in reverse to find the last occurrence
        if "upgrades available" in line.lower():
            upgrades_count_line = line
            print(f"Found upgrades count line: {line}")
            break

    # Check if we found any upgrades
    if upgrades_count_line and "0 upgrades available" not in upgrades_count_line:
        # Find the header line (contains "Name", "Id", "Version", "Available")
        header_index = -1
        header_pattern = re.compile(r'name.*id.*version.*available', re.IGNORECASE)
        for i, line in enumerate(lines):
            if header_pattern.search(line):
                header_index = i
                print(f"Found header at line {i}: {line}")
                break

        if header_index == -1:
            print("Header not found in output")
            return []

        # Locate the separator line (typically dashes)
        separator_index = header_index + 1
        if separator_index < len(lines) and all(c == '-' for c in lines[separator_index].strip().replace(" ", "")):
            print(f"Found separator at line {separator_index}")

            # Process all lines between separator and upgrades count
            for i in range(separator_index + 1, len(lines)):
                line = lines[i].strip()

                # Stop when we reach the upgrades count line or an empty line near the end
                if "upgrades available" in line.lower() or (not line and i > len(lines) - 3):
                    break

                # Skip empty lines or lines with just dashes
                if not line or line.startswith('-') or all(c == '-' for c in line.replace(" ", "")):
                    continue

                # Skip progress indicator lines
                if any(char in line for char in ['█', '▒', '\\', '|', '/', '●']):
                    continue

                print(f"Processing upgrade line: {line}")

                # Try different parsing approaches
                try:
                    # First try parsing as whitespace-delimited columns
                    parts = re.split(r'\s{2,}', line)

                    if len(parts) >= 4:  # Name, ID, Version, Available
                        app = {
                            "name": parts[0].strip(),
                            "id": parts[1].strip(),
                            "current_version": parts[2].strip(),
                            "available_version": parts[3].strip(),
                        }

                        # Add source if present
                        if len(parts) > 4:
                            app["source"] = parts[4].strip()

                        print(
                            f"Found upgrade: {app['name']} ({app['id']}) - {app['current_version']} → {app['available_version']}")
                        upgradable_apps.append(app)
                    elif len(parts) == 2:
                        # Special case where the output might be formatted differently
                        # Try to parse: "Discord Discord.Discord 1.0.9186 1.0.9187  winget"
                        match = re.match(r'(.+?)\s+(.+?)\s+(\S+)\s+(\S+)(?:\s+(.+))?', line)
                        if match:
                            app = {
                                "name": match.group(1).strip(),
                                "id": match.group(2).strip(),
                                "current_version": match.group(3).strip(),
                                "available_version": match.group(4).strip(),
                            }
                            if match.group(5):
                                app["source"] = match.group(5).strip()

                            print(
                                f"Found upgrade (alternative parse): {app['name']} ({app['id']}) - {app['current_version']} → {app['available_version']}")
                            upgradable_apps.append(app)
                except Exception as e:
                    print(f"Failed to parse line: {line} - {e}")

    # Manual fallback for discord pattern specifically if nothing was found
    if not upgradable_apps and "discord discord.discord" in output.lower():
        print("Applying Discord-specific fallback parsing")
        pattern = r'discord\s+discord\.discord\s+(\S+)\s+(\S+)'
        match = re.search(pattern, output.lower())
        if match:
            app = {
                "name": "Discord",
                "id": "Discord.Discord",
                "current_version": match.group(1),
                "available_version": match.group(2),
                "source": "winget"
            }
            print(f"Found Discord update using fallback: {app['current_version']} → {app['available_version']}")
            upgradable_apps.append(app)

    print(f"Found {len(upgradable_apps)} applications with available updates")
    return upgradable_apps


def display_installed_apps(installed_apps):
    """Display list of installed applications."""
    if not installed_apps:
        print("\nNo installed applications found.")
        return

    print(f"\nFound {len(installed_apps)} installed applications")
    if installed_apps:
        # Display first few apps
        for i, app in enumerate(installed_apps[:3]):
            version_info = app['current_version']
            if 'available_version' in app:
                version_info += f" → {app['available_version']}"

            print(f"  {i + 1}. {app['name']} (ID: {app['id']}, Version: {version_info})")
        if len(installed_apps) > 3:
            print(f"  ... and {len(installed_apps) - 3} more")


def display_upgradable_apps(upgradable_apps):
    """Display list of applications with available upgrades."""
    if not upgradable_apps:
        print("\nNo updatable applications found.")
        return

    print(f"\nFound {len(upgradable_apps)} applications with available updates")
    if upgradable_apps:
        # Display all upgradable apps
        for i, app in enumerate(upgradable_apps):
            print(f"  {i + 1}. {app['name']}")
            print(f"     ID: {app['id']}")
            print(f"     Current Version: {app['current_version']}")
            print(f"     Available Version: {app['available_version']}")
            if 'source' in app:
                print(f"     Source: {app['source']}")
            print()