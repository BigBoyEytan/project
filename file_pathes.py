import os
from pathlib import Path
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


def find_file_in_directory(filename: str, root_dir: str) -> List[Path]:
    """
    Search a directory for files matching the given filename.

    Args:
        filename (str): Name of the file to search for (case-insensitive)
        root_dir (str): Directory to search in

    Returns:
        List[Path]: List of paths where the file was found
    """
    found_paths = []
    try:
        for root, _, files in os.walk(root_dir):
            for file in files:
                if filename.lower() in file.lower():
                    full_path = Path(root) / file
                    found_paths.append(full_path.resolve())
    except (PermissionError, OSError):
        pass
    return found_paths


def find_paths(target: str, search_path: Optional[str] = None) -> List[Path]:
    """
    Find all instances of a file based on name or full path.

    Args:
        target (str): Full path to a file or just the filename to search for
        search_path (str, optional): Directory to start search from.
            Defaults to user's home directory

    Returns:
        List[Path]: List of all matching file paths
    """
    # If target is a full path, get just the filename
    filename = Path(target).name

    # Set default search path to user's home if none provided
    if not search_path:
        search_path = str(Path.home())

    # Initialize paths list
    found_paths = []

    # Search directories in parallel
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(find_file_in_directory, filename, search_path)]

        for future in as_completed(futures):
            found_paths.extend(future.result())

    # Remove duplicates while preserving order
    unique_paths = list(dict.fromkeys(found_paths))

    return unique_paths


def main():
    """
    Main function that takes user input and displays results.
    """
    # Get input from user
    print("Enter either:")
    print("1. A full file path")
    print("2. Just a filename to search for")
    target = input("Your input: ").strip()

    # Optional: get custom search path
    print("\nEnter search directory (optional, press Enter to search from home directory):")
    search_path = input().strip()
    if not search_path:
        search_path = None

    # Find the files
    print("\nSearching...")
    found = find_paths(target, search_path)

    # Print results
    if found:
        print(f"\nFound {len(found)} matches:")
        for path in found:
            print(path)
    else:
        print("\nNo matches found")

    return found


if __name__ == "__main__":
    paths = main()
