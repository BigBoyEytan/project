import os
from pathlib import Path
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# Define a set of file extensions to be excluded (e.g., LNK, tmp, bak, etc.)
EXCLUDED_EXTENSIONS = {'.lnk', '.tmp', '.bak', '.swp', '.dat', '.ini', '.log'}


def find_file_in_directory(filename: str, root_dir: str) -> List[Path]:
    """
    Search a specific directory for files matching the given filename, excluding certain file types.

    Args:
        filename (str): The filename (without extension) to search for (case-insensitive).
        root_dir (str): The directory to search within.

    Returns:
        List[Path]: A list of found file paths excluding unwanted file extensions.
    """
    found_paths = []
    try:
        # Walk through directory tree
        for root, _, files in os.walk(root_dir):
            # Look for files where the filename is part of the actual file name (case-insensitive)
            for file in files:
                if filename.lower() in file.lower():
                    full_path = Path(root) / file
                    # Exclude files with unwanted extensions
                    if full_path.suffix.lower() not in EXCLUDED_EXTENSIONS:
                        resolved_path = full_path.resolve()
                        found_paths.append(resolved_path)  # Store full path with file extension
    except (PermissionError, OSError):
        # Ignore permission errors and other OS errors
        pass

    return found_paths


def find_file(filename: str, start_path: Optional[str] = None) -> List[Path]:
    """
    Find all instances of a file by name starting from a specified directory,
    without requiring the file type/extension, and return the full path with the file type.

    Args:
        filename (str): Name of the file to find (case-insensitive).
        start_path (str, optional): Starting directory for search.
            Defaults to the root of the current drive.

    Returns:
        List[Path]: List of full paths where the file was found.
    """
    # If no start path provided, use the root of the current drive
    if not start_path:
        start_path = os.path.abspath(os.sep)  # Root of current drive

    found_paths = []
    directories_to_search = []

    # Step 1: Prioritize searching in user directories
    user_home = Path.home()
    common_user_folders = ['Documents', 'Downloads', 'Desktop']

    # Add user directories (Documents, Downloads, Desktop) to search list if they exist
    for folder in common_user_folders:
        folder_path = user_home / folder
        if folder_path.exists() and folder_path.is_dir():
            directories_to_search.append(folder_path)

    # Step 2: Add broader directories if necessary (i.e., everything else)
    directories_to_search.append(start_path)

    # Step 3: Thread pool for parallel search in multiple directories
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = []
        for directory in directories_to_search:
            futures.append(executor.submit(find_file_in_directory, filename, directory))

        # Collect results from the threads
        for future in as_completed(futures):
            found_paths.extend(future.result())

    # Remove duplicates by converting to a set and back to a list
    found_paths = list(set(found_paths))

    return found_paths


def main():
    """
    Interactive function to search for files from the Python console.
    Returns the list of found paths for further use.
    """
    filename = input("Enter filename to search for (without extension): ").strip()

    # Ask for start directory
    start_dir = input("Enter start directory (press Enter for full drive search): ").strip()
    if not start_dir:
        start_dir = os.path.abspath(os.sep)  # Root of current drive

    print(f"\nSearching for '{filename}' starting from {start_dir}")
    print("This may take a while for broad searches...")

    # Perform search
    paths = find_file(filename, start_dir)

    # Display results
    if paths:
        print(f"\nFound {len(paths)} matches:")
        for i, path in enumerate(paths, 1):
            # Print the full path, including file extension
            print(f"{i}. {path}")  # Print full path with file extension
    else:
        print("\nNo matches found")

    return paths


if __name__ == "__main__":
    found_paths = main()
