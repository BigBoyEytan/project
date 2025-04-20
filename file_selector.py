import os
import tkinter as tk
from tkinter import filedialog


class FileSelector:
    """A simplified file selector that just lets you pick files once with no additional prompts"""

    def __init__(self, initial_dir=None):
        # Set initial directory
        if initial_dir and os.path.exists(initial_dir):
            self.initial_dir = initial_dir
        else:
            self.initial_dir = os.path.expanduser("~")

    def select_files(self):
        """Select files using tkinter's filedialog with no follow-up prompts"""
        try:
            # Create a root window and hide it
            root = tk.Tk()
            root.withdraw()

            # Open the file dialog
            file_paths = filedialog.askopenfilenames(
                initialdir=self.initial_dir,
                title="Select Files",
                filetypes=(
                    ("All Files", "*.*"),
                    ("Text Files", "*.txt"),
                    ("Word Files", "*.docx"),
                    ("PDF Files", "*.pdf")
                )
            )

            # Convert tuple to list
            selected_files = list(file_paths)

            # Clean up resources
            root.destroy()

            # Print selected files for debugging
            if selected_files:
                print(f"Selected {len(selected_files)} files:")
                for idx, file_path in enumerate(selected_files, 1):
                    print(f"{idx}. {file_path}")

            return selected_files

        except Exception as e:
            print(f"Error selecting files: {e}")
            import traceback
            traceback.print_exc()

            # Make sure to clean up the root window
            try:
                if 'root' in locals() and root:
                    root.destroy()
            except:
                pass

            return []