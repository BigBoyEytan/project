import os
import win32gui
import win32con
import win32com.client
import pythoncom


class FileSelector:
    def __init__(self, initial_dir=r"C:\Users\student"):
        """
        Initialize FileSelector with a starting directory
        Args:
            initial_dir (str): Starting directory path
        """
        self.initial_dir = initial_dir
        self.selected_files = []

    def resolve_shortcut(self, shortcut_path):
        """
        Resolve a Windows shortcut (.lnk) file to its target path
        Args:
            shortcut_path (str): Path to the shortcut file
        Returns:
            str: Target path of the shortcut
        """
        try:
            pythoncom.CoInitialize()
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortCut(shortcut_path)
            return shortcut.Targetpath
        except:
            return shortcut_path
        finally:
            pythoncom.CoUninitialize()

    def select_files(self, show_dialog=True):
        """
        Open file selection dialog and add selected files to the list
        Args:
            show_dialog (bool): Whether to show the continue dialog after selection
        Returns:
            list: Currently selected files
        """
        buffer_size = 4096
        buffer = "\0" * buffer_size

        file_filter = "All Files (*.*)\0*.*\0" \
                      "Shortcuts (*.lnk)\0*.lnk\0" \
                      "Text Files (*.txt)\0*.txt\0" \
                      "Word Files (*.docx)\0*.docx\0" \
                      "PDF Files (*.pdf)\0*.pdf\0" \
                      "Image Files (*.png;*.jpg;*.jpeg)\0*.png;*.jpg;*.jpeg\0\0"

        flags = win32con.OFN_EXPLORER | win32con.OFN_FILEMUSTEXIST | win32con.OFN_ALLOWMULTISELECT

        try:
            file_name, customfilter, flags = win32gui.GetOpenFileNameW(
                InitialDir=self.initial_dir,
                Flags=flags,
                File=buffer,
                DefExt="txt",
                Title="בחר קבצים",
                Filter=file_filter,
                MaxFile=buffer_size
            )

            if file_name:
                parts = file_name.split('\0')

                if len(parts) > 1:
                    directory = parts[0]
                    files = parts[1:]
                    for f in files:
                        full_path = os.path.join(directory, f)
                        if full_path.lower().endswith('.lnk'):
                            target_path = self.resolve_shortcut(full_path)
                            if target_path and os.path.exists(target_path):
                                self.selected_files.append(target_path)
                        else:
                            self.selected_files.append(full_path)
                else:
                    if file_name.lower().endswith('.lnk'):
                        target_path = self.resolve_shortcut(file_name)
                        if target_path and os.path.exists(target_path):
                            self.selected_files.append(target_path)
                    else:
                        self.selected_files.append(file_name)

                if show_dialog:
                    self.print_current_files()
                    if self.ask_continue():
                        self.select_files()

        except Exception as e:
            print(f"Error: {e}")

        return self.selected_files

    def print_current_files(self):
        """Print the current list of selected files"""
        print("\nCurrent list of selected files:")
        for idx, file in enumerate(self.selected_files, 1):
            print(f"{idx}. {file}")

    def ask_continue(self):
        """Ask if user wants to select more files"""
        while True:
            response = input("\nDo you want to select more files? (y/n): ").lower()
            if response in ['y', 'n']:
                return response == 'y'
            print("Please enter 'y' for yes or 'n' for no.")

    def get_selected_files(self):
        """Return the list of selected files"""
        return self.selected_files

    def clear_selected_files(self):
        """Clear the list of selected files"""
        self.selected_files = []