import os
import sys
import tkinter as tk
from tkinter import messagebox
import traceback

# Get absolute path to project directories
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)  # Project root


# Create __init__.py files in all subdirectories if they don't exist
def ensure_init_files(base_path):
    """Create __init__.py files in all subdirectories if they don't exist"""
    for root, dirs, files in os.walk(base_path):
        # Skip __pycache__ directories
        if '__pycache__' in root:
            continue

        # Create __init__.py if it doesn't exist
        init_file = os.path.join(root, '__init__.py')
        if not os.path.exists(init_file):
            with open(init_file, 'w') as f:
                f.write('# Auto-generated __init__.py file\n')
            print(f"Created: {init_file}")


# Create necessary init files
ensure_init_files(current_dir)

# Add all necessary directories to system path
sys.path.extend([
    parent_dir,  # Project root
    current_dir,  # client_side
    os.path.join(current_dir, "client_app"),
    os.path.join(current_dir, "scan_file"),
    os.path.join(current_dir, "apps"),
    os.path.join(current_dir, "client_app", "ui"),
    os.path.join(current_dir, "client_app", "utils")
])


def main():
    try:
        # Set application theme and styling
        print("Setting up application style...")
        try:
            # Try to use a modern theme
            import ttkthemes
            root = ttkthemes.ThemedTk(theme="arc")  # Use a modern theme if ttkthemes is available
        except ImportError:
            # Fall back to standard Tk
            root = tk.Tk()

        # Set application icon if available
        try:
            icon_path = os.path.join(current_dir, 'client_app', 'assets', 'security_icon.ico')
            if os.path.exists(icon_path):
                root.iconbitmap(icon_path)
        except Exception as e:
            print(f"Could not load icon: {e}")
            pass  # Icon not critical, continue without it

        # Configure window properties
        root.title("Security Scanner & Optimizer")
        root.geometry("950x650")
        root.minsize(800, 600)  # Set minimum window size

        # Center window on screen
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width - 950) // 2
        y = (screen_height - 650) // 2
        root.geometry(f"+{x}+{y}")

        # Import the client module directly
        from client import SecureClient

        # Import from client_app
        from client_app.app import SecurityApp

        # Initialize the app
        print("Creating SecurityApp...")
        app = SecurityApp(root)

        # Set up closing protocol
        print("Setting up window close protocol...")

        def on_close():
            # Ask for confirmation if logged in
            if hasattr(app, 'is_logged_in') and app.is_logged_in:
                if messagebox.askyesno("Confirm Exit", "Are you sure you want to exit? This will log you out."):
                    if hasattr(app, 'logout'):
                        app.logout()  # Properly log out
                    root.destroy()
            else:
                # Just exit if not logged in
                root.destroy()

        root.protocol("WM_DELETE_WINDOW", on_close)

        # Start the main loop
        print("Starting main loop...")
        root.mainloop()
        print("Main loop ended.")

    except Exception as e:
        print(f"Error occurred: {e}")
        traceback.print_exc()

        # Show error to user
        try:
            messagebox.showerror("Application Error",
                                 f"A critical error has occurred: {str(e)}\n\n"
                                 "Please restart the application.")
        except:
            pass  # If even the error message fails, just exit


if __name__ == "__main__":
    main()