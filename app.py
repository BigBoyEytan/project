"""
Security Scanner & Optimizer Application
Main application class that handles UI setup and client operations
"""
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import traceback

# Add current directory to path to allow imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
parent_parent_dir = os.path.dirname(parent_dir)

# Set up paths for imports
sys.path.extend([
    parent_dir,
    parent_parent_dir,
    os.path.join(parent_dir, 'scan_file'),
    os.path.join(parent_dir, 'apps'),
])

# Import client
try:
    from client import SecureClient
except ImportError:
    print("Error importing SecureClient, trying alternative path")
    from client_side.client import SecureClient

# Import UI components with improved error handling
try:
    from client_app.ui.styles import configure_styles
    from client_app.ui.login import setup_login_window, connect_with_splash, show_splash_screen
    from client_app.ui.register import register
    from client_app.ui.apps_tab import setup_apps_tab
    from client_app.ui.score_tab import setup_score_tab
    from client_app.ui.scan_tab import setup_scan_tab
except ImportError as e:
    print(f"Error importing UI components: {e}")
    from ui.styles import configure_styles
    from ui.login import setup_login_window, connect_with_splash, show_splash_screen
    from ui.register import register
    from ui.apps_tab import setup_apps_tab
    from ui.score_tab import setup_score_tab
    from ui.scan_tab import setup_scan_tab

# Import utilities with improved error handling
try:
    from client_app.utils.device_info import get_device_info
    from client_app.utils.file_utils import format_size
except ImportError:
    print("Error importing utilities, trying alternative path")
    from utils.device_info import get_device_info
    from utils.file_utils import format_size

# Import apps interactor with improved error handling
try:
    from apps.apps_interact import AppsInterface
except ImportError:
    print("Error importing AppsInterface, trying alternative path")
    from client_side.apps.apps_interact import AppsInterface


class SecurityApp:
    """Main application class for Security Scanner & Optimizer"""

    def __init__(self, root):
        """Initialize the application with the given root window"""
        self.root = root
        self.is_connected = False
        self.is_logged_in = False
        self.user_email = None
        self.session_token = None
        self.scan_results = []
        self.last_dir = os.path.expanduser("~")  # Default to user's home directory

        try:
            # Connect to server
            self.client = SecureClient(host='localhost', port=8000)

            # Configure styles
            configure_styles(self.root)

            # Initialize the apps interface
            self.apps_interface = AppsInterface()

            # Show splash screen and attempt to connect
            show_splash_screen(self)
            connect_with_splash(self)

            # Setup initial login window
            setup_login_window(self)
        except Exception as e:
            print(f"Error initializing SecurityApp: {e}")
            traceback.print_exc()
            messagebox.showerror("Initialization Error", f"Failed to initialize the application: {str(e)}")

    def register(self):
        """Handle user registration"""
        try:
            register(self)
        except Exception as e:
            print(f"Error during registration: {e}")
            traceback.print_exc()
            messagebox.showerror("Registration Error", f"An error occurred during registration: {str(e)}")

    def setup_main_app(self):
        """Set up the main application after successful login"""
        print("Setting up main application...")

        try:
            # Create main notebook for tabs
            self.notebook = ttk.Notebook(self.root)
            self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            # Create tabs
            self.scan_tab = ttk.Frame(self.notebook)
            self.apps_tab = ttk.Frame(self.notebook)
            self.score_tab = ttk.Frame(self.notebook)

            # Add tabs to notebook
            self.notebook.add(self.scan_tab, text="Scan Files")
            self.notebook.add(self.apps_tab, text="Applications")
            self.notebook.add(self.score_tab, text="Security Score")

            print("Tabs created, setting up tab content...")

            # Set up each tab with error handling
            try:
                setup_scan_tab(self)
                print("Scan tab setup complete")
            except Exception as e:
                print(f"Error setting up scan tab: {e}")
                traceback.print_exc()
                self.scan_tab_error = ttk.Label(self.scan_tab, text=f"Error setting up scan tab: {str(e)}")
                self.scan_tab_error.pack(pady=20)

            try:
                setup_apps_tab(self)
                print("Apps tab setup complete")
            except Exception as e:
                print(f"Error setting up apps tab: {e}")
                traceback.print_exc()
                self.apps_tab_error = ttk.Label(self.apps_tab, text=f"Error setting up apps tab: {str(e)}")
                self.apps_tab_error.pack(pady=20)

            try:
                setup_score_tab(self)
                print("Score tab setup complete")
            except Exception as e:
                print(f"Error setting up score tab: {e}")
                traceback.print_exc()
                self.score_tab_error = ttk.Label(self.score_tab, text=f"Error setting up score tab: {str(e)}")
                self.score_tab_error.pack(pady=20)

            # Create status bar
            self.status_bar = ttk.Frame(self.root, relief=tk.SUNKEN)
            self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

            self.status_var = tk.StringVar(value="Ready")
            status_label = ttk.Label(self.status_bar, textvariable=self.status_var, anchor=tk.W)
            status_label.pack(side=tk.LEFT, padx=5, pady=2)

            # Add logout button to status bar
            logout_btn = ttk.Button(self.status_bar, text="Logout", command=self.logout)
            logout_btn.pack(side=tk.RIGHT, padx=5, pady=2)

            print("Main app setup complete")
        except Exception as e:
            print(f"Error in setup_main_app: {e}")
            traceback.print_exc()
            messagebox.showerror("Error", f"Failed to set up main application: {str(e)}")

    def logout(self):
        """Log out the current user"""
        if self.is_logged_in and self.client and self.session_token:
            try:
                # Show logout in progress
                self.update_status("Logging out...")

                # Create a simple progress dialog
                progress_window = tk.Toplevel(self.root)
                progress_window.title("Logging Out")
                progress_window.geometry("300x100")
                progress_window.transient(self.root)
                progress_window.grab_set()

                ttk.Label(progress_window, text="Logging out, please wait...").pack(pady=10)
                progress = ttk.Progressbar(progress_window, mode="indeterminate")
                progress.pack(padx=20, pady=10, fill=tk.X)
                progress.start()

                def logout_thread():
                    try:
                        logout_success = self.client.logout()
                        self.root.after(0, lambda: complete_logout(logout_success))
                    except Exception as e:
                        print(f"Error in logout thread: {e}")
                        traceback.print_exc()
                        self.root.after(0, lambda: complete_logout(False))

                def complete_logout(success):
                    try:
                        # Stop progress
                        progress.stop()
                        progress_window.destroy()

                        # Update status regardless of success
                        self.is_logged_in = False
                        self.user_email = None
                        self.session_token = None

                        if success:
                            messagebox.showinfo("Logout", "You have been logged out successfully")
                        else:
                            messagebox.showwarning("Logout", "Logout may not have completed successfully on the server")

                        # Destroy current UI
                        if hasattr(self, 'notebook'):
                            self.notebook.destroy()
                        if hasattr(self, 'status_bar'):
                            self.status_bar.destroy()

                        # Show login screen again
                        setup_login_window(self)
                    except Exception as e:
                        print(f"Error completing logout: {e}")
                        traceback.print_exc()
                        messagebox.showerror("Logout Error", f"Error during logout completion: {str(e)}")

                # Start logout in background
                threading.Thread(target=logout_thread).start()

            except Exception as e:
                print(f"Error during logout: {e}")
                traceback.print_exc()
                messagebox.showerror("Logout Error", f"An error occurred during logout: {str(e)}")
        else:
            # Not logged in or no valid session, just return to login
            if hasattr(self, 'notebook'):
                self.notebook.destroy()
            if hasattr(self, 'status_bar'):
                self.status_bar.destroy()

            setup_login_window(self)

    def update_status(self, message):
        """Update the status bar message"""
        if hasattr(self, 'status_var'):
            self.status_var.set(message)
            self.root.update_idletasks()

    def get_device_info(self):
        """Get device information for authentication and security tracking"""
        try:
            return get_device_info(self.root)
        except Exception as e:
            print(f"Error getting device info: {e}")
            traceback.print_exc()
            return {"error": str(e), "hostname": "unknown"}