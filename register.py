import re
import threading
import tkinter as tk
from tkinter import ttk, messagebox


def register(app):
    """Handle user registration without phone number"""
    if not app.is_connected:
        messagebox.showerror("Error", "Not connected to server")
        return

    # Create a registration window
    reg_window = tk.Toplevel(app.root)
    reg_window.title("Register New Account")
    reg_window.geometry("350x290")  # Small size
    reg_window.transient(app.root)
    reg_window.grab_set()
    reg_window.geometry("+%d+%d" % (
        app.root.winfo_rootx() + 50,
        app.root.winfo_rooty() + 200
    ))  # Position lower

    # Make window not resizable
    reg_window.resizable(False, False)

    # Header
    header_label = ttk.Label(reg_window, text="Create Account", font=("Arial", 12, "bold"))
    header_label.grid(row=0, column=0, columnspan=2, pady=(10, 15))

    # Registration form with improved layout
    ttk.Label(reg_window, text="Full Name:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
    name_var = tk.StringVar()
    name_entry = ttk.Entry(reg_window, textvariable=name_var, width=25)
    name_entry.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)
    name_entry.focus_set()  # Set focus to first field

    ttk.Label(reg_window, text="Email:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
    reg_email_var = tk.StringVar()
    ttk.Entry(reg_window, textvariable=reg_email_var, width=25).grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)

    ttk.Label(reg_window, text="Password:").grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)
    reg_password_var = tk.StringVar()
    ttk.Entry(reg_window, textvariable=reg_password_var, show="*", width=25).grid(row=3, column=1, padx=10, pady=5,
                                                                                  sticky=tk.W)

    ttk.Label(reg_window, text="Confirm Password:").grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)
    confirm_password_var = tk.StringVar()
    ttk.Entry(reg_window, textvariable=confirm_password_var, show="*", width=25).grid(row=4, column=1, padx=10, pady=5,
                                                                                      sticky=tk.W)

    # Progress bar with better appearance
    reg_progress = ttk.Progressbar(reg_window, orient=tk.HORIZONTAL, mode='indeterminate')
    reg_progress.grid(row=5, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=(15, 5))
    reg_progress.grid_remove()  # Hide initially

    # Status label with color indication
    status_var = tk.StringVar(value="")
    status_label = ttk.Label(reg_window, textvariable=status_var)
    status_label.grid(row=6, column=0, columnspan=2, pady=5)

    def do_register():
        # Reset status color
        status_label.config(style="")

        # Get form values
        name = name_var.get().strip()
        email = reg_email_var.get().strip()
        password = reg_password_var.get()
        confirm_password = confirm_password_var.get()

        # Validate inputs
        if not all([name, email, password, confirm_password]):
            status_var.set("All fields are required")
            status_label.config(style="Red.TLabel")
            return

        if password != confirm_password:
            status_var.set("Passwords do not match")
            status_label.config(style="Red.TLabel")
            return

        # Email validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            status_var.set("Invalid email format")
            status_label.config(style="Red.TLabel")
            return

        # Password strength validation
        if not password:
            status_var.set("Password cannot be empty")
            status_label.config(style="Red.TLabel")
            return

        # Show progress
        reg_progress.grid()
        reg_progress.start(10)
        status_var.set("Registering...")
        register_btn.config(state="disabled")

        def register_thread():
            # Call client registration method
            response = app.client._send_command('register', {
                'name': name,
                'email': email,
                'password': password,
                'device_info': app.get_device_info()
            })

            reg_window.after(0, lambda: reg_progress.stop())

            if response['status'] == 'success':
                reg_window.after(0, lambda: status_var.set("Registration successful! You can now log in."))
                reg_window.after(0, lambda: status_label.config(style="Green.TLabel"))

                # Pre-fill login form with the registered email
                app.root.after(0, lambda: app.email_var.set(email))

                # Close window after a short delay (800ms)
                reg_window.after(800, reg_window.destroy)
            else:
                reg_window.after(0, lambda: status_var.set(
                    f"Registration failed: {response.get('message', 'Unknown error')}"))
                reg_window.after(0, lambda: status_label.config(style="Red.TLabel"))
                reg_window.after(0, lambda: register_btn.config(state="normal"))

        threading.Thread(target=register_thread).start()

    # Register button with primary styling
    register_btn = ttk.Button(reg_window, text="Register", command=do_register, style="Primary.TButton")
    register_btn.grid(row=7, column=0, columnspan=2, pady=15)

    # Handle Enter key
    reg_window.bind('<Return>', lambda event: do_register())