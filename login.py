import threading
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import scrolledtext

import time


def show_splash_screen(app):
    """Show a splash screen while initializing"""
    # Create a splash screen frame
    app.splash = tk.Toplevel(app.root)
    app.splash.overrideredirect(True)  # No window decorations

    # Calculate position (center on screen)
    screen_width = app.root.winfo_screenwidth()
    screen_height = app.root.winfo_screenheight()
    splash_width = 400
    splash_height = 250
    x = (screen_width - splash_width) // 2
    y = (screen_height - splash_height) // 2
    app.splash.geometry(f"{splash_width}x{splash_height}+{x}+{y}")

    # Add content to splash screen
    splash_frame = ttk.Frame(app.splash, padding=20)
    splash_frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(splash_frame, text="Security Scanner & Optimizer",
              font=("Arial", 16, "bold")).pack(pady=(0, 20))

    ttk.Label(splash_frame, text="Initializing application...",
              font=("Arial", 10)).pack(pady=5)

    # Progress bar
    app.splash_progress = ttk.Progressbar(splash_frame, mode="indeterminate", length=300)
    app.splash_progress.pack(pady=20)
    app.splash_progress.start(10)

    app.splash_status = ttk.Label(splash_frame, text="Connecting to server...")
    app.splash_status.pack(pady=5)

    # Make splash screen visible on top
    app.splash.lift()
    app.splash.grab_set()

    # Force update to show splash immediately
    app.splash.update()


def connect_with_splash(app):
    """Connect to server with splash screen feedback"""

    def connect_thread():
        # Simulate initializing components
        app.splash_status.config(text="Initializing security components...")
        time.sleep(0.5)

        # Connect to server
        app.splash_status.config(text="Connecting to security server...")
        success = app.client.connect()

        # Update connection status
        if success:
            app.is_connected = True
            app.splash_status.config(text="Connected to server")
            time.sleep(0.5)
        else:
            app.is_connected = False
            app.splash_status.config(text="Not connected to server - continuing offline")
            time.sleep(1)

        # Close splash and update login window
        app.root.after(0, lambda: _finish_splash_and_update_status(app))

    threading.Thread(target=connect_thread).start()


def _finish_splash_and_update_status(app):
    """Finish splash screen and update connection status"""
    if hasattr(app, 'splash') and app.splash:
        app.splash_progress.stop()
        app.splash.destroy()

    # Update login connection status
    if app.is_connected:
        app.connection_status.config(text="Connected to server", style="Green.TLabel")
    else:
        app.connection_status.config(text="Not connected to server - check server status", style="Red.TLabel")


def setup_login_window(app):
    """Set up the login window that appears on startup"""
    # Create a frame for the login window
    app.login_window = ttk.Frame(app.root)
    app.login_window.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

    # Create header with app logo/title
    header_frame = ttk.Frame(app.login_window)
    header_frame.pack(fill=tk.X, pady=(0, 30))

    title_label = ttk.Label(header_frame, text="Security Scanner & Optimizer",
                            style="Title.TLabel")
    title_label.pack(pady=10)

    subtitle_label = ttk.Label(header_frame,
                               text="Protect your system and improve security with advanced scanning")
    subtitle_label.pack(pady=(0, 10))

    # Connection status indicator
    status_frame = ttk.Frame(app.login_window)
    status_frame.pack(fill=tk.X, pady=(0, 20))

    app.connection_status = ttk.Label(status_frame, text="Connecting to server...", style="Red.TLabel")
    app.connection_status.pack(side=tk.LEFT, padx=5)

    # Login form
    login_frame = ttk.LabelFrame(app.login_window, text="User Login")
    login_frame.pack(fill=tk.X, pady=10, padx=100)

    # Grid layout with padding
    login_frame.columnconfigure(0, weight=1)
    login_frame.columnconfigure(1, weight=3)

    # Email field
    ttk.Label(login_frame, text="Email:").grid(row=0, column=0, sticky=tk.W, padx=15, pady=10)
    app.email_var = tk.StringVar()
    email_entry = ttk.Entry(login_frame, textvariable=app.email_var, width=30)
    email_entry.grid(row=0, column=1, sticky=tk.W + tk.E, padx=15, pady=10)
    email_entry.focus_set()  # Auto-focus on email field

    # Password field
    ttk.Label(login_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=15, pady=10)
    app.password_var = tk.StringVar()
    ttk.Entry(login_frame, textvariable=app.password_var, show="*", width=30).grid(
        row=1, column=1, sticky=tk.W + tk.E, padx=15, pady=10)


    # Login buttons
    btn_frame = ttk.Frame(login_frame)
    btn_frame.grid(row=3, column=0, columnspan=2, pady=15)

    app.login_btn = ttk.Button(btn_frame, text="Login", style="Primary.TButton",
                               width=15, command=lambda: login(app))
    app.login_btn.pack(side=tk.LEFT, padx=5)

    app.register_btn = ttk.Button(btn_frame, text="Register", width=15, command=app.register)
    app.register_btn.pack(side=tk.LEFT, padx=5)

    # 2FA verification frame
    app.verification_frame = ttk.LabelFrame(app.login_window, text="Two-Factor Authentication")
    app.verification_frame.pack(fill=tk.X, padx=150, pady=20)
    app.verification_frame.pack_forget()  # Hide initially

    verification_info = ttk.Label(app.verification_frame,
                                  text="A verification code has been sent to your email.\nPlease enter it below:")
    verification_info.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky=tk.W)

    ttk.Label(app.verification_frame, text="Verification Code:").grid(
        row=1, column=0, sticky=tk.W, padx=10, pady=10)

    app.verification_code_var = tk.StringVar()
    verification_entry = ttk.Entry(app.verification_frame, textvariable=app.verification_code_var,
                                   width=10, font=("Arial", 12, "bold"))
    verification_entry.grid(row=1, column=1, sticky=tk.W, padx=10, pady=10)

    verify_btn = ttk.Button(app.verification_frame, text="Verify", style="Primary.TButton",
                            command=lambda: verify_2fa(app))
    verify_btn.grid(row=1, column=2, padx=10, pady=10)

    resend_btn = ttk.Button(app.verification_frame, text="Resend Code",
                            command=lambda: login(app, resend=True))
    resend_btn.grid(row=2, column=1, columnspan=2, padx=10, pady=(0, 10), sticky=tk.E)

    # Progress bar for login process
    app.login_progress = ttk.Progressbar(app.login_window, orient=tk.HORIZONTAL, mode='indeterminate')
    app.login_progress.pack(fill=tk.X, padx=100, pady=15)
    app.login_progress.pack_forget()  # Hide initially

    # Status message
    app.login_status = ttk.Label(app.login_window, text="")
    app.login_status.pack(pady=10)

    # Bottom info section
    info_frame = ttk.Frame(app.login_window)
    info_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)

    version_label = ttk.Label(info_frame, text="Version 1.0.0")
    version_label.pack(side=tk.RIGHT, padx=10)


def login(app, resend=False):
    """Handle user login"""
    if not app.is_connected:
        messagebox.showerror("Connection Error", "Not connected to server. Please check if the server is running.")
        return

    # If resending verification code, use the existing email
    if resend and app.user_email:
        email = app.user_email
        password = app.password_var.get()
    else:
        email = app.email_var.get().strip()
        password = app.password_var.get()

    verification_method = "email"  # Always use email for 2FA

    if not email or not password:
        messagebox.showerror("Error", "Please enter both email and password")
        return

    # Show progress bar and update status
    app.login_progress.pack(fill=tk.X, padx=100, pady=10)
    app.login_progress.start(10)

    if resend:
        app.login_status.config(text=f"Resending verification code to {email}...")
    else:
        app.login_status.config(text=f"Logging in as {email}...")

    # Disable buttons during login
    app.login_btn.config(state="disabled")
    app.register_btn.config(state="disabled")

    def login_thread():
        # Store email for later use in 2FA verification
        if not resend:
            app.user_email = email

        # Call client login method
        response = app.client._send_command('login', {
            'email': email,
            'password': password,
            'verification_method': verification_method,
            'device_info': app.get_device_info()
        })

        # Stop progress
        app.root.after(0, lambda: app.login_progress.stop())

        if response['status'] == 'success':
            if resend:
                status_text = "Verification code resent. Please check your email."
            else:
                status_text = "Verification code sent. Please check your email."

            app.root.after(0, lambda: app.login_status.config(text=status_text, style="Green.TLabel"))

            # Show verification frame if not already visible
            app.root.after(0, lambda: app.verification_frame.pack(fill=tk.X, padx=150, pady=20))

            # If this is a resend, flash the background of the verification frame to indicate success
            if resend:
                def flash_frame():
                    orig_bg = app.verification_frame.cget('background')
                    app.verification_frame.configure(background='#AAFFAA')  # Light green
                    app.root.after(500, lambda: app.verification_frame.configure(background=orig_bg))

                app.root.after(100, flash_frame)

            # Focus on verification code entry
            for child in app.verification_frame.winfo_children():
                if isinstance(child, ttk.Entry):
                    child.focus_set()
                    break
        else:
            error_msg = response.get('message', 'Unknown error')

            # Handle special error cases
            if not app.is_connected and "credentials" in error_msg.lower():
                error_msg = "Correct credentials but no server connection"

            app.root.after(0, lambda: app.login_status.config(
                text=f"Login failed: {error_msg}", style="Red.TLabel"))

            if not resend:
                app.user_email = None  # Clear stored email on failure only if not resending

        # Re-enable buttons
        app.root.after(0, lambda: app.login_btn.config(state="normal"))
        app.root.after(0, lambda: app.register_btn.config(state="normal"))

    threading.Thread(target=login_thread).start()


def verify_2fa(app):
    """Handle 2FA verification"""
    verification_code = app.verification_code_var.get().strip()

    if not verification_code:
        messagebox.showerror("Error", "Please enter the verification code")
        return

    # Show progress
    app.login_progress.pack(fill=tk.X, padx=100, pady=10)
    app.login_progress.start(10)
    app.login_status.config(text="Verifying code...")

    # Disable verification button during processing
    for child in app.verification_frame.winfo_children():
        if isinstance(child, ttk.Button) and child.cget('text') == "Verify":
            child.config(state="disabled")

    def verify_thread():
        try:
            print(f"Sending verification code: {verification_code}")

            # Send the verification request
            response = app.client._send_command('verify_2fa', {
                'email': app.user_email,
                'code': verification_code,
                'device_info': app.get_device_info()
            })

            print(f"Verification response: {response}")

            if response and response.get('status') == 'success':
                # Store the session token
                app.session_token = response.get('token')
                app.client.session_token = app.session_token
                app.is_logged_in = True

                # Update UI in main thread
                app.root.after(0, lambda: app.login_status.config(
                    text="Login successful! Loading main application...",
                    style="Green.TLabel"))

                # Directly transition to main app - no animation
                app.root.after(100, lambda: direct_transition())
            else:
                error_msg = response.get('message', 'Unknown error')
                app.root.after(0, lambda: app.login_status.config(
                    text=f"Verification failed: {error_msg}",
                    style="Red.TLabel"))

                # Re-enable the verify button
                app.root.after(0, lambda: enable_verify_button())
        except Exception as e:
            print(f"Verification error: {e}")
            app.root.after(0, lambda: app.login_status.config(
                text=f"Verification error: {str(e)}",
                style="Red.TLabel"))
            app.root.after(0, lambda: enable_verify_button())

    def enable_verify_button():
        app.login_progress.stop()
        app.login_progress.pack_forget()
        for child in app.verification_frame.winfo_children():
            if isinstance(child, ttk.Button) and child.cget('text') == "Verify":
                child.config(state="normal")

    def direct_transition():
        """Directly transition to main app without animations"""
        try:
            # Hide login window
            app.login_window.destroy()

            # Set up main app UI
            app.setup_main_app()

            print("Main app setup complete")
        except Exception as e:
            print(f"Error transitioning to main app: {e}")
            messagebox.showerror("Error", f"Failed to load main application: {str(e)}")

    # Start verification in background
    threading.Thread(target=verify_thread).start()

    def transition_to_main_app():
        """Transition from login screen to main application UI"""
        # Hide login window
        app.login_window.destroy()

        # Create a transition animation
        transition = tk.Toplevel(app.root)
        transition.overrideredirect(True)  # No window decorations
        transition.attributes("-alpha", 0.9)  # Slightly transparent

        # Make it cover the whole application window
        transition.geometry(
            f"{app.root.winfo_width()}x{app.root.winfo_height()}+{app.root.winfo_x()}+{app.root.winfo_y()}")

        # Add loading animation
        loading_frame = ttk.Frame(transition, padding=20)
        loading_frame.pack(expand=True)

        ttk.Label(loading_frame, text=f"Welcome, {app.user_email}",
                  font=("Arial", 14, "bold")).pack(pady=(0, 20))

        ttk.Label(loading_frame, text="Loading application...",
                  font=("Arial", 10)).pack(pady=5)

        progress = ttk.Progressbar(loading_frame, mode="indeterminate", length=300)
        progress.pack(pady=20)
        progress.start(10)

        # Show the transition window
        transition.lift()
        transition.update()

        # Important: Make sure this function exists in your app class
        app.setup_main_app()

        # Close transition after a short delay
        app.root.after(800, transition.destroy)