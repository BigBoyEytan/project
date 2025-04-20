import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import time
from tkinter import scrolledtext
from .score_tab import calculate_security_score




def setup_apps_tab(app):
    """Set up the apps management tab with improved UI"""
    # Control frame
    control_frame = ttk.Frame(app.apps_tab)
    control_frame.pack(fill=tk.X, padx=10, pady=10)

    ttk.Button(control_frame, text="List Installed Apps", command=lambda: list_installed_apps(app)).pack(side=tk.LEFT,
                                                                                                         padx=5)
    ttk.Button(control_frame, text="Check for Updates", command=lambda: check_app_updates(app)).pack(side=tk.LEFT,
                                                                                                     padx=5)
    ttk.Button(control_frame, text="Update All", command=lambda: update_all_apps(app)).pack(side=tk.LEFT, padx=5)

    # Progress bar
    app.apps_progress_frame = ttk.LabelFrame(app.apps_tab, text="Progress")
    app.apps_progress_frame.pack(fill=tk.X, padx=10, pady=5)

    app.apps_progress_var = tk.StringVar(value="Ready")
    app.apps_progress_label = ttk.Label(app.apps_progress_frame, textvariable=app.apps_progress_var)
    app.apps_progress_label.pack(side=tk.TOP, anchor=tk.W, padx=5, pady=2)

    app.apps_progress = ttk.Progressbar(app.apps_progress_frame, orient=tk.HORIZONTAL, mode='indeterminate')
    app.apps_progress.pack(fill=tk.X, expand=True, padx=5, pady=5)

    # Hide progress initially
    app.apps_progress_frame.pack_forget()

    # Apps list frame
    apps_frame = ttk.LabelFrame(app.apps_tab, text="Installed Applications")
    apps_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # Create treeview for apps
    apps_tree_frame = ttk.Frame(apps_frame)
    apps_tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # Add scrollbar
    apps_y_scroll = ttk.Scrollbar(apps_tree_frame, orient="vertical")
    apps_y_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    apps_x_scroll = ttk.Scrollbar(apps_tree_frame, orient="horizontal")
    apps_x_scroll.pack(side=tk.BOTTOM, fill=tk.X)

    app.apps_tree = ttk.Treeview(apps_tree_frame, columns=("name", "id", "version", "status"), show="headings",
                                 yscrollcommand=apps_y_scroll.set, xscrollcommand=apps_x_scroll.set)
    app.apps_tree.heading("name", text="Application Name")
    app.apps_tree.heading("id", text="ID")
    app.apps_tree.heading("version", text="Version")
    app.apps_tree.heading("status", text="Status")

    app.apps_tree.column("name", width=200, minwidth=100)
    app.apps_tree.column("id", width=250, minwidth=150)
    app.apps_tree.column("version", width=150, minwidth=100)
    app.apps_tree.column("status", width=120, minwidth=80)

    # Configure tags for color coding
    app.apps_tree.tag_configure("security_update", background="#FFDDDD")
    app.apps_tree.tag_configure("normal_update", background="#EAEAEA")

    apps_y_scroll.config(command=app.apps_tree.yview)
    apps_x_scroll.config(command=app.apps_tree.xview)
    app.apps_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Store apps data
    app.installed_apps = []
    app.updatable_apps = []

    # Add app details display
    app.app_details_frame = ttk.LabelFrame(app.apps_tab, text="Application Details")
    app.app_details_frame.pack(fill=tk.X, padx=10, pady=5)

    app.app_details_text = scrolledtext.ScrolledText(app.app_details_frame, height=6)
    app.app_details_text.pack(fill=tk.X, expand=True, padx=5, pady=5)

    # Add selection event
    app.apps_tree.bind("<<TreeviewSelect>>", lambda event: show_app_details(app, event))


def show_app_details(app, event):
    """Show details of the selected application"""
    selected_items = app.apps_tree.selection()
    if not selected_items:
        return

    # Get the selected item
    item_id = selected_items[0]
    values = app.apps_tree.item(item_id, "values")

    if not values or len(values) < 3:
        return

    app_name = values[0]
    app_id = values[1]
    version_info = values[2]
    status = values[3]

    # Clear details text
    app.app_details_text.delete(1.0, tk.END)

    # Add details
    app.app_details_text.insert(tk.END, f"Application: {app_name}\n", "title")
    app.app_details_text.insert(tk.END, f"ID: {app_id}\n")
    app.app_details_text.insert(tk.END, f"Version: {version_info}\n")
    app.app_details_text.insert(tk.END, f"Status: {status}\n\n")

    # Add specific actions based on status
    if "Update Available" in status:
        app.app_details_text.insert(tk.END, "This application has an update available. Updates may include:\n")
        app.app_details_text.insert(tk.END, "• Security patches\n")
        app.app_details_text.insert(tk.END, "• Bug fixes\n")
        app.app_details_text.insert(tk.END, "• New features\n\n")
        app.app_details_text.insert(tk.END, "Click 'Update All' to install this update along with others.")
    else:
        app.app_details_text.insert(tk.END, "This application is up to date. No action required.")

    # Configure tag styles
    app.app_details_text.tag_configure("title", font=("Arial", 10, "bold"))


def list_installed_apps(app):
    """List installed applications with visual progress indicators"""
    app.update_status("Listing installed applications...")
    app.apps_tree.delete(*app.apps_tree.get_children())

    # Show progress indicator
    app.apps_progress_frame.pack(fill=tk.X, padx=10, pady=5)
    app.apps_progress_var.set("Retrieving installed applications...")
    app.apps_progress.start(10)

    def list_apps_thread():
        try:
            # Get installed apps - using the correct method name from your AppsInterface
            app.installed_apps = app.apps_interface.list_installed()

            # Update progress status
            app.root.after(0, lambda: app.apps_progress_var.set(
                f"Found {len(app.installed_apps)} applications, preparing display..."))

            # Display in tree
            for installed_app in app.installed_apps:
                app.root.after(0, lambda a=installed_app: app.apps_tree.insert("", "end", values=(
                    a.get('name', 'Unknown'),
                    a.get('id', 'Unknown'),
                    a.get('current_version', 'Unknown'),
                    "Installed"
                )))

            # Stop progress and update status
            app.root.after(0, lambda: app.apps_progress.stop())
            app.root.after(0, lambda: app.apps_progress_frame.pack_forget())
            app.update_status(f"Found {len(app.installed_apps)} installed applications")

            # Update security score
            from ui.score_tab import calculate_security_score
            calculate_security_score(app)

        except Exception as e:
            # Show error and hide progress
            app.root.after(0, lambda: app.apps_progress.stop())
            app.root.after(0, lambda: app.apps_progress_frame.pack_forget())
            app.update_status(f"Error listing applications: {str(e)}")
            app.root.after(0, lambda: messagebox.showerror("Error", f"Could not list applications: {str(e)}"))

    threading.Thread(target=list_apps_thread).start()


def check_app_updates(app):
    """Check for application updates with visual progress indicators"""
    app.update_status("Checking for application updates...")

    # Show progress indicator
    app.apps_progress_frame.pack(fill=tk.X, padx=10, pady=5)
    app.apps_progress_var.set("Checking for updates...")
    app.apps_progress.start(10)

    # Clear apps list
    app.apps_tree.delete(*app.apps_tree.get_children())

    def check_updates_thread():
        try:
            # First update progress to show source refreshing
            app.root.after(0, lambda: app.apps_progress_var.set("Refreshing package sources..."))

            # Get updatable apps
            app.updatable_apps = app.apps_interface.check_updates()

            # Update progress
            app.root.after(0, lambda: app.apps_progress_var.set(
                f"Found {len(app.updatable_apps)} applications with updates"))

            # Display in tree with color coding for security updates
            for updatable_app in app.updatable_apps:
                app_name = updatable_app.get('name', 'Unknown')
                tag = "security_update" if "security" in app_name.lower() else ""

                app.root.after(0, lambda a=updatable_app, t=tag: app.apps_tree.insert("", "end", values=(
                    a.get('name', 'Unknown'),
                    a.get('id', 'Unknown'),
                    f"{a.get('current_version', 'Unknown')} → {a.get('available_version', 'Unknown')}",
                    "Update Available"
                ), tags=(t,)))

            # Stop and hide progress
            app.root.after(0, lambda: app.apps_progress.stop())
            app.root.after(0, lambda: app.apps_progress_frame.pack_forget())
            app.update_status(f"Found {len(app.updatable_apps)} applications with updates available")

            # Update security score
            from ui.score_tab import calculate_security_score
            calculate_security_score(app)

            # Send app information to server if logged in
            if app.is_logged_in and app.session_token:
                app.root.after(0, lambda: app.apps_progress_var.set("Uploading data to server..."))
                app.root.after(0, lambda: app.apps_progress_frame.pack(fill=tk.X, padx=10, pady=5))
                app.root.after(0, lambda: app.apps_progress.start(10))

                try:
                    apps_data = {
                        'total_apps': len(app.installed_apps) if app.installed_apps else 0,
                        'updatable_apps': len(app.updatable_apps),
                        'app_ids': [updatable_app.get('id') for updatable_app in app.updatable_apps],
                        'timestamp': datetime.now().isoformat()
                    }

                    success = app.client.submit_apps_data(apps_data)
                    if success:
                        app.update_status("App information uploaded to server")

                    # Hide progress after server communication
                    app.root.after(0, lambda: app.apps_progress.stop())
                    app.root.after(0, lambda: app.apps_progress_frame.pack_forget())

                except Exception as e:
                    app.root.after(0, lambda: app.apps_progress.stop())
                    app.root.after(0, lambda: app.apps_progress_frame.pack_forget())
                    app.update_status(f"Error uploading app information: {str(e)}")

        except Exception as e:
            # Handle errors and hide progress
            app.root.after(0, lambda: app.apps_progress.stop())
            app.root.after(0, lambda: app.apps_progress_frame.pack_forget())
            app.update_status(f"Error checking for updates: {str(e)}")
            app.root.after(0, lambda: messagebox.showerror("Error", f"Could not check for updates: {str(e)}"))

    threading.Thread(target=check_updates_thread).start()


def update_all_apps(app):
    """Update all applications with available updates"""
    if not app.updatable_apps:
        messagebox.showinfo("Information", "No updates available")
        return

    # Show confirmation dialog with progress bar
    confirm = messagebox.askyesno("Update Applications",
                                  f"Do you want to upgrade all {len(app.updatable_apps)} applications?\n\n"
                                  "This process may take several minutes and require\n"
                                  "administrator permissions for some applications.",
                                  icon="question")

    if not confirm:
        return

    # Show progress indicator
    app.apps_progress_frame.pack(fill=tk.X, padx=10, pady=5)
    app.apps_progress_var.set("Preparing to update applications...")
    app.apps_progress.start(10)

    def update_apps_thread():
        try:
            # Update progress status
            app.root.after(0, lambda: app.apps_progress_var.set(
                f"Updating {len(app.updatable_apps)} applications..."))

            # Start updating
            updated_apps = app.apps_interface.upgrade(app.updatable_apps)

            # Show completion and update status
            app.root.after(0, lambda: app.apps_progress_var.set(
                f"Successfully updated {len(updated_apps)} applications"))
            app.root.after(0, lambda: app.apps_progress.stop())

            # Let user see completion message for a moment
            time.sleep(2)

            # Refresh the list
            app.root.after(0, lambda: app.apps_progress_var.set("Refreshing application list..."))
            app.root.after(0, lambda: app.apps_progress.start())
            app.update_status(f"Updated {len(updated_apps)} applications. Refreshing list...")

            # Check for any remaining updates
            app.updatable_apps = app.apps_interface.check_updates()

            # Clear the tree and show updated list
            app.root.after(0, lambda: app.apps_tree.delete(*app.apps_tree.get_children()))

            # Add any remaining updatable apps to the tree
            for updatable_app in app.updatable_apps:
                app.root.after(0, lambda a=updatable_app: app.apps_tree.insert("", "end", values=(
                    a.get('name', 'Unknown'),
                    a.get('id', 'Unknown'),
                    f"{a.get('current_version', 'Unknown')} → {a.get('available_version', 'Unknown')}",
                    "Update Available"
                )))

            # Hide progress and update status
            app.root.after(0, lambda: app.apps_progress.stop())
            app.root.after(0, lambda: app.apps_progress_frame.pack_forget())

            if app.updatable_apps:
                app.update_status(f"Updates completed with {len(app.updatable_apps)} updates remaining")
            else:
                app.update_status("All applications successfully updated")

            # Show completion message
            app.root.after(0, lambda: messagebox.showinfo("Update Complete",
                                                          f"Successfully updated {len(updated_apps)} applications."))

            # Update security score
            from ui.score_tab import calculate_security_score
            calculate_security_score(app)

        except Exception as e:
            # Handle errors and hide progress
            app.root.after(0, lambda: app.apps_progress.stop())
            app.root.after(0, lambda: app.apps_progress_frame.pack_forget())
            app.update_status(f"Error updating applications: {str(e)}")
            app.root.after(0, lambda: messagebox.showerror("Error", f"Could not update applications: {str(e)}"))

    threading.Thread(target=update_apps_thread).start()