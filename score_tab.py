import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime


def setup_score_tab(app):
    """Set up the security score tab with simplified UI"""
    # Score overview frame
    score_frame = ttk.LabelFrame(app.score_tab, text="Security Score")
    score_frame.pack(fill=tk.X, padx=10, pady=10)

    # Create a frame for the score display with visual elements
    score_display_frame = ttk.Frame(score_frame)
    score_display_frame.pack(fill=tk.X, padx=10, pady=10)

    # Add a circular or visual indicator for the score
    # (Since tkinter doesn't have built-in circular progress bars, we'll use a colored label)
    app.score_indicator_frame = ttk.Frame(score_display_frame, width=120, height=120)
    app.score_indicator_frame.pack(side=tk.LEFT, padx=20)
    app.score_indicator_frame.pack_propagate(False)  # Don't shrink

    app.score_indicator = ttk.Label(app.score_indicator_frame, text="?",
                                    font=("Arial", 40, "bold"), foreground="gray",
                                    background="#E0E0E0", anchor="center")
    app.score_indicator.pack(fill=tk.BOTH, expand=True)

    # Score text display
    score_text_frame = ttk.Frame(score_display_frame)
    score_text_frame.pack(side=tk.LEFT, fill=tk.Y, expand=True, padx=10)

    app.score_label = ttk.Label(score_text_frame, text="Your Security Score: N/A",
                                font=("Arial", 18, "bold"))
    app.score_label.pack(anchor=tk.W, pady=5)

    app.score_description = ttk.Label(score_text_frame,
                                      text="Complete scans and updates to improve your score",
                                      wraplength=400)
    app.score_description.pack(anchor=tk.W, pady=5)

    # Progress bar for score visualization
    app.score_progress = ttk.Progressbar(score_frame, orient=tk.HORIZONTAL, length=400, mode='determinate')
    app.score_progress.pack(padx=10, pady=10, fill=tk.X)

    # Recommendations frame
    recommend_frame = ttk.LabelFrame(app.score_tab, text="Security Recommendations")
    recommend_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # Use a text widget with custom tags for color-coded recommendations
    app.recommendations_text = scrolledtext.ScrolledText(recommend_frame, font=("Arial", 10))
    app.recommendations_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    app.recommendations_text.tag_configure("high_risk", foreground="red", font=("Arial", 10, "bold"))
    app.recommendations_text.tag_configure("medium_risk", foreground="orange", font=("Arial", 10, "bold"))
    app.recommendations_text.tag_configure("low_risk", foreground="blue")

    # Refresh button
    refresh_frame = ttk.Frame(app.score_tab)
    refresh_frame.pack(pady=10)

    ttk.Button(refresh_frame, text="Refresh Security Score", command=lambda: calculate_security_score(app)).pack(
        side=tk.LEFT, padx=5)
    ttk.Button(refresh_frame, text="Export Security Report", command=lambda: export_security_report(app)).pack(
        side=tk.LEFT, padx=5)


def calculate_security_score(app):
    """Calculate the security score based on all gathered data"""
    # Show calculation in progress
    app.score_label.config(text="Calculating Security Score...")
    app.score_progress.start(10)

    def calculate_score_thread():
        # Default category scores
        score_categories = {
            "System Updates": {"score": 0, "weight": 25, "details": "Not assessed yet"},
            "Malware Protection": {"score": 0, "weight": 30, "details": "Not assessed yet"},
            "Suspicious Files": {"score": 0, "weight": 20, "details": "Not assessed yet"},
            "Authentication": {"score": 0, "weight": 15, "details": "Not assessed yet"},
            "Network Security": {"score": 0, "weight": 10, "details": "Not assessed yet"}
        }

        # Calculate System Updates score based on app updates
        if hasattr(app, 'updatable_apps') and hasattr(app, 'installed_apps'):
            if app.installed_apps:
                total_apps = len(app.installed_apps)
                updates_needed = len(app.updatable_apps) if app.updatable_apps else 0
                update_percentage = updates_needed / total_apps if total_apps > 0 else 0
                system_score = int(100 - (update_percentage * 100))
                score_categories["System Updates"]["score"] = system_score
                score_categories["System Updates"]["details"] = f"{updates_needed} of {total_apps} apps need updates"

        # Calculate Malware Protection score based on scan results
        if hasattr(app, 'scan_results') and app.scan_results:
            malicious_count = sum(
                1 for result in app.scan_results if result.get('detections', {}).get('malicious_content', False))
            malware_score = int(100 - (malicious_count / len(app.scan_results) * 100)) if len(
                app.scan_results) > 0 else 0
            score_categories["Malware Protection"]["score"] = malware_score
            score_categories["Malware Protection"][
                "details"] = f"{malicious_count} of {len(app.scan_results)} files contain malware"

        # Calculate Suspicious Files score
        if hasattr(app, 'scan_results') and app.scan_results:
            suspicious_count = sum(1 for result in app.scan_results
                                   if result.get('detections', {}).get('suspicious_content', False)
                                   or result.get('detections', {}).get('suspicious_extension', False))
            suspicious_score = int(100 - (suspicious_count / len(app.scan_results) * 100)) if len(
                app.scan_results) > 0 else 0
            score_categories["Suspicious Files"]["score"] = suspicious_score
            score_categories["Suspicious Files"][
                "details"] = f"{suspicious_count} of {len(app.scan_results)} files are suspicious"

        # Authentication score - based on login status and 2FA use
        if app.is_logged_in and app.session_token:
            score_categories["Authentication"]["score"] = 100
            score_categories["Authentication"]["details"] = "Using secure authentication with 2FA"
        else:
            score_categories["Authentication"]["score"] = 0
            score_categories["Authentication"]["details"] = "Not logged in securely"

        # Network Security score - based on server connection status
        if app.is_connected:
            score_categories["Network Security"]["score"] = 100
            score_categories["Network Security"]["details"] = "Using secure TLS connection"
        else:
            score_categories["Network Security"]["score"] = 0
            score_categories["Network Security"]["details"] = "Not using secure connection"

        # Calculate total weighted score
        total_weight = sum(cat["weight"] for cat in score_categories.values())
        weighted_score = sum(
            cat["score"] * cat["weight"] for cat in score_categories.values()) / total_weight if total_weight > 0 else 0

        # Update the score display
        app.total_score = int(weighted_score)

        # Update UI in the main thread
        app.root.after(0, lambda: app.score_progress.stop())

        # Set score text and color based on score value
        score_color = "green" if app.total_score >= 80 else "orange" if app.total_score >= 60 else "red"

        # Update indicator label with score
        app.root.after(0, lambda: app.score_indicator.config(
            text=str(app.total_score),
            foreground="white",
            background=score_color))

        # Set score description
        score_description = ""
        if app.total_score >= 80:
            score_description = "Excellent! Your system has a high security score."
        elif app.total_score >= 60:
            score_description = "Fair. Your system has some security concerns that should be addressed."
        else:
            score_description = "Poor. Your system has critical security issues that need immediate attention!"

        # Update labels and progress bar
        app.root.after(0, lambda: app.score_label.config(
            text=f"Your Security Score: {app.total_score}/100",
            foreground=score_color))
        app.root.after(0, lambda: app.score_description.config(
            text=score_description,
            foreground=score_color))
        app.root.after(0, lambda: app.score_progress.config(mode="determinate", value=app.total_score))

        # Generate recommendations
        generate_recommendations(app, score_categories)

        # If logged in, send score to server
        if app.is_logged_in and app.session_token:
            try:
                score_data = {
                    'total_score': app.total_score,
                    'categories': score_categories,
                    'timestamp': datetime.now().isoformat()
                }

                # You can add a submit_score method to your client if needed
                # app.client.submit_score(score_data)
            except Exception as e:
                app.update_status(f"Error uploading security score: {str(e)}")

    # Run calculation in background thread
    threading.Thread(target=calculate_score_thread).start()
    return app.total_score


def generate_recommendations(app, score_categories):
    """Generate security recommendations based on scores - simplified version with color coding"""
    app.recommendations_text.delete(1.0, tk.END)

    # Add header
    app.recommendations_text.insert(tk.END, "SECURITY RECOMMENDATIONS\n\n", "medium_risk")

    # Check System Updates score
    if score_categories["System Updates"]["score"] < 70:
        app.recommendations_text.insert(tk.END,
                                        "• Update your applications regularly to patch security vulnerabilities.\n",
                                        "high_risk" if score_categories["System Updates"][
                                                           "score"] < 50 else "medium_risk")

    # Check Malware Protection score
    if score_categories["Malware Protection"]["score"] < 70:
        app.recommendations_text.insert(tk.END, "• Remove detected malware immediately.\n", "high_risk")
        app.recommendations_text.insert(tk.END, "• Install a reputable antivirus solution and keep it updated.\n",
                                        "high_risk" if score_categories["Malware Protection"][
                                                           "score"] < 50 else "medium_risk")

    # Check Suspicious Files score
    if score_categories["Suspicious Files"]["score"] < 70:
        app.recommendations_text.insert(tk.END, "• Review and remove suspicious files.\n",
                                        "high_risk" if score_categories["Suspicious Files"][
                                                           "score"] < 50 else "medium_risk")
        app.recommendations_text.insert(tk.END, "• Avoid downloading files from untrusted sources.\n", "medium_risk")

    # Check Authentication score
    if score_categories["Authentication"]["score"] < 100:
        app.recommendations_text.insert(tk.END, "• Use two-factor authentication for all accounts.\n", "medium_risk")
        app.recommendations_text.insert(tk.END, "• Use strong, unique passwords for each service.\n", "medium_risk")

    # Check Network Security score
    if score_categories["Network Security"]["score"] < 100:
        app.recommendations_text.insert(tk.END, "• Ensure you're using encrypted connections (HTTPS, SSL/TLS).\n",
                                        "high_risk" if score_categories["Network Security"][
                                                           "score"] < 50 else "medium_risk")
        app.recommendations_text.insert(tk.END, "• Consider using a VPN for enhanced privacy and security.\n",
                                        "low_risk")

    # Add general recommendations
    app.recommendations_text.insert(tk.END, "\nGENERAL RECOMMENDATIONS\n\n", "medium_risk")
    app.recommendations_text.insert(tk.END, "• Keep your operating system and all software up to date.\n", "low_risk")
    app.recommendations_text.insert(tk.END, "• Regularly back up your important data.\n", "low_risk")
    app.recommendations_text.insert(tk.END, "• Be cautious about clicking links or opening attachments in emails.\n",
                                    "low_risk")
    app.recommendations_text.insert(tk.END, "• Use a password manager to create and store strong passwords.\n",
                                    "low_risk")
    app.recommendations_text.insert(tk.END, "• Enable firewall protection on all devices.\n", "low_risk")


def export_security_report(app):
    """Export the security report to a file"""
    if not hasattr(app, 'total_score'):
        messagebox.showinfo("No Data", "Please calculate security score first")
        return

    try:
        # Get file path for saving
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Security Report"
        )

        if not file_path:
            return  # User cancelled

        # Show progress
        app.update_status("Generating security report...")

        # Create report content
        report = f"SECURITY SCANNER & OPTIMIZER REPORT\n"
        report += f"======================================\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        report += f"SECURITY SCORE: {app.total_score}/100\n\n"

        # Add recommendations
        report += "SECURITY RECOMMENDATIONS:\n"
        report += "------------------------\n"
        report += app.recommendations_text.get(1.0, tk.END)

        # Add scan results summary if available
        if hasattr(app, 'scan_results') and app.scan_results:
            report += "\nSCAN RESULTS SUMMARY:\n"
            report += "---------------------\n"
            malicious = sum(1 for r in app.scan_results if r.get('detections', {}).get('malicious_content', False))
            suspicious = sum(1 for r in app.scan_results if r.get('detections', {}).get('suspicious_content', False))
            report += f"Files scanned: {len(app.scan_results)}\n"
            report += f"Malicious files detected: {malicious}\n"
            report += f"Suspicious files detected: {suspicious}\n\n"

        # Add app updates summary if available
        if hasattr(app, 'updatable_apps') and app.updatable_apps:
            report += "\nAPPLICATION UPDATES NEEDED:\n"
            report += "-------------------------\n"
            for updatable_app in app.updatable_apps:
                report += f"• {updatable_app.get('name', 'Unknown')}: {updatable_app.get('current_version', 'Unknown')} → {updatable_app.get('available_version', 'Unknown')}\n"

        # Write to file
        with open(file_path, 'w') as f:
            f.write(report)

        app.update_status(f"Security report saved to {file_path}")
        messagebox.showinfo("Export Complete", "Security report has been saved successfully")

    except Exception as e:
        app.update_status(f"Error exporting report: {str(e)}")
        messagebox.showerror("Export Error", f"Could not export security report: {str(e)}")