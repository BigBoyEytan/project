"""
Security Scanner & Optimizer - Scan Tab
Handles file scanning functionality with self-contained file selection
"""
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from datetime import datetime
import traceback

# Try to import scanner modules, with fallbacks
try:
    from scan_file.scanner_final import FileScanner, scan_and_score_files
    print("Successfully imported scanner modules")
except ImportError as e:
    print(f"First import attempt failed: {e}")

    try:
        from scanner_final import FileScanner, scan_and_score_files
        print("Successfully imported scanner modules (alternative path)")
    except ImportError as e:
        print(f"Second import attempt failed: {e}")

        try:
            from client_side.scan_file.scanner_final import FileScanner, scan_and_score_files
            print("Successfully imported scanner modules (full path)")
        except ImportError as e:
            print(f"All import attempts failed: {e}")

            # Create dummy classes to prevent crashes if imports fail
            class FileScanner:
                def __init__(self):
                    pass

                def scan_file(self, file_path):
                    return {"error": "Scanner module not available", "file_path": file_path}

            def scan_and_score_files(file_paths):
                return [{"file_path": path, "file_name": os.path.basename(path),
                         "score": 0, "recommendation": "Scanner not available",
                         "scan_results": {"error": "Scanner module not available"}}
                        for path in file_paths]


def select_files(app):
    """
    Select files for scanning without replacing previously selected files.
    Allows adding more files to the existing selection.
    """
    print("Starting file selection...")
    try:
        # Create a root window and hide it
        root = tk.Tk()
        root.withdraw()

        # Determine initial directory
        initial_dir = os.path.expanduser("~")  # Default to user's home
        if hasattr(app, 'last_dir') and app.last_dir:
            initial_dir = app.last_dir

        # Open the file dialog directly
        file_paths = filedialog.askopenfilenames(
            initialdir=initial_dir,
            title="Select Files to Add",
            filetypes=[
                ("All Files", "*.*"),
                ("Text Files", "*.txt"),
                ("Document Files", "*.doc;*.docx;*.pdf"),
                ("Image Files", "*.jpg;*.jpeg;*.png;*.gif"),
                ("Executable Files", "*.exe;*.dll;*.sys")
            ]
        )

        # Convert tuple to list
        new_files = list(file_paths)

        # Clean up the root window
        root.destroy()

        # Skip if no files were selected
        if not new_files:
            print("No new files selected")
            return

        # Remember last directory for next time
        if new_files:
            app.last_dir = os.path.dirname(new_files[0])

        # Create selected_files list if it doesn't exist
        if not hasattr(app, 'selected_files') or app.selected_files is None:
            app.selected_files = []

        # Get existing file paths for comparison
        existing_paths = set(app.selected_files)

        # Add only new files that aren't already in the list
        added_files = []
        for file_path in new_files:
            if file_path not in existing_paths:
                app.selected_files.append(file_path)
                added_files.append(file_path)
                existing_paths.add(file_path)

        # Print selected files for debugging
        print(f"New files added: {len(added_files)}")
        if added_files:
            print("\nAdded files:")
            for idx, file_path in enumerate(added_files, 1):
                print(f"{idx}. {file_path}")

        print(f"Total files selected: {len(app.selected_files)}")

        if not added_files:
            messagebox.showinfo("File Selection", "No new files were added.\nAll selected files were already in the list.")
            return

        # Update status
        app.update_status(f"Added {len(added_files)} file(s). Total: {len(app.selected_files)} files")

        # Update file count display if it exists
        if hasattr(app, 'file_count_var'):
            app.file_count_var.set(f"Selected files: {len(app.selected_files)}")

        # Add new files to the tree as pending
        for file_path in added_files:
            try:
                app.results_tree.insert("", "end", values=(
                    os.path.basename(file_path),
                    file_path,
                    "Pending",
                    "N/A"
                ))
            except Exception as e:
                print(f"Error adding file to results tree: {e}")
                traceback.print_exc()
                # Continue with other files

    except Exception as e:
        print(f"Error in file selection: {e}")
        traceback.print_exc()
        messagebox.showerror("Error", f"Error selecting files: {str(e)}")


def clear_selected_files(app):
    """Clear all selected files from the list and tree"""
    try:
        # Clear the list of selected files
        app.selected_files = []

        # Clear all items from the results tree
        app.results_tree.delete(*app.results_tree.get_children())

        # Clear the details text
        app.file_details_text.delete(1.0, tk.END)

        # Update status
        app.update_status("Cleared all selected files")

        # Update file count display if it exists
        if hasattr(app, 'file_count_var'):
            app.file_count_var.set("No files selected")

        print("Cleared all selected files")

    except Exception as e:
        print(f"Error clearing files: {e}")
        traceback.print_exc()
        messagebox.showerror("Error", f"Error clearing files: {str(e)}")


def setup_scan_tab(app):
    """Set up the file scanning tab with improved UI"""
    # Control frame for scan options
    control_frame = ttk.Frame(app.scan_tab)
    control_frame.pack(fill=tk.X, padx=10, pady=10)

    # Scan type selection
    scan_type_frame = ttk.LabelFrame(control_frame, text="Scan Type")
    scan_type_frame.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)

    app.scan_type_var = tk.StringVar(value="standard")
    ttk.Radiobutton(scan_type_frame, text="Standard Scan", variable=app.scan_type_var,
                    value="standard").pack(side=tk.LEFT, padx=10)
    ttk.Radiobutton(scan_type_frame, text="Deep Scan", variable=app.scan_type_var,
                    value="deep").pack(side=tk.LEFT, padx=10)
    ttk.Radiobutton(scan_type_frame, text="Quick Scan", variable=app.scan_type_var,
                    value="quick").pack(side=tk.LEFT, padx=10)

    # Scan actions frame
    actions_frame = ttk.Frame(control_frame)
    actions_frame.pack(side=tk.RIGHT, padx=5, pady=5)

    ttk.Button(actions_frame, text="Add Files",
               command=lambda: select_files(app)).pack(side=tk.LEFT, padx=5)

    ttk.Button(actions_frame, text="Clear Files",
               command=lambda: clear_selected_files(app)).pack(side=tk.LEFT, padx=5)

    app.scan_button = ttk.Button(actions_frame, text="Start Scan",
                                 command=lambda: start_scan(app), style="Primary.TButton")
    app.scan_button.pack(side=tk.LEFT, padx=5)

    # Progress frame
    app.scan_progress_frame = ttk.LabelFrame(app.scan_tab, text="Scan Progress")
    app.scan_progress_frame.pack(fill=tk.X, padx=10, pady=5)

    app.scan_progress_var = tk.StringVar(value="Ready")
    app.scan_progress_label = ttk.Label(app.scan_progress_frame, textvariable=app.scan_progress_var)
    app.scan_progress_label.pack(side=tk.TOP, anchor=tk.W, padx=5, pady=2)

    app.scan_progress = ttk.Progressbar(app.scan_progress_frame, orient=tk.HORIZONTAL, mode='indeterminate')
    app.scan_progress.pack(fill=tk.X, expand=True, padx=5, pady=5)

    # Hide progress initially
    app.scan_progress_frame.pack_forget()

    # Results frame
    results_frame = ttk.LabelFrame(app.scan_tab, text="Scan Results")
    results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # Create treeview for results
    tree_frame = ttk.Frame(results_frame)
    tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    # Add scrollbar
    y_scroll = ttk.Scrollbar(tree_frame, orient="vertical")
    y_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    x_scroll = ttk.Scrollbar(tree_frame, orient="horizontal")
    x_scroll.pack(side=tk.BOTTOM, fill=tk.X)

    app.results_tree = ttk.Treeview(tree_frame, columns=("name", "path", "status", "score"), show="headings",
                                    yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
    app.results_tree.heading("name", text="File Name")
    app.results_tree.heading("path", text="Path")
    app.results_tree.heading("status", text="Status")
    app.results_tree.heading("score", text="Security Score")

    app.results_tree.column("name", width=200, minwidth=100)
    app.results_tree.column("path", width=300, minwidth=150)
    app.results_tree.column("status", width=100, minwidth=80)
    app.results_tree.column("score", width=100, minwidth=80)

    # Configure tags for color coding
    app.results_tree.tag_configure("safe", background="#CCFFCC")
    app.results_tree.tag_configure("warning", background="#FFFFCC")
    app.results_tree.tag_configure("danger", background="#FFCCCC")

    y_scroll.config(command=app.results_tree.yview)
    x_scroll.config(command=app.results_tree.xview)
    app.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Add file details display
    app.file_details_frame = ttk.LabelFrame(app.scan_tab, text="File Details")
    app.file_details_frame.pack(fill=tk.X, padx=10, pady=5)

    app.file_details_text = scrolledtext.ScrolledText(app.file_details_frame, height=8)
    app.file_details_text.pack(fill=tk.X, expand=True, padx=5, pady=5)

    # Add selection event with error handling
    def safe_show_details(event):
        try:
            show_file_details(app, event)
        except Exception as e:
            print(f"Error in show_file_details: {e}")
            traceback.print_exc()
            app.file_details_text.delete(1.0, tk.END)
            app.file_details_text.insert(tk.END, f"Error displaying file details: {str(e)}\n", "danger")

    app.results_tree.bind("<<TreeviewSelect>>", safe_show_details)

    # Add counter of selected files
    status_frame = ttk.Frame(app.scan_tab)
    status_frame.pack(fill=tk.X, padx=10, pady=(0, 5))

    app.file_count_var = tk.StringVar(value="No files selected")
    file_count_label = ttk.Label(status_frame, textvariable=app.file_count_var, anchor=tk.W)
    file_count_label.pack(side=tk.LEFT, padx=5)

    # Initialize file list
    app.selected_files = []


def start_scan(app):
    """Start the scanning process for selected files"""
    if not app.selected_files:
        messagebox.showinfo("Scan", "Please select files to scan first")
        return

    # Verify files still exist
    existing_files = []
    for file_path in app.selected_files:
        if os.path.exists(file_path):
            existing_files.append(file_path)
        else:
            # Remove non-existent files from the tree
            for item in app.results_tree.get_children():
                if app.results_tree.item(item, "values")[1] == file_path:
                    app.results_tree.delete(item)
                    break

    if not existing_files:
        messagebox.showinfo("Scan", "None of the selected files exist anymore")
        app.selected_files = []
        return

    app.selected_files = existing_files

    # Clear previous scan results
    app.scan_results = []

    # Update UI
    app.scan_button.config(state="disabled")
    app.update_status("Starting scan process...")

    # Show progress frame
    app.scan_progress_frame.pack(fill=tk.X, padx=10, pady=5)
    app.scan_progress_var.set("Initializing scanner...")
    app.scan_progress.start(10)

    # Reset tree items to "Scanning" status
    for item in app.results_tree.get_children():
        app.results_tree.item(item, values=(
            app.results_tree.item(item, "values")[0],
            app.results_tree.item(item, "values")[1],
            "Scanning...",
            "N/A"
        ))

    def scan_thread():
        try:
            # Update progress
            app.root.after(0, lambda: app.scan_progress_var.set("Scanning files..."))

            # Get the selected scan type
            scan_type = app.scan_type_var.get()

            # Create a scanner instance
            scanner = FileScanner()
            scan_results = []

            # Scan each file individually to prevent one file from causing entire scan to fail
            for file_path in app.selected_files:
                try:
                    # Scan the file
                    file_result = scanner.scan_file(file_path)

                    # Calculate security score for this file
                    score, recommendation = calculate_security_score_for_file(file_result)

                    # Store the results
                    scan_results.append({
                        "file_path": file_path,
                        "file_name": os.path.basename(file_path),
                        "score": score,
                        "recommendation": recommendation,
                        "scan_results": file_result
                    })

                    # Update UI with this file's result
                    status = "Safe" if score > 7 else "Warning" if score > 3 else "Danger"
                    tag = "safe" if score > 7 else "warning" if score > 3 else "danger"

                    # Find the tree item for this file
                    for item in app.results_tree.get_children():
                        if app.results_tree.item(item, "values")[1] == file_path:
                            app.root.after(0, lambda item=item, file_name=os.path.basename(file_path),
                                              file_path=file_path, status=status, score=score, tag=tag:
                                app.results_tree.item(item, values=(
                                    file_name, file_path, status, score), tags=(tag,))
                            )
                            break
                except Exception as e:
                    print(f"Error scanning file {file_path}: {e}")
                    traceback.print_exc()

                    # Find the tree item for this file and mark as error
                    for item in app.results_tree.get_children():
                        if app.results_tree.item(item, "values")[1] == file_path:
                            app.root.after(0, lambda item=item, file_name=os.path.basename(file_path),
                                             file_path=file_path:
                                app.results_tree.item(item, values=(
                                    file_name, file_path, "Error", "N/A"), tags=("danger",))
                            )
                            break

            # Store the results
            app.scan_results = scan_results

            # Complete scan
            app.root.after(0, lambda: app.scan_progress.stop())
            app.root.after(0, lambda: app.scan_progress_frame.pack_forget())
            app.root.after(0, lambda: app.scan_button.config(state="normal"))
            app.root.after(0, lambda: app.update_status(f"Scan completed for {len(scan_results)} files"))

            # If logged in, submit scan results to server
            if hasattr(app, 'is_logged_in') and app.is_logged_in and hasattr(app, 'session_token') and app.session_token:
                try:
                    # Prepare data for submission
                    submission_data = {
                        'timestamp': datetime.now().isoformat(),
                        'scan_type': scan_type,
                        'files_scanned': len(app.selected_files),
                        'malicious_files': sum(1 for r in scan_results if r['score'] and r['score'] <= 3),
                        'suspicious_files': sum(1 for r in scan_results if r['score'] and 3 < r['score'] <= 7)
                    }

                    success = app.client.submit_scan_data(submission_data)
                    if success:
                        app.root.after(0, lambda: app.update_status("Scan results uploaded to server"))

                except Exception as e:
                    app.root.after(0, lambda: app.update_status(f"Error uploading scan results: {str(e)}"))
                    print(f"Error uploading scan results: {e}")
                    traceback.print_exc()

            # Try to update security score
            try:
                update_security_score(app)
            except Exception as e:
                print(f"Error updating security score: {e}")
                traceback.print_exc()

        except Exception as e:
            # Handle errors
            app.root.after(0, lambda: app.scan_progress.stop())
            app.root.after(0, lambda: app.scan_progress_frame.pack_forget())
            app.root.after(0, lambda: app.scan_button.config(state="normal"))
            app.root.after(0, lambda: app.update_status(f"Scan error: {str(e)}"))
            app.root.after(0,
                           lambda: messagebox.showerror("Scan Error", f"An error occurred during scanning: {str(e)}"))
            print(f"Error in scan thread: {e}")
            traceback.print_exc()

    # Start scan in background
    threading.Thread(target=scan_thread).start()


def update_security_score(app):
    """Update the security score if the function exists"""
    try:
        # Try multiple import paths
        try:
            from client_app.ui.score_tab import calculate_security_score
        except ImportError:
            try:
                from ui.score_tab import calculate_security_score
            except ImportError:
                try:
                    from score_tab import calculate_security_score
                except ImportError:
                    print("Could not import calculate_security_score")
                    return

        # Call the function if found
        calculate_security_score(app)
    except Exception as e:
        print(f"Error updating security score: {e}")
        traceback.print_exc()


def calculate_security_score_for_file(scan_result):
    """Calculate a security score for a single file based on scan results"""
    try:
        # Initialize score (10 is safest, 1 is definitely malware)
        score = 10
        recommendation = "SAFE: No security concerns detected"

        # Check if result is valid
        if not scan_result or "error" in scan_result and scan_result["error"]:
            return 0, f"ERROR: {scan_result.get('error', 'Unknown error')}"

        # Get detection results
        detections = scan_result.get("detections", {})
        details = scan_result.get("details", {})

        # VirusTotal detection = automatic score of 1 (definitely malware)
        if detections.get("malicious_content"):
            return 1, "REMOVE IMMEDIATELY: Detected as malware by VirusTotal"

        # Check if VirusTotal scan failed or timed out
        virustotal_results = details.get("virustotal_results", {})
        virustotal_failed = not virustotal_results or virustotal_results.get("status") in ["Error", "Timeout"]

        # Apply signature verification factors
        if "signature_info" in details:
            signature_info = details.get("signature_info", {})

            # If the file is signed and verified, it's a positive signal
            if signature_info and signature_info.get("is_signed") and signature_info.get("is_verified"):
                # If VirusTotal failed but signature is good, rely on signature
                if virustotal_failed:
                    score = max(score, 8)  # Set minimum score of 8 in this case

                # If suspicious content but properly signed, signature validates it
                if detections.get("suspicious_content") or detections.get("suspicious_extension"):
                    score -= 1  # Only small penalty
            else:
                # File is not signed or signature is invalid
                if virustotal_failed:
                    score -= 1  # Slight penalty for VirusTotal failure

                # Found signature but couldn't verify it (possible tampering)
                if signature_info and signature_info.get("is_signed") and not signature_info.get("is_verified"):
                    score -= 3

                # Suspicious content but not properly signed
                if detections.get("suspicious_content"):
                    score -= 2

                # Suspicious extension but not properly signed
                if detections.get("suspicious_extension"):
                    score -= 1

        # Ensure score stays within 1-10 range
        score = max(1, min(10, score))

        # Generate recommendation based on score
        if score <= 3:
            recommendation = "REMOVE: High security risk detected"
        elif score <= 5:
            recommendation = "CAUTION: Moderate security risk, review before using"
        elif score <= 7:
            recommendation = "ACCEPTABLE: Some concerns but likely safe"
        # else keep the default "SAFE" recommendation

        return score, recommendation
    except Exception as e:
        print(f"Error calculating security score: {e}")
        traceback.print_exc()
        return 0, f"ERROR: Could not calculate security score: {str(e)}"


def show_file_details(app, event):
    """Show details of the selected file in the scan results"""
    try:
        selected_items = app.results_tree.selection()
        if not selected_items:
            return

        # Get the selected item
        item_id = selected_items[0]
        values = app.results_tree.item(item_id, "values")

        if not values or len(values) < 4:
            return

        file_name = values[0]
        file_path = values[1]
        status = values[2]
        score = values[3]

        # Find full scan results for this file
        file_result = None
        if hasattr(app, 'scan_results'):
            for result in app.scan_results:
                if result.get("file_path") == file_path:
                    file_result = result
                    break

        # Clear details text
        app.file_details_text.delete(1.0, tk.END)

        # Add details
        app.file_details_text.insert(tk.END, f"File: {file_name}\n", "title")
        app.file_details_text.insert(tk.END, f"Path: {file_path}\n")
        app.file_details_text.insert(tk.END, f"Status: {status}\n")
        app.file_details_text.insert(tk.END, f"Security Score: {score}\n\n")

        # Add detailed scan information if available
        if file_result and "scan_results" in file_result:
            scan_result = file_result["scan_results"]

            if "details" in scan_result:
                details = scan_result["details"]

                # File info
                if "file_info" in details:
                    file_info = details["file_info"]
                    app.file_details_text.insert(tk.END, "File Information:\n", "section")
                    app.file_details_text.insert(tk.END, f"  MIME Type: {file_info.get('mime_type', 'Unknown')}\n")
                    app.file_details_text.insert(tk.END, f"  File Type: {file_info.get('file_type', 'Unknown')}\n")

                    # Hashes
                    if "hashes" in file_info:
                        hashes = file_info["hashes"]
                        app.file_details_text.insert(tk.END, "  Hashes:\n")
                        for hash_type, hash_value in hashes.items():
                            app.file_details_text.insert(tk.END, f"    {hash_type.upper()}: {hash_value}\n")

                # Suspicious findings
                if "suspicious_findings" in details and details["suspicious_findings"]:
                    app.file_details_text.insert(tk.END, "\nSuspicious Findings:\n", "warning")
                    for finding in details["suspicious_findings"]:
                        app.file_details_text.insert(tk.END, f"  • {finding}\n")

                # VirusTotal results
                if "virustotal_results" in details and details["virustotal_results"]:
                    vt_results = details["virustotal_results"]
                    app.file_details_text.insert(tk.END, "\nVirusTotal Results:\n", "section")

                    if "malware_detected" in vt_results:
                        if vt_results["malware_detected"]:
                            app.file_details_text.insert(tk.END, "  Malware Detected: YES\n", "danger")
                        else:
                            app.file_details_text.insert(tk.END, "  Malware Detected: No\n")

                    if "detection_rate" in vt_results:
                        app.file_details_text.insert(tk.END, f"  Detection Rate: {vt_results['detection_rate']:.1f}%\n")

                # Signature info
                if "signature_info" in details and details["signature_info"]:
                    sig_info = details["signature_info"]
                    app.file_details_text.insert(tk.END, "\nDigital Signature:\n", "section")

                    if sig_info.get("is_signed", False):
                        app.file_details_text.insert(tk.END, "  Digitally Signed: Yes\n")

                        if sig_info.get("is_verified", False):
                            app.file_details_text.insert(tk.END, "  Signature Verified: Yes\n", "safe")
                        else:
                            app.file_details_text.insert(tk.END, "  Signature Verified: No\n", "warning")

                        if "publisher" in sig_info and sig_info["publisher"]:
                            app.file_details_text.insert(tk.END, f"  Publisher: {sig_info['publisher']}\n")
                    else:
                        app.file_details_text.insert(tk.END, "  Digitally Signed: No\n", "warning")

        # Recommendation based on score
        app.file_details_text.insert(tk.END, "\nRecommendation:\n", "section")
        if file_result and "recommendation" in file_result:
            app.file_details_text.insert(tk.END, f"  {file_result['recommendation']}\n")
        else:
            if score == "N/A":
                app.file_details_text.insert(tk.END, "  Could not determine file safety\n")
            elif str(score).replace('.', '', 1).isdigit() and float(score) <= 3:
                app.file_details_text.insert(tk.END, "  REMOVE: High security risk detected\n", "danger")
            elif str(score).replace('.', '', 1).isdigit() and float(score) <= 7:
                app.file_details_text.insert(tk.END, "  CAUTION: Moderate security risk, review before using\n",
                                            "warning")
            else:
                app.file_details_text.insert(tk.END, "  SAFE: No security concerns detected\n", "safe")

        # Configure tag styles
        app.file_details_text.tag_configure("title", font=("Arial", 10, "bold"))
        app.file_details_text.tag_configure("section", font=("Arial", 9, "bold"))
        app.file_details_text.tag_configure("warning", foreground="orange")
        app.file_details_text.tag_configure("danger", foreground="red")
        app.file_details_text.tag_configure("safe", foreground="green")
    except Exception as e:
        print(f"Error showing file details: {e}")
        traceback.print_exc()

        # Show the error in the details text
        app.file_details_text.delete(1.0, tk.END)
        app.file_details_text.insert(tk.END, "Error showing file details:\n", "danger")
        app.file_details_text.insert(tk.END, str(e))