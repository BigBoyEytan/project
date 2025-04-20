from tkinter import ttk


def configure_styles(root):
    """Configure styles for the application"""
    style = ttk.Style()

    # Basic styles
    style.configure("TLabel", font=("Arial", 10))
    style.configure("TButton", font=("Arial", 10), padding=5)
    style.configure("TEntry", font=("Arial", 10), padding=5)

    # Specific styles for different states
    style.configure("Red.TLabel", foreground="red", font=("Arial", 10, "bold"))
    style.configure("Green.TLabel", foreground="green", font=("Arial", 10))
    style.configure("Title.TLabel", font=("Arial", 16, "bold"))
    style.configure("Header.TLabel", font=("Arial", 12, "bold"))

    # Button styles
    style.configure("Primary.TButton", background="#4CAF50", foreground="white")
    style.configure("Warning.TButton", background="#FFC107")
    style.configure("Danger.TButton", background="#F44336", foreground="white")