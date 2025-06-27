import os
from tkinter import filedialog, simpledialog, messagebox
import logging

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Setup logging
logging.basicConfig(
    filename="logs/app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def select_file(title="Select a file"):
    file_path = filedialog.askopenfilename(title=title)
    if file_path:
        logging.info(f"Selected file: {file_path}")
    return file_path

def select_save_location(default_name="output.enc"):
    save_path = filedialog.asksaveasfilename(title="Save as", initialfile=default_name)
    if save_path:
        logging.info(f"Selected save location: {save_path}")
    return save_path

def get_password(prompt_window, prompt="Enter encryption password:"):
    password = simpledialog.askstring("Password Required", prompt, show='*', parent=prompt_window)
    if password is None:
        messagebox.showinfo("Action Cancelled", "Operation cancelled by user.")
        logging.warning("User cancelled password prompt.")
        return None
    logging.info("Password entered.")
    return password.encode()

def file_exists(path):
    exists = os.path.exists(path)
    logging.info(f"Checked existence of {path}: {exists}")
    return exists

def get_text_input(prompt_window, prompt="Enter message to encrypt:"):
    text = simpledialog.askstring("Input Required", prompt, parent=prompt_window)
    if text:
        logging.info("Text input received.")
    else:
        logging.warning("User cancelled text input.")
    return text
