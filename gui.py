import tkinter as tk
from tkinter import messagebox
from crypto_utils import (
    generate_keys, load_private_key, load_public_key,
    hybrid_encrypt_file, hybrid_decrypt_file,
    hybrid_encrypt_message, hybrid_decrypt_message
)
from file_utils import select_file, select_save_location, get_password, get_text_input
import os

window = tk.Tk()
window.title("CipherNova - Secure File & Message Encryption")
window.configure(background="#2E3440")
window.geometry("600x400")

status_text = tk.StringVar()

if not os.path.exists("keys/private_key.pem"):
    pw = get_password(window, "Set a password to protect your private key:")
    if pw:
        generate_keys(pw)
        status_text.set("Keys generated successfully.")
    else:
        status_text.set("Key generation cancelled.")
else:
    status_text.set("Keys loaded.")

def encrypt_file_handler():
    try:
        file_path = select_file("Select file to encrypt")
        if not file_path:
            return
        save_path = select_save_location(os.path.basename(file_path) + ".enc")
        if not save_path:
            return
        public_key = load_public_key()
        hybrid_encrypt_file(file_path, save_path, public_key)
        status_text.set(f"Encrypted and saved to {save_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_file_handler():
    try:
        file_path = select_file("Select encrypted file to decrypt")
        if not file_path:
            return
        save_path = select_save_location(os.path.basename(file_path).replace(".enc", "_decrypted"))
        if not save_path:
            return
        pw = get_password(window)
        if not pw:
            return
        private_key = load_private_key(pw)
        hybrid_decrypt_file(file_path, save_path, private_key)
        status_text.set(f"Decrypted and saved to {save_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def encrypt_message_handler():
    try:
        message = get_text_input(window, "Enter message to encrypt:")
        if not message:
            return
        public_key = load_public_key()
        encrypted = hybrid_encrypt_message(message.encode(), public_key)
        result_box.delete(1.0, tk.END)
        result_box.insert(tk.END, encrypted)
        status_text.set("Message encrypted.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_message_handler():
    try:
        encrypted = get_text_input(window, "Paste encrypted message:")
        if not encrypted:
            return
        pw = get_password(window)
        if not pw:
            return
        private_key = load_private_key(pw)
        decrypted = hybrid_decrypt_message(encrypted, private_key)
        result_box.delete(1.0, tk.END)
        result_box.insert(tk.END, decrypted.decode())
        status_text.set("Message decrypted.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Layout
file_frame = tk.LabelFrame(window, text="File Encryption", bg="#ECEFF4", padx=10, pady=10)
file_frame.pack(padx=10, pady=10, fill="x")

tk.Button(file_frame, text="Encrypt File", command=encrypt_file_handler, width=20).pack(side="left", padx=5, pady=5)
tk.Button(file_frame, text="Decrypt File", command=decrypt_file_handler, width=20).pack(side="left", padx=5, pady=5)

msg_frame = tk.LabelFrame(window, text="Message Encryption", bg="#ECEFF4", padx=10, pady=10)
msg_frame.pack(padx=10, pady=10, fill="x")

tk.Button(msg_frame, text="Encrypt Message", command=encrypt_message_handler, width=20).pack(side="left", padx=5, pady=5)
tk.Button(msg_frame, text="Decrypt Message", command=decrypt_message_handler, width=20).pack(side="left", padx=5, pady=5)

result_frame = tk.LabelFrame(window, text="Result", bg="#ECEFF4", padx=10, pady=10)
result_frame.pack(padx=10, pady=10, fill="both", expand=True)

result_box = tk.Text(result_frame, wrap=tk.WORD, height=8)
result_box.pack(fill="both", expand=True)

status_bar = tk.Label(window, textvariable=status_text, bg="#D8DEE9", anchor="w")
status_bar.pack(fill="x", side="bottom")

window.mainloop()
