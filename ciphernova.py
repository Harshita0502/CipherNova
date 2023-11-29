import os
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

private_key_file = "private_key.pem"

def generate_private_key():
    if not os.path.exists(private_key_file):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(private_key_file, "wb") as key_file:
            key_file.write(private_key_pem)

generate_private_key()

def encrypt_message():
    message = input_message.get().encode()
    cipher_text = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_text = '\n'.join([cipher_text.hex()[i:i+50] for i in range(0, len(cipher_text.hex()), 50)])
    output_text.set(encrypted_text)
    decrypted_text_box.delete(1.0, tk.END)

def decrypt_message():
    try:
        cipher_text_hex = input_message.get()
        cipher_text = bytes.fromhex(cipher_text_hex)
        decrypted_message = private_key.decrypt(
            cipher_text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        output_text.set(decrypted_message.decode())
        decrypted_text_box.delete(1.0, tk.END)
        decrypted_text_box.insert(1.0, decrypted_message)
    except ValueError:
        output_text.set("Invalid input format. Please enter the cipher text in hexadecimal format.")
        decrypted_text_box.delete(1.0, tk.END)

def encrypt_file():
    file_path = filedialog.askopenfilename()  # Open a file dialog to select a file to encrypt
    if file_path:
        try:
            with open(file_path, "r") as file:
                original_text = file.read()
                cipher_text = public_key.encrypt(
                    original_text.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

            with open(file_path, "w") as file:
                file.write(cipher_text.hex())  # Write the encrypted data in hexadecimal format

            file_size = os.path.getsize(file_path)
            output_text.set(f"Text from {file_path} has been encrypted and saved.\nFile size: {file_size} bytes")
            decrypted_text_box.delete(1.0, tk.END)

        except PermissionError:
            output_text.set(f"Permission denied. Please grant read and write permissions to the file.")
            decrypted_text_box.delete(1.0, tk.END)

def decrypt_file():
    file_path = filedialog.askopenfilename()  # Open a file dialog to select a file to decrypt
    if file_path:
        try:
            with open(file_path, "r") as file:
                cipher_text_hex = file.read()
                cipher_text = bytes.fromhex(cipher_text_hex)

                decrypted_message = private_key.decrypt(
                    cipher_text,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

            with open(file_path, "w") as file:
                file.write(decrypted_message.decode())

            file_size = os.path.getsize(file_path)
            output_text.set(f"Text from {file_path} has been decrypted and saved.\nFile size: {file_size} bytes")
            decrypted_text_box.delete(1.0, tk.END)

        except PermissionError:
            output_text.set(f"Permission denied. Please grant read and write permissions to the file.")
            decrypted_text_box.delete(1.0, tk.END)

private_key_pem = open(private_key_file, "rb").read()
private_key = serialization.load_pem_private_key(
    private_key_pem,
    password=None,
    backend=default_backend()
)
public_key = private_key.public_key()

def copy_text():
    window.clipboard_clear()
    window.clipboard_append(output_text.get())

# Create a Tkinter window
window = tk.Tk()
window.title("CipherNova")
window.configure(background="#45496A")



# Configure row and column weights to make the GUI responsive
for i in range(6):
    window.grid_rowconfigure(i, weight=1)
    window.grid_columnconfigure(i, weight=1)

# Create and place input fields
input_message = tk.StringVar()
output_text = tk.StringVar()

message_entry = tk.Entry(window, textvariable=input_message, bg="#7D8BAE",bd=4)
message_entry.grid(row=0, column=0, padx=10, pady=10, columnspan=6, sticky="ew")

result_label = tk.Label(window, textvariable=output_text, bg="#7D8BAE",bd=4)  # Set background color for the label
result_label.grid(row=1, column=0, padx=10, pady=10, columnspan=6, sticky="ew")

# Create buttons for different operations
encrypt_message_button = tk.Button(window, text="Encrypt Message",font="arial 10 bold ", command=encrypt_message,bg="#F1B2B2",bd=4)
decrypt_message_button = tk.Button(window, text="Decrypt Message",font="arial 10 bold ", command=decrypt_message,bg="#F1B2B2",bd=4)
encrypt_file_button = tk.Button(window, text="Encrypt File",font="arial 10 bold ", command=encrypt_file,bg="#F1B2B2",bd=4)
decrypt_file_button = tk.Button(window, text="Decrypt File",font="arial 10 bold ", command=decrypt_file,bg="#F1B2B2",bd=4)

encrypt_message_button.grid(row=2, column=0, padx=10, pady=10, columnspan=2, sticky="ew")
decrypt_message_button.grid(row=2, column=2, padx=10, pady=10, columnspan=2, sticky="ew")
encrypt_file_button.grid(row=3, column=0, padx=10, pady=10, columnspan=2, sticky="ew")
decrypt_file_button.grid(row=3, column=2, padx=10, pady=10, columnspan=2, sticky="ew")

# Create text box for displaying decrypted text
decrypted_text_box = tk.Text(window, wrap=tk.WORD, height=5, width=40, bg="#7D8BAE",bd=4)
decrypted_text_box.grid(row=4, column=0, padx=10, pady=10, columnspan=6, sticky="ew")

# Create a single "Copy" button at the bottom right
copy_button = tk.Button(window, text="Copy",font="arial 10 bold ", command=copy_text,bg="#F1B2B2",bd=4)
copy_button.grid(row=5, column=5, padx=10, pady=10, sticky="se")

# Start the Tkinter event loop
window.mainloop()
