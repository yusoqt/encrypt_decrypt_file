import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
from aes_utils import encrypt_method, decrypt_method, generate_key

class AESImageApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 AES Image Encrypt/Decrypt")
        self.root.geometry("500x430")
        self.root.config(bg="#f0f8ff")

        self.current_key = None

        self.setup_ui()

    def setup_ui(self):
        tk.Label(self.root, text="AES File Encryption Tool", font=("Helvetica", 16, "bold"), bg="#f0f8ff", fg="#003366").pack(pady=10)

        self.key_label = tk.Label(self.root, text="🔑 Current Key: None", bg="#f0f8ff", wraplength=400, fg="black")
        self.key_label.pack(pady=5)

        key_frame = tk.Frame(self.root, bg="#f0f8ff")
        key_frame.pack()

        tk.Label(key_frame, text="Key Length: ", bg="#f0f8ff").pack(side=tk.LEFT)
        self.key_length = ttk.Combobox(key_frame, values=[16, 24, 32], width=5)
        self.key_length.set(16)
        self.key_length.pack(side=tk.LEFT, padx=5)

        tk.Button(key_frame, text="Generate Key", command=self.generate_new_key, bg="#add8e6").pack(side=tk.LEFT)

        action_frame = tk.Frame(self.root, bg="#f0f8ff")
        action_frame.pack(pady=5)

        tk.Button(action_frame, text="📋 Copy Key", command=self.copy_key, bg="#ffe4b5").pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="📂 Import Key", command=self.import_key, bg="#ffe4e1").pack(side=tk.LEFT, padx=5)

        tk.Button(self.root, text="🔒 Encrypt File", command=self.select_file_to_encrypt,
                width=25, bg="#87cefa").pack(pady=10)
        tk.Button(self.root, text="🔓 Decrypt File", command=self.select_file_to_decrypt,
                width=25, bg="#90ee90").pack(pady=10)

        self.status_label = tk.Label(self.root, text="", fg="green", bg="#f0f8ff", wraplength=450)
        self.status_label.pack(pady=20)

    def generate_new_key(self):
        try:
            length = int(self.key_length.get())
            self.current_key = generate_key(length)
            self.key_label.config(text=f"🔑 Current Key ({length} bytes): {self.current_key.hex()}")
            self.status_label.config(text="Key generated successfully.", fg="green")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key: {e}")

    def copy_key(self):
        if self.current_key:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.current_key.hex())
            self.root.update()
            self.status_label.config(text="Key copied to clipboard.", fg="green")
        else:
            messagebox.showwarning("No Key", "No key to copy. Please generate or import a key first.")

    def import_key(self):
        key_input = simpledialog.askstring("Import Key", "Enter hex key:")
        if key_input:
            try:
                key_bytes = bytes.fromhex(key_input.strip())
                if len(key_bytes) not in [16, 24, 32]:
                    raise ValueError("Key length must be 16, 24, or 32 bytes.")
                self.current_key = key_bytes
                self.key_label.config(text=f"🔑 Current Key ({len(key_bytes)} bytes): {key_input.strip()}")
                self.status_label.config(text="Key imported successfully.", fg="green")
            except Exception as e:
                messagebox.showerror("Error", f"Invalid key: {e}")

    def select_file_to_encrypt(self):
        if not self.current_key:
            messagebox.showwarning("Missing Key", "Please generate a key first.")
            return

        filepath = filedialog.askopenfilename(
            title="Select File to Encrypt",
            filetypes=[
                ("All Supported", "*.png *.jpg *.jpeg *.pdf *.mp4 *.avi *.mov"),
                ("Image Files", "*.png *.jpg *.jpeg"),
                ("PDF Files", "*.pdf"),
                ("Video Files", "*.mp4 *.avi *.mov"),
                ("All Files", "*.*")
            ]
        )
        if filepath:
            try:
                os.makedirs("./encrypt", exist_ok=True)
                output_path = os.path.join("./encrypt", os.path.basename(filepath) + ".enc")
                encrypt_method(filepath, output_path, self.current_key)
                self.status_label.config(text=f"File encrypted to {output_path}", fg="blue")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {e}")

    def select_file_to_decrypt(self):
        if not self.current_key:
            messagebox.showwarning("Missing Key", "Please generate or input the key first.")
            return

        filepath = filedialog.askopenfilename(
            title="Select Encrypted File",
            filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        )
        if filepath:
            try:
                os.makedirs("./decrypt", exist_ok=True)
                original_name = os.path.basename(filepath).replace(".enc", "")
                output_path = os.path.join("./decrypt", original_name)
                decrypt_method(filepath, output_path, self.current_key)
                self.status_label.config(text=f"File decrypted to {output_path}", fg="blue")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AESImageApp(root)
    root.mainloop()
