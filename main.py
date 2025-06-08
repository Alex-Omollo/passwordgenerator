import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
import random
import string
import os
from cryptography.fernet import Fernet

# File constants
KEY_FILE = "secret.key"
PASSWORD_FILE = "passwords.enc"


# ---------------------- Password and Encryption Logic ----------------------

def generate_password(length=12):
    if length < 4:
        raise ValueError("Password length must be at least 4.")

    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = string.punctuation

    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(symbols)
    ]
    all_chars = lowercase + uppercase + digits + symbols
    password += random.choices(all_chars, k=length - 4)
    random.shuffle(password)

    return ''.join(password)


def write_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)


def load_key():
    if not os.path.exists(KEY_FILE):
        write_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()


def save_password(label, password):
    key = load_key()
    fernet = Fernet(key)

    entry = f"{label}: {password}\n".encode()
    encrypted = fernet.encrypt(entry)

    with open(PASSWORD_FILE, "ab") as f:
        f.write(encrypted + b"\n")


def decrypt_passwords():
    key = load_key()
    fernet = Fernet(key)
    results = []

    if not os.path.exists(PASSWORD_FILE):
        return ["No passwords stored yet."]

    with open(PASSWORD_FILE, "rb") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    decrypted = fernet.decrypt(line).decode()
                    results.append(decrypted)
                except Exception:
                    results.append("[!] Could not decrypt one entry.")
    return results


# ---------------------- GUI Components ----------------------

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Password Manager")
        self.root.geometry("500x500")
        self.root.configure(bg="#f5f5f5")

        self.create_widgets()

    def create_widgets(self):
        # Title
        tk.Label(self.root, text="Password Generator", font=("Helvetica", 18, "bold"), bg="#f5f5f5").pack(pady=10)

        # Label input
        tk.Label(self.root, text="Label (e.g., Gmail):", bg="#f5f5f5").pack()
        self.label_entry = tk.Entry(self.root, width=40)
        self.label_entry.pack(pady=5)

        # Length input
        tk.Label(self.root, text="Password Length:", bg="#f5f5f5").pack()
        self.length_entry = tk.Entry(self.root, width=10)
        self.length_entry.insert(0, "12")
        self.length_entry.pack(pady=5)

        # Generate button
        tk.Button(self.root, text="Generate & Save Password", command=self.handle_generate, bg="#007acc",
                  fg="white").pack(pady=10)

        # Display area
        self.result_label = tk.Label(self.root, text="", bg="#f5f5f5", font=("Courier", 12, "bold"))
        self.result_label.pack(pady=5)

        # Copy button
        self.copy_button = tk.Button(self.root, text="Copy to Clipboard", command=self.copy_to_clipboard,
                                     state=tk.DISABLED)
        self.copy_button.pack()

        # View button
        tk.Button(self.root, text="🔓 View Stored Passwords", command=self.show_passwords, bg="#28a745",
                  fg="white").pack(pady=20)

    def handle_generate(self):
        try:
            label = self.label_entry.get().strip()
            length = int(self.length_entry.get().strip())
            if not label:
                messagebox.showwarning("Input Error", "Please enter a label.")
                return

            password = generate_password(length)
            save_password(label, password)
            self.result_label.config(text=f"Generated: {password}")
            self.copy_button.config(state=tk.NORMAL)
            self.generated_password = password
        except ValueError:
            messagebox.showerror("Input Error", "Please enter a valid number for length.")

    def copy_to_clipboard(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.generated_password)
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    def show_passwords(self):
        confirm = messagebox.askyesno("Confirm", "Do you want to view saved passwords?")
        if not confirm:
            return

        passwords = decrypt_passwords()
        view_win = tk.Toplevel(self.root)
        view_win.title("Stored Passwords")
        view_win.geometry("450x300")
        view_win.configure(bg="#ffffff")

        text_area = scrolledtext.ScrolledText(view_win, wrap=tk.WORD, font=("Courier", 11))
        text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        for p in passwords:
            text_area.insert(tk.END, p + "\n")
        text_area.config(state=tk.DISABLED)


# ---------------------- Launch App ----------------------

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()