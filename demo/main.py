import streamlit as st
import random
import string
from cryptography.fernet import Fernet
import os

KEY_FILE = "secret.key"
PASSWORD_FILE = "passwords.enc"

# ---------------------- Logic ----------------------

def generate_password(length=12):
    if length < 4:
        st.error("Password length must be at least 4.")
        return None
    
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
                    results.append("[!] Decryption error.")
    return results

# ---------------------- Streamlit UI ----------------------

st.set_page_config(page_title="🔐 Password Manager", page_icon="🔐")

st.title("🔐 Secure Password Generator")

generated_password = None  # Store outside form

with st.form("generate_form"):
    label = st.text_input("Label (e.g., Gmail):")
    length = st.slider("Password length:", min_value=4, max_value=40, value=12)
    submitted = st.form_submit_button("Generate & Save")

if submitted:
    password = generate_password(length)
    if password:
        save_password(label, password)
        st.success(f"Generated password: `{password}`")
        st.code(password, language="text")
        generated_password = password  # store for use outside form

# 🪄 Show copy button only after generation
if generated_password:
    st.download_button("📋 Copy Password", generated_password, file_name="password.txt", mime="text/plain")

# ---------------------- View Passwords ----------------------

if st.checkbox("🔓 View Stored Passwords"):
    confirm = st.text_input("Type 'yes' to view saved passwords:")
    if confirm.lower() == "yes":
        passwords = decrypt_passwords()
        for p in passwords:
            st.text(p)
