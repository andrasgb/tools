#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import subprocess
import tempfile
import os
import shlex

# -------------------- ENCRYPT SSH FUNCTIONS --------------------

def browse_pubkey():
    path = filedialog.askopenfilename(title="Select public SSH key")
    if path:
        encrypt_pubkey_var.set(path)

def browse_encrypt_input():
    path = filedialog.askopenfilename(title="Select file to encrypt")
    if path:
        encrypt_input_var.set(path)

def browse_encrypt_output():
    path = filedialog.asksaveasfilename(title="Save encrypted file as", defaultextension=".enc")
    if path:
        encrypt_output_var.set(path)

def do_encrypt():
    pub_key = encrypt_pubkey_var.get()
    infile = encrypt_input_var.get()
    outfile = encrypt_output_var.get()

    if not pub_key or not infile or not outfile:
        messagebox.showerror("Error", "All fields are required")
        return

    pem_fd, pem_path = tempfile.mkstemp(prefix="pubkey_", suffix=".pem")
    os.close(pem_fd)

    try:
        # Convert SSH public key to PKCS8
        with open(pem_path, "w") as pem_out:
            subprocess.check_call([
                "ssh-keygen", "-e", "-f", pub_key, "-m", "PKCS8"
            ], stdout=pem_out)

        subprocess.check_call([
            "openssl", "pkeyutl", "-encrypt", "-pubin",
            "-inkey", pem_path, "-in", infile, "-out", outfile
        ])
        messagebox.showinfo("Success", f"Encrypted file created:\n{outfile}")

    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Encryption failed:\n{e}")

    finally:
        if os.path.exists(pem_path):
            os.remove(pem_path)

# -------------------- DECRYPT SSH FUNCTIONS --------------------

def browse_privkey():
    path = filedialog.askopenfilename(title="Select private key")
    if path:
        decrypt_privkey_var.set(path)

def browse_decrypt_input():
    path = filedialog.askopenfilename(title="Select encrypted file")
    if path:
        decrypt_input_var.set(path)

def browse_decrypt_output():
    path = filedialog.asksaveasfilename(title="Save decrypted file as")
    if path:
        decrypt_output_var.set(path)

def do_decrypt():
    priv_key = decrypt_privkey_var.get()
    infile = decrypt_input_var.get()
    outfile = decrypt_output_var.get()

    if not priv_key or not infile or not outfile:
        messagebox.showerror("Error", "All fields are required")
        return

    password = simpledialog.askstring(
        "Private key password",
        "Enter password (leave empty if none):",
        show="*"
    )

    try:
        cmd = f"openssl pkeyutl -decrypt -inkey {shlex.quote(priv_key)} -in {shlex.quote(infile)} -out {shlex.quote(outfile)}"
        env = os.environ.copy()
        if password:
            env["PASS"] = password
            cmd = f"openssl pkeyutl -decrypt -inkey {shlex.quote(priv_key)} -passin env:PASS -in {shlex.quote(infile)} -out {shlex.quote(outfile)}"

        result = subprocess.run(cmd, shell=True, env=env, capture_output=True)
        if result.returncode != 0:
            messagebox.showerror("Error", result.stderr.decode())
            return

        messagebox.showinfo("Success", f"File decrypted successfully:\n{outfile}")

    except Exception as e:
        messagebox.showerror("Error", str(e))

# -------------------- PGP ENCRYPT --------------------

def browse_pgp_pub():
    path = filedialog.askopenfilename(title="Select PGP public key (.asc or .gpg)")
    if path:
        pgp_encrypt_pubkey_var.set(path)

def browse_pgp_encrypt_input():
    path = filedialog.askopenfilename(title="Select file to encrypt")
    if path:
        pgp_encrypt_input_var.set(path)

def browse_pgp_encrypt_output():
    path = filedialog.asksaveasfilename(title="Save encrypted file as", defaultextension=".gpg")
    if path:
        pgp_encrypt_output_var.set(path)

def do_pgp_encrypt():
    pub_key = pgp_encrypt_pubkey_var.get()
    infile = pgp_encrypt_input_var.get()
    outfile = pgp_encrypt_output_var.get()

    if not pub_key or not infile or not outfile:
        messagebox.showerror("Error", "All fields are required")
        return

    try:
        subprocess.check_call([
            "gpg", "--batch", "--yes", "--trust-model", "always",
            "--output", outfile, "--encrypt", "--recipient-file", pub_key, infile
        ])
        messagebox.showinfo("Success", f"PGP encrypted file created:\n{outfile}")

    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"PGP encrypt failed:\n{e}")

# -------------------- PGP DECRYPT --------------------

def browse_pgp_priv():
    path = filedialog.askopenfilename(title="Select PGP private key (.asc or .gpg)")
    if path:
        pgp_decrypt_privkey_var.set(path)

def browse_pgp_decrypt_input():
    path = filedialog.askopenfilename(title="Select encrypted PGP file")
    if path:
        pgp_decrypt_input_var.set(path)

def browse_pgp_decrypt_output():
    path = filedialog.asksaveasfilename(title="Save decrypted file as")
    if path:
        pgp_decrypt_output_var.set(path)

def do_pgp_decrypt():
    priv_key = pgp_decrypt_privkey_var.get()
    infile = pgp_decrypt_input_var.get()
    outfile = pgp_decrypt_output_var.get()

    if not priv_key or not infile or not outfile:
        messagebox.showerror("Error", "All fields are required")
        return

    password = simpledialog.askstring(
        "Private key password",
        "Enter password (leave empty if none):",
        show="*"
    )

    try:
        import_cmd = ["gpg", "--batch", "--yes"]
        if password:
            import_cmd += ["--passphrase", password]
        import_cmd += ["--import", priv_key]
        subprocess.check_call(import_cmd)

        dec_cmd = ["gpg", "--batch", "--yes", "--output", outfile, "--decrypt", infile]
        if password:
            dec_cmd = ["gpg", "--batch", "--yes", "--passphrase", password, "--output", outfile, "--decrypt", infile]

        subprocess.check_call(dec_cmd)

        messagebox.showinfo("Success", f"PGP decrypted file saved:\n{outfile}")

    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"PGP decrypt failed:\n{e}")

# -------------------- MAIN GUI --------------------

root = tk.Tk()
root.title("SSH RSA & PGP Encrypt/Decrypt")

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill='both')

# --- SSH Encrypt Tab ---
encrypt_frame = ttk.Frame(notebook)
notebook.add(encrypt_frame, text="SSH Encrypt")

encrypt_pubkey_var = tk.StringVar()
encrypt_input_var = tk.StringVar()
encrypt_output_var = tk.StringVar()

ttk.Label(encrypt_frame, text="Public SSH Key").grid(row=0, column=0, sticky="w", padx=5, pady=5)
ttk.Entry(encrypt_frame, textvariable=encrypt_pubkey_var, width=50).grid(row=0, column=1, padx=5)
ttk.Button(encrypt_frame, text="Browse", command=browse_pubkey).grid(row=0, column=2, padx=5)

ttk.Label(encrypt_frame, text="File to Encrypt").grid(row=1, column=0, sticky="w", padx=5, pady=5)
ttk.Entry(encrypt_frame, textvariable=encrypt_input_var, width=50).grid(row=1, column=1, padx=5)
ttk.Button(encrypt_frame, text="Browse", command=browse_encrypt_input).grid(row=1, column=2, padx=5)

ttk.Label(encrypt_frame, text="Output Encrypted File").grid(row=2, column=0, sticky="w", padx=5, pady=5)
ttk.Entry(encrypt_frame, textvariable=encrypt_output_var, width=50).grid(row=2, column=1, padx=5)
ttk.Button(encrypt_frame, text="Browse", command=browse_encrypt_output).grid(row=2, column=2, padx=5)

ttk.Button(encrypt_frame, text="Encrypt", command=do_encrypt, width=25).grid(row=3, column=1, pady=15)

# --- SSH Decrypt Tab ---
decrypt_frame = ttk.Frame(notebook)
notebook.add(decrypt_frame, text="SSH Decrypt")

decrypt_privkey_var = tk.StringVar()
decrypt_input_var = tk.StringVar()
decrypt_output_var = tk.StringVar()

ttk.Label(decrypt_frame, text="Private Key").grid(row=0, column=0, sticky="w", padx=5, pady=5)
ttk.Entry(decrypt_frame, textvariable=decrypt_privkey_var, width=50).grid(row=0, column=1, padx=5)
ttk.Button(decrypt_frame, text="Browse", command=browse_privkey).grid(row=0, column=2, padx=5)

ttk.Label(decrypt_frame, text="Encrypted File").grid(row=1, column=0, sticky="w", padx=5, pady=5)
ttk.Entry(decrypt_frame, textvariable=decrypt_input_var, width=50).grid(row=1, column=1, padx=5)
ttk.Button(decrypt_frame, text="Browse", command=browse_decrypt_input).grid(row=1, column=2, padx=5)

ttk.Label(decrypt_frame, text="Output Decrypted File").grid(row=2, column=0, sticky="w", padx=5, pady=5)
ttk.Entry(decrypt_frame, textvariable=decrypt_output_var, width=50).grid(row=2, column=1, padx=5)
ttk.Button(decrypt_frame, text="Browse", command=browse_decrypt_output).grid(row=2, column=2, padx=5)

ttk.Button(decrypt_frame, text="Decrypt", command=do_decrypt, width=25).grid(row=3, column=1, pady=15)

# --- PGP Encrypt Tab ---
pgp_encrypt_frame = ttk.Frame(notebook)
notebook.add(pgp_encrypt_frame, text="PGP Encrypt")

pgp_encrypt_pubkey_var = tk.StringVar()
pgp_encrypt_input_var = tk.StringVar()
pgp_encrypt_output_var = tk.StringVar()

ttk.Label(pgp_encrypt_frame, text="PGP Public Key").grid(row=0, column=0, sticky="w", padx=5, pady=5)
ttk.Entry(pgp_encrypt_frame, textvariable=pgp_encrypt_pubkey_var, width=50).grid(row=0, column=1, padx=5)
ttk.Button(pgp_encrypt_frame, text="Browse", command=browse_pgp_pub).grid(row=0, column=2, padx=5)

ttk.Label(pgp_encrypt_frame, text="File to Encrypt").grid(row=1, column=0, sticky="w", padx=5, pady=5)
ttk.Entry(pgp_encrypt_frame, textvariable=pgp_encrypt_input_var, width=50).grid(row=1, column=1, padx=5)
ttk.Button(pgp_encrypt_frame, text="Browse", command=browse_pgp_encrypt_input).grid(row=1, column=2, padx=5)

ttk.Label(pgp_encrypt_frame, text="Output Encrypted File").grid(row=2, column=0, sticky="w", padx=5, pady=5)
ttk.Entry(pgp_encrypt_frame, textvariable=pgp_encrypt_output_var, width=50).grid(row=2, column=1, padx=5)
ttk.Button(pgp_encrypt_frame, text="Browse", command=browse_pgp_encrypt_output).grid(row=2, column=2, padx=5)

ttk.Button(pgp_encrypt_frame, text="Encrypt", command=do_pgp_encrypt, width=25).grid(row=3, column=1, pady=15)

# --- PGP Decrypt Tab ---
pgp_decrypt_frame = ttk.Frame(notebook)
notebook.add(pgp_decrypt_frame, text="PGP Decrypt")

pgp_decrypt_privkey_var = tk.StringVar()
pgp_decrypt_input_var = tk.StringVar()
pgp_decrypt_output_var = tk.StringVar()

ttk.Label(pgp_decrypt_frame, text="PGP Private Key").grid(row=0, column=0, sticky="w", padx=5, pady=5)
ttk.Entry(pgp_decrypt_frame, textvariable=pgp_decrypt_privkey_var, width=50).grid(row=0, column=1, padx=5)
ttk.Button(pgp_decrypt_frame, text="Browse", command=browse_pgp_priv).grid(row=0, column=2, padx=5)

ttk.Label(pgp_decrypt_frame, text="Encrypted File").grid(row=1, column=0, sticky="w", padx=5, pady=5)
ttk.Entry(pgp_decrypt_frame, textvariable=pgp_decrypt_input_var, width=50).grid(row=1, column=1, padx=5)
ttk.Button(pgp_decrypt_frame, text="Browse", command=browse_pgp_decrypt_input).grid(row=1, column=2, padx=5)

ttk.Label(pgp_decrypt_frame, text="Output Decrypted File").grid(row=2, column=0, sticky="w", padx=5, pady=5)
ttk.Entry(pgp_decrypt_frame, textvariable=pgp_decrypt_output_var, width=50).grid(row=2, column=1, padx=5)
ttk.Button(pgp_decrypt_frame, text="Browse", command=browse_pgp_decrypt_output).grid(row=2, column=2, padx=5)

ttk.Button(pgp_decrypt_frame, text="Decrypt", command=do_pgp_decrypt, width=25).grid(row=3, column=1, pady=15)

root.mainloop()
