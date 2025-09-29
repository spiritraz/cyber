import socket
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

AES_KEY = os.urandom(32)

def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(plaintext) % 16)
    padded_data = plaintext + bytes([pad_len] * pad_len)
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key, ciphertext_with_iv):
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = padded_plaintext[-1]
    return padded_plaintext[:-pad_len]

def recv_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SafeNimble CloudApp")
        self.root.geometry("650x520")
        self.root.configure(bg="#0F0F0F") 

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton",
                        font=("Segoe UI", 11, "bold"),
                        padding=8,
                        relief="flat",
                        background="#FF004D",
                        foreground="white",
                        borderwidth=0)
        style.map("TButton",
                  background=[("active", "#FF1E8E")],
                  foreground=[("active", "white")])

        self.title_label = tk.Label(root,
                                    text="🚀 SafeNimble GX",
                                    font=("Segoe UI", 22, "bold"),
                                    bg="#0F0F0F",
                                    fg="#FF004D")
        self.title_label.pack(pady=15)

        button_frame = tk.Frame(root, bg="#0F0F0F")
        button_frame.pack(pady=5, fill=tk.X)

        self.upload_btn = ttk.Button(button_frame, text="⬆️ Upload", command=self.upload_file_threaded, state=tk.DISABLED)
        self.upload_btn.pack(side=tk.LEFT, padx=12, pady=5)

        self.refresh_btn = ttk.Button(button_frame, text="🔃 Refresh", command=self.refresh_file_list_threaded, state=tk.DISABLED)
        self.refresh_btn.pack(side=tk.LEFT, padx=12, pady=5)

        self.download_btn = ttk.Button(button_frame, text="⬇️ Download", command=self.download_file_threaded, state=tk.DISABLED)
        self.download_btn.pack(side=tk.LEFT, padx=12, pady=5)

        list_frame = tk.Frame(root, bg="#0F0F0F")
        list_frame.pack(pady=15, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.file_listbox = tk.Listbox(list_frame,
                                       width=80,
                                       height=20,
                                       bg="#1A1A1A",
                                       fg="#FFFFFF",
                                       selectbackground="#FF004D",
                                       selectforeground="white",
                                       font=("Consolas", 11),
                                       yscrollcommand=scrollbar.set,
                                       border=0,
                                       highlightthickness=1,
                                       highlightbackground="#FF004D")
        self.file_listbox.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.file_listbox.yview)

        self.sock = None
        threading.Thread(target=self.connect_to_server, daemon=True).start()

        self.glow_state = True
        self.animate_title()

    def connect_to_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect(("127.0.0.1", 5555))

            pubkey_len_bytes = recv_all(self.sock, 4)
            if not pubkey_len_bytes:
                raise RuntimeError("Did not receive server public key length")
            pubkey_len = int.from_bytes(pubkey_len_bytes, 'big')
            pubkey_bytes = recv_all(self.sock, pubkey_len)
            if pubkey_bytes is None:
                raise RuntimeError("Did not receive complete server public key")

            server_public_key = serialization.load_pem_public_key(pubkey_bytes, backend=default_backend())

            aes_key_encrypted = server_public_key.encrypt(
                AES_KEY,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.sock.sendall(len(aes_key_encrypted).to_bytes(4, 'big'))
            self.sock.sendall(aes_key_encrypted)

            self.root.after(0, lambda: self.upload_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.refresh_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.download_btn.config(state=tk.NORMAL))

            self.refresh_file_list()

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Connection Error", f"Could not connect to server:\n{e}"))

    # ====== Threads ======
    def upload_file_threaded(self):
        threading.Thread(target=self.upload_file, daemon=True).start()

    def refresh_file_list_threaded(self):
        threading.Thread(target=self.refresh_file_list, daemon=True).start()

    def download_file_threaded(self):
        threading.Thread(target=self.download_file, daemon=True).start()

    # ====== File Operations ======
    def upload_file(self):
        file_path = filedialog.askopenfilename(title="Choose file to upload")
        if not file_path:
            return
        filename = os.path.basename(file_path)
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()
            encrypted_file = aes_encrypt(AES_KEY, file_data)
            command = f"UPLOAD {filename} {len(encrypted_file)}".encode()
            encrypted_command = aes_encrypt(AES_KEY, command)

            self.sock.sendall(len(encrypted_command).to_bytes(4, 'big'))
            self.sock.sendall(encrypted_command)
            self.sock.sendall(encrypted_file)

            self.root.after(0, lambda: messagebox.showinfo("Success", f"Uploaded {filename}"))
            self.refresh_file_list()
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Upload Error", f"Failed to upload:\n{e}"))

    def refresh_file_list(self):
        try:
            self.root.after(0, lambda: self.file_listbox.delete(0, tk.END))
            command = "LIST".encode()
            encrypted_command = aes_encrypt(AES_KEY, command)
            self.sock.sendall(len(encrypted_command).to_bytes(4, 'big'))
            self.sock.sendall(encrypted_command)

            list_len_bytes = recv_all(self.sock, 4)
            if not list_len_bytes:
                raise RuntimeError("No response from server when listing files")
            list_len = int.from_bytes(list_len_bytes, 'big')
            encrypted_list = recv_all(self.sock, list_len)
            if encrypted_list is None:
                raise RuntimeError("Incomplete file list received")
            file_list_str = aes_decrypt(AES_KEY, encrypted_list).decode()

            files = file_list_str.split("\n")
            for f in files:
                if f.strip():
                    self.root.after(0, lambda item=f.strip(): self.file_listbox.insert(tk.END, item))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to refresh file list:\n{e}"))

    def download_file(self):
        selection = self.file_listbox.curselection()
        if not selection:
            self.root.after(0, lambda: messagebox.showwarning("Warning", "Please select a file to download"))
            return
        server_filename = self.file_listbox.get(selection[0])
        try:
            command = f"DOWNLOAD {server_filename}".encode()
            encrypted_command = aes_encrypt(AES_KEY, command)
            self.sock.sendall(len(encrypted_command).to_bytes(4, 'big'))
            self.sock.sendall(encrypted_command)

            file_len_bytes = recv_all(self.sock, 4)
            if not file_len_bytes:
                raise RuntimeError("No response from server for download")
            file_len = int.from_bytes(file_len_bytes, 'big')
            if file_len == 0:
                self.root.after(0, lambda: messagebox.showerror("Error", "File not found on server."))
                return

            encrypted_file = recv_all(self.sock, file_len)
            if encrypted_file is None:
                raise RuntimeError("Incomplete file data received")
            file_data = aes_decrypt(AES_KEY, encrypted_file)

            save_path = filedialog.asksaveasfilename(defaultextension="", initialfile=server_filename, title="Save downloaded file as")
            if not save_path:
                return
            with open(save_path, "wb") as f:
                f.write(file_data)
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Downloaded {save_path}"))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to download file:\n{e}"))

    def animate_title(self):
        if self.glow_state:
            self.title_label.config(fg="#FF1E8E")  
        else:
            self.title_label.config(fg="#FF004D")  
        self.glow_state = not self.glow_state
        self.root.after(800, self.animate_title)


if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
