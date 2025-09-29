import socket
import threading
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
server_public_key = server_private_key.public_key()

def rsa_decrypt(ciphertext):
    return server_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

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

def recv_all(conn, n):
    data = b''
    while len(data) < n:
        try:
            packet = conn.recv(n - len(data))
        except Exception:
            return None
        if not packet:
            return None
        data += packet
    return data

def handle_client(conn, addr):
    print(f"[+] Connected to {addr}")

    try:
        pubkey_bytes = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.sendall(len(pubkey_bytes).to_bytes(4, 'big'))
        conn.sendall(pubkey_bytes)

        aes_key_len_bytes = recv_all(conn, 4)
        if not aes_key_len_bytes:
            print("[-] Client disconnected before sending AES key")
            conn.close()
            return
        aes_key_len = int.from_bytes(aes_key_len_bytes, 'big')
        aes_key_encrypted = recv_all(conn, aes_key_len)
        if aes_key_encrypted is None:
            print("[-] Failed receiving AES key bytes")
            conn.close()
            return
        aes_key = rsa_decrypt(aes_key_encrypted)

        while True:
            command_len_bytes = recv_all(conn, 4)
            if not command_len_bytes:
                break
            command_len = int.from_bytes(command_len_bytes, 'big')
            command_encrypted = recv_all(conn, command_len)
            if command_encrypted is None:
                break
            try:
                command = aes_decrypt(aes_key, command_encrypted).decode(errors='ignore')
            except Exception as e:
                print(f"[!] Failed to decrypt command: {e}")
                break

            if command.startswith("UPLOAD"):
                parts = command.split(" ", 2)
                if len(parts) < 3:
                    print("[!] Malformed UPLOAD command")
                    break
                filename = parts[1]
                try:
                    file_size = int(parts[2])
                except ValueError:
                    print("[!] Invalid file size")
                    break

                encrypted_data = recv_all(conn, file_size)
                if encrypted_data is None:
                    print("[!] Client disconnected during file upload")
                    break
                try:
                    file_data = aes_decrypt(aes_key, encrypted_data)
                except Exception as e:
                    print(f"[!] Failed to decrypt uploaded file: {e}")
                    break

                safe_path = os.path.join("server_storage", os.path.basename(filename))
                with open(safe_path, "wb") as f:
                    f.write(file_data)
                print(f"[+] File {filename} uploaded and stored as {safe_path}.")

            elif command.startswith("DOWNLOAD"):
                parts = command.split(" ", 1)
                if len(parts) < 2:
                    print("[!] Malformed DOWNLOAD command")
                    break
                filename = parts[1]
                filepath = os.path.join("server_storage", os.path.basename(filename))
                if os.path.exists(filepath):
                    with open(filepath, "rb") as f:
                        file_data = f.read()
                    encrypted_data = aes_encrypt(aes_key, file_data)
                    conn.sendall(len(encrypted_data).to_bytes(4, 'big'))
                    conn.sendall(encrypted_data)
                    print(f"[+] Sent {filename} to client.")
                else:
                    conn.sendall((0).to_bytes(4, 'big'))  # not found

            elif command.startswith("LIST"):
                files = os.listdir("server_storage")
                files_str = "\n".join(files).encode()
                encrypted_list = aes_encrypt(aes_key, files_str)
                conn.sendall(len(encrypted_list).to_bytes(4, 'big'))
                conn.sendall(encrypted_list)

            else:
                print(f"[!] Unknown command: {command}")

    except Exception as ex:
        print(f"[!] Exception in client handler: {ex}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        print(f"[-] Disconnected from {addr}")

# === Server main ===
def start_server():
    if not os.path.exists("server_storage"):
        os.makedirs("server_storage")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("0.0.0.0", 5555))
    except OSError as e:
        print(f"[!] Port 5555 unavailable ({e}), switching to 5566...")
        server.bind(("0.0.0.0", 5566))

    server.listen(5)
    print(f"[*] Server listening on {server.getsockname()}")

    try:
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()
    finally:
        server.close()

if __name__ == "__main__":
    start_server()
