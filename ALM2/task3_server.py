import socket
import struct
import json
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'
PORT = 65434


def aes_encrypt(plaintext_bytes, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return iv, ciphertext

def aes_decrypt(ciphertext_bytes, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext_bytes)
    return unpad(padded_plaintext, AES.block_size)


def send_binary_packet(sock, meta_dict, payload_data=b""):
    meta_bytes = json.dumps(meta_dict).encode('utf-8')
    header = struct.pack("!II", len(meta_bytes), len(payload_data))
    sock.sendall(header + meta_bytes + payload_data)

def recv_exact_bytes(sock, num_bytes):
    buffer = bytearray()
    while len(buffer) < num_bytes:
        chunk = sock.recv(num_bytes - len(buffer))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        buffer.extend(chunk)
    return bytes(buffer)

def recv_binary_packet(sock):
    header = recv_exact_bytes(sock, 8)
    meta_len, payload_len = struct.unpack("!II", header)
    meta_bytes = recv_exact_bytes(sock, meta_len)
    meta_dict = json.loads(meta_bytes.decode('utf-8'))
    payload_bytes = b""
    if payload_len > 0:
        payload_bytes = recv_exact_bytes(sock, payload_len)
    return meta_dict, payload_bytes


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    server_txt_path = os.path.join(script_dir, "server_5kb.txt")

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind((HOST, PORT))
    srv_sock.listen(5)

    print(f"\n[SERVER] AES-256-CBC File Transfer Server started on {HOST}:{PORT}")

    try:
        while True:
            conn, client_addr = srv_sock.accept()
            print(f"[SERVER] Client connected from {client_addr[0]}:{client_addr[1]}")

            while True:
                try:
                    meta, payload = recv_binary_packet(conn)
                except (ConnectionError, struct.error):
                    print("[SERVER] Client disconnected.")
                    break

                action = meta.get("action")

                if action == "UPLOAD_10KB":
                    aes_key = bytes.fromhex(meta.get("key"))
                    iv = bytes.fromhex(meta.get("iv"))

                    print(f"\n[SERVER] STEP 1: Received 10 KB encrypted file from client")
                    print(f"[SERVER] Key  : {meta.get('key')}")
                    print(f"[SERVER] IV   : {meta.get('iv')}")
                    print(f"[SERVER] Size : {len(payload)} bytes (ciphertext)")
                    print(f"[SERVER] Ciphertext (hex): {payload[:64].hex()}")

                    decrypted = aes_decrypt(payload, aes_key, iv)

                    print(f"[SERVER] Decrypted size  : {len(decrypted)} bytes")
                    print(f"[SERVER] Plaintext (preview): {decrypted[:200].decode('utf-8', errors='replace')}...")
                    print(f"[SERVER] 10 KB decryption successful.")

                    send_binary_packet(conn, {"status": "UPLOAD_SUCCESS"})

                elif action == "DOWNLOAD_5KB_REQ":
                    aes_key = bytes.fromhex(meta.get("key"))

                    with open(server_txt_path, 'rb') as f:
                        server_plaintext = f.read()

                    print(f"\n[SERVER] STEP 2: Sending 5 KB encrypted file to client")
                    print(f"[SERVER] Loaded server_5kb.txt: {len(server_plaintext)} bytes")
                    print(f"[SERVER] Plaintext (preview): {server_plaintext[:200].decode('utf-8', errors='replace')}...")

                    iv, ciphertext = aes_encrypt(server_plaintext, aes_key)

                    print(f"[SERVER] IV   : {iv.hex()}")
                    print(f"[SERVER] Size : {len(ciphertext)} bytes (ciphertext)")
                    print(f"[SERVER] Ciphertext (hex): {ciphertext[:64].hex()}")

                    send_binary_packet(conn, {
                        "action": "DOWNLOAD_5KB_RESP",
                        "iv": iv.hex()
                    }, ciphertext)

                    print(f"[SERVER] 5 KB encryption and transmission successful.")

                elif action == "DISCONNECT":
                    print("[SERVER] Session ended by client.")
                    break

    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down.")
    finally:
        srv_sock.close()

if __name__ == '__main__':
    main()
