import socket
import struct
import json
import os
import time

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
    client_txt_path = os.path.join(script_dir, "client_10kb.txt")

    print(f"[CLIENT] Connecting to AES server at {HOST}:{PORT}...")
    try:
        cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli_sock.settimeout(3.0)
        cli_sock.connect((HOST, PORT))
        cli_sock.settimeout(None)
        print("[CLIENT] Connected.\n")
    except (ConnectionRefusedError, socket.timeout, OSError):
        print("[CLIENT] Server is not running. Start task3_server.py first.")
        return

    aes_key = get_random_bytes(32)
    aes_key_hex = aes_key.hex()

    print(f"[CLIENT] AES-256 Key: {aes_key_hex}")
    print(f"[CLIENT] Key Size   : {len(aes_key) * 8} bits")

    try:
        # STEP 1: Send 10 KB file to server
        with open(client_txt_path, 'rb') as f:
            client_plaintext = f.read()

        print(f"\n[CLIENT] STEP 1: Sending 10 KB encrypted file to server")
        print(f"[CLIENT] Loaded client_10kb.txt: {len(client_plaintext)} bytes")
        print(f"[CLIENT] Plaintext (preview): {client_plaintext[:200].decode('utf-8', errors='replace')}...")

        iv, ciphertext = aes_encrypt(client_plaintext, aes_key)

        print(f"[CLIENT] IV   : {iv.hex()}")
        print(f"[CLIENT] Size : {len(ciphertext)} bytes (ciphertext)")
        print(f"[CLIENT] Ciphertext (hex): {ciphertext[:64].hex()}")

        send_binary_packet(cli_sock, {
            "action": "UPLOAD_10KB",
            "key": aes_key_hex,
            "iv": iv.hex()
        }, ciphertext)

        ack_meta, _ = recv_binary_packet(cli_sock)
        print(f"[CLIENT] Server response: {ack_meta.get('status')}")
        print(f"[CLIENT] 10 KB upload successful.")

        time.sleep(1)

        # STEP 2: Receive 5 KB file from server
        print(f"\n[CLIENT] STEP 2: Requesting 5 KB encrypted file from server")

        send_binary_packet(cli_sock, {
            "action": "DOWNLOAD_5KB_REQ",
            "key": aes_key_hex
        })

        resp_meta, enc_payload = recv_binary_packet(cli_sock)
        resp_iv = bytes.fromhex(resp_meta.get("iv"))

        print(f"[CLIENT] Received ciphertext: {len(enc_payload)} bytes")
        print(f"[CLIENT] IV   : {resp_meta.get('iv')}")
        print(f"[CLIENT] Ciphertext (hex): {enc_payload[:64].hex()}")

        decrypted = aes_decrypt(enc_payload, aes_key, resp_iv)

        print(f"[CLIENT] Decrypted size  : {len(decrypted)} bytes")
        print(f"[CLIENT] Plaintext (preview): {decrypted[:200].decode('utf-8', errors='replace')}...")
        print(f"[CLIENT] 5 KB decryption successful.")

        send_binary_packet(cli_sock, {"action": "DISCONNECT"})

    except (KeyboardInterrupt, ConnectionError, BrokenPipeError, OSError) as err:
        print(f"\n[CLIENT] Error: {err}")
    finally:
        cli_sock.close()

if __name__ == '__main__':
    main()
