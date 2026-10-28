"""
client.py
Client side of the client-server encryption demo.

Flow:
    1. Displays a menu: 1) Caesar 2) Playfair 3) S-DES 4) Quit
    2. Prompts for a key and a plaintext message.
    3. Encrypts the message locally and displays the ciphertext.
    4. Sends {algo, key, ciphertext} to the server.
    5. Waits for the server's reply, which contains the server's
       plaintext and ciphertext, and displays both.
    The menu repeats so multiple messages can be sent in one run;
    choosing "Quit" (or the server ending the session) exits cleanly.
"""

import socket
import json
import ciphers

HOST = "127.0.0.1"
PORT = 65432

MENU_CHOICES = {**ciphers.ALGORITHMS, "4": "Quit"}


def recv_json(sock):
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\n" in chunk:
            break
    return json.loads(data.decode().strip())


def send_json(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())


def show_menu():
    print("\nSelect an option:")
    for k, v in MENU_CHOICES.items():
        print(f"  {k}. {v}")


def ask_key(algo):
    if algo == "1":
        return input("Enter Caesar shift key (integer, e.g. 3): ").strip()
    elif algo == "2":
        return input("Enter Playfair keyword (e.g. MONARCHY): ").strip()
    else:
        return input("Enter 10-bit S-DES key (e.g. 1010000010): ").strip()


def one_exchange(algo, key, message):
    """Encrypt, send to server, print server's reply. Returns False if the
    server signalled it is shutting down (so the client should stop too)."""

    # ---- Step 3: client encrypts and displays ----
    ciphertext = ciphers.encrypt(algo, message, key)
    print("\n================ CLIENT: MESSAGE TO SEND ================")
    print(f"Algorithm         : {ciphers.ALGORITHMS[algo]}")
    print(f"Key               : {key}")
    print(f"Plaintext         : {message}")
    print(f"Ciphertext (sent) : {ciphertext}")
    print("===========================================================\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        send_json(s, {"algo": algo, "key": key, "ciphertext": ciphertext})

        # ---- Step 5: receive server's reply ----
        reply = recv_json(s)

        if reply.get("quit"):
            print("[CLIENT] Server ended the session.")
            return False

        print("================ CLIENT: MESSAGE RECEIVED FROM SERVER ================")
        print(f"Ciphertext (recv)   : {reply['ciphertext']}")
        print(f"Plaintext (as sent by server): {reply['plaintext']}")
        decrypted_locally = ciphers.decrypt(algo, reply["ciphertext"], key)
        print(f"Decrypted by client : {decrypted_locally}")
        print("========================================================================\n")
    return True


def main():
    while True:
        show_menu()
        choice = input("Enter choice (1/2/3/4): ").strip()
        while choice not in MENU_CHOICES:
            choice = input("Invalid choice. Enter 1, 2, 3, or 4: ").strip()

        if choice == "4":
            print("[CLIENT] Quitting. Goodbye!")
            break

        algo = choice
        key = ask_key(algo)
        message = input("Enter the message to send: ")

        try:
            keep_going = one_exchange(algo, key, message)
        except ConnectionRefusedError:
            print("[CLIENT] Could not connect to the server. Is server.py running?")
            break

        if not keep_going:
            break


if __name__ == "__main__":
    main()