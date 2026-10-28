"""
server.py
Server side of the client-server encryption demo.

Flow (repeats for each client message, until quit):
    1. Waits for a client connection.
    2. Receives a JSON packet from the client containing:
           algo, key, ciphertext (client-encrypted)
       Displays the received ciphertext AND the decrypted plaintext
       (decrypted on the server using the same key, proving the round
       trip works).
    3. Prompts the server operator for a reply message. Typing "quit"
       (case-insensitive) ends the session: the client is told the
       server is quitting, and the server program exits.
       Otherwise the server encrypts its reply with the same
       algorithm/key, displays both plaintext and ciphertext, and
       sends the ciphertext back to the client.
    4. Loops back to step 1 to accept the next client connection.
"""

import socket
import json
import ciphers

HOST = "127.0.0.1"
PORT = 65432


def recv_json(conn):
    data = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\n" in chunk:
            break
    return json.loads(data.decode().strip())


def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())


def handle_client(conn, addr):
    """Returns False if the server operator chose to quit."""
    print(f"[SERVER] Connected by {addr}")

    # ---- Step 4: receive client's message ----
    packet = recv_json(conn)
    algo = packet["algo"]
    key = packet["key"]
    client_ciphertext = packet["ciphertext"]

    print("\n================ MESSAGE RECEIVED FROM CLIENT ================")
    print(f"Algorithm         : {ciphers.ALGORITHMS[algo]}")
    print(f"Key               : {key}")
    print(f"Ciphertext (recv) : {client_ciphertext}")

    decrypted = ciphers.decrypt(algo, client_ciphertext, key)
    print(f"Decrypted plaintext: {decrypted}")
    print("================================================================\n")

    # ---- Step 5: server sends its own message back to client ----
    reply_input = input(
        "[SERVER] Enter a message to send back to the client "
        "(or type 'quit' to end the server): "
    )

    if reply_input.strip().lower() == "quit":
        send_json(conn, {"quit": True})
        print("[SERVER] Quit requested. Notified client and shutting down.")
        return False

    server_ciphertext = ciphers.encrypt(algo, reply_input, key)

    print("\n================ MESSAGE SERVER IS SENDING =====================")
    print(f"Algorithm         : {ciphers.ALGORITHMS[algo]}")
    print(f"Key               : {key}")
    print(f"Plaintext (send)  : {reply_input}")
    print(f"Ciphertext (send) : {server_ciphertext}")
    print("==================================================================\n")

    send_json(conn, {
        "plaintext": reply_input,
        "ciphertext": server_ciphertext,
    })
    print("[SERVER] Reply sent. Waiting for next client...\n")
    return True


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[SERVER] Listening on {HOST}:{PORT} ...")

        try:
            while True:
                conn, addr = s.accept()
                with conn:
                    keep_running = handle_client(conn, addr)
                if not keep_running:
                    break
        except KeyboardInterrupt:
            print("\n[SERVER] Interrupted. Shutting down.")


if __name__ == "__main__":
    main()