# Client-Server Cipher Demo (Python Sockets)

Three files, all in the same folder:

- `ciphers.py` — Caesar, Playfair, and S-DES implementations (shared by both sides)
- `server.py` — server program
- `client.py` — client program

## How to run

Open **two terminals** in this folder.

**Terminal 1 (start the server first):**
```
python3 server.py
```
It will print `Listening on 127.0.0.1:65432 ...` and wait for a connection.

**Terminal 2 (run the client):**
```
python3 client.py
```
You'll see a menu:
```
1. Caesar Cipher
2. Playfair Cipher
3. S-DES
4. Quit
```
Pick 1–3, enter a key, and enter a message. After the exchange completes the
menu reappears so you can send another message (with the same or a
different algorithm) without restarting the program.

## What happens (matches the assignment steps)

1. **Client menu** — choose 1 (Caesar), 2 (Playfair), or 3 (S-DES).
2. **Client encrypts** the typed message locally and **displays the ciphertext**.
3. Client **sends** `{algorithm, key, ciphertext}` to the server over a TCP socket.
4. **Server receives** the ciphertext, **displays it**, decrypts it with the same
   key/algorithm, and **displays the recovered plaintext**.
5. **Server then composes its own reply** (you type it into the server terminal
   when prompted), encrypts it with the same algorithm/key, and **displays both
   its plaintext and ciphertext** before sending. The **client receives the
   reply, displays the ciphertext**, and decrypts it to **show the plaintext** too.

## Quitting

- **Client**: choose option `4. Quit` from the menu at any time to exit
  immediately — no server connection is needed for this.
- **Server**: after showing a client's decrypted message, it prompts you for
  a reply. Type `quit` (instead of a reply message) to end the session — the
  server notifies the connected client that it's shutting down (the client
  prints `Server ended the session.` and exits too) and then the server
  program itself exits.
- The server otherwise **loops to accept additional client connections**, so
  you don't need to restart `server.py` between messages — only `client.py`'s
  own menu loop or the server's `quit` command end things.

---

# Task 2 — S-DES whole-file transfer

A separate pair of scripts handles this task, since sending large files is a
different job from typing a short message: `sdes_file_client.py`,
`sdes_file_server.py`, `ciphers.py`, and `file_transfer.py` (a small helper
for sending length-prefixed binary data over the socket).

**i.** Client encrypts a ~1 MB file with S-DES and sends it to the server;
both sides display the ciphertext and plaintext.
**ii.** Server encrypts a ~10 KB file with S-DES and sends it back to the
client; both sides display the ciphertext and plaintext.

Both steps happen in a single run — start the server, then the client.

## How to run

**Terminal 1:**
```
python3 sdes_file_server.py
```

**Terminal 2:**
```
python3 sdes_file_client.py
```
It will ask for:
- a 10-bit S-DES key (e.g. `1010000010`)
- a path to the ~1 MB file to send — **just press Enter** to auto-generate a
  1 MB sample file (`sample_1mb.bin`) if you don't have one handy

The server auto-generates its own 10 KB sample file (`sample_10kb.bin`) the
same way if one isn't already present.

## What gets displayed

A full 1 MB of ciphertext/plaintext obviously can't be dumped to a terminal
usefully, so each side prints:
- file size and how long encryption/decryption took
- a preview of the first bytes of plaintext (as text) and ciphertext (as hex)

The **full** decrypted files are also saved to disk so you can verify them
byte-for-byte against the originals:
- `server_received_plaintext.bin` — server's decrypted copy of the client's
  1 MB file (should match `sample_1mb.bin` exactly)
- `client_received_plaintext.bin` — client's decrypted copy of the server's
  10 KB file (should match `sample_10kb.bin` exactly)

You can confirm an exact match with a checksum, e.g.:
```
md5sum sample_1mb.bin server_received_plaintext.bin
```

## Performance note

`ciphers.py` includes a fast byte-oriented S-DES path
(`sdes_encrypt_bytes` / `sdes_decrypt_bytes`) used only by these file
scripts. Because S-DES encrypts one 8-bit block at a time with fixed
subkeys, there are only 256 possible input→output byte mappings for a given
key — so it precomputes that 256-entry substitution table once and applies
it with `bytes.translate()`, which encrypts/decrypts a full megabyte in
well under a second.

## Keys expected by each algorithm

| Algorithm | Key format | Example |
|---|---|---|
| Caesar Cipher | integer shift | `3` |
| Playfair Cipher | keyword (letters only) | `MONARCHY` |
| S-DES | 10-bit binary string | `1010000010` |

## Notes

- The key is sent alongside the ciphertext over the socket so the other side
  can decrypt — this is purely for classroom/demo purposes; a real system
  would never transmit the key in the clear.
- S-DES encrypts the message one 8-bit (1-character) block at a time and the
  ciphertext is shown/transmitted as hex.
- Playfair uses the standard I/J-merged 5×5 grid, doubled-letter splitting
  (inserts `X`), and pads an odd-length message with a trailing `X`.
- Both scripts use `127.0.0.1:65432` by default — change `HOST`/`PORT` at the
  top of `server.py` and `client.py` if you want to run them on different
  machines on a network.
