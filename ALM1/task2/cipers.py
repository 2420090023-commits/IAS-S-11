"""
ciphers.py
Shared cipher library used by both client.py and server.py.

Implements:
    1. Caesar Cipher
    2. Playfair Cipher
    3. Simplified DES (S-DES)

Each cipher exposes an encrypt(...) and decrypt(...) function with a
consistent, simple signature so the client/server code can treat all
three algorithms uniformly.
"""

import string

# ======================================================================
# 1. CAESAR CIPHER
# ======================================================================

def caesar_encrypt(plaintext: str, key) -> str:
    """key: integer shift value (e.g. 3)."""
    shift = int(key) % 26
    result = []
    for ch in plaintext:
        if ch.isupper():
            result.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        elif ch.islower():
            result.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        else:
            result.append(ch)
    return "".join(result)


def caesar_decrypt(ciphertext: str, key) -> str:
    shift = int(key) % 26
    return caesar_encrypt(ciphertext, -shift)


# ======================================================================
# 2. PLAYFAIR CIPHER
# ======================================================================

def _playfair_matrix(key: str):
    key = "".join(ch for ch in key.upper() if ch.isalpha())
    key = key.replace("J", "I")
    seen = []
    for ch in key + string.ascii_uppercase:
        if ch == "J":
            continue
        if ch not in seen:
            seen.append(ch)
    matrix = [seen[i:i + 5] for i in range(0, 25, 5)]
    pos = {}
    for r in range(5):
        for c in range(5):
            pos[matrix[r][c]] = (r, c)
    return matrix, pos


def _playfair_prepare(text: str):
    text = "".join(ch for ch in text.upper() if ch.isalpha())
    text = text.replace("J", "I")
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 < len(text):
            b = text[i + 1]
            if a == b:
                pairs.append((a, "X"))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        else:
            pairs.append((a, "X"))
            i += 1
    return pairs


def playfair_encrypt(plaintext: str, key: str) -> str:
    matrix, pos = _playfair_matrix(key)
    pairs = _playfair_prepare(plaintext)
    out = []
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(matrix[ra][(ca + 1) % 5])
            out.append(matrix[rb][(cb + 1) % 5])
        elif ca == cb:
            out.append(matrix[(ra + 1) % 5][ca])
            out.append(matrix[(rb + 1) % 5][cb])
        else:
            out.append(matrix[ra][cb])
            out.append(matrix[rb][ca])
    return "".join(out)


def playfair_decrypt(ciphertext: str, key: str) -> str:
    matrix, pos = _playfair_matrix(key)
    ciphertext = "".join(ch for ch in ciphertext.upper() if ch.isalpha())
    pairs = [(ciphertext[i], ciphertext[i + 1]) for i in range(0, len(ciphertext) - 1, 2)]
    out = []
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            out.append(matrix[ra][(ca - 1) % 5])
            out.append(matrix[rb][(cb - 1) % 5])
        elif ca == cb:
            out.append(matrix[(ra - 1) % 5][ca])
            out.append(matrix[(rb - 1) % 5][cb])
        else:
            out.append(matrix[ra][cb])
            out.append(matrix[rb][ca])
    return "".join(out)


# ======================================================================
# 3. SIMPLIFIED DES (S-DES)
# ======================================================================

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
P4 = [2, 4, 3, 1]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]

S0 = [[1, 0, 3, 2],
      [3, 2, 1, 0],
      [0, 2, 1, 3],
      [3, 1, 3, 2]]

S1 = [[0, 1, 2, 3],
      [2, 0, 1, 3],
      [3, 0, 1, 0],
      [2, 1, 0, 3]]


def _permute(bits, table):
    return [bits[i - 1] for i in table]


def _left_shift(bits, n):
    return bits[n:] + bits[:n]


def _xor(a, b):
    return [x ^ y for x, y in zip(a, b)]


def _sbox_lookup(bits4, sbox):
    row = (bits4[0] << 1) | bits4[3]
    col = (bits4[1] << 1) | bits4[2]
    val = sbox[row][col]
    return [(val >> 1) & 1, val & 1]


def _generate_keys(key10):
    key10 = [int(b) for b in key10]
    p10 = _permute(key10, P10)
    left, right = p10[:5], p10[5:]

    left1, right1 = _left_shift(left, 1), _left_shift(right, 1)
    k1 = _permute(left1 + right1, P8)

    left2, right2 = _left_shift(left1, 2), _left_shift(right1, 2)
    k2 = _permute(left2 + right2, P8)

    return k1, k2


def _fk(bits8, subkey):
    left, right = bits8[:4], bits8[4:]
    ep = _permute(right, EP)
    xored = _xor(ep, subkey)
    left_s, right_s = xored[:4], xored[4:]
    s0_out = _sbox_lookup(left_s, S0)
    s1_out = _sbox_lookup(right_s, S1)
    p4_out = _permute(s0_out + s1_out, P4)
    new_left = _xor(p4_out, left)
    return new_left + right


def _sdes_block(bits8, k1, k2):
    ip = _permute(bits8, IP)
    temp = _fk(ip, k1)
    switched = temp[4:] + temp[:4]
    temp2 = _fk(switched, k2)
    return _permute(temp2, IP_INV)


def sdes_encrypt_block(bits8, key10):
    k1, k2 = _generate_keys(key10)
    return _sdes_block(bits8, k1, k2)


def sdes_decrypt_block(bits8, key10):
    k1, k2 = _generate_keys(key10)
    return _sdes_block(bits8, k2, k1)


def _text_to_bits(text: str):
    bits = []
    for ch in text:
        b = format(ord(ch) & 0xFF, "08b")
        bits.extend(int(x) for x in b)
    return bits


def _bits_to_hex(bits):
    out = ""
    for i in range(0, len(bits), 4):
        nibble = bits[i:i + 4]
        val = int("".join(str(b) for b in nibble), 2)
        out += format(val, "x")
    return out


def _hex_to_bits(hexstr):
    bits = []
    for ch in hexstr:
        val = int(ch, 16)
        bits.extend(int(x) for x in format(val, "04b"))
    return bits


def _bits_to_text(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        val = int("".join(str(b) for b in byte), 2)
        chars.append(chr(val))
    return "".join(chars)


def sdes_encrypt(plaintext: str, key10: str) -> str:
    """Returns ciphertext as a hex string (2 hex chars per input char)."""
    bits = _text_to_bits(plaintext)
    out_bits = []
    for i in range(0, len(bits), 8):
        block = bits[i:i + 8]
        out_bits.extend(sdes_encrypt_block(block, key10))
    return _bits_to_hex(out_bits)


def sdes_decrypt(cipher_hex: str, key10: str) -> str:
    bits = _hex_to_bits(cipher_hex)
    out_bits = []
    for i in range(0, len(bits), 8):
        block = bits[i:i + 8]
        out_bits.extend(sdes_decrypt_block(block, key10))
    return _bits_to_text(out_bits)


# ----------------------------------------------------------------------
# Fast byte-oriented S-DES (used for whole-file encryption)
#
# S-DES encrypts one 8-bit block at a time with fixed subkeys, so for a
# given key there are only 256 possible input bytes -> output bytes.
# We precompute that 256-entry substitution table once, then encrypt the
# whole file with bytes.translate(), which runs at C speed. This makes
# multi-megabyte files practical (looping bit-by-bit in pure Python would
# be far too slow).
# ----------------------------------------------------------------------

def _sdes_build_tables(key10: str):
    k1, k2 = _generate_keys(key10)
    enc_table = bytearray(256)
    dec_table = bytearray(256)
    for byte in range(256):
        bits = [int(b) for b in format(byte, "08b")]
        enc_bits = _sdes_block(bits, k1, k2)
        enc_table[byte] = int("".join(str(b) for b in enc_bits), 2)
        dec_bits = _sdes_block(bits, k2, k1)
        dec_table[byte] = int("".join(str(b) for b in dec_bits), 2)
    return bytes(enc_table), bytes(dec_table)


def sdes_encrypt_bytes(data: bytes, key10: str) -> bytes:
    enc_table, _ = _sdes_build_tables(key10)
    return data.translate(enc_table)


def sdes_decrypt_bytes(data: bytes, key10: str) -> bytes:
    _, dec_table = _sdes_build_tables(key10)
    return data.translate(dec_table)


# ======================================================================
# UNIFIED DISPATCH HELPERS
# ======================================================================

ALGORITHMS = {
    "1": "Caesar Cipher",
    "2": "Playfair Cipher",
    "3": "S-DES",
}


def encrypt(algo_choice: str, plaintext: str, key) -> str:
    if algo_choice == "1":
        return caesar_encrypt(plaintext, key)
    elif algo_choice == "2":
        return playfair_encrypt(plaintext, key)
    elif algo_choice == "3":
        return sdes_encrypt(plaintext, key)
    raise ValueError("Unknown algorithm choice")


def decrypt(algo_choice: str, ciphertext: str, key) -> str:
    if algo_choice == "1":
        return caesar_decrypt(ciphertext, key)
    elif algo_choice == "2":
        return playfair_decrypt(ciphertext, key)
    elif algo_choice == "3":
        return sdes_decrypt(ciphertext, key)
    raise ValueError("Unknown algorithm choice")