"""
Group-based binary cipher
Cryptography and Network Security

Step 1: Convert plaintext to binary (8 bits per character)
Step 2: Generate a key with a mathematical function (LCG, randomly seeded)
Step 3: Check closure, associativity and identity for the operation.
        Encrypt ONLY if all three properties hold.

Set       : B = {0, 1, ..., 255}   (all 8-bit binary strings)
Operation : XOR (bitwise exclusive OR)
"""

import random

BITS = 8
SET_B = range(2 ** BITS)          # 0 .. 255


# --------------------------------------------------------------
# STEP 1: Plaintext -> binary
# --------------------------------------------------------------
def text_to_binary(text):
    """Each character -> its 8-bit ASCII binary string."""
    return [format(ord(ch), '08b') for ch in text]


def binary_to_text(bin_list):
    return ''.join(chr(int(b, 2)) for b in bin_list)


# --------------------------------------------------------------
# STEP 2: Mathematical key generation
# --------------------------------------------------------------
def generate_key(length, seed=None):
    """
    Linear Congruential Generator:
        x(n+1) = (a * x(n) + c) mod m
    m = 256, a = 137, c = 187
    a - 1 is divisible by 4 and c is odd, so the sequence has the
    full period of 256 (every byte value appears before repeating).
    The seed x(0) is chosen with random() if not given.
    """
    a, c, m = 137, 187, 2 ** BITS
    if seed is None:
        seed = random.randint(0, m - 1)
    x = seed
    key = []
    for _ in range(length):
        x = (a * x + c) % m
        key.append(x)
    return seed, key


# --------------------------------------------------------------
# STEP 3: Group-property checks
# --------------------------------------------------------------
def xor_op(a, b):
    return a ^ b


def check_closure(op, S, key):
    """a op b must stay inside S for every a in S and every key byte."""
    for a in S:
        for k in key:
            if op(a, k) not in S:
                return False, f"{a} op {k} = {op(a, k)} is outside the set"
    return True, "every result stays in {0..255}"


def check_associativity(op, S, key):
    """(a op b) op k == a op (b op k) for all a, b in S and each key byte."""
    for k in set(key):
        for a in S:
            for b in S:
                if op(op(a, b), k) != op(a, op(b, k)):
                    return False, f"fails at a={a}, b={b}, k={k}"
    return True, "(a op b) op k = a op (b op k) for all tested values"


def check_identity(op, S, key):
    """Find e in S with e op a == a and a op e == a for every a in S."""
    for e in S:
        if all(op(e, a) == a and op(a, e) == a for a in S):
            return True, f"identity element e = {e} ({format(e, '08b')})", e
    return False, "no identity element exists", None


# --------------------------------------------------------------
# Encryption / decryption (runs only after checks pass)
# --------------------------------------------------------------
def encrypt(plain_bin, key, op):
    return [format(op(int(p, 2), k), '08b') for p, k in zip(plain_bin, key)]


def decrypt(cipher_bin, key, op):
    # Under XOR every key byte is its own inverse: k XOR k = 0 (identity)
    return [format(op(int(c, 2), k), '08b') for c, k in zip(cipher_bin, key)]


# --------------------------------------------------------------
# Main
# --------------------------------------------------------------
def main():
    plaintext = input("Enter plaintext: ") or "SAHIL"

    print("\nSTEP 1: Plaintext to binary")
    plain_bin = text_to_binary(plaintext)
    for ch, b in zip(plaintext, plain_bin):
        print(f"  {ch} -> {ord(ch):3d} -> {b}")

    print("\nSTEP 2: Key generation (LCG: x = (137x + 187) mod 256)")
    seed, key = generate_key(len(plain_bin))
    print(f"  Random seed x0 = {seed}")
    for i, k in enumerate(key, 1):
        print(f"  k{i} = {k:3d} -> {format(k, '08b')}")

    print("\nSTEP 3: Checking group properties for (B, XOR)")
    c_ok, c_msg = check_closure(xor_op, SET_B, key)
    print(f"  Closure       : {'YES' if c_ok else 'NO'}  ({c_msg})")
    a_ok, a_msg = check_associativity(xor_op, SET_B, key)
    print(f"  Associativity : {'YES' if a_ok else 'NO'}  ({a_msg})")
    i_ok, i_msg, _ = check_identity(xor_op, SET_B, key)
    print(f"  Identity      : {'YES' if i_ok else 'NO'}  ({i_msg})")

    if not (c_ok and a_ok and i_ok):
        print("\n  Key/operation REJECTED. Ciphertext not generated.")
        return

    print("\n  All three properties hold. Proceeding to encryption.")

    print("\nCIPHERTEXT (plaintext XOR key)")
    cipher_bin = encrypt(plain_bin, key, xor_op)
    for p, k, c in zip(plain_bin, key, cipher_bin):
        print(f"  {p} XOR {format(k, '08b')} = {c}")
    print(f"  Ciphertext (binary): {' '.join(cipher_bin)}")
    print(f"  Ciphertext (hex)   : {' '.join(format(int(c, 2), '02X') for c in cipher_bin)}")

    print("\nVERIFY: decrypting with the same key")
    recovered = binary_to_text(decrypt(cipher_bin, key, xor_op))
    print(f"  Recovered plaintext: {recovered}")


if __name__ == "__main__":
    main()
