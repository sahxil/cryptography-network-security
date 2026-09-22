"""
Multiplicative Cipher for a single letter
Cryptography and Network Security

    Encryption : C = (P x K) mod 26
    Decryption : P = (C x K^-1) mod 26

The key K is valid ONLY if gcd(K, 26) = 1, because only then does the
modular inverse K^-1 exist, and without K^-1 decryption is impossible.
"""

N = 26


def ask(prompt):
    """Print the prompt and flush it before reading, so web terminals show it."""
    print(prompt, end="", flush=True)
    return input()


def letter_to_num(ch):
    return ord(ch.upper()) - ord('A')


def num_to_letter(n):
    return chr(n + ord('A'))


# --------------------------------------------------------------
# Extended Euclidean Algorithm (Forouzan table: q r1 r2 r t1 t2 t)
# Gives gcd(n, K) and, when gcd = 1, the inverse of K mod n.
# --------------------------------------------------------------
def extended_euclid(n, k, show=True):
    r1, r2 = n, k
    t1, t2 = 0, 1
    if show:
        print(f"    {'q':>3} {'r1':>4} {'r2':>4} {'r':>4} {'t1':>5} {'t2':>5} {'t':>5}")
    while r2 > 0:
        q = r1 // r2
        r = r1 - q * r2
        t = t1 - q * t2
        if show:
            print(f"    {q:>3} {r1:>4} {r2:>4} {r:>4} {t1:>5} {t2:>5} {t:>5}")
        r1, r2 = r2, r
        t1, t2 = t2, t
    if show:
        print(f"    {'':>3} {r1:>4} {r2:>4} {'':>4} {t1:>5} {t2:>5}")
    return r1, t1          # gcd, raw inverse (may be negative)


def collision_example(k):
    """For an invalid key, find two different letters that encrypt the same."""
    seen = {}
    for p in range(N):
        c = (p * k) % N
        if c in seen:
            return seen[c], p, c
        seen[c] = p
    return None


# --------------------------------------------------------------
# Main demo for one letter + one key
# --------------------------------------------------------------
def run_cipher():
    print()
    letter = ask("  Enter ONE plaintext letter (A-Z): ").strip()
    if len(letter) != 1 or not letter.isalpha():
        print("  Invalid input: please enter exactly one letter.")
        return

    try:
        k = int(ask("  Enter key K (integer): ").strip())
    except ValueError:
        print("  Invalid input: key must be an integer.")
        return

    P = letter_to_num(letter)
    K = k % N
    print(f"\n  Plaintext letter  : {letter.upper()}  ->  P = {P}")
    if K != k:
        print(f"  Key reduced mod 26: {k} mod 26 = {K}")
    print(f"  Key               : K = {K}")

    # STEP 1: gcd check
    print(f"\n  STEP 1: Check gcd({N}, {K}) with the Extended Euclidean Algorithm")
    if K == 0:
        print("    K = 0: every letter maps to A (0 x P = 0). gcd(26, 0) = 26.")
        g, raw = N, None
    else:
        g, raw = extended_euclid(N, K)
    print(f"\n    gcd({N}, {K}) = {g}")

    if g != 1:
        print(f"\n  KEY REJECTED: gcd({N}, {K}) = {g} != 1, so {K} has NO modular inverse mod 26.")
        ex = collision_example(K) if K != 0 else (0, 1, 0)
        if ex:
            a, b, c = ex
            print(f"  Proof: {num_to_letter(a)} ({a}) x {K} mod 26 = {c}  and  "
                  f"{num_to_letter(b)} ({b}) x {K} mod 26 = {c}")
            print(f"  Both {num_to_letter(a)} and {num_to_letter(b)} encrypt to "
                  f"{num_to_letter(c)}, so the receiver cannot tell which was sent.")
        print("  Encryption is refused because decryption would be impossible.")
        return

    # STEP 2: modular inverse
    inv = raw % N
    print(f"\n  STEP 2: Modular inverse")
    print(f"    t1 = {raw}  ->  K^-1 = {raw} mod 26 = {inv}")
    print(f"    Check: {K} x {inv} = {K * inv} = {(K * inv) // N} x 26 + {(K * inv) % N}"
          f"  ->  {K} x {inv} mod 26 = {(K * inv) % N}  (correct)")

    # STEP 3: encrypt
    C = (P * K) % N
    print(f"\n  STEP 3: Encrypt   C = (P x K) mod 26")
    print(f"    C = ({P} x {K}) mod 26 = {P * K} mod 26 = {C}  ->  {num_to_letter(C)}")

    # STEP 4: decrypt
    D = (C * inv) % N
    print(f"\n  STEP 4: Decrypt   P = (C x K^-1) mod 26")
    print(f"    P = ({C} x {inv}) mod 26 = {C * inv} mod 26 = {D}  ->  {num_to_letter(D)}")

    status = "SUCCESS" if D == P else "MISMATCH"
    print(f"\n  RESULT: {letter.upper()} --(K={K})--> {num_to_letter(C)} "
          f"--(K^-1={inv})--> {num_to_letter(D)}   [{status}]")


def show_valid_keys():
    print("\n  Valid keys in Z26* (gcd(K, 26) = 1) and their inverses:\n")
    print(f"    {'K':>3}  {'K^-1':>5}  {'K x K^-1 mod 26':>16}")
    for k in range(1, N):
        g, raw = extended_euclid(N, k, show=False)
        if g == 1:
            inv = raw % N
            print(f"    {k:>3}  {inv:>5}  {(k * inv) % N:>16}")
    print(f"\n  12 valid keys. Invalid keys: 0, all even numbers, and 13"
          f" (they share a factor 2 or 13 with 26 = 2 x 13).")


def explain():
    print("""
  WHY THE MODULAR INVERSE MATTERS
  --------------------------------
  1. Decryption depends on it. Encryption multiplies by K, so decryption
     must "undo" that multiplication. In modular arithmetic there is no
     division; instead we multiply by K^-1, the number with
     K x K^-1 = 1 (mod 26).

  2. It guarantees a one-to-one mapping. If K^-1 exists, every plaintext
     letter maps to a different ciphertext letter, so the cipher is
     reversible. If it does not exist, two letters collide (e.g. K = 13:
     A -> A and C -> A), and the message can never be recovered.

  3. It is used across cryptography: the multiplicative and affine
     ciphers, the Hill cipher (inverse of the key matrix), RSA
     (d = e^-1 mod phi(n)), and the AES S-box (inverse in GF(2^8)).

  CONDITION FOR EXISTENCE
  -----------------------
  K has a multiplicative inverse modulo n  <=>  gcd(K, n) = 1.
  For n = 26 = 2 x 13, K must be odd and not 13:
      Z26* = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25}   (12 keys)
  The inverse is found with the Extended Euclidean Algorithm.
""")


def main():
    print("=" * 62)
    print("   MULTIPLICATIVE CIPHER  |  C = P.K mod 26,  P = C.K^-1 mod 26")
    print("=" * 62)
    while True:
        print()
        print("  1. Encrypt and decrypt a letter")
        print("  2. Show all valid keys and their inverses")
        print("  3. Why the modular inverse matters (theory)")
        print("  4. Quit")
        choice = ask("  Choose 1-4: ").strip()
        if choice == "1":
            run_cipher()
        elif choice == "2":
            show_valid_keys()
        elif choice == "3":
            explain()
        elif choice == "4":
            print("  Bye.")
            break
        else:
            print("  Please choose 1, 2, 3 or 4.")


if __name__ == "__main__":
    main()
