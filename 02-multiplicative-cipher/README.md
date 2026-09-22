# Multiplicative Cipher (Single Letter)

**Course:** Cryptography and Network Security (UPES, B.Tech CSE)  
**Author:** Sahil Singh | SAP ID 500093998 | Batch B14

A Python program that encrypts and decrypts a single letter with the multiplicative cipher, and shows **why the modular inverse is essential** and **when it exists**.

```
Encryption : C = (P × K) mod 26
Decryption : P = (C × K⁻¹) mod 26
```

## What the program does

1. **Accepts** one plaintext letter and a key K
2. **Checks** whether gcd(K, 26) = 1, using the Extended Euclidean Algorithm (printed in the q, r1, r2, r, t1, t2, t table format)
3. **Finds** the modular inverse K⁻¹ of a valid key and verifies K × K⁻¹ ≡ 1 (mod 26)
4. **Encrypts** the letter
5. **Decrypts** the ciphertext back to the original letter
6. **Rejects** invalid keys, and proves why by showing two letters that collide to the same ciphertext

The menu also lists all 12 valid keys with their inverses, and includes a theory screen.

## Why the modular inverse matters

- **Decryption depends on it.** Encryption multiplies by K. Modular arithmetic has no division, so decryption multiplies by K⁻¹, the number with K × K⁻¹ ≡ 1 (mod 26).
- **It guarantees a one-to-one mapping.** If K⁻¹ exists, every letter encrypts to a different letter. If it doesn't, letters collide: with K = 13, both A and C encrypt to A, so the message can never be recovered.
- **It appears throughout cryptography:** affine and Hill ciphers, RSA (d = e⁻¹ mod φ(n)), and the AES S-box (inverses in GF(2⁸)).

## Condition for existence

> K has a multiplicative inverse modulo n **if and only if gcd(K, n) = 1**.

Since 26 = 2 × 13, K must be odd and not 13:

| K | 1 | 3 | 5 | 7 | 9 | 11 | 15 | 17 | 19 | 21 | 23 | 25 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| K⁻¹ | 1 | 9 | 21 | 15 | 3 | 19 | 7 | 23 | 11 | 5 | 17 | 25 |

## Run it

```bash
cd 02-multiplicative-cipher
python multiplicative_cipher.py
```

Python 3 standard library only. It also runs on online editors such as online-python.com.

## Sample runs

**Valid key (H, K = 7):**

```
  STEP 1: Check gcd(26, 7) with the Extended Euclidean Algorithm
      q   r1   r2    r    t1    t2     t
      3   26    7    5     0     1    -3
      1    7    5    2     1    -3     4
      2    5    2    1    -3     4   -11
      2    2    1    0     4   -11    26
           1    0        -11    26

    gcd(26, 7) = 1

  STEP 2: Modular inverse
    t1 = -11  ->  K^-1 = -11 mod 26 = 15
    Check: 7 x 15 = 105 = 4 x 26 + 1  ->  7 x 15 mod 26 = 1  (correct)

  STEP 3: Encrypt   C = (P x K) mod 26
    C = (7 x 7) mod 26 = 49 mod 26 = 23  ->  X

  STEP 4: Decrypt   P = (C x K^-1) mod 26
    P = (23 x 15) mod 26 = 345 mod 26 = 7  ->  H

  RESULT: H --(K=7)--> X --(K^-1=15)--> H   [SUCCESS]
```

**Invalid key (H, K = 13):**

```
  STEP 1: Check gcd(26, 13) with the Extended Euclidean Algorithm
      q   r1   r2    r    t1    t2     t
      2   26   13    0     0     1    -2
          13    0          1    -2

    gcd(26, 13) = 13

  KEY REJECTED: gcd(26, 13) = 13 != 1, so 13 has NO modular inverse mod 26.
  Proof: A (0) x 13 mod 26 = 0  and  C (2) x 13 mod 26 = 0
  Both A and C encrypt to A, so the receiver cannot tell which was sent.
  Encryption is refused because decryption would be impossible.
```
