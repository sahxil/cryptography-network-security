# Group-Based Binary Cipher

**Course:** Cryptography and Network Security (UPES, B.Tech CSE)  
**Author:** Sahil Singh | SAP ID 500093998 | Batch B14

A Python program that encrypts plaintext **only after verifying that the key and operation satisfy the group properties** of closure, associativity and identity.

## How it works

### Step 1: Plaintext to binary
Each character is converted to its 8-bit ASCII binary form.

```
S -> 83 -> 01010011
```

### Step 2: Mathematical key generation
Keys are generated with a **Linear Congruential Generator (LCG)**, seeded randomly:

```
x(n+1) = (137 * x(n) + 187) mod 256
```

The constants satisfy the full-period conditions (a − 1 divisible by 4 and c odd), so every byte value 0–255 appears once before the sequence repeats. One key byte is produced per plaintext character.

### Step 3: Group-property verification
The set is **B = {0, 1, ..., 255}** (all 8-bit strings) and the operation is **XOR**.

| Property | Condition checked | Result |
|---|---|---|
| Closure | a ⊕ k ∈ B for every a ∈ B and every key byte k | ✅ |
| Associativity | (a ⊕ b) ⊕ k = a ⊕ (b ⊕ k) for all a, b ∈ B | ✅ |
| Identity | there exists e with e ⊕ a = a for every a ∈ B | ✅ e = 0 |

**Ciphertext is produced only if all three checks pass.** Otherwise the key/operation is rejected.

### Encryption and decryption
```
Cipher = Plain ⊕ Key
Plain  = Cipher ⊕ Key      (each key byte is its own inverse: k ⊕ k = 0)
```

## Run it

```bash
cd 01-group-cipher
python group_cipher.py
```

No external libraries are needed (Python 3 standard library only).

## Sample output

```
STEP 1: Plaintext to binary
  S ->  83 -> 01010011
  A ->  65 -> 01000001
  H ->  72 -> 01001000
  I ->  73 -> 01001001
  L ->  76 -> 01001100

STEP 2: Key generation (LCG: x = (137x + 187) mod 256)
  Random seed x0 = 60
  k1 = 215 -> 11010111
  k2 = 202 -> 11001010
  k3 = 213 -> 11010101
  k4 = 184 -> 10111000
  k5 =  51 -> 00110011

STEP 3: Checking group properties for (B, XOR)
  Closure       : YES  (every result stays in {0..255})
  Associativity : YES  ((a op b) op k = a op (b op k) for all tested values)
  Identity      : YES  (identity element e = 0 (00000000))

  All three properties hold. Proceeding to encryption.

CIPHERTEXT (plaintext XOR key)
  01010011 XOR 11010111 = 10000100
  01000001 XOR 11001010 = 10001011
  01001000 XOR 11010101 = 10011101
  01001001 XOR 10111000 = 11110001
  01001100 XOR 00110011 = 01111111
  Ciphertext (binary): 10000100 10001011 10011101 11110001 01111111
  Ciphertext (hex)   : 84 8B 9D F1 7F

VERIFY: decrypting with the same key
  Recovered plaintext: SAHIL
```

The seed is random, so the key and ciphertext change on every run.

## Why the check matters
Replacing XOR with ordinary subtraction makes the program **reject** the key: 5 − 200 = −195 is outside B (closure fails), subtraction is not associative, and there is no two-sided identity.
