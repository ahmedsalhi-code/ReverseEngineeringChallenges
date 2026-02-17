# SecurinetsENIT CTF – "Layered" (Reverse Engineering, Intermediate)

**Flag:** `SecurinetsENIT{r3v3rs1ng_1s_4rt}`

---

## Challenge Description

> "The truth is in the layers. Peel them back carefully."
>
> `nc challenge.securinets.tn 4444`
>
> Attachment: `challenge` (Linux x86-64 ELF)

---

## Overview of the Binary

Running `file challenge` confirms a stripped x86-64 ELF binary. Running it:

```
$ ./challenge
[*] Initialization: ki²1 " 
Enter flag:
```

Loading into Ghidra or IDA reveals four relevant functions: `decrypt_hint`, `fake_check`, and three transformation stages inside `main`.

---

## Red Herrings & Misdirection

### Red Herring #1 — `decrypt_hint()` and the "key = B" bait

The first thing the binary does is call `decrypt_hint()`. In decompiled output it looks like:

```c
unsigned char fake[] = { 0x29, 0x2b, 0xf0, 0x73, 0x62, 0x60, 0x62 };
for (int i = 0; i < 7; i++)
    fake[i] ^= 0x42;
printf("[*] Initialization: %s\n", fake);
```

The decoded string is `ki²1 " ` — visually meaningless — but the XOR key `0x42` is prominently hardcoded, leading many solvers to try a fixed XOR-0x42 attack on the target blob. This goes nowhere. The function exists purely to waste time.

**Why it works as misdirection:** The function runs at startup and is the first XOR a reverser encounters. The key `0x42` ('B') looks like a classic CTF "key = B" hint. It isn't.

---

### Red Herring #2 — `fake_check()` and the fake flag

The binary contains a visible `strcmp` against the string `S3cur1n3ts`:

```c
if (strcmp(input, "S3cur1n3ts") == 0) {
    printf("[+] Access granted. Decrypting...\n");
    printf("    Flag: SecurinetsENIT{n0t_th3_fl4g_k33p_l00k1ng}\n");
}
```

This looks *exactly* like a flag check. Solvers who patch the branch or input `S3cur1n3ts` get a convincing-looking (but wrong) flag string. The fake flag is even in the correct `SecurinetsENIT{}` format.

**Why it works as misdirection:** In decompilers, a `strcmp` with a success branch printing a flag is the most recognizable pattern in RE challenges. Experienced solvers will see it and trust it. The fake flag string is stored in the binary and visible in `strings` output, reinforcing the trap.

---

## The Real Check — Three Transformation Stages

After the two red herrings, `main` runs the actual check:

```
input → stage1() → buf1 → stage2() → buf2 → stage3() → buf3
                                                          ↓
                                              memcmp with target[]
```

### Stage 1: Position-dependent XOR

```c
out[i] = in[i] ^ ((i % 7) + 3);
```

The XOR key is not fixed — it cycles through values `3, 4, 5, 6, 7, 8, 9, 3, 4, ...` based on the byte index. A naive single-key XOR bruteforce will fail.

**Inversion:** Straightforward — XOR is self-inverse, so:
```python
stage1_out[i] = input_char ^ ((i % 7) + 3)
```

### Stage 2: Feedback-dependent rotate-left

```c
unsigned int running_sum = 0;
for (int i = 0; i < len; i++) {
    int rot = (running_sum % 5) + 1;
    out[i] = rotl8(in[i], rot);
    running_sum += in[i];   // accumulate STAGE1 value (pre-rotation)
}
```

The rotation amount for byte `i` depends on the sum of all preceding stage1 bytes. This makes the transformation **stateful** — you cannot invert any byte without knowing all previous ones. It also means a single wrong input character shifts the rotation schedule for all subsequent bytes, causing a cascade of failures.

**Inversion:** Track the same running sum, but accumulate the *inverted* value:

```python
def rotr8(v, n):
    n &= 7
    return ((v >> n) | (v << (8 - n))) & 0xFF

running_sum = 0
for i in range(len):
    rot = (running_sum % 5) + 1
    original = rotr8(stage2_out[i], rot)
    stage2_in[i] = original
    running_sum += original
```

### Stage 3: Inter-byte additive mixing

```c
out[0] = in[0];
out[i] = (in[i] + (in[i-1] ^ 0xAA)) & 0xFF;
```

Each output byte depends on the previous input byte (XOR'd with `0xAA` then added). This chains the bytes together so that any single error corrupts all subsequent bytes in a non-obvious way.

**Inversion:** Walk forward through the output, subtracting the contribution of the previous byte:

```python
inv[0] = stage3_out[0]
for i in range(1, len):
    inv[i] = (stage3_out[i] - (inv[i-1] ^ 0xAA)) & 0xFF
```

---

## Solution Script

```python
# solve.py

target = bytes([
    0xa0, 0xcc, 0x9b, 0x07, 0x72, 0x89, 0xa5, 0x75,
    0x3a, 0x99, 0x7a, 0x30, 0x4c, 0x93, 0x60, 0x24,
    0x39, 0x73, 0x15, 0x95, 0xc8, 0xad, 0x0b, 0x16,
    0x6b, 0xde, 0x23, 0x76, 0xac, 0xc6, 0xfb, 0xff
])

def rotr8(v, n):
    n &= 7
    return ((v >> n) | (v << (8 - n))) & 0xFF

# Invert stage3
s2 = [target[0]]
for i in range(1, len(target)):
    s2.append((target[i] - (s2[i-1] ^ 0xAA)) & 0xFF)

# Invert stage2
s1 = []
running_sum = 0
for i, b in enumerate(s2):
    rot = (running_sum % 5) + 1
    original = rotr8(b, rot)
    s1.append(original)
    running_sum += original

# Invert stage1
flag = ""
for i, b in enumerate(s1):
    flag += chr(b ^ ((i % 7) + 3))

print("Flag:", flag)
```

**Output:**
```
Flag: SecurinetsENIT{r3v3rs1ng_1s_4rt}
```

---

## Intended Solver Path

1. Load binary in Ghidra/IDA. See `decrypt_hint` → notice XOR 0x42 → try it on target bytes → nothing useful. (Red herring #1 consumed.)

2. See `fake_check` with `strcmp("S3cur1n3ts")` and a printf'd flag string → input it → get wrong fake flag `SecurinetsENIT{n0t_th3_fl4g_k33p_l00k1ng}` → submit → rejected. (Red herring #2 consumed.)

3. Continue reversing `main`. Spot three loops operating on input before `memcmp`.

4. Reverse stage1 (position-dependent XOR) — recognize it's not a fixed key.

5. Reverse stage2 (rotl with feedback sum) — key insight: **must accumulate the same running sum** when inverting. This is the main difficulty spike.

6. Reverse stage3 (additive mixing with previous byte) — straightforward once noticed.

7. Write `solve.py` inverting all three stages on `target[]`. Recover flag.

---

## Compilation

```bash
gcc -O2 -o challenge challenge.c -s   # -s strips symbols for added difficulty
```

For distribution, strip the binary and optionally pack with UPX to add a layer of anti-analysis friction.

---

## Difficulty Justification

| Element | Why it's intermediate |
|---|---|
| Position-dependent XOR | Not immediately obvious it's index-based; looks like fixed key at first glance |
| Feedback-dependent rotation | Requires understanding stateful inversion; can't attack byte-by-byte |
| Additive byte mixing | Subtle chaining; breaks differential approaches |
| Two red herrings | Consume time and misdirect tooling (strings, patchseeking) |
| No anti-debug / no packing | Keeps it accessible for static analysis — fair intermediate challenge |
