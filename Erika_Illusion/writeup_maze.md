# SecurinetsENIT CTF 2025 — "The Shattered Maze"
**Category:** Reverse Engineering | **Difficulty:** Intermediate–Hard

> *The maze shifts with every heartbeat.*  
> *What was true before will not be true again.*  
> *You must find all six fragments.*  
> *But you can only walk one path.*

**Flag:** `SecurinetsENIT{qr_m4st3r_0f_l4y3rs}`  
**Binary:** `maze` (Linux x86-64 ELF, stripped)  
**Build:** `gcc -O1 -s -o maze maze.c -lz`

---

## Challenge Summary

The player is dropped into a text adventure with 9 rooms arranged in a 3×3 maze. Six rooms contain a real fragment of a QR code. Three rooms hold decoys. Per run, the player can visit at most **3 rooms** — and the assignment of which room holds which shard is **reshuffled every execution** using `srand(getpid() ^ time(NULL))`.

The naive approach — running the program repeatedly and accumulating shards — fails because the shuffle is different every time. The intended approach is to ignore the runtime entirely and solve it statically.

---

## Maze Structure

```
                       [START]
                          │
        ┌─────────────────┼─────────────────┐
      Branch A          Branch B          Branch C
    (rooms 0,3,6)     (rooms 1,4,7)     (rooms 2,5,8)
```

Each run the player makes 3 binary choices and visits exactly 3 rooms. Maximum real shards reachable in one run: **3 of 6**.

---

## Why Accumulation Fails

```c
srand((unsigned)getpid() ^ (unsigned)time(NULL));
shuffle_rooms(order, 9);  // Fisher-Yates over 9 room slots
```

Two sources of entropy are XOR'd together:
- `getpid()` — different every process, even if launched the same second
- `time(NULL)` — changes every second

This makes the seed **unpredictable from outside the process**. Even if you know the timestamp, you don't know the PID. Running six times gives six different shuffles — you'll never accumulate a complete set.

The game even taunts you when you collect fragments:
> *"The maze has already reshuffled behind you. Running again will not give you the other half. Think differently."*

---

## Binary Layout

Loading in Ghidra reveals:

```c
static const Shard SHARD_TABLE[9] = {
    // 6 real entries (is_real == 1)
    { _real_0, 0x5a, 0,  0,  14, 9,  16, 1 },
    { _real_1, 0x71, 0,  9,  14, 10, 18, 1 },
    { _real_2, 0x88, 0,  19, 14, 10, 18, 1 },
    { _real_3, 0x9f, 14, 0,  15, 9,  17, 1 },
    { _real_4, 0xb6, 14, 9,  15, 10, 19, 1 },
    { _real_5, 0xcd, 14, 19, 15, 10, 19, 1 },
    // 3 decoy entries (is_real == 0)
    { _fake_0, 0x7f, 7,  0,  14, 9,  16, 0 },
    { _fake_1, 0xa2, 0,  19, 14, 10, 18, 0 },
    { _fake_2, 0xc5, 14, 0,  15, 10, 19, 0 },
};
```

The `is_real` field (last integer in each struct) is the tell. Real = `1`, decoy = `0`.

**Struct layout (Ghidra):**
```c
typedef struct {
    uint8_t *enc;    // pointer to encrypted blob
    uint8_t  key;    // XOR key
    int      qr_row; // target row in 29×29 QR grid
    int      qr_col; // target col
    int      rows;   // tile height
    int      cols;   // tile width
    int      nbytes; // length of enc array
    int      is_real;// 1 = real tile, 0 = decoy
} Shard;
```

---

## Intended Solution Path

### Step 1 — Observe the maze behavior

```bash
./maze
# → 3 rooms visited, 0-3 shards collected
# → "Running again will not give you the other half. Think differently."
```

The taunting message confirms accumulation is the wrong approach.

### Step 2 — Load in Ghidra

Find `main`. The shuffle call is immediately visible:
```c
srand((unsigned)getpid() ^ (unsigned)time(NULL));
shuffle_rooms(order, 9);
```

Find `SHARD_TABLE` — a 9-element array of `Shard` structs. Each entry has a pointer to an encrypted blob, a key, position data, and `is_real`.

### Step 3 — Identify the 6 real shards

Filter `SHARD_TABLE` entries where `is_real == 1`. There are exactly 6.

Extract for each:
- Encrypted byte array (pointer to `.rodata`)
- XOR key
- `qr_row`, `qr_col` (placement in the 29×29 grid)
- `rows`, `cols` (tile dimensions)

### Step 4 — Decode each tile

```python
def decode_tile(enc, key, rows, cols):
    bits, total = [], rows * cols
    for byte in enc:
        dec = byte ^ key
        for b in range(7, -1, -1):
            bits.append((dec >> b) & 1)
            if len(bits) == total:
                return bits
    return bits[:total]
```

Each byte XOR'd with its key, then unpacked MSB-first into individual module bits.

### Step 5 — Reconstruct the 29×29 QR matrix

Place each tile's bits at its `(qr_row, qr_col)` offset:

```python
SIZE = 29
matrix = [[0]*SIZE for _ in range(SIZE)]
for enc, key, r0, c0, rows, cols in REAL_SHARDS:
    bits = decode_tile(enc, key, rows, cols)
    idx = 0
    for r in range(rows):
        for c in range(cols):
            matrix[r0+r][c0+c] = bits[idx]; idx += 1
```

### Step 6 — Render and scan

```python
from PIL import Image
SCALE, QUIET = 10, 4
IMG = (SIZE + 2*QUIET) * SCALE
img = Image.new("L", (IMG, IMG), 255)
# ... paint modules ...
img.save("solved_qr.png")
```

Scan `solved_qr.png` → **`SecurinetsENIT{qr_m4st3r_0f_l4y3rs}`**

---

## Why Decoys Don't Help

The 3 decoy entries in `SHARD_TABLE` have:
- **Wrong `qr_row`/`qr_col`:** Some overlap with real tiles, others place garbage outside the grid
- **Random data:** Decrypted bits are ~50% random (noise), not structured QR modules
- **Wrong keys:** Using a decoy's key on a real blob (or vice versa) produces garbage

A solver who accidentally includes a decoy in their assembly will get a broken QR that won't scan.

---

## Difficulty Justification

| Element | Why it challenges |
|---|---|
| Text adventure wrapper | Disguises the binary as a game, not a crypto challenge |
| 9-room layout with only 3 visited | Creates the illusion that multiple runs are needed |
| `getpid() ^ time(NULL)` seed | Makes runtime prediction genuinely hard |
| Taunting messages | Confirms the solver's wrong assumptions, wastes time |
| Decoys with same struct layout | Can't filter by size or structure — must check `is_real` flag |
| XOR key per tile (not global) | Simple per-tile keys but different for each, no global key attack |

---

## Compile & Distribute

```bash
gcc -O1 -s -o maze maze.c -lz
# -O1: preserve opaque predicates (if any), keep structure readable but not trivial
# -s:  strip symbol table
```
