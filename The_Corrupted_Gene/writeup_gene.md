# SecurinetsENIT CTF 2025 — "The Corrupted Gene"
**Category:** Reverse Engineering | **Difficulty:** Intermediate

> *A gene sequencer processes a hardcoded DNA strand through the central dogma.*  
> *The pipeline has a mutation. Find it. Fix it. Read the sequence.*

**Flag:** `SecurinetsENIT{c3ntr4l_d0gm4_br0k3n}`  
**Binary:** `gene` (Linux x86-64 ELF, stripped)  
**Build:** `gcc -O1 -s -o gene gene.c`

---

## Running the Binary

```
  ╔══════════════════════════════════════════╗
  ║       G E N E S E Q  v 2 . 3 . 1        ║
  ║   Central Dogma Processing Pipeline     ║
  ╚══════════════════════════════════════════╝

  [1/4] Transcribing DNA → mRNA...
        mRNA: CUACCUCCGUAGUGUUGAUCUUUAUUCCAA...

  [2/4] Analysing codon composition...
  [GeneSeq] Codon frequency analysis:
    UUU : 1   UUC : 1   UUA : 1   UUG : 1
    CUU : 1   CUC : 1   CUA : 1   CUG : 1

  [3/4] Applying codon reordering matrix...
  [4/4] Translating and folding...
  [!!] MUTATION DETECTED — sequence does not match reference.
       Position of first deviation: 4
```

The binary helpfully tells us **where** the mutation is (position 4) but not **what** it is.

---

## Pipeline Overview

```
DNA_TEMPLATE (108 bases, hardcoded)
        │
        ▼  Stage 1: Transcription
        │  A→U, T→A, C→G, G→C
        ▼
    mRNA (108 bases = 36 codons)
        │
        ▼  Stage 2: Codon Reordering
        │  codon_out[i] = codon_in[PERM[i]]
        │  ← MUTATION IS HERE (PERM[4] ↔ PERM[11] swapped)
        ▼
    Reordered mRNA
        │
        ▼  Stage 3: Translation
        │  Each 3-base codon → amino acid code (custom table)
        ▼
    aa_seq[36]
        │
        ▼  Stage 4: Folding XOR
        │  folded[i] = aa_seq[i] ^ ((i × 0x0B + 0x1F) & 0x7F)
        ▼
    folded[36]  ──memcmp──▶  TARGET[36]
```

---

## Misdirection Elements

### Red Herring 1 — `analyse_codon_frequency()`

Stage 2 prints a codon frequency table that looks diagnostic. It's completely unrelated to the flag check — pure flavor to distract solvers from focusing on `PERM`.

### Red Herring 2 — `validate_structure()`

```c
static int validate_structure(const uint8_t *seq, int n) {
    int x = (int)seq[0];
    if (!(x * x >= 0)) return 0;   /* opaque: always true */
    int gc = 0;
    for (int i = 0; i < n; i++)
        if (seq[i] > 64) gc++;
    return (gc > 0) ? 1 : 1;       /* always returns 1 */
}
```

Looks like a gatekeeping function — it's called before the memcmp and appears to control program flow. In reality it always returns 1. A solver who tries to understand or patch it wastes time.

---

## Finding the Mutation

In Ghidra, `PERM` is a 36-element `int` array. Inspecting it:

```
PERM = [0, 1, 2, 3, 11, 5, 6, 7, 8, 9, 10, 4, 12, 13, 14, ...]
                        ↑                        ↑
                   PERM[4] = 11              PERM[11] = 4
```

A correct permutation table for an identity reorder would have `PERM[i] = i` for all `i`. Two entries are transposed: positions 4 and 11 hold each other's values.

The binary even announces the first deviation is at position 4 — which directly points to `PERM[4]` being wrong.

---

## Intended Solution Path

### Step 1 — Understand the 4 stages

Load in Ghidra, follow `main` through the 4 function calls:
- `transcribe()` — standard complement rule, straightforward
- `reorder_codons()` — uses `PERM[]`, identify this is where the mutation lives
- `translate()` — lookup table (`CODON_TABLE_KEYS` + `CODON_TABLE_VALS`)
- `fold()` — XOR with `(i * 0x0B + 0x1F) & 0x7F`

### Step 2 — Extract the codon table

`CODON_TABLE_KEYS` is an array of 31 string pointers in `.rodata`, `CODON_TABLE_VALS` is the corresponding byte values. Extract both.

### Step 3 — Identify and fix the mutation

Dump `PERM[36]`. Notice `PERM[4] = 11` and `PERM[11] = 4`. These should both be their own indices. Swap them back to get the identity permutation.

### Step 4 — Run the corrected pipeline

```python
# Stage 1
mrna = transcribe(DNA)
codons = [mrna[i*3:(i+1)*3] for i in range(36)]

# Stage 2 — FIXED perm
fixed_perm = list(PERM)
fixed_perm[4], fixed_perm[11] = fixed_perm[11], fixed_perm[4]
reordered = [codons[fixed_perm[i]] for i in range(36)]

# Stage 3
aa_seq = [chr(CODON_TABLE[c]) for c in reordered]

# Stage 4 — XOR is self-inverse
flag = "".join(chr(ord(aa) ^ ((i*0x0B + 0x1F) & 0x7F))
               for i, aa in enumerate(aa_seq))
```

**Output:** `SecurinetsENIT{c3ntr4l_d0gm4_br0k3n}`

---

## Why it's Intermediate

| Element | Challenge it creates |
|---|---|
| 4-stage pipeline | Solver must understand each stage before inverting |
| Custom codon table | Not the standard genetic code — must extract from binary |
| Mutation is a swap not a corruption | Single transposition is subtle, easy to miss if only checking values not indices |
| `validate_structure()` red herring | Looks like a gate but isn't — wastes time for solvers who trust appearances |
| Codon frequency table | Makes Stage 2 look like analysis, obscures that `PERM` is the key object |
| XOR fold key formula | `(i × 0x0B + 0x1F) & 0x7F` must be extracted and understood, not just copied |
