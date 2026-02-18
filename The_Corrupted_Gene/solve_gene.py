#!/usr/bin/env python3
"""
SecurinetsENIT CTF 2025 — "The Corrupted Gene" — Solver

Pipeline: DNA → transcription → codon reorder (MUTATED) → translation → XOR fold → compare
The mutation: PERM[4] and PERM[11] are swapped.
Fix: swap them back → identity permutation → correct amino acids → XOR unfold → flag.
"""

# ─── Extracted from binary ───
DNA = "GATGGAGGCATCACAACTAGAAATAAGGTTGAGGGCGTGGCAACCATGGCTATTAGGAAAGGAGTGGACGTCAGCGGTGGGGCTAACACGATAGAAAGTACAGCGGTA"

CODON_TABLE = { "UUU": 2, "UUC": 3, "UUA": 9, "UUG": 12, "UCU": 15, "UCC": 17, "UCA": 20, "UCG": 23, "UAU": 27, "UAC": 39, "UAA": 52, "UAG": 53, "UGU": 57, "UGC": 60, "UGA": 63, "UGG": 66, "CUU": 68, "CUC": 72, "CUA": 76, "CUG": 78, "CCU": 79, "CCC": 80, "CCA": 85, "CCG": 86, "CAU": 93, "CAC": 106, "CAA": 113, "CAG": 120, "CGU": 122, "CGC": 123, "CGA": 124 }

PERM = [0, 1, 2, 3, 11, 5, 6, 7, 8, 9, 10, 4, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35]  # mutated: positions 4 and 11 are swapped

# ─── Stage 1: Transcription ───
def transcribe(dna):
    return "".join({"A":"U","T":"A","C":"G","G":"C"}[b] for b in dna)

mrna   = transcribe(DNA)
codons = [mrna[i*3:(i+1)*3] for i in range(36)]

# ─── Stage 2: Fix the mutation (swap perm[4] and perm[11] back) ───
fixed_perm        = list(PERM)
fixed_perm[4], fixed_perm[11] = fixed_perm[11], fixed_perm[4]
reordered = [codons[fixed_perm[i]] for i in range(36)]

# ─── Stage 3: Translation ───
aa_seq = [chr(CODON_TABLE.get(c, ord("?"))) for c in reordered]

# ─── Stage 4: Unfold (XOR is self-inverse) ───
flag = "".join(chr(ord(aa) ^ ((i * 0x0B + 0x1F) & 0x7F))
               for i, aa in enumerate(aa_seq))

print(f"Flag: {flag}")
