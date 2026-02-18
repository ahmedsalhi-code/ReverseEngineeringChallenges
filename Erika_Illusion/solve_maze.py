#!/usr/bin/env python3
"""
SecurinetsENIT CTF 2025 — "The Shattered Maze" — Solver

The maze randomizes which room gets which shard on every run.
Running multiple times and accumulating shards does NOT work.

Intended approach: static reverse engineering.
1. Identify SHARD_TABLE in the binary (9 entries, is_real field = last int)
2. Extract the 6 entries where is_real == 1
3. Decode each: XOR encrypted blob with its key, unpack bits
4. Place each tile at its (qr_row, qr_col) offset in a 29x29 grid
5. Render as PNG and scan

Requires: pip install pillow
"""
from PIL import Image

# ─── Real shards extracted from SHARD_TABLE (is_real == 1) ───
# Format: (enc_bytes, xor_key, qr_row, qr_col, tile_rows, tile_cols)
REAL_SHARDS = [
    # Shard 0 — tile at QR rows 0-13, cols 0-8
    (bytes([0xa4, 0x1b, 0x74, 0xed, 0x11, 0xfe, 0x49, 0xa0, 0x5b, 0xb5, 0xfe, 0x9d, 0xf4, 0xfc, 0x75, 0x72]), 0x5a, 0, 0, 14, 9),
    # Shard 1 — tile at QR rows 0-13, cols 9-18
    (bytes([0xd5, 0x73, 0x7f, 0x50, 0x50, 0x88, 0x60, 0xb4, 0x27, 0xbf, 0xa3, 0x6b, 0x2f, 0x3a, 0x82, 0xa5, 0xb0, 0x01]), 0x71, 0, 9, 14, 10),
    # Shard 2 — tile at QR rows 0-13, cols 19-28
    (bytes([0x57, 0x6c, 0x99, 0xff, 0xd5, 0x1f, 0xfc, 0x9d, 0x74, 0x88, 0xb9, 0x90, 0x9c, 0xb7, 0x99, 0xbe, 0xc8, 0x38]), 0x88, 0, 19, 14, 10),
    # Shard 3 — tile at QR rows 14-28, cols 0-8
    (bytes([0x99, 0x7f, 0x90, 0x30, 0x26, 0xfc, 0xfd, 0x47, 0x9e, 0x61, 0x5e, 0xf1, 0x28, 0xd4, 0x33, 0x88, 0x65]), 0x9f, 14, 0, 15, 9),
    # Shard 4 — tile at QR rows 14-28, cols 9-18
    (bytes([0xbf, 0xfe, 0x9d, 0xbe, 0x50, 0xc2, 0x31, 0x96, 0xf6, 0xa7, 0x8e, 0x3e, 0x0a, 0x9f, 0xf2, 0x93, 0xbd, 0x59, 0x3a]), 0xb6, 14, 9, 15, 10),
    # Shard 5 — tile at QR rows 14-28, cols 19-28
    (bytes([0xf1, 0x35, 0xc2, 0x80, 0x82, 0xc6, 0x1b, 0xd2, 0x08, 0xd9, 0x99, 0x1c, 0xda, 0x0a, 0xde, 0xa2, 0x97, 0xe2, 0x21]), 0xcd, 14, 19, 15, 10),
]

def decode_tile(enc, key, rows, cols):
    bits, total = [], rows * cols
    for byte in enc:
        dec = byte ^ key
        for b in range(7, -1, -1):
            bits.append((dec >> b) & 1)
            if len(bits) == total:
                return bits
    return bits[:total]

SIZE = 29
matrix = [[0]*SIZE for _ in range(SIZE)]

for enc, key, r0, c0, rows, cols in REAL_SHARDS:
    bits = decode_tile(enc, key, rows, cols)
    idx = 0
    for r in range(rows):
        for c in range(cols):
            matrix[r0+r][c0+c] = bits[idx]; idx += 1

print("[*] QR reconstructed:")
for row in matrix:
    print("".join("██" if v else "  " for v in row))

SCALE, QUIET = 10, 4
IMG = (SIZE + 2*QUIET) * SCALE
img = Image.new("L", (IMG, IMG), 255)
p = img.load()
for r in range(SIZE):
    for c in range(SIZE):
        color = 0 if matrix[r][c] else 255
        for dy in range(SCALE):
            for dx in range(SCALE):
                p[(QUIET+c)*SCALE+dx, (QUIET+r)*SCALE+dy] = color

img.save("solved_qr.png")
print("[+] Saved: solved_qr.png — scan for the flag!")
