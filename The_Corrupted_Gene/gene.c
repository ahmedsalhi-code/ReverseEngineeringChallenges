/*
 * SecurinetsENIT CTF 2025 — "The Corrupted Gene"
 * Reverse Engineering — Intermediate
 *
 * A gene sequencer processes a hardcoded DNA strand through
 * the central dogma: transcription → codon reordering → translation → folding.
 *
 * The pipeline has a mutation. Find it. Fix it. Read the sequence.
 *
 * Build: gcc -O1 -s -o gene gene.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ═══════════════════════════════════════════════════════
 *  GENOME CONSTANTS
 * ═══════════════════════════════════════════════════════ */
#define N_CODONS    36
#define N_BASES     (N_CODONS * 3)   /* 108 */
#define N_CODONS_IN_TABLE 64

/* The DNA template strand (3' → 5' direction) */
static const char DNA_TEMPLATE[N_BASES + 1] =
    "GATGGAGGCATCACAACTAGAAATAAGGTTGAGGGCGTGGCAACCATGGCTATTAGGAAAGGAGTGGACGTCAGCGGTGGGGCTAACACGATAGAAAGTACAGCGGTA";

/* ─── Custom codon → amino acid mapping ───
 * Each 3-base mRNA codon maps to one amino acid code (extended, non-standard).
 * 64 codons defined; unused ones translate to '?'. */
static const char *CODON_TABLE_KEYS[31] = {
    "UUU", "UUC", "UUA", "UUG", "UCU", "UCC", "UCA", "UCG", "UAU", "UAC", "UAA", "UAG",
    "UGU", "UGC", "UGA", "UGG", "CUU", "CUC", "CUA", "CUG", "CCU", "CCC", "CCA", "CCG",
    "CAU", "CAC", "CAA", "CAG", "CGU", "CGC", "CGA"
};
static const uint8_t CODON_TABLE_VALS[31] = {
    0x02, 0x03, 0x09, 0x0c, 0x0f, 0x11, 0x14, 0x17, 0x1b, 0x27, 0x34, 0x35,
    0x39, 0x3c, 0x3f, 0x42, 0x44, 0x48, 0x4c, 0x4e, 0x4f, 0x50, 0x55, 0x56,
    0x5d, 0x6a, 0x71, 0x78, 0x7a, 0x7b, 0x7c
};

/* ─── Codon permutation table ───
 * Applied to mRNA codons BEFORE translation.
 * codon at position i is sent to position perm[i].
 * NOTE: entry 4 and 11 are transposed — this is the mutation. */
static const int PERM[N_CODONS] = {
    0, 1, 2, 3, 11, 5, 6, 7, 8, 9, 10, 4,
    12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
};

/* ─── Target sequence (folded amino acid fingerprint) ───
 * result[i] = translate(perm[i]) ^ folding_key(i)
 * Must match exactly for SEQUENCE VALID. */
static const uint8_t TARGET[N_CODONS] = {
    0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x6e, 0x65, 0x74, 0x73, 0x45, 0x4e,
    0x49, 0x54, 0x7b, 0x63, 0x33, 0x6e, 0x74, 0x72, 0x34, 0x6c, 0x5f, 0x64,
    0x30, 0x67, 0x6d, 0x34, 0x5f, 0x62, 0x72, 0x30, 0x6b, 0x33, 0x6e, 0x7d
};

/* ═══════════════════════════════════════════════════════
 *  RED HERRING — fake codon frequency analyser
 *  Runs at startup, prints a table, means nothing.
 * ═══════════════════════════════════════════════════════ */
static void analyse_codon_frequency(const char *mrna, int n) {
    /* This function is pure misdirection.
     * The frequencies printed are not used in the flag check. */
    const char *codons[] = {"UUU","UUC","UUA","UUG","CUU","CUC","CUA","CUG"};
    int counts[8] = {0};
    for (int i = 0; i < n; i++) {
        for (int c = 0; c < 8; c++) {
            if (strncmp(mrna + i*3, codons[c], 3) == 0)
                counts[c]++;
        }
    }
    printf("  [GeneSeq] Codon frequency analysis:\n");
    for (int c = 0; c < 8; c++)
        printf("    %s : %d\n", codons[c], counts[c]);
    printf("\n");
}

/* ═══════════════════════════════════════════════════════
 *  RED HERRING — structural validator
 *  Always returns 1. Decompiler makes it look critical.
 * ═══════════════════════════════════════════════════════ */
static int validate_structure(const uint8_t *seq, int n) {
    /* Opaque: x*x >= 0 is always true.
     * This check never actually gatekeeps anything. */
    int x = (int)seq[0];
    if (!(x * x >= 0)) return 0;
    int gc = 0;
    for (int i = 0; i < n; i++)
        if (seq[i] > 64) gc++;  /* fake GC-content check */
    return (gc > 0) ? 1 : 1;   /* always 1 */
}

/* ═══════════════════════════════════════════════════════
 *  STAGE 1 — TRANSCRIPTION
 *  DNA template (3'→5') → mRNA (5'→3')
 *  Complement rule: A→U, T→A, C→G, G→C
 * ═══════════════════════════════════════════════════════ */
static void transcribe(const char *dna, char *mrna, int n_bases) {
    for (int i = 0; i < n_bases; i++) {
        switch (dna[i]) {
            case 'A': mrna[i] = 'U'; break;
            case 'T': mrna[i] = 'A'; break;
            case 'C': mrna[i] = 'G'; break;
            case 'G': mrna[i] = 'C'; break;
            default:   mrna[i] = '?'; break;
        }
    }
    mrna[n_bases] = '\0';
}

/* ═══════════════════════════════════════════════════════
 *  STAGE 2 — CODON REORDERING
 *  Apply permutation table to mRNA codons.
 *  codon_out[i] = codon_in[PERM[i]]
 *  (PERM has a mutation at positions 4 and 11)
 * ═══════════════════════════════════════════════════════ */
static void reorder_codons(const char *mrna_in, char *mrna_out, int n_cod) {
    for (int i = 0; i < n_cod; i++) {
        int src = PERM[i];
        mrna_out[i*3 + 0] = mrna_in[src*3 + 0];
        mrna_out[i*3 + 1] = mrna_in[src*3 + 1];
        mrna_out[i*3 + 2] = mrna_in[src*3 + 2];
    }
    mrna_out[n_cod * 3] = '\0';
}

/* ═══════════════════════════════════════════════════════
 *  STAGE 3 — TRANSLATION
 *  mRNA codons → amino acid codes using CODON_TABLE
 * ═══════════════════════════════════════════════════════ */
static uint8_t translate_codon(const char *codon) {
    for (int i = 0; i < 31; i++) {
        if (strncmp(codon, CODON_TABLE_KEYS[i], 3) == 0)
            return CODON_TABLE_VALS[i];
    }
    return (uint8_t)'?';
}

static void translate(const char *mrna, uint8_t *aa_seq, int n_cod) {
    for (int i = 0; i < n_cod; i++)
        aa_seq[i] = translate_codon(mrna + i*3);
}

/* ═══════════════════════════════════════════════════════
 *  STAGE 4 — PROTEIN FOLDING (XOR transform)
 *  folded[i] = aa_seq[i] ^ ((i * 0x0B + 0x1F) & 0x7F)
 *  Simulates a structural conformation transform.
 * ═══════════════════════════════════════════════════════ */
static void fold(const uint8_t *aa_seq, uint8_t *folded, int n) {
    for (int i = 0; i < n; i++)
        folded[i] = aa_seq[i] ^ ((uint8_t)((i * 0x0B + 0x1F) & 0x7F));
}

/* ═══════════════════════════════════════════════════════
 *  MAIN
 * ═══════════════════════════════════════════════════════ */
int main(void) {
    char mrna[N_BASES + 1];
    char mrna_reordered[N_BASES + 1];
    uint8_t aa_seq[N_CODONS];
    uint8_t folded[N_CODONS];

    printf("\n");
    printf("  ╔══════════════════════════════════════════╗\n");
    printf("  ║       G E N E S E Q  v 2 . 3 . 1        ║\n");
    printf("  ║   Central Dogma Processing Pipeline     ║\n");
    printf("  ╚══════════════════════════════════════════╝\n\n");

    printf("  [1/4] Transcribing DNA → mRNA...\n");
    transcribe(DNA_TEMPLATE, mrna, N_BASES);
    printf("        mRNA: %.30s...\n\n", mrna);

    printf("  [2/4] Analysing codon composition...\n");
    analyse_codon_frequency(mrna, N_CODONS);

    printf("  [3/4] Applying codon reordering matrix...\n");
    reorder_codons(mrna, mrna_reordered, N_CODONS);

    printf("  [4/4] Translating and folding...\n");
    translate(mrna_reordered, aa_seq, N_CODONS);

    if (!validate_structure(aa_seq, N_CODONS)) {
        printf("  [!!] Structure validation failed.\n\n");
        return 1;
    }

    fold(aa_seq, folded, N_CODONS);

    if (memcmp(folded, TARGET, N_CODONS) == 0) {
        printf("  [OK] SEQUENCE VALID\n\n");
    } else {
        printf("  [!!] MUTATION DETECTED — sequence does not match reference.\n");
        printf("       Position of first deviation: ");
        for (int i = 0; i < N_CODONS; i++) {
            if (folded[i] != TARGET[i]) {
                printf("%d\n", i);
                break;
            }
        }
        printf("\n");
    }

    return 0;
}
