// brute_feistel v3: 测试各种 plain 假设
// 假设:
//   1. 整个 16 字节 = "athena{? + 8 字节 (含 }+pad)"
//   2. 或者 block 1 = 全 NUL, block 2 = 全 NUL
//   3. 或者 block 1 = "athena{?" (8 字节), block 2 = "}" + 7 字节 pad
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define MASK32 0xFFFFFFFFu

static inline uint32_t ror32(uint32_t x, int n) {
    n &= 31;
    return (x >> n) | (x << (32 - n));
}

static void expand_key(uint64_t master_key, uint32_t rk[8]) {
    uint32_t low = (uint32_t)(master_key & MASK32);
    uint32_t high = (uint32_t)((master_key >> 32) & MASK32);
    for (int i = 0; i < 8; i++) {
        int edx = (i * 7) & 0x1F;
        uint32_t eax = ror32(low, edx);
        uint32_t ecx = (uint32_t)(i * 0xB7E15163);
        rk[i] = (eax ^ ecx) & MASK32;
    }
    if (high == 0xFFFFFFFFu) {
        rk[0] = (rk[0] ^ 0xFFFFFFFFu) & MASK32;
    }
}

static inline uint32_t mix32(uint32_t R, uint32_t rk) {
    uint32_t x = (R ^ rk) & MASK32;
    x = (x * 0x5BD1E995u) & MASK32;
    x = (x ^ (x >> 13)) & MASK32;
    x = (x + ror32(x, 28)) & MASK32;
    x = (x ^ 0xA5C3E1D7u) & MASK32;
    x = (x ^ (x >> 11)) & MASK32;
    return x;
}

static uint64_t block_cipher(uint64_t plain, uint64_t key) {
    uint32_t rk[8];
    expand_key(key, rk);
    uint32_t L = (uint32_t)(plain >> 32);
    uint32_t R = (uint32_t)(plain & MASK32);
    for (int i = 0; i < 8; i++) {
        uint32_t T = R;
        uint32_t f_out = mix32(R, rk[i]);
        R = (L ^ f_out) & MASK32;
        L = T;
    }
    return ((uint64_t)L << 32) | R;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <c0> <plain_mode> [high=0|f]\n", argv[0]);
        fprintf(stderr, "Modes:\n");
        fprintf(stderr, "  0: all-zero block (8 NUL)\n");
        fprintf(stderr, "  1: athena{? (7 fixed + 1 variable)\n");
        fprintf(stderr, "  2: 'a' * 8 (0x6161616161616161)\n");
        fprintf(stderr, "  3: 0x0123456789abcdef (test)\n");
        return 1;
    }
    uint64_t c0 = strtoull(argv[1], NULL, 16);
    int mode = atoi(argv[2]);
    int use_high_ff = (argc >= 5 && argv[4][0] == 'f');
    uint64_t high = use_high_ff ? 0xFFFFFFFFull : 0x0ull;

    // 多个 plain 候选
    uint64_t p_candidates[256];
    int n_p = 0;

    if (mode == 0) {
        p_candidates[n_p++] = 0x0000000000000000ull;
    } else if (mode == 1) {
        // 'athena{?' - 7 字节固定, 1 字节变化
        for (int b = 0; b < 256; b++) {
            p_candidates[n_p++] = ((uint64_t)b << 56) | 0x7b616e65687461ull;
        }
    } else if (mode == 2) {
        p_candidates[n_p++] = 0x6161616161616161ull;
    } else if (mode == 3) {
        p_candidates[n_p++] = 0x0123456789abcdefull;
    } else if (mode == 4) {
        // 模式: 'athena{' + NUL = 0x007b616e65687461
        p_candidates[n_p++] = 0x007b616e65687461ull;
    } else if (mode == 5) {
        // 模式: BE 'athena{' + 1 字节
        for (int b = 0; b < 256; b++) {
            p_candidates[n_p++] = ((uint64_t)0x6174656e61417bull << 8) | b;
        }
    }

    fprintf(stderr, "Mode %d, %d plain candidates, searching 2^32 keys (high=0x%llx)...\n",
            mode, n_p, (unsigned long long)high);
    fprintf(stderr, "Target: c0=0x%016llx\n", (unsigned long long)c0);

    int found = 0;
    for (uint64_t low = 0; low <= 0xFFFFFFFFull; low++) {
        uint64_t key = (high << 32) | low;
        for (int p = 0; p < n_p; p++) {
            if (block_cipher(p_candidates[p], key) == c0) {
                printf("FOUND: key=0x%016llx plain=0x%016llx (mode=%d)\n",
                       (unsigned long long)key, (unsigned long long)p_candidates[p], mode);
                fflush(stdout);
                found++;
            }
        }
        if ((low & 0xFFFFFF) == 0) {
            fprintf(stderr, "  progress: 0x%08llx / 0x100000000 (%.1f%%, found=%d)\n",
                    (unsigned long long)low, (double)low * 100.0 / (double)0x100000000ull, found);
        }
    }
    fprintf(stderr, "DONE: found %d candidates\n", found);
    return 0;
}
