// - brute_feistel v2: 只验证 c1, 输出所有候选 key
// 然后用 Python 在候选中找满足 c2 的
// 优化: 不要 early skip, 直接输出所有可能的 key (c1 match)
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
    uint64_t c1 = (argc >= 2) ? strtoull(argv[1], NULL, 16) : 0xab28667c0fc996f7ull;
    uint64_t p1 = (argc >= 3) ? strtoull(argv[2], NULL, 16) : 0x007b616e65687461ull;
    int use_high_ff = (argc >= 4 && argv[3][0] == 'f');

    uint64_t high = use_high_ff ? 0xFFFFFFFFull : 0x0ull;

    fprintf(stderr, "Searching 2^32 keys (high=0x%llx, p1=0x%016llx, c1=0x%016llx)...\n",
            (unsigned long long)high, (unsigned long long)p1, (unsigned long long)c1);

    int found = 0;
    for (uint64_t low = 0; low <= 0xFFFFFFFFull; low++) {
        uint64_t key = (high << 32) | low;
        if (block_cipher(p1, key) == c1) {
            // 输出到 stdout, 每行一个 key
            printf("%016llx\n", (unsigned long long)key);
            fflush(stdout);
            found++;
        }
        if ((low & 0xFFFFFF) == 0) {
            fprintf(stderr, "  progress: 0x%08llx / 0x100000000 (%.1f%%, found=%d)\n",
                    (unsigned long long)low, (double)low * 100.0 / (double)0x100000000ull, found);
        }
    }
    fprintf(stderr, "DONE: found %d candidates\n", found);
    return 0;
}
