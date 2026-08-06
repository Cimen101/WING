// Sprint 15 P0 - brute_decrypt: 反向暴力 (解密 c0, 找 'athena{' 前缀)
// 策略: 对每个 key, decrypt(c0, key) → 检查低 56 位 == LE 'athena{' = 0x007b616e65687461
// 然后用找到的 key 解密 c1, 拼接得 flag
//
// 用法: ./brute_decrypt <c0_hex> <c1_hex> [high=0|f]
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
    x = (x + ror32(x, 28)) & MASK32;  // ROL 4 = ROR 28
    x = (x ^ 0xA5C3E1D7u) & MASK32;
    x = (x ^ (x >> 11)) & MASK32;
    return x;
}

// 加密: 40128c block_cipher
static uint64_t block_cipher_enc(uint64_t plain, uint64_t key) {
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

// 解密: 40131f block_cipher_decr (倒序, 用 L 不用 R)
static uint64_t block_cipher_decr(uint64_t cipher, uint64_t key) {
    uint32_t rk[8];
    expand_key(key, rk);
    uint32_t L = (uint32_t)(cipher >> 32);
    uint32_t R = (uint32_t)(cipher & MASK32);
    for (int i = 7; i >= 0; i--) {
        uint32_t T = L;
        uint32_t f_out = mix32(L, rk[i]);
        L = (R ^ f_out) & MASK32;
        R = T;
    }
    return ((uint64_t)L << 32) | R;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <c0_hex> <c1_hex> [high=0|f]\n", argv[0]);
        return 1;
    }
    uint64_t c0 = strtoull(argv[1], NULL, 16);
    uint64_t c1 = strtoull(argv[2], NULL, 16);
    int use_high_ff = (argc >= 4 && argv[3][0] == 'f');
    uint64_t high = use_high_ff ? 0xFFFFFFFFull : 0x0ull;

    // LE 'athena{' = 0x007b616e65687461, 取低 56 位 (丢弃 MSB byte)
    uint64_t athena_prefix = 0x007b616e65687461ull;  // 7 字节 LE
    uint64_t prefix_mask = 0x00FFFFFFFFFFFFFFull;     // 56 位

    fprintf(stderr, "Decrypt-brute 2^32 keys (high=0x%llx)...\n", (unsigned long long)high);
    fprintf(stderr, "Target c0=0x%016llx, c1=0x%016llx\n", (unsigned long long)c0, (unsigned long long)c1);
    fprintf(stderr, "Looking for: dec(c0) low-56-bit == 0x%014llx ('athena{' LE)\n",
            (unsigned long long)athena_prefix);

    int found = 0;
    for (uint64_t low = 0; low <= 0xFFFFFFFFull; low++) {
        uint64_t key = (high << 32) | low;
        uint64_t p0 = block_cipher_decr(c0, key);
        if ((p0 & prefix_mask) == athena_prefix) {
            // 找到候选! 解密 c1 看完整 flag
            uint64_t p1 = block_cipher_decr(c1, key);
            printf("FOUND: key=0x%016llx\n", (unsigned long long)key);
            printf("  p0 = 0x%016llx = ", (unsigned long long)p0);
            for (int i = 7; i >= 0; i--) {
                uint8_t b = (p0 >> (i * 8)) & 0xff;
                printf("%c", (b >= 32 && b < 127) ? b : '.');
            }
            printf("\n  p1 = 0x%016llx = ", (unsigned long long)p1);
            for (int i = 7; i >= 0; i--) {
                uint8_t b = (p1 >> (i * 8)) & 0xff;
                printf("%c", (b >= 32 && b < 127) ? b : '.');
            }
            printf("\n");
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
