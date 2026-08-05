// 复杂逆向题 2^32 brute-force (C 加速) - LE 字节序
// 按真实反汇编实现:
// - ror32, expand_key, mix32, block_cipher
// - LE 字节序 (binary 是 x86-64, 默认小端)
//
// 攻击策略:
//   假设 flag = "athena{...}" (7+ bytes)
//   plaintext block 1 = "athena{" + NUL = bytes 0x61 0x74 0x68 0x65 0x6e 0x61 0x7b 0x00
//   plaintext block 1 LE = 0x007b616e65687461
//   plaintext block 2 = 8 个 NUL = 0x0000000000000000
//   验证: block_cipher(p1, key) == c1 AND block_cipher(p2, key) == c2
//   2^32 key search (low 32 bits), 1 thread ~ 25-50s
//
// 用法: ./brute_feistel [c1] [c2] [p1] [p2] [use_high_ff]
// 默认值: 复杂逆向题密文
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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
    // 默认值: 复杂逆向题 encrypted_flag.bin (LE)
    uint64_t c1 = (argc >= 2) ? strtoull(argv[1], NULL, 16) : 0xab28667c0fc996f7ull;
    uint64_t c2 = (argc >= 3) ? strtoull(argv[2], NULL, 16) : 0xea61293090fc4b5dull;
    uint64_t p1 = (argc >= 4) ? strtoull(argv[3], NULL, 16) : 0x007b616e65687461ull;  // "athena{?" LE
    uint64_t p2 = (argc >= 5) ? strtoull(argv[4], NULL, 16) : 0x0000000000000000ull;  // 8 NUL
    int use_high_ff = (argc >= 6 && argv[5][0] == 'f');

    uint64_t high = use_high_ff ? 0xFFFFFFFFull : 0x0ull;

    fprintf(stderr, "Brute-forcing 2^32 keys (high=0x%llx, p1=0x%016llx, p2=0x%016llx)...\n",
            (unsigned long long)high, (unsigned long long)p1, (unsigned long long)p2);
    fprintf(stderr, "Target: c1=0x%016llx, c2=0x%016llx\n",
            (unsigned long long)c1, (unsigned long long)c2);

    int found = 0;
    for (uint64_t low = 0; low <= 0xFFFFFFFFull; low++) {
        uint64_t key = (high << 32) | low;
        if (block_cipher(p1, key) == c1 && block_cipher(p2, key) == c2) {
            printf("FOUND: key=0x%016llx (low=0x%08llx)\n",
                   (unsigned long long)key, (unsigned long long)low);
            fflush(stdout);
            found++;
        }
        if ((low & 0xFFFFFF) == 0) {
            fprintf(stderr, "  progress: 0x%08llx / 0x100000000 (%.1f%%)\n",
                    (unsigned long long)low, (double)low * 100.0 / (double)0x100000000ull);
        }
    }
    if (!found) {
        fprintf(stderr, "NOT FOUND\n");
        return 2;
    }
    return 0;
}
