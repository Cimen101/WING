// Sprint 14 P4 - des_cryptanalysis MITM C 加速
// 24-bit sub-key 搜索 (与 Python MITM 一致, 提供 C 加速)
//
// 限制: 假设 sub_key 的高 8 位 = 0. 若实际 sub_key 高 8 位非 0 (SHA-256 keys 通常如此),
//       则 24-bit 搜索会失败. 此时应使用 Z3 fallback.
//
// 编译 (在 Kali 上):
//   gcc -O3 -march=native -o des_mitm_main des_mitm.c
//
// 用法:
//   ./des_mitm_main m1 c1 m2 c2 [m3 c3 ...]
//   例: ./des_mitm_main 0x0123456789ab 0xba768d58d874 0x000000000000 0x1891ba5cec2a

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// S/P-box 与 narrow_des_server.py 一致
static const int P[24] = {
    8, 18, 3, 2, 15, 24, 10, 14, 20, 7, 5, 13, 1, 6, 21, 9,
    4, 11, 23, 22, 12, 19, 16, 17
};

static const int S[8][16] = {
    {5, 3, 0, 2, 7, 1, 4, 6, 1, 6, 4, 7, 5, 0, 3, 2},
    {4, 1, 0, 5, 3, 7, 6, 2, 1, 4, 0, 5, 2, 6, 3, 7},
    {3, 4, 2, 0, 7, 6, 1, 5, 3, 7, 6, 0, 4, 2, 1, 5},
    {5, 6, 4, 2, 7, 0, 3, 1, 6, 5, 7, 2, 1, 3, 4, 0},
    {5, 6, 7, 3, 1, 0, 4, 2, 3, 6, 2, 1, 7, 4, 0, 5},
    {0, 3, 1, 4, 6, 5, 2, 7, 0, 3, 5, 4, 7, 6, 1, 2},
    {6, 0, 4, 2, 3, 5, 1, 7, 0, 6, 7, 3, 2, 1, 4, 5},
    {0, 5, 6, 2, 3, 7, 4, 1, 2, 4, 0, 7, 3, 1, 5, 6}
};

// 16 轮 Feistel 前向 (用于 24-bit sub-key, k0 实际是 32-bit 但高 8 位 XOR 不影响结果)
static inline void forward_16(uint32_t msg, uint32_t k0, uint32_t *out_L, uint32_t *out_R) {
    uint32_t L = (msg >> 24) & 0xFFFFFF;
    uint32_t R = msg & 0xFFFFFF;
    for (int i = 0; i < 16; i++) {
        uint32_t expanded = 0;
        for (int j = 0; j < 7; j++) {
            expanded |= ((R >> (20 - 3 * j)) & 0xF) << (28 - 4 * j);
        }
        expanded |= (R & 7) << 1 | (R >> 23);
        expanded ^= k0;
        uint32_t s_output = 0;
        for (int j = 0; j < 8; j++) {
            uint32_t temp = (expanded >> (4 * j)) & 0xF;
            s_output = (s_output << 3) | S[j][temp];
        }
        uint32_t p_output = 0;
        for (int j = 0; j < 24; j++) {
            p_output = (p_output << 1) | ((s_output >> (24 - P[j])) & 1);
        }
        uint32_t temp_R = R;
        R = L ^ p_output;
        L = temp_R;
    }
    *out_L = L;
    *out_R = R;
}

// 16 轮 Feistel 反向
static inline void backward_16(uint32_t ct, uint32_t k1, uint32_t *out_L, uint32_t *out_R) {
    uint32_t L = (ct >> 24) & 0xFFFFFF;
    uint32_t R = ct & 0xFFFFFF;
    for (int i = 0; i < 16; i++) {
        uint32_t expanded = 0;
        for (int j = 0; j < 7; j++) {
            expanded |= ((L >> (20 - 3 * j)) & 0xF) << (28 - 4 * j);
        }
        expanded |= (L & 7) << 1 | (L >> 23);
        expanded ^= k1;
        uint32_t s_output = 0;
        for (int j = 0; j < 8; j++) {
            uint32_t temp = (expanded >> (4 * j)) & 0xF;
            s_output = (s_output << 3) | S[j][temp];
        }
        uint32_t p_output = 0;
        for (int j = 0; j < 24; j++) {
            p_output = (p_output << 1) | ((s_output >> (24 - P[j])) & 1);
        }
        uint32_t new_L = R ^ p_output;
        uint32_t new_R = L;
        L = new_L;
        R = new_R;
    }
    *out_L = L;
    *out_R = R;
}

// 完整 32 轮 DES 加密 (验证用)
static inline uint64_t des_block_32(uint64_t msg, uint64_t key) {
    uint32_t L = (uint32_t)((msg >> 24) & 0xFFFFFF);
    uint32_t R = (uint32_t)(msg & 0xFFFFFF);
    uint32_t k0 = (uint32_t)((key >> 32) & 0xFFFFFFFF);
    uint32_t k1 = (uint32_t)(key & 0xFFFFFFFF);
    for (int i = 0; i < 32; i++) {
        uint32_t sk = (i < 16) ? k0 : k1;
        uint32_t expanded = 0;
        for (int j = 0; j < 7; j++) {
            expanded |= ((R >> (20 - 3 * j)) & 0xF) << (28 - 4 * j);
        }
        expanded |= (R & 7) << 1 | (R >> 23);
        expanded ^= sk;
        uint32_t s_output = 0;
        for (int j = 0; j < 8; j++) {
            uint32_t temp = (expanded >> (4 * j)) & 0xF;
            s_output = (s_output << 3) | S[j][temp];
        }
        uint32_t p_output = 0;
        for (int j = 0; j < 24; j++) {
            p_output = (p_output << 1) | ((s_output >> (24 - P[j])) & 1);
        }
        uint32_t temp_R = R;
        R = L ^ p_output;
        L = temp_R;
    }
    return ((uint64_t)L << 24) | R;
}

// 24-bit MITM: 2^24 + 2^24 = 2^25 ops (~10s in C)
// 使用 2^24 hash buckets, 每 entry 20 bytes = 320MB
int mitm_attack_24(
    uint64_t m1, uint64_t c1, uint64_t m2, uint64_t c2,
    uint64_t *out_keys, int max_out
) {
    const uint32_t HASH_SIZE = 1u << 24;
    typedef struct {
        uint32_t L1, R1, L2, R2;
        uint32_t k0;
    } __attribute__((packed)) fwd_entry_t;

    fwd_entry_t *fwd_map = (fwd_entry_t *)calloc(HASH_SIZE, sizeof(fwd_entry_t));
    if (!fwd_map) {
        fprintf(stderr, "calloc failed\n");
        return -1;
    }

    fprintf(stderr, "Phase 1: forward 2^24 = %u k0 candidates...\n", 1u << 24);
    for (uint32_t k0 = 0; k0 < (1u << 24); k0++) {
        uint32_t L1, R1, L2, R2;
        forward_16((uint32_t)m1, k0, &L1, &R1);
        forward_16((uint32_t)m2, k0, &L2, &R2);
        uint32_t h = ((L1 * 0x9E3779B1u) ^ (R1 * 0x85EBCA77u) ^ (L2 * 0xC2B2AE3Du) ^ (R2 * 0x27D4EB2Fu)) % HASH_SIZE;
        fwd_map[h].L1 = L1;
        fwd_map[h].R1 = R1;
        fwd_map[h].L2 = L2;
        fwd_map[h].R2 = R2;
        fwd_map[h].k0 = k0;
    }
    fprintf(stderr, "Phase 1 done.\n");

    fprintf(stderr, "Phase 2: backward 2^24 = %u k1 candidates...\n", 1u << 24);
    int found = 0;
    for (uint32_t k1 = 0; k1 < (1u << 24); k1++) {
        uint32_t L1, R1, L2, R2;
        backward_16((uint32_t)c1, k1, &L1, &R1);
        backward_16((uint32_t)c2, k1, &L2, &R2);
        uint32_t h = ((L1 * 0x9E3779B1u) ^ (R1 * 0x85EBCA77u) ^ (L2 * 0xC2B2AE3Du) ^ (R2 * 0x27D4EB2Fu)) % HASH_SIZE;
        if (fwd_map[h].L1 == L1 && fwd_map[h].R1 == R1 &&
            fwd_map[h].L2 == L2 && fwd_map[h].R2 == R2) {
            uint32_t k0 = fwd_map[h].k0;
            uint64_t full_key = ((uint64_t)k0 << 32) | k1;
            if (des_block_32(m1, full_key) == c1 && des_block_32(m2, full_key) == c2) {
                if (found < max_out) {
                    out_keys[found++] = full_key;
                    fprintf(stderr, "  candidate[%d]: 0x%016llx (verified)\n",
                            found-1, (unsigned long long)full_key);
                }
            }
        }
    }
    fprintf(stderr, "Phase 2 done. Found %d verified candidates.\n", found);

    free(fwd_map);
    return found;
}

// Main 函数: 命令行调用
int main(int argc, char **argv) {
    if (argc < 5 || (argc - 1) % 2 != 0) {
        fprintf(stderr, "Usage: %s m1 c1 m2 c2 [m3 c3 ...]\n", argv[0]);
        fprintf(stderr, "Each is 12 hex chars (48-bit)\n");
        return 1;
    }

    int n_pairs = (argc - 1) / 2;
    if (n_pairs < 2) {
        fprintf(stderr, "Need at least 2 pairs\n");
        return 1;
    }

    uint64_t m[8], c_arr[8];
    for (int i = 0; i < n_pairs && i < 8; i++) {
        m[i] = strtoull(argv[1 + 2*i], NULL, 16) & 0xFFFFFFFFFFFFULL;
        c_arr[i] = strtoull(argv[2 + 2*i], NULL, 16) & 0xFFFFFFFFFFFFULL;
    }

    fprintf(stderr, "=== des_mitm_main (Sprint 14 P4, 24-bit sub-key) ===\n");
    fprintf(stderr, "  Pairs: %d\n", n_pairs);
    for (int i = 0; i < n_pairs; i++) {
        fprintf(stderr, "  Pair %d: m=0x%012llx, c=0x%012llx\n", i+1,
                (unsigned long long)m[i], (unsigned long long)c_arr[i]);
    }
    fprintf(stderr, "  WARNING: 24-bit search only tests sub_keys with high 8 bits = 0.\n");
    fprintf(stderr, "           If actual key has non-zero high 8 bits, this will fail.\n");

    uint64_t candidates[16];
    int n = mitm_attack_24(m[0], c_arr[0], m[1], c_arr[1], candidates, 16);

    if (n > 0) {
        printf("SUCCESS: Found %d candidate(s):\n", n);
        for (int i = 0; i < n; i++) {
            printf("0x%016llx\n", (unsigned long long)candidates[i]);
        }
        return 0;
    } else {
        printf("FAILED: No key found with 24-bit sub-key search\n");
        printf("        (actual key may have non-zero high 8 bits in sub_keys)\n");
        return 1;
    }
}
