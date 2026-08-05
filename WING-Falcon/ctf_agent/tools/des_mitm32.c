/*
 * des_mitm32.c - Narrow_DES 32-bit 子密钥 MITM (正确恢复完整 64-bit key)
 *
 * 背景:
 *   narrow_des_server.py 用 64-bit key = sha256(flag)[:8], 拆成两个 32-bit 子密钥
 *   sub_key0 (rounds 0..15), sub_key1 (rounds 16..31). 子密钥高 8 位一般非 0,
 *   旧版 des_mitm.c 只搜索低 24 位 (假设高 8 位=0) 对真实部署必然失败.
 *
 * 本程序对两个 32-bit 子密钥做完整 2^NB + 2^NB 中间相遇 (meet-in-the-middle):
 *   前向 forward_16(plaintext, k0) -> 中间状态 (L16,R16)
 *   后向 backward_16(ciphertext, k1) -> 同一中间状态
 *   两半独立, 用 2 对明文-密文构造 96-bit meet 值, 分桶落盘后 join.
 *
 * 性能 (+ OpenMP):
 *   - 枚举两趟各 2^NB 个半轮次, OpenMP 并行 (默认全部核).
 *   - 每线程写独立分桶文件, pass 结束合并为 fwd_<b>.bin / bwd_<b>.bin.
 *   - 每条记录仅 10 字节: 48-bit meet 指纹 + 4 字节子密钥.
 *   - NB=32 全量约需 ~86GB 磁盘 + (16 核 ~10-15min / 单核 ~2h).
 *
 * 用法:
 *   des_mitm32 M1 C1 M2 C2 [M3 C3 ...] [--nbits N] [--k0base H] [--k1base H]
 *            [--dir D] [--qbits Q] [--clean] [--verify-only]
 *   明文/密文为 12 位十六进制 (48-bit). 默认 nbits=32, dir=/root/des_mitm_tmp.
 *   成功输出: FOUND key=0x............ k0=0x........ k1=0x........
 *   失败输出: NOTFOUND
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>
#include <omp.h>

#define DEF_QBITS 9
#define DEF_DIR "/root/des_mitm_tmp"
#define MASK24 0xFFFFFFu
#define MASK32 0xFFFFFFFFu

static const int P[24] = {8,18,3,2,15,24,10,14,20,7,5,13,1,6,21,9,
                          4,11,23,22,12,19,16,17};
static const int S[8][16] = {
    {5,3,0,2,7,1,4,6,1,6,4,7,5,0,3,2},
    {4,1,0,5,3,7,6,2,1,4,0,5,2,6,3,7},
    {3,4,2,0,7,6,1,5,3,7,6,0,4,2,1,5},
    {5,6,4,2,7,0,3,1,6,5,7,2,1,3,4,0},
    {5,6,7,3,1,0,4,2,3,6,2,1,7,4,0,5},
    {0,3,1,4,6,5,2,7,0,3,5,4,7,6,1,2},
    {6,0,4,2,3,5,1,7,0,6,7,3,2,1,4,5},
    {0,5,6,2,3,7,4,1,2,4,0,7,3,1,5,6}
};

static int NBITS = 32;
static uint64_t KSPAN = (1ULL << 32);
static uint64_t K0BASE = 0, K1BASE = 0;
static int QBITS = DEF_QBITS;
static int Q = (1 << DEF_QBITS);
static const char *DIR = DEF_DIR;
static int DO_CLEAN = 0;

static uint32_t expand_xor(uint32_t half, uint32_t k) {
    uint32_t expanded = 0;
    int j;
    for (j = 0; j < 7; j++) {
        expanded |= ((half >> (20 - 3 * j)) & 0xF) << (28 - 4 * j);
    }
    expanded |= (half & 7) << 1 | (half >> 23);
    expanded ^= k;
    return expanded;
}

static uint32_t sboxes(uint32_t expanded) {
    uint32_t s_output = 0;
    int j;
    for (j = 0; j < 8; j++) {
        int temp = (expanded >> (4 * j)) & 0xF;
        s_output <<= 3;
        s_output |= S[j][temp];
    }
    return s_output;
}

static uint32_t permute(uint32_t s_output) {
    uint32_t p_output = 0;
    int j;
    for (j = 0; j < 24; j++) {
        p_output <<= 1;
        p_output |= (s_output >> (24 - P[j])) & 1;
    }
    return p_output;
}

/* 前向 16 轮 (子密钥 k0), 返回中间状态 (L,R) 各 24-bit */
static void forward_16(uint64_t msg, uint32_t k0, uint32_t *oL, uint32_t *oR) {
    uint32_t L = (msg >> 24) & MASK24;
    uint32_t R = msg & MASK24;
    int i;
    for (i = 0; i < 16; i++) {
        uint32_t expanded = expand_xor(R, k0);
        uint32_t s_output = sboxes(expanded);
        uint32_t p_output = permute(s_output);
        uint32_t t = R;
        R = L ^ p_output;
        L = t;
    }
    *oL = L & MASK24;
    *oR = R & MASK24;
}

/* 后向 16 轮 (子密钥 k1), 返回中间状态 (L,R) 各 24-bit (forward 的逆) */
static void backward_16(uint64_t ct, uint32_t k1, uint32_t *oL, uint32_t *oR) {
    uint32_t L = (ct >> 24) & MASK24;
    uint32_t R = ct & MASK24;
    int i;
    for (i = 0; i < 16; i++) {
        uint32_t expanded = expand_xor(L, k1);
        uint32_t s_output = sboxes(expanded);
        uint32_t p_output = permute(s_output);
        uint32_t new_L = R ^ p_output;
        uint32_t new_R = L;
        L = new_L;
        R = new_R;
    }
    *oL = L & MASK24;
    *oR = R & MASK24;
}

/* 完整 32 轮验证 (用于候选密钥确认) */
static uint64_t des_block(uint64_t msg, uint64_t key) {
    uint32_t L = (msg >> 24) & MASK24;
    uint32_t R = msg & MASK24;
    uint32_t sub_k[2];
    sub_k[0] = (key >> 32) & MASK32;
    sub_k[1] = key & MASK32;
    int i;
    for (i = 0; i < 32; i++) {
        uint32_t expanded = expand_xor(R, sub_k[i / 16]);
        uint32_t s_output = sboxes(expanded);
        uint32_t p_output = permute(s_output);
        uint32_t t = R;
        R = L ^ p_output;
        L = t;
    }
    return ((uint64_t)(L & MASK24) << 24) | (R & MASK24);
}

/* 由 4 个中间状态构造 96-bit meet 的 3 个 uint32 (top/mid/low) */
static void make_meet(uint32_t L1, uint32_t R1, uint32_t L2, uint32_t R2,
                      uint32_t *top, uint32_t *mid, uint32_t *low) {
    *top = (L1 << 8) | ((R1 >> 16) & 0xFF);
    *mid = ((R1 & 0xFFFF) << 16) | ((L2 >> 8) & 0xFFFF);
    *low = ((L2 & 0xFF) << 24) | (R2 & MASK24);
}

/* 48-bit 指纹 (splitmix 风格混合) 用于外排 join 键 */
static uint64_t mix64(uint64_t x) {
    x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ULL;
    x ^= x >> 27; x *= 0x94D049BB133111EBULL;
    x ^= x >> 31;
    return x;
}
static uint64_t fp_of(uint32_t top, uint32_t mid, uint32_t low) {
    uint64_t h = 0x9E3779B97F4A7C15ULL;
    h ^= (uint64_t)top;  h = mix64(h);
    h ^= (uint64_t)mid;  h = mix64(h);
    h ^= (uint64_t)low;  h = mix64(h);
    return h & 0xFFFFFFFFFFFFULL;  /* 48 bits */
}

static int bucket_of(uint32_t top) {
    return (int)((top >> (32 - QBITS)) & (Q - 1));
}

/* 写一条 10 字节记录: 6 字节 fp48 + 4 字节 key */
static void write_rec(FILE *f, uint64_t fp, uint32_t key) {
    uint8_t buf[10];
    int i;
    for (i = 0; i < 6; i++) buf[i] = (fp >> (8 * i)) & 0xFF;
    for (i = 0; i < 4; i++) buf[6 + i] = (key >> (8 * i)) & 0xFF;
    fwrite(buf, 1, 10, f);
}

int main(int argc, char **argv) {
    int nargs = 0;
    char *pairs_hex[12];
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--nbits") == 0 && i + 1 < argc) {
            NBITS = atoi(argv[++i]); if (NBITS < 1 || NBITS > 32) NBITS = 32;
        } else if (strcmp(argv[i], "--qbits") == 0 && i + 1 < argc) {
            QBITS = atoi(argv[++i]); if (QBITS < 1 || QBITS > 16) QBITS = DEF_QBITS;
        } else if (strcmp(argv[i], "--k0base") == 0 && i + 1 < argc) {
            K0BASE = strtoull(argv[++i], NULL, 16);
        } else if (strcmp(argv[i], "--k1base") == 0 && i + 1 < argc) {
            K1BASE = strtoull(argv[++i], NULL, 16);
        } else if (strcmp(argv[i], "--dir") == 0 && i + 1 < argc) {
            DIR = argv[++i];
        } else if (strcmp(argv[i], "--clean") == 0) {
            DO_CLEAN = 1;
        } else {
            if (nargs >= 12) { fprintf(stderr, "too many args\n"); return 2; }
            pairs_hex[nargs++] = argv[i];
        }
    }
    Q = (1 << QBITS);
    KSPAN = (1ULL << NBITS);

    /* 提高文件描述符上限 (每线程打开 Q 个分桶文件) */
    struct rlimit rl;
    rl.rlim_cur = 65536;
    rl.rlim_max = 65536;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "warn: setrlimit NOFILE failed\n");
    }

    if (nargs < 4 || (nargs % 2) != 0) {
        fprintf(stderr, "usage: %s M1 C1 M2 C2 [M3 C3 ...] [--nbits N] "
                "[--k0base H] [--k1base H] [--dir D] [--qbits Q] [--clean]\n", argv[0]);
        return 2;
    }
    int npairs = nargs / 2;
    uint64_t M[6], C[6];
    for (i = 0; i < npairs; i++) {
        M[i] = strtoull(pairs_hex[2 * i],     NULL, 16) & 0xFFFFFFFFFFFFu;
        C[i] = strtoull(pairs_hex[2 * i + 1], NULL, 16) & 0xFFFFFFFFFFFFu;
    }

    char mkcmd[256];
    snprintf(mkcmd, sizeof(mkcmd), "mkdir -p %s", DIR);
    if (system(mkcmd) != 0) { fprintf(stderr, "cannot mkdir %s\n", DIR); return 3; }
    char rmcmd[256];
    snprintf(rmcmd, sizeof(rmcmd), "rm -f %s/fwd_*.bin %s/bwd_*.bin", DIR, DIR);
    system(rmcmd);

    /* Pass 1: 枚举 k0 (OpenMP 并行, 每线程独立分桶文件) */
    fprintf(stderr, "pass1: forward k0 in [0x%llx, 0x%llx) [%d threads]\n",
            (unsigned long long)K0BASE, (unsigned long long)(K0BASE + KSPAN),
            omp_get_max_threads());
    uint64_t total = 0;
    uint64_t k0end = K0BASE + KSPAN;
    #pragma omp parallel
    {
        int tid = omp_get_thread_num();
        FILE *fwd[Q];
        char fn[200];
        int ii;
        for (ii = 0; ii < Q; ii++) {
            snprintf(fn, sizeof(fn), "%s/fwd_%05d_t%02d.bin", DIR, ii, tid);
            fwd[ii] = fopen(fn, "wb");
            if (!fwd[ii]) { fprintf(stderr, "cannot open %s\n", fn); exit(3); }
        }
        uint64_t tc = 0;
        #pragma omp for schedule(dynamic, 4096)
        for (uint64_t k0 = K0BASE; k0 < k0end; k0++) {
            uint32_t L1, R1, L2, R2;
            forward_16(M[0], (uint32_t)(k0 & MASK32), &L1, &R1);
            forward_16(M[1], (uint32_t)(k0 & MASK32), &L2, &R2);
            uint32_t top, mid, low;
            make_meet(L1, R1, L2, R2, &top, &mid, &low);
            uint64_t fp = fp_of(top, mid, low);
            write_rec(fwd[bucket_of(top)], fp, (uint32_t)(k0 & MASK32));
            tc++;
        }
        for (ii = 0; ii < Q; ii++) fclose(fwd[ii]);
        #pragma omp atomic
        total += tc;
    }
    fprintf(stderr, "wrote %llu forward records\n", (unsigned long long)total);
    /* 合并每桶线程文件 */
    char catcmd[300];
    for (i = 0; i < Q; i++) {
        snprintf(catcmd, sizeof(catcmd),
                 "cat %s/fwd_%05d_t*.bin > %s/fwd_%05d.bin 2>/dev/null; rm -f %s/fwd_%05d_t*.bin",
                 DIR, i, DIR, i, DIR, i);
        system(catcmd);
    }

    /* Pass 2: 枚举 k1 (OpenMP 并行) */
    fprintf(stderr, "pass2: backward k1 in [0x%llx, 0x%llx) [%d threads]\n",
            (unsigned long long)K1BASE, (unsigned long long)(K1BASE + KSPAN),
            omp_get_max_threads());
    total = 0;
    uint64_t k1end = K1BASE + KSPAN;
    #pragma omp parallel
    {
        int tid = omp_get_thread_num();
        FILE *bwd[Q];
        char fn[200];
        int ii;
        for (ii = 0; ii < Q; ii++) {
            snprintf(fn, sizeof(fn), "%s/bwd_%05d_t%02d.bin", DIR, ii, tid);
            bwd[ii] = fopen(fn, "wb");
            if (!bwd[ii]) { fprintf(stderr, "cannot open %s\n", fn); exit(3); }
        }
        uint64_t tc = 0;
        #pragma omp for schedule(dynamic, 4096)
        for (uint64_t k1 = K1BASE; k1 < k1end; k1++) {
            uint32_t L1, R1, L2, R2;
            backward_16(C[0], (uint32_t)(k1 & MASK32), &L1, &R1);
            backward_16(C[1], (uint32_t)(k1 & MASK32), &L2, &R2);
            uint32_t top, mid, low;
            make_meet(L1, R1, L2, R2, &top, &mid, &low);
            uint64_t fp = fp_of(top, mid, low);
            write_rec(bwd[bucket_of(top)], fp, (uint32_t)(k1 & MASK32));
            tc++;
        }
        for (ii = 0; ii < Q; ii++) fclose(bwd[ii]);
        #pragma omp atomic
        total += tc;
    }
    fprintf(stderr, "wrote %llu backward records\n", (unsigned long long)total);
    for (i = 0; i < Q; i++) {
        snprintf(catcmd, sizeof(catcmd),
                 "cat %s/bwd_%05d_t*.bin > %s/bwd_%05d.bin 2>/dev/null; rm -f %s/bwd_%05d_t*.bin",
                 DIR, i, DIR, i, DIR, i);
        system(catcmd);
    }

    /* Pass 3: 分桶 join (OpenMP 并行加速) */
    fprintf(stderr, "pass3: join (%d buckets, %d threads)\n", Q, omp_get_max_threads());
    volatile int found_flag = 0;  /* 找到密钥后通知其他线程停止 */
    uint64_t found_key = 0;
    uint32_t found_k0 = 0, found_k1 = 0;
    #pragma omp parallel for schedule(dynamic, 1) shared(found_flag, found_key, found_k0, found_k1)
    for (int b = 0; b < Q; b++) {
        if (found_flag) continue;  /* 已找到, 跳过 */
        char fn2[200];
        snprintf(fn2, sizeof(fn2), "%s/fwd_%05d.bin", DIR, b);
        FILE *ff = fopen(fn2, "rb");
        if (!ff) continue;
        fseek(ff, 0, SEEK_END);
        long fsz = ftell(ff);
        fseek(ff, 0, SEEK_SET);
        long n_fwd = fsz / 10;
        if (n_fwd == 0) { fclose(ff); continue; }
        uint8_t *fraw = (uint8_t *)malloc((size_t)fsz);
        if (!fraw) { fclose(ff); continue; }
        fread(fraw, 1, (size_t)fsz, ff);
        fclose(ff);

        long cap = 1024;
        while (cap * 2 < n_fwd * 2) cap *= 2;
        if (cap < 1024) cap = 1024;
        /* cap 上限 1<<22 (4M entries, ~32MB) 避免 32-bit 搜索时 32GB htab OOM */
        if (cap > (1L << 22)) cap = 1L << 22;
        long *htab = (long *)calloc((size_t)cap, sizeof(long));
        if (!htab) { free(fraw); continue; }
        for (long j = 0; j < n_fwd; j++) {
            uint8_t *r = fraw + j * 10;
            uint64_t fp = 0;
            for (int bi = 0; bi < 6; bi++) fp |= (uint64_t)r[bi] << (8 * bi);
            unsigned long long h = (fp >> 7) & (cap - 1);
            while (htab[h] != 0) h = (h + 1) & (cap - 1);
            htab[h] = j + 1;
        }

        snprintf(fn2, sizeof(fn2), "%s/bwd_%05d.bin", DIR, b);
        FILE *bf = fopen(fn2, "rb");
        if (!bf) { free(htab); free(fraw); continue; }
        uint8_t rec[10];
        int local_found = 0;
        while (!found_flag && !local_found && fread(rec, 1, 10, bf) == 10) {
            uint64_t bfp = 0;
            for (int bi = 0; bi < 6; bi++) bfp |= (uint64_t)rec[bi] << (8 * bi);
            uint32_t k1 = 0;
            for (int bi = 0; bi < 4; bi++) k1 |= (uint32_t)rec[6 + bi] << (8 * bi);
            unsigned long long h = (bfp >> 7) & (cap - 1);
            while (htab[h] != 0) {
                if (found_flag) break;
                long idx = htab[h] - 1;
                uint8_t *fr = fraw + idx * 10;
                uint64_t ffp = 0;
                for (int bi = 0; bi < 6; bi++) ffp |= (uint64_t)fr[bi] << (8 * bi);
                if (ffp == bfp) {
                    uint32_t k0 = 0;
                    for (int bi = 0; bi < 4; bi++) k0 |= (uint32_t)fr[6 + bi] << (8 * bi);
                    uint64_t key = ((uint64_t)k0 << 32) | (uint64_t)k1;
                    int ok = 1;
                    for (int p = 0; p < npairs; p++) {
                        if (des_block(M[p], key) != C[p]) { ok = 0; break; }
                    }
                    if (ok) {
                        /* 记录结果 + 设置全局标志 */
                        found_key = key;
                        found_k0 = k0;
                        found_k1 = k1;
                        found_flag = 1;
                        local_found = 1;
                        break;
                    }
                }
                h = (h + 1) & (cap - 1);
            }
        }
        fclose(bf);
        free(htab);
        free(fraw);
    }

    if (found_flag) {
        printf("FOUND key=0x%016llx k0=0x%08x k1=0x%08x\n",
               (unsigned long long)found_key, found_k0, found_k1);
        if (DO_CLEAN) { char c[256]; snprintf(c,sizeof(c),"rm -f %s/fwd_*.bin %s/bwd_*.bin",DIR,DIR); system(c); }
        return 0;
    }
    if (DO_CLEAN) { char c[256]; snprintf(c,sizeof(c),"rm -f %s/fwd_*.bin %s/bwd_*.bin",DIR,DIR); system(c); }
    printf("NOTFOUND\n");
    return 1;
}
