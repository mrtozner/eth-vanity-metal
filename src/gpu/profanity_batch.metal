#include <metal_stdlib>
using namespace metal;

// ==========================================
// PROFANITY2-STYLE BATCH INVERSION FOR ETH
// ==========================================
// Algorithm: Store (deltaX, prevLambda) instead of (X, Y, Z)
// Batch inverse 255 values with 1 inverse + ~765 muls
// Point iteration: only 2 field multiplications!

// ==========================================
// 1. Data Structures (32-bit words like profanity2)
// ==========================================

#define MP_WORDS 8

struct mp_number {
    uint d[MP_WORDS];  // 8 x 32-bit words, Little Endian
};

// ==========================================
// 2. Secp256k1 Constants (32-bit format)
// ==========================================

// mod = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
constant mp_number MOD = {{0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};

// G_x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
constant mp_number G_X = {{0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E}};

// G_y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
constant mp_number G_Y = {{0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77}};

// -G_x mod p = p - G_x
constant mp_number NEG_G_X = {{0xE907E497, 0xA60D7EA3, 0xD231D726, 0xFD640324, 0x3178F4F8, 0xAA5F9D6A, 0x06234453, 0x86419981}};

// -G_y mod p = p - G_y
constant mp_number NEG_G_Y = {{0x04EF2777, 0x63B82F6F, 0x597AABE6, 0x02E84BB7, 0xF1EEF757, 0xA25B0403, 0xD95C3B9A, 0xB7C52588}};

// -2*G_y mod p
constant mp_number NEG_DOUBLE_G_Y = {{0x09DE52BF, 0xC7705EDF, 0xB2F557CC, 0x05D0976E, 0xE3DDEEAE, 0x44B60807, 0xB2B87735, 0x6F8A4B11}};

// -3*G_x mod p (for d' = lambda^2 - 3*G_x - d)
constant mp_number TRIPLE_NEG_G_X = {{0xBB17B196, 0xF2287BEC, 0x76958573, 0xF82C096E, 0x946ADEEA, 0xFF1ED83E, 0x1269CCFA, 0x92C4CC83}};

// ==========================================
// 3. Multi-precision Arithmetic (32-bit)
// ==========================================

// Addition with carry
inline uint mp_add(thread mp_number& r, thread const mp_number& a, thread const mp_number& b) {
    uint c = 0;
    for (int i = 0; i < MP_WORDS; i++) {
        uint sum = a.d[i] + b.d[i] + c;
        c = (sum < a.d[i]) ? 1 : ((sum == a.d[i]) ? c : 0);
        r.d[i] = sum;
    }
    return c;
}

// Add MOD to number
inline uint mp_add_mod(thread mp_number& r) {
    uint c = 0;
    for (int i = 0; i < MP_WORDS; i++) {
        r.d[i] += MOD.d[i] + c;
        c = (r.d[i] < MOD.d[i]) ? 1 : ((r.d[i] == MOD.d[i]) ? c : 0);
    }
    return c;
}

// Subtraction with borrow
inline uint mp_sub(thread mp_number& r, thread const mp_number& a, thread const mp_number& b) {
    uint c = 0;
    for (int i = 0; i < MP_WORDS; i++) {
        uint diff = a.d[i] - b.d[i] - c;
        c = (a.d[i] < b.d[i]) ? 1 : ((a.d[i] == b.d[i]) ? c : 0);
        r.d[i] = diff;
    }
    return c;
}

// Subtract MOD from number
inline uint mp_sub_mod(thread mp_number& r) {
    uint c = 0;
    for (int i = 0; i < MP_WORDS; i++) {
        uint diff = r.d[i] - MOD.d[i] - c;
        c = (r.d[i] < MOD.d[i]) ? 1 : ((r.d[i] == MOD.d[i]) ? c : 0);
        r.d[i] = diff;
    }
    return c;
}

// Modular subtraction: r = (a - b) mod p
inline void mp_mod_sub(thread mp_number& r, thread const mp_number& a, thread const mp_number& b) {
    uint c = 0;
    for (int i = 0; i < MP_WORDS; i++) {
        uint diff = a.d[i] - b.d[i] - c;
        c = (a.d[i] < b.d[i]) ? 1 : ((a.d[i] == b.d[i]) ? c : 0);
        r.d[i] = diff;
    }
    if (c) {
        c = 0;
        for (int i = 0; i < MP_WORDS; i++) {
            r.d[i] += MOD.d[i] + c;
            c = (r.d[i] < MOD.d[i]) ? 1 : ((r.d[i] == MOD.d[i]) ? c : 0);
        }
    }
}

// Modular subtraction from constant: r = (a - b) mod p where a is constant
inline void mp_mod_sub_const(thread mp_number& r, constant const mp_number& a, thread const mp_number& b) {
    uint c = 0;
    for (int i = 0; i < MP_WORDS; i++) {
        uint diff = a.d[i] - b.d[i] - c;
        c = (a.d[i] < b.d[i]) ? 1 : ((a.d[i] == b.d[i]) ? c : 0);
        r.d[i] = diff;
    }
    if (c) {
        c = 0;
        for (int i = 0; i < MP_WORDS; i++) {
            r.d[i] += MOD.d[i] + c;
            c = (r.d[i] < MOD.d[i]) ? 1 : ((r.d[i] == MOD.d[i]) ? c : 0);
        }
    }
}

// Modular subtraction with constant: r = (a - b) mod p where b is constant
inline void mp_mod_sub_const2(thread mp_number& r, thread const mp_number& a, constant const mp_number& b) {
    uint c = 0;
    for (int i = 0; i < MP_WORDS; i++) {
        uint diff = a.d[i] - b.d[i] - c;
        c = (a.d[i] < b.d[i]) ? 1 : ((a.d[i] == b.d[i]) ? c : 0);
        r.d[i] = diff;
    }
    if (c) {
        c = 0;
        for (int i = 0; i < MP_WORDS; i++) {
            r.d[i] += MOD.d[i] + c;
            c = (r.d[i] < MOD.d[i]) ? 1 : ((r.d[i] == MOD.d[i]) ? c : 0);
        }
    }
}

// Greater than or equal comparison
inline bool mp_gte(thread const mp_number& a, thread const mp_number& b) {
    for (int i = MP_WORDS - 1; i >= 0; i--) {
        if (a.d[i] > b.d[i]) return true;
        if (a.d[i] < b.d[i]) return false;
    }
    return true;
}

// Shift right by 1 bit
inline void mp_shr(thread mp_number& r) {
    r.d[0] = (r.d[1] << 31) | (r.d[0] >> 1);
    r.d[1] = (r.d[2] << 31) | (r.d[1] >> 1);
    r.d[2] = (r.d[3] << 31) | (r.d[2] >> 1);
    r.d[3] = (r.d[4] << 31) | (r.d[3] >> 1);
    r.d[4] = (r.d[5] << 31) | (r.d[4] >> 1);
    r.d[5] = (r.d[6] << 31) | (r.d[5] >> 1);
    r.d[6] = (r.d[7] << 31) | (r.d[6] >> 1);
    r.d[7] >>= 1;
}

// Shift right with extra word
inline void mp_shr_extra(thread mp_number& r, thread uint& e) {
    r.d[0] = (r.d[1] << 31) | (r.d[0] >> 1);
    r.d[1] = (r.d[2] << 31) | (r.d[1] >> 1);
    r.d[2] = (r.d[3] << 31) | (r.d[2] >> 1);
    r.d[3] = (r.d[4] << 31) | (r.d[3] >> 1);
    r.d[4] = (r.d[5] << 31) | (r.d[4] >> 1);
    r.d[5] = (r.d[6] << 31) | (r.d[5] >> 1);
    r.d[6] = (r.d[7] << 31) | (r.d[6] >> 1);
    r.d[7] = (e << 31) | (r.d[7] >> 1);
    e >>= 1;
}

// Add with extra word
inline uint mp_add_more(thread mp_number& r, thread uint& extraR, thread const mp_number& a, thread const uint& extraA) {
    uint c = mp_add(r, r, a);
    extraR += extraA + c;
    return (extraR < extraA) ? 1 : ((extraR == extraA) ? c : 0);
}

// ==========================================
// 4. Modular Multiplication (profanity2 style)
// ==========================================

// Multiply word and add to accumulator with extra word
inline uint mp_mul_word_add_extra(thread mp_number& r, thread const mp_number& a, uint w, thread uint& extra) {
    uint cM = 0; // Carry for multiplication
    uint cA = 0; // Carry for addition

    for (int i = 0; i < MP_WORDS; i++) {
        // 32x32 -> 64 bit multiplication
        ulong prod = (ulong)a.d[i] * (ulong)w + (ulong)cM;
        uint tM = (uint)prod;
        cM = (uint)(prod >> 32);

        // Add to accumulator
        uint sum = r.d[i] + tM + cA;
        cA = (sum < r.d[i]) ? 1 : ((sum == r.d[i]) ? cA : 0);
        r.d[i] = sum;
    }

    extra += cM + cA;
    return (extra < cM) ? 1 : ((extra == cM) ? cA : 0);
}

// Multiply MOD by word and subtract from number
inline void mp_mul_mod_word_sub(thread mp_number& r, uint w, bool withModHigher) {
    // modhigher = MOD << 32
    uint cM = 0, cS = 0, cA = 0;

    for (int i = 0; i < MP_WORDS; i++) {
        // MOD * w
        ulong prod = (ulong)MOD.d[i] * (ulong)w + (ulong)cM;
        uint tM = (uint)prod;
        cM = (uint)(prod >> 32);

        // Add modhigher if needed (MOD shifted left by 32 bits)
        uint modh = (i > 0) ? MOD.d[i-1] : 0;
        if (withModHigher) {
            tM += modh + cA;
            cA = (tM < modh) ? 1 : ((tM == modh) ? cA : 0);
        }

        // Subtract from r
        uint diff = r.d[i] - tM - cS;
        cS = (r.d[i] < tM) ? 1 : ((r.d[i] == tM) ? cS : 0);
        r.d[i] = diff;
    }
}

// Modular multiplication: r = (X * Y) mod p
// Based on profanity2's mp_mod_mul
void mp_mod_mul(thread mp_number& r, thread const mp_number& X, thread const mp_number& Y) {
    mp_number Z = {{0, 0, 0, 0, 0, 0, 0, 0}};
    uint extraWord;

    for (int i = MP_WORDS - 1; i >= 0; i--) {
        // Z = Z * 2^32 (shift left by one word)
        extraWord = Z.d[7];
        Z.d[7] = Z.d[6]; Z.d[6] = Z.d[5]; Z.d[5] = Z.d[4]; Z.d[4] = Z.d[3];
        Z.d[3] = Z.d[2]; Z.d[2] = Z.d[1]; Z.d[1] = Z.d[0]; Z.d[0] = 0;

        // Z = Z + X * Y_i
        bool overflow = mp_mul_word_add_extra(Z, X, Y.d[i], extraWord);

        // Z = Z - q*M (reduction)
        mp_mul_mod_word_sub(Z, extraWord, overflow);
    }

    r = Z;
}

// ==========================================
// 5. Modular Inverse (Binary Extended GCD)
// ==========================================

void mp_mod_inverse(thread mp_number& r) {
    mp_number A = {{1, 0, 0, 0, 0, 0, 0, 0}};
    mp_number C = {{0, 0, 0, 0, 0, 0, 0, 0}};
    mp_number v = MOD;

    uint extraA = 0;
    uint extraC = 0;

    // Binary extended GCD
    while (r.d[0] || r.d[1] || r.d[2] || r.d[3] || r.d[4] || r.d[5] || r.d[6] || r.d[7]) {
        while (!(r.d[0] & 1)) {
            mp_shr(r);
            if (A.d[0] & 1) {
                extraA += mp_add_mod(A);
            }
            mp_shr_extra(A, extraA);
        }

        while (!(v.d[0] & 1)) {
            mp_shr(v);
            if (C.d[0] & 1) {
                extraC += mp_add_mod(C);
            }
            mp_shr_extra(C, extraC);
        }

        if (mp_gte(r, v)) {
            mp_sub(r, r, v);
            mp_add_more(A, extraA, C, extraC);
        } else {
            mp_sub(v, v, r);
            mp_add_more(C, extraC, A, extraA);
        }
    }

    while (extraC) {
        extraC -= mp_sub_mod(C);
    }

    v = MOD;
    mp_sub(r, v, C);
}

// ==========================================
// 6. Keccak-256 (from profanity2)
// ==========================================

#define KECCAK_ROUNDS 24

constant ulong KECCAK_RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
    0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
    0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

inline ulong rotl64(ulong x, uint n) {
    return (x << n) | (x >> (64 - n));
}

void keccak_f1600(thread ulong* st) {
    for (int r = 0; r < KECCAK_ROUNDS; r++) {
        // Theta
        ulong bc0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        ulong bc1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        ulong bc2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        ulong bc3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        ulong bc4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

        ulong t0 = bc4 ^ rotl64(bc1, 1);
        ulong t1 = bc0 ^ rotl64(bc2, 1);
        ulong t2 = bc1 ^ rotl64(bc3, 1);
        ulong t3 = bc2 ^ rotl64(bc4, 1);
        ulong t4 = bc3 ^ rotl64(bc0, 1);

        st[0] ^= t0; st[5] ^= t0; st[10] ^= t0; st[15] ^= t0; st[20] ^= t0;
        st[1] ^= t1; st[6] ^= t1; st[11] ^= t1; st[16] ^= t1; st[21] ^= t1;
        st[2] ^= t2; st[7] ^= t2; st[12] ^= t2; st[17] ^= t2; st[22] ^= t2;
        st[3] ^= t3; st[8] ^= t3; st[13] ^= t3; st[18] ^= t3; st[23] ^= t3;
        st[4] ^= t4; st[9] ^= t4; st[14] ^= t4; st[19] ^= t4; st[24] ^= t4;

        // Rho & Pi
        ulong temp = st[1];
        st[1] = rotl64(st[6], 44);
        st[6] = rotl64(st[9], 20);
        st[9] = rotl64(st[22], 61);
        st[22] = rotl64(st[14], 39);
        st[14] = rotl64(st[20], 18);
        st[20] = rotl64(st[2], 62);
        st[2] = rotl64(st[12], 43);
        st[12] = rotl64(st[13], 25);
        st[13] = rotl64(st[19], 8);
        st[19] = rotl64(st[23], 56);
        st[23] = rotl64(st[15], 41);
        st[15] = rotl64(st[4], 27);
        st[4] = rotl64(st[24], 14);
        st[24] = rotl64(st[21], 2);
        st[21] = rotl64(st[8], 55);
        st[8] = rotl64(st[16], 45);
        st[16] = rotl64(st[5], 36);
        st[5] = rotl64(st[3], 28);
        st[3] = rotl64(st[18], 21);
        st[18] = rotl64(st[17], 15);
        st[17] = rotl64(st[11], 10);
        st[11] = rotl64(st[7], 6);
        st[7] = rotl64(st[10], 3);
        st[10] = rotl64(temp, 1);

        // Chi
        for (int j = 0; j < 25; j += 5) {
            ulong v0 = st[j], v1 = st[j+1], v2 = st[j+2], v3 = st[j+3], v4 = st[j+4];
            st[j] ^= (~v1) & v2;
            st[j+1] ^= (~v2) & v3;
            st[j+2] ^= (~v3) & v4;
            st[j+3] ^= (~v4) & v0;
            st[j+4] ^= (~v0) & v1;
        }

        // Iota
        st[0] ^= KECCAK_RC[r];
    }
}

// ==========================================
// 7. Batch Inversion Kernel
// ==========================================
// Computes inverse of PROFANITY_INVERSE_SIZE deltaX values with ONE inverse
// Also multiplies in -2*G_y for use in iteration

#define PROFANITY_INVERSE_SIZE 255

kernel void profanity_inverse(
    device const mp_number* pDeltaX   [[ buffer(0) ]],
    device mp_number* pInverse        [[ buffer(1) ]],
    uint gid [[ thread_position_in_grid ]])
{
    const uint id = gid * PROFANITY_INVERSE_SIZE;

    mp_number buffer[PROFANITY_INVERSE_SIZE];
    mp_number buffer2[PROFANITY_INVERSE_SIZE];

    // Build product chain: buffer[i] = deltaX[0] * deltaX[1] * ... * deltaX[i]
    buffer[0] = pDeltaX[id];
    for (uint i = 1; i < PROFANITY_INVERSE_SIZE; i++) {
        buffer2[i] = pDeltaX[id + i];
        mp_mod_mul(buffer[i], buffer2[i], buffer[i - 1]);
    }

    // Invert the product (ONE expensive inverse)
    mp_number copy1 = buffer[PROFANITY_INVERSE_SIZE - 1];
    mp_mod_inverse(copy1);

    // Multiply in -2*G_y constant
    mp_number negDoubleGy = NEG_DOUBLE_G_Y;
    mp_mod_mul(copy1, copy1, negDoubleGy);

    // Unwind to get individual inverses
    mp_number copy2;
    for (uint i = PROFANITY_INVERSE_SIZE - 1; i > 0; i--) {
        mp_mod_mul(copy2, copy1, buffer[i - 1]);
        mp_mod_mul(copy1, copy1, buffer2[i]);
        pInverse[id + i] = copy2;
    }

    pInverse[id] = copy1;
}

// ==========================================
// 8. Point Iteration Kernel
// ==========================================
// Only 2 field multiplications per point!
// Also computes Keccak hash and stores address

kernel void profanity_iterate(
    device mp_number* pDeltaX           [[ buffer(0) ]],
    device mp_number* pInverse          [[ buffer(1) ]],
    device mp_number* pPrevLambda       [[ buffer(2) ]],
    device uint* pAddressHash           [[ buffer(3) ]],  // Store 5 uints (20 bytes) per address
    uint gid [[ thread_position_in_grid ]])
{
    mp_number dX = pDeltaX[gid];
    mp_number inv = pInverse[gid];
    mp_number lambda = pPrevLambda[gid];  // Read original prevLambda

    // Step 1: Compute new point using CURRENT prevLambda
    // tmp = prevLambda^2 (MUL 1)
    mp_number tmp;
    mp_mod_mul(tmp, lambda, lambda);  // Use original prevLambda!

    // new_dX = -3*G_x - (dX - prevLambda^2) = tripleNegGx - (dX - tmp)
    mp_number new_dX;
    mp_mod_sub(new_dX, dX, tmp);
    mp_mod_sub_const(new_dX, TRIPLE_NEG_G_X, new_dX);

    // SAVE original prevLambda before updating
    mp_number orig_prevLambda = lambda;  // lambda holds the original prevLambda

    // Step 2: Compute new lambda for NEXT iteration
    // new_lambda = inv - prevLambda (inv already contains -2*G_y / deltaX)
    mp_number new_lambda;
    mp_mod_sub(new_lambda, inv, lambda);

    // Step 3: Store updated values for next iteration
    pDeltaX[gid] = new_dX;
    pPrevLambda[gid] = new_lambda;

    // Step 4: Calculate y using ORIGINAL prevLambda (not new_lambda!)
    // R_y = -prevLambda * new_dX - G_y
    mp_number term;
    mp_mod_mul(term, orig_prevLambda, new_dX);  // term = prevLambda * new_dX
    mp_mod_sub_const(tmp, NEG_G_Y, term);       // tmp = -G_y - term = R_y

    // Restore X coordinate from delta: x = new_dX - (-G_x) = new_dX + G_x
    mp_number x;
    mp_mod_sub_const2(x, new_dX, NEG_G_X);  // x = new_dX - negGx = new_dX + Gx

    // Convert to big-endian bytes for Keccak
    ulong state[25] = {0};

    // Pack x into state[0..3] - correct little-endian order for Keccak
    state[0] = (ulong)__builtin_bswap32(x.d[7]) | ((ulong)__builtin_bswap32(x.d[6]) << 32);
    state[1] = (ulong)__builtin_bswap32(x.d[5]) | ((ulong)__builtin_bswap32(x.d[4]) << 32);
    state[2] = (ulong)__builtin_bswap32(x.d[3]) | ((ulong)__builtin_bswap32(x.d[2]) << 32);
    state[3] = (ulong)__builtin_bswap32(x.d[1]) | ((ulong)__builtin_bswap32(x.d[0]) << 32);

    // Pack y (tmp) into state[4..7] - same fix
    state[4] = (ulong)__builtin_bswap32(tmp.d[7]) | ((ulong)__builtin_bswap32(tmp.d[6]) << 32);
    state[5] = (ulong)__builtin_bswap32(tmp.d[5]) | ((ulong)__builtin_bswap32(tmp.d[4]) << 32);
    state[6] = (ulong)__builtin_bswap32(tmp.d[3]) | ((ulong)__builtin_bswap32(tmp.d[2]) << 32);
    state[7] = (ulong)__builtin_bswap32(tmp.d[1]) | ((ulong)__builtin_bswap32(tmp.d[0]) << 32);

    // Keccak padding for 64 bytes
    state[8] = 0x0000000000000001UL;  // Start of padding
    state[16] = 0x8000000000000000UL; // End of padding

    keccak_f1600(state);

    // Extract last 20 bytes of hash (ETH address)
    // Hash bytes 12-31 = address
    // state[1] bits 32-63 = hash bytes 12-15
    // state[2] = hash bytes 16-23
    // state[3] = hash bytes 24-31

    // Store as 5 x uint (20 bytes) - byte-swap to get big-endian address format
    uint base = gid * 5;
    pAddressHash[base + 0] = __builtin_bswap32((uint)(state[1] >> 32));  // bytes 12-15
    pAddressHash[base + 1] = __builtin_bswap32((uint)state[2]);          // bytes 16-19
    pAddressHash[base + 2] = __builtin_bswap32((uint)(state[2] >> 32));  // bytes 20-23
    pAddressHash[base + 3] = __builtin_bswap32((uint)state[3]);          // bytes 24-27
    pAddressHash[base + 4] = __builtin_bswap32((uint)(state[3] >> 32));  // bytes 28-31
}

// ==========================================
// 9. Debug: Keccak Test Kernel
// ==========================================
// Test Keccak with known public key coordinates

kernel void debug_keccak_test(
    device const mp_number* inputX    [[ buffer(0) ]],
    device const mp_number* inputY    [[ buffer(1) ]],
    device uint* outputHash           [[ buffer(2) ]],
    uint gid [[ thread_position_in_grid ]])
{
    if (gid != 0) return;  // Only thread 0 runs

    mp_number x = inputX[0];
    mp_number y = inputY[0];

    ulong state[25] = {0};

    // Pack x into state[0..3]
    state[0] = (ulong)__builtin_bswap32(x.d[7]) | ((ulong)__builtin_bswap32(x.d[6]) << 32);
    state[1] = (ulong)__builtin_bswap32(x.d[5]) | ((ulong)__builtin_bswap32(x.d[4]) << 32);
    state[2] = (ulong)__builtin_bswap32(x.d[3]) | ((ulong)__builtin_bswap32(x.d[2]) << 32);
    state[3] = (ulong)__builtin_bswap32(x.d[1]) | ((ulong)__builtin_bswap32(x.d[0]) << 32);

    // Pack y into state[4..7]
    state[4] = (ulong)__builtin_bswap32(y.d[7]) | ((ulong)__builtin_bswap32(y.d[6]) << 32);
    state[5] = (ulong)__builtin_bswap32(y.d[5]) | ((ulong)__builtin_bswap32(y.d[4]) << 32);
    state[6] = (ulong)__builtin_bswap32(y.d[3]) | ((ulong)__builtin_bswap32(y.d[2]) << 32);
    state[7] = (ulong)__builtin_bswap32(y.d[1]) | ((ulong)__builtin_bswap32(y.d[0]) << 32);

    // Keccak padding
    state[8] = 0x0000000000000001UL;
    state[16] = 0x8000000000000000UL;

    keccak_f1600(state);

    // Extract address (bytes 12-31) - byte-swap for big-endian address format
    outputHash[0] = __builtin_bswap32((uint)(state[1] >> 32));
    outputHash[1] = __builtin_bswap32((uint)state[2]);
    outputHash[2] = __builtin_bswap32((uint)(state[2] >> 32));
    outputHash[3] = __builtin_bswap32((uint)state[3]);
    outputHash[4] = __builtin_bswap32((uint)(state[3] >> 32));
}

// ==========================================
// 10. Pattern Matching Kernel
// ==========================================

// Reusable switch-case checker at any offset (for pattern matching)
inline bool check_at_offset(thread const uchar* hash,
                             constant const uchar* pat,
                             uint len, uint offset) {
    switch (len) {
        case 0: return true;
        case 1: return hash[offset] == pat[0];
        case 2: return hash[offset] == pat[0] && hash[offset+1] == pat[1];
        case 3: return hash[offset] == pat[0] && hash[offset+1] == pat[1] && hash[offset+2] == pat[2];
        case 4: return hash[offset] == pat[0] && hash[offset+1] == pat[1] && hash[offset+2] == pat[2] && hash[offset+3] == pat[3];
        case 5: return hash[offset] == pat[0] && hash[offset+1] == pat[1] && hash[offset+2] == pat[2] && hash[offset+3] == pat[3] && hash[offset+4] == pat[4];
        case 6: return hash[offset] == pat[0] && hash[offset+1] == pat[1] && hash[offset+2] == pat[2] && hash[offset+3] == pat[3] && hash[offset+4] == pat[4] && hash[offset+5] == pat[5];
        case 7: return hash[offset] == pat[0] && hash[offset+1] == pat[1] && hash[offset+2] == pat[2] && hash[offset+3] == pat[3] && hash[offset+4] == pat[4] && hash[offset+5] == pat[5] && hash[offset+6] == pat[6];
        case 8: return hash[offset] == pat[0] && hash[offset+1] == pat[1] && hash[offset+2] == pat[2] && hash[offset+3] == pat[3] && hash[offset+4] == pat[4] && hash[offset+5] == pat[5] && hash[offset+6] == pat[6] && hash[offset+7] == pat[7];
        case 9: return hash[offset] == pat[0] && hash[offset+1] == pat[1] && hash[offset+2] == pat[2] && hash[offset+3] == pat[3] && hash[offset+4] == pat[4] && hash[offset+5] == pat[5] && hash[offset+6] == pat[6] && hash[offset+7] == pat[7] && hash[offset+8] == pat[8];
        case 10: return hash[offset] == pat[0] && hash[offset+1] == pat[1] && hash[offset+2] == pat[2] && hash[offset+3] == pat[3] && hash[offset+4] == pat[4] && hash[offset+5] == pat[5] && hash[offset+6] == pat[6] && hash[offset+7] == pat[7] && hash[offset+8] == pat[8] && hash[offset+9] == pat[9];
        default:
            for (uint i = 0; i < len && i < 20; i++) {
                if (hash[offset + i] != pat[i]) return false;
            }
            return true;
    }
}

kernel void profanity_score_matching(
    device const uint* pAddressHash     [[ buffer(0) ]],
    device atomic_uint* pFoundFlag      [[ buffer(1) ]],
    device uint* pFoundId               [[ buffer(2) ]],
    constant uchar* pattern             [[ buffer(3) ]],  // [prefix|suffix] concatenated
    constant uint& prefix_len           [[ buffer(4) ]],  // was pattern_len
    constant uint& suffix_len           [[ buffer(5) ]],  // was is_suffix
    uint gid [[ thread_position_in_grid ]])
{
    // Early exit if already found
    if (atomic_load_explicit(pFoundFlag, memory_order_relaxed) > 0) return;

    // Get address hash (20 bytes as 5 uints)
    uint base = gid * 5;
    uchar hash[20];

    // Unpack 5 uints to 20 bytes
    uint h0 = pAddressHash[base + 0];
    uint h1 = pAddressHash[base + 1];
    uint h2 = pAddressHash[base + 2];
    uint h3 = pAddressHash[base + 3];
    uint h4 = pAddressHash[base + 4];

    // Unpack from big-endian format (MSB first)
    hash[0] = (h0 >> 24) & 0xFF;
    hash[1] = (h0 >> 16) & 0xFF;
    hash[2] = (h0 >> 8) & 0xFF;
    hash[3] = h0 & 0xFF;
    hash[4] = (h1 >> 24) & 0xFF;
    hash[5] = (h1 >> 16) & 0xFF;
    hash[6] = (h1 >> 8) & 0xFF;
    hash[7] = h1 & 0xFF;
    hash[8] = (h2 >> 24) & 0xFF;
    hash[9] = (h2 >> 16) & 0xFF;
    hash[10] = (h2 >> 8) & 0xFF;
    hash[11] = h2 & 0xFF;
    hash[12] = (h3 >> 24) & 0xFF;
    hash[13] = (h3 >> 16) & 0xFF;
    hash[14] = (h3 >> 8) & 0xFF;
    hash[15] = h3 & 0xFF;
    hash[16] = (h4 >> 24) & 0xFF;
    hash[17] = (h4 >> 16) & 0xFF;
    hash[18] = (h4 >> 8) & 0xFF;
    hash[19] = h4 & 0xFF;

    // Dual pattern matching: check prefix at start, suffix at end
    bool match = true;
    if (prefix_len > 0 && !check_at_offset(hash, pattern, prefix_len, 0))
        match = false;
    if (match && suffix_len > 0 && !check_at_offset(hash, pattern + prefix_len, suffix_len, 20 - suffix_len))
        match = false;
    if (prefix_len == 0 && suffix_len == 0)
        match = false;

    if (match) {
        uint expected = 0;
        if (atomic_compare_exchange_weak_explicit(pFoundFlag, &expected, 1,
                                                   memory_order_relaxed, memory_order_relaxed)) {
            *pFoundId = gid;
        }
    }
}
