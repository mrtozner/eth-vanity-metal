#include <metal_stdlib>
using namespace metal;

// ==========================================
// ETHEREUM VANITY ADDRESS SEARCH (GPU-NATIVE)
// ==========================================
// Simpler than Tron: No SHA-256, No Base58!
// Just Keccak-256 + hex pattern matching

// ==========================================
// 1. Data Structures
// ==========================================

struct uint256_t {
    ulong d[4]; // 4 x 64-bit limbs, Little Endian (d[0] is LSB)
};

struct JacobianPoint {
    uint256_t x;
    uint256_t y;
    uint256_t z;
};

// Affine Point (for precomputation table)
// Stores only (x, y) coordinates - more memory efficient than Jacobian
struct AffinePoint {
    uint256_t x;
    uint256_t y;
};

// ==========================================
// 2. Secp256k1 Constants
// ==========================================

// Secp256k1 Prime P: 2^256 - 2^32 - 977
constant uint256_t SECP256K1_P = {
    {0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
     0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}
};

// Generator Point G (Affine coordinates)
constant uint256_t G_X = {
    {0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
     0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL}
};

constant uint256_t G_Y = {
    {0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
     0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL}
};


// GLV Endomorphism constants for secp256k1
// β (beta): cube root of unity mod p, where β³ ≡ 1 (mod p)
// β = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE
// Used for GLV endomorphism: ψ(x, y) = (β·x, y)
constant uint256_t BETA = {
    {0xC1396C28719501EEULL, 0x9CF0497512F58995ULL,
     0x6E64479EAC3434E9ULL, 0x7AE96A2B657C0710ULL}
};

// beta^2 (beta squared): second cube root of unity mod p
// beta^2 = beta * beta mod p, where beta^3 = 1 (mod p)
constant uint256_t BETA_SQ = {
    {0x3EC693D68E6AFA40ULL, 0x630FB68AED0A766AULL,
     0x919BB86153CBCB16ULL, 0x851695D49A83F8EFULL}
};

// Add two 256-bit numbers with carry
inline uint add_with_carry(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    ulong carry = 0;
    for (int i = 0; i < 4; i++) {
        ulong sum = a.d[i] + b.d[i] + carry;
        r.d[i] = sum;
        // Carry occurs if sum < a.d[i], or if carry was 1 and sum == a.d[i]
        carry = (sum < a.d[i]) || (carry && sum == a.d[i]) ? 1 : 0;
    }
    return (uint)carry;
}

// Add with constant address space (overload for SECP256K1_P)
inline uint add_with_carry_const(thread uint256_t& r, thread const uint256_t& a, constant uint256_t& b) {
    ulong carry = 0;
    for (int i = 0; i < 4; i++) {
        ulong sum = a.d[i] + b.d[i] + carry;
        r.d[i] = sum;
        carry = (sum < a.d[i]) || (carry && sum == a.d[i]) ? 1 : 0;
    }
    return (uint)carry;
}

// Subtract two 256-bit numbers with borrow
inline uint sub_with_borrow(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    ulong borrow = 0;
    for (int i = 0; i < 4; i++) {
        ulong diff = a.d[i] - b.d[i] - borrow;
        // Check for borrow: either a < b, OR a == b and we had incoming borrow
        borrow = (a.d[i] < b.d[i]) || (a.d[i] == b.d[i] && borrow) ? 1 : 0;
        r.d[i] = diff;
    }
    return (uint)borrow;
}

// Subtract with constant address space (overload for SECP256K1_P)
inline uint sub_with_borrow_const(thread uint256_t& r, thread const uint256_t& a, constant uint256_t& b) {
    ulong borrow = 0;
    for (int i = 0; i < 4; i++) {
        ulong diff = a.d[i] - b.d[i] - borrow;
        // Check for borrow: either a < b, OR a == b and we had incoming borrow
        borrow = (a.d[i] < b.d[i]) || (a.d[i] == b.d[i] && borrow) ? 1 : 0;
        r.d[i] = diff;
    }
    return (uint)borrow;
}

// Compare two 256-bit numbers (returns true if a >= b)
inline bool gte(thread const uint256_t& a, thread const uint256_t& b) {
    for (int i = 3; i >= 0; i--) {
        if (a.d[i] > b.d[i]) return true;
        if (a.d[i] < b.d[i]) return false;
    }
    return true; // Equal
}

// Compare with constant address space (overload for SECP256K1_P)
inline bool gte_const(thread const uint256_t& a, constant uint256_t& b) {
    for (int i = 3; i >= 0; i--) {
        if (a.d[i] > b.d[i]) return true;
        if (a.d[i] < b.d[i]) return false;
    }
    return true; // Equal
}

// ==========================================
// 4. Modular Arithmetic
// ==========================================

// Modular addition: r = (a + b) mod P
inline void mod_add(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    uint carry = add_with_carry(r, a, b);
    if (carry || gte_const(r, SECP256K1_P)) {
        // Must use a copy to avoid aliasing issues when r is passed as both input and output
        uint256_t tmp = r;
        sub_with_borrow_const(r, tmp, SECP256K1_P);
    }
}

// Modular subtraction: r = (a - b) mod P
inline void mod_sub(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    uint borrow = sub_with_borrow(r, a, b);
    if (borrow) {
        // Must use a copy to avoid aliasing issues when r is passed as both input and output
        uint256_t tmp = r;
        add_with_carry_const(r, tmp, SECP256K1_P);
    }
}

// Modular multiplication: r = (a * b) mod P
// Full 512-bit product with fast reduction using 2^256 ≡ 2^32 + 977 (mod P)
void mul_mod(thread uint256_t& r, thread const uint256_t& a, thread const uint256_t& b) {
    // Schoolbook multiplication: 4x4 limbs producing 8 limbs (512 bits)
    ulong c[8] = {0};

    for (int i = 0; i < 4; i++) {
        ulong carry = 0;
        for (int j = 0; j < 4; j++) {
            // 64×64 → 128-bit product using metal::mulhi
            ulong lo = a.d[i] * b.d[j];
            ulong hi = metal::mulhi(a.d[i], b.d[j]);

            // Add low part to accumulator with CORRECT carry detection
            // Step 1: c[i+j] + lo
            ulong temp = c[i+j] + lo;
            ulong carry1 = (temp < c[i+j]) ? 1 : 0;

            // Step 2: temp + carry
            ulong sum = temp + carry;
            ulong carry2 = (sum < temp) ? 1 : 0;

            c[i+j] = sum;

            // Propagate carry: hi + both potential overflows
            carry = hi + carry1 + carry2;
        }
        c[i+4] += carry;  // Add, don't replace (might have accumulated value)
    }

    // Split into upper and lower 256 bits
    uint256_t U, L;
    for (int i = 0; i < 4; i++) {
        L.d[i] = c[i];
        U.d[i] = c[i+4];
    }

    // Reduction: 2^256 ≡ 2^32 + 977 (mod P)
    uint256_t U_times_977 = {{0,0,0,0}};
    ulong carry_977 = 0;
    for (int i = 0; i < 4; i++) {
        ulong prod_lo = U.d[i] * 977ULL;
        ulong prod_hi = metal::mulhi(U.d[i], 977ULL);

        ulong temp = U_times_977.d[i] + prod_lo;
        ulong c1 = (temp < U_times_977.d[i]) ? 1 : 0;
        ulong sum = temp + carry_977;
        ulong c2 = (sum < temp) ? 1 : 0;

        U_times_977.d[i] = sum;
        carry_977 = prod_hi + c1 + c2;
    }

    uint carry_main = add_with_carry(r, L, U_times_977);

    ulong u_shift = U.d[0] << 32;
    ulong old_r0 = r.d[0];
    r.d[0] += u_shift;
    ulong shift_carry = (r.d[0] < old_r0) ? 1 : 0;

    for (int i = 1; i < 4; i++) {
        ulong part = (U.d[i-1] >> 32) | (U.d[i] << 32);
        ulong old_ri = r.d[i];
        ulong temp = r.d[i] + part;
        ulong c1 = (temp < old_ri) ? 1 : 0;
        ulong sum = temp + shift_carry;
        ulong c2 = (sum < temp) ? 1 : 0;
        r.d[i] = sum;
        shift_carry = c1 + c2;
    }

    ulong total_overflow = carry_977 + carry_main + shift_carry + (U.d[3] >> 32);

    while (total_overflow > 0) {
        ulong val_977 = total_overflow * 977ULL;
        old_r0 = r.d[0];
        r.d[0] += val_977;
        ulong final_carry = (r.d[0] < old_r0) ? 1 : 0;

        for (int i = 1; i < 4 && final_carry; i++) {
            ulong old = r.d[i];
            r.d[i] += final_carry;
            final_carry = (r.d[i] < old) ? 1 : 0;
        }

        ulong add_to_d0 = total_overflow << 32;
        ulong add_to_d1 = total_overflow >> 32;

        old_r0 = r.d[0];
        r.d[0] += add_to_d0;
        ulong carry2 = (r.d[0] < old_r0) ? 1 : 0;

        ulong old_r1 = r.d[1];
        r.d[1] += add_to_d1;
        ulong c1 = (r.d[1] < old_r1) ? 1 : 0;
        old_r1 = r.d[1];
        r.d[1] += carry2;
        ulong c2 = (r.d[1] < old_r1) ? 1 : 0;
        carry2 = c1 + c2;

        for (int i = 2; i < 4 && carry2; i++) {
            ulong old = r.d[i];
            r.d[i] += carry2;
            carry2 = (r.d[i] < old) ? 1 : 0;
        }

        total_overflow = final_carry + carry2;
    }

    while (gte_const(r, SECP256K1_P)) {
        uint256_t tmp = r;
        sub_with_borrow_const(r, tmp, SECP256K1_P);
    }
}

// Modular multiplication with constant (for G_X, G_Y)
void mul_mod_const(thread uint256_t& r, constant uint256_t& a, thread const uint256_t& b) {
    uint256_t a_copy;
    for (int i = 0; i < 4; i++) a_copy.d[i] = a.d[i];
    mul_mod(r, a_copy, b);
}

// Modular multiplication with second arg constant
void mul_mod_const2(thread uint256_t& r, thread const uint256_t& a, constant uint256_t& b) {
    uint256_t b_copy;
    for (int i = 0; i < 4; i++) b_copy.d[i] = b.d[i];
    mul_mod(r, a, b_copy);
}

// Modular squaring: r = (a * a) mod P
// Delegates to mul_mod - on Apple Silicon GPU, the register-friendly loop
// structure of mul_mod outperforms explicit symmetry optimization.
void sqr_mod(thread uint256_t& r, thread const uint256_t& a) {
    mul_mod(r, a, a);
}


// ==========================================
// 5. Modular Inverse (Fermat's Little Theorem)
// ==========================================

// Optimized modular inverse for secp256k1: r = x^(P-2) mod P
// Uses addition chain exploiting the structure of secp256k1's prime.
// P-2 has 5 blocks of 1-bits: {1, 2, 1, 22, 223}
// Cost: 255 squarings + 15 multiplications (vs generic: 256 sqr + ~234 mul)
// Based on the approach from Bitcoin's libsecp256k1 library.
void inv_mod(thread uint256_t& r, thread const uint256_t& x) {
    uint256_t x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;

    // --- Build precomputed powers of x^(2^n - 1) ---

    // x2 = x^(2^2 - 1) = x^3
    sqr_mod(x2, x);          // x^2
    mul_mod(x2, x2, x);      // x^3

    // x3 = x^(2^3 - 1) = x^7
    sqr_mod(x3, x2);         // x^6
    mul_mod(x3, x3, x);      // x^7

    // x6 = x^(2^6 - 1) = x^63
    sqr_mod(t1, x3);         // x^14
    sqr_mod(t1, t1);         // x^28
    sqr_mod(t1, t1);         // x^56
    mul_mod(x6, t1, x3);     // x^63

    // x9 = x^(2^9 - 1) = x^511
    sqr_mod(t1, x6);         // x^126
    sqr_mod(t1, t1);         // x^252
    sqr_mod(t1, t1);         // x^504
    mul_mod(x9, t1, x3);     // x^511

    // x11 = x^(2^11 - 1) = x^2047
    sqr_mod(t1, x9);         // x^1022
    sqr_mod(t1, t1);         // x^2044
    mul_mod(x11, t1, x2);    // x^2047

    // x22 = x^(2^22 - 1)
    sqr_mod(t1, x11);        // x^(2^12 - 2)
    for (int i = 1; i < 11; i++) sqr_mod(t1, t1);  // x^(2^22 - 2^11)
    mul_mod(x22, t1, x11);   // x^(2^22 - 1)

    // x44 = x^(2^44 - 1)
    sqr_mod(t1, x22);
    for (int i = 1; i < 22; i++) sqr_mod(t1, t1);  // x^(2^44 - 2^22)
    mul_mod(x44, t1, x22);   // x^(2^44 - 1)

    // x88 = x^(2^88 - 1)
    sqr_mod(t1, x44);
    for (int i = 1; i < 44; i++) sqr_mod(t1, t1);  // x^(2^88 - 2^44)
    mul_mod(x88, t1, x44);   // x^(2^88 - 1)

    // x176 = x^(2^176 - 1)
    sqr_mod(t1, x88);
    for (int i = 1; i < 88; i++) sqr_mod(t1, t1);  // x^(2^176 - 2^88)
    mul_mod(x176, t1, x88);  // x^(2^176 - 1)

    // x220 = x^(2^220 - 1)
    sqr_mod(t1, x176);
    for (int i = 1; i < 44; i++) sqr_mod(t1, t1);  // x^(2^220 - 2^44)
    mul_mod(x220, t1, x44);  // x^(2^220 - 1)

    // x223 = x^(2^223 - 1)
    sqr_mod(t1, x220);
    sqr_mod(t1, t1);
    sqr_mod(t1, t1);         // x^(2^223 - 2^3)
    mul_mod(x223, t1, x3);   // x^(2^223 - 1)

    // --- Final assembly: x^(P-2) ---
    // P-2 = (2^223-1)*2^33 + (2^22-1)*2^10 + 2^5 + (2^2-1)*2^2 + 1

    // Start with x^(2^223-1), square 23 times, multiply by x22
    sqr_mod(t1, x223);
    for (int i = 1; i < 23; i++) sqr_mod(t1, t1);  // x^((2^223-1)*2^23)
    mul_mod(t1, t1, x22);    // x^((2^223-1)*2^23 + 2^22-1)

    // Square 5 times, multiply by x
    for (int i = 0; i < 5; i++) sqr_mod(t1, t1);
    mul_mod(t1, t1, x);

    // Square 3 times, multiply by x2 (=x^3)
    for (int i = 0; i < 3; i++) sqr_mod(t1, t1);
    mul_mod(t1, t1, x2);

    // Square 2 times, multiply by x
    sqr_mod(t1, t1);
    sqr_mod(t1, t1);
    mul_mod(r, t1, x);
}

// ==========================================
// Montgomery's Trick (Batch Inversion) - Window 8
// ==========================================
// Inverts 8 numbers simultaneously.
// Cost: 1 inv_mod + 21 mul_mod (vs 8 inv_mod = ~4x speedup)

inline void batch_inverse_8(thread uint256_t* values) {
    uint256_t c[8]; // Prefix products

    // 1. Calculate Prefix Products (7 muls)
    c[0] = values[0];
    mul_mod(c[1], c[0], values[1]);
    mul_mod(c[2], c[1], values[2]);
    mul_mod(c[3], c[2], values[3]);
    mul_mod(c[4], c[3], values[4]);
    mul_mod(c[5], c[4], values[5]);
    mul_mod(c[6], c[5], values[6]);
    mul_mod(c[7], c[6], values[7]);

    // 2. Invert the Final Product (The ONLY expensive step)
    uint256_t inv_all;
    inv_mod(inv_all, c[7]);

    // 3. Unwind backwards to find individual inverses (14 muls)
    uint256_t accum_inv = inv_all;
    uint256_t temp_v, next_accum;

    // Process indices 7 down to 1
    mul_mod(temp_v, accum_inv, c[6]);
    mul_mod(next_accum, accum_inv, values[7]);
    values[7] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[5]);
    mul_mod(next_accum, accum_inv, values[6]);
    values[6] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[4]);
    mul_mod(next_accum, accum_inv, values[5]);
    values[5] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[3]);
    mul_mod(next_accum, accum_inv, values[4]);
    values[4] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[2]);
    mul_mod(next_accum, accum_inv, values[3]);
    values[3] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[1]);
    mul_mod(next_accum, accum_inv, values[2]);
    values[2] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[0]);
    mul_mod(next_accum, accum_inv, values[1]);
    values[1] = temp_v;
    accum_inv = next_accum;

    // Index 0: accum_inv is now values[0]^-1
    values[0] = accum_inv;
}

// ==========================================
// Montgomery's Trick (Batch Inversion) - Window 16
// ==========================================
// Inverts 16 numbers simultaneously.
// Cost: 1 inv_mod + 45 mul_mod (vs 16 inv_mod = ~2x speedup over window=8)

inline void batch_inverse_16(thread uint256_t* values) {
    uint256_t c[16]; // Prefix products

    // 1. Calculate Prefix Products (15 muls)
    c[0] = values[0];
    mul_mod(c[1], c[0], values[1]);
    mul_mod(c[2], c[1], values[2]);
    mul_mod(c[3], c[2], values[3]);
    mul_mod(c[4], c[3], values[4]);
    mul_mod(c[5], c[4], values[5]);
    mul_mod(c[6], c[5], values[6]);
    mul_mod(c[7], c[6], values[7]);
    mul_mod(c[8], c[7], values[8]);
    mul_mod(c[9], c[8], values[9]);
    mul_mod(c[10], c[9], values[10]);
    mul_mod(c[11], c[10], values[11]);
    mul_mod(c[12], c[11], values[12]);
    mul_mod(c[13], c[12], values[13]);
    mul_mod(c[14], c[13], values[14]);
    mul_mod(c[15], c[14], values[15]);

    // 2. Invert the Final Product (The ONLY expensive step)
    uint256_t inv_all;
    inv_mod(inv_all, c[15]);

    // 3. Unwind backwards to find individual inverses (30 muls)
    uint256_t accum_inv = inv_all;
    uint256_t temp_v, next_accum;

    // Process indices 15 down to 1
    mul_mod(temp_v, accum_inv, c[14]);
    mul_mod(next_accum, accum_inv, values[15]);
    values[15] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[13]);
    mul_mod(next_accum, accum_inv, values[14]);
    values[14] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[12]);
    mul_mod(next_accum, accum_inv, values[13]);
    values[13] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[11]);
    mul_mod(next_accum, accum_inv, values[12]);
    values[12] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[10]);
    mul_mod(next_accum, accum_inv, values[11]);
    values[11] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[9]);
    mul_mod(next_accum, accum_inv, values[10]);
    values[10] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[8]);
    mul_mod(next_accum, accum_inv, values[9]);
    values[9] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[7]);
    mul_mod(next_accum, accum_inv, values[8]);
    values[8] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[6]);
    mul_mod(next_accum, accum_inv, values[7]);
    values[7] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[5]);
    mul_mod(next_accum, accum_inv, values[6]);
    values[6] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[4]);
    mul_mod(next_accum, accum_inv, values[5]);
    values[5] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[3]);
    mul_mod(next_accum, accum_inv, values[4]);
    values[4] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[2]);
    mul_mod(next_accum, accum_inv, values[3]);
    values[3] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[1]);
    mul_mod(next_accum, accum_inv, values[2]);
    values[2] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[0]);
    mul_mod(next_accum, accum_inv, values[1]);
    values[1] = temp_v;
    accum_inv = next_accum;

    // Index 0: accum_inv is now values[0]^-1
    values[0] = accum_inv;
}

// ==========================================
// Montgomery's Trick (Batch Inversion) - Window 32
// ==========================================
// Inverts 32 numbers simultaneously.
// Cost: 1 inv_mod + 93 mul_mod (vs 32 inv_mod = ~4x speedup over window=8)

inline void batch_inverse_32(thread uint256_t* values) {
    uint256_t c[32]; // Prefix products

    // 1. Calculate Prefix Products (31 muls)
    c[0] = values[0];
    mul_mod(c[1], c[0], values[1]);
    mul_mod(c[2], c[1], values[2]);
    mul_mod(c[3], c[2], values[3]);
    mul_mod(c[4], c[3], values[4]);
    mul_mod(c[5], c[4], values[5]);
    mul_mod(c[6], c[5], values[6]);
    mul_mod(c[7], c[6], values[7]);
    mul_mod(c[8], c[7], values[8]);
    mul_mod(c[9], c[8], values[9]);
    mul_mod(c[10], c[9], values[10]);
    mul_mod(c[11], c[10], values[11]);
    mul_mod(c[12], c[11], values[12]);
    mul_mod(c[13], c[12], values[13]);
    mul_mod(c[14], c[13], values[14]);
    mul_mod(c[15], c[14], values[15]);
    mul_mod(c[16], c[15], values[16]);
    mul_mod(c[17], c[16], values[17]);
    mul_mod(c[18], c[17], values[18]);
    mul_mod(c[19], c[18], values[19]);
    mul_mod(c[20], c[19], values[20]);
    mul_mod(c[21], c[20], values[21]);
    mul_mod(c[22], c[21], values[22]);
    mul_mod(c[23], c[22], values[23]);
    mul_mod(c[24], c[23], values[24]);
    mul_mod(c[25], c[24], values[25]);
    mul_mod(c[26], c[25], values[26]);
    mul_mod(c[27], c[26], values[27]);
    mul_mod(c[28], c[27], values[28]);
    mul_mod(c[29], c[28], values[29]);
    mul_mod(c[30], c[29], values[30]);
    mul_mod(c[31], c[30], values[31]);

    // 2. Invert the Final Product (The ONLY expensive step)
    uint256_t inv_all;
    inv_mod(inv_all, c[31]);

    // 3. Unwind backwards to find individual inverses (62 muls)
    uint256_t accum_inv = inv_all;
    uint256_t temp_v, next_accum;

    // Process indices 31 down to 1
    mul_mod(temp_v, accum_inv, c[30]);
    mul_mod(next_accum, accum_inv, values[31]);
    values[31] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[29]);
    mul_mod(next_accum, accum_inv, values[30]);
    values[30] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[28]);
    mul_mod(next_accum, accum_inv, values[29]);
    values[29] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[27]);
    mul_mod(next_accum, accum_inv, values[28]);
    values[28] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[26]);
    mul_mod(next_accum, accum_inv, values[27]);
    values[27] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[25]);
    mul_mod(next_accum, accum_inv, values[26]);
    values[26] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[24]);
    mul_mod(next_accum, accum_inv, values[25]);
    values[25] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[23]);
    mul_mod(next_accum, accum_inv, values[24]);
    values[24] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[22]);
    mul_mod(next_accum, accum_inv, values[23]);
    values[23] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[21]);
    mul_mod(next_accum, accum_inv, values[22]);
    values[22] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[20]);
    mul_mod(next_accum, accum_inv, values[21]);
    values[21] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[19]);
    mul_mod(next_accum, accum_inv, values[20]);
    values[20] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[18]);
    mul_mod(next_accum, accum_inv, values[19]);
    values[19] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[17]);
    mul_mod(next_accum, accum_inv, values[18]);
    values[18] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[16]);
    mul_mod(next_accum, accum_inv, values[17]);
    values[17] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[15]);
    mul_mod(next_accum, accum_inv, values[16]);
    values[16] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[14]);
    mul_mod(next_accum, accum_inv, values[15]);
    values[15] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[13]);
    mul_mod(next_accum, accum_inv, values[14]);
    values[14] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[12]);
    mul_mod(next_accum, accum_inv, values[13]);
    values[13] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[11]);
    mul_mod(next_accum, accum_inv, values[12]);
    values[12] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[10]);
    mul_mod(next_accum, accum_inv, values[11]);
    values[11] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[9]);
    mul_mod(next_accum, accum_inv, values[10]);
    values[10] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[8]);
    mul_mod(next_accum, accum_inv, values[9]);
    values[9] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[7]);
    mul_mod(next_accum, accum_inv, values[8]);
    values[8] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[6]);
    mul_mod(next_accum, accum_inv, values[7]);
    values[7] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[5]);
    mul_mod(next_accum, accum_inv, values[6]);
    values[6] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[4]);
    mul_mod(next_accum, accum_inv, values[5]);
    values[5] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[3]);
    mul_mod(next_accum, accum_inv, values[4]);
    values[4] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[2]);
    mul_mod(next_accum, accum_inv, values[3]);
    values[3] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[1]);
    mul_mod(next_accum, accum_inv, values[2]);
    values[2] = temp_v;
    accum_inv = next_accum;

    mul_mod(temp_v, accum_inv, c[0]);
    mul_mod(next_accum, accum_inv, values[1]);
    values[1] = temp_v;
    accum_inv = next_accum;

    // Index 0: accum_inv is now values[0]^-1
    values[0] = accum_inv;
}

// ==========================================
// Montgomery's Trick (Batch Inversion) - Window 64
// ==========================================
// Inverts 64 numbers simultaneously.
// Cost: 1 inv_mod + 189 mul_mod (vs 2x batch_inverse_32 = ~2x speedup)

inline void batch_inverse_64(thread uint256_t* values) {
    uint256_t c[64]; // Prefix products

    // 1. Calculate Prefix Products (63 multiplications)
    c[0] = values[0];
    for (int i = 1; i < 64; i++) {
        mul_mod(c[i], c[i-1], values[i]);
    }

    // 2. Invert the Final Product (The ONLY expensive step)
    uint256_t inv_all;
    inv_mod(inv_all, c[63]);

    // 3. Unwind backwards to find individual inverses (126 multiplications)
    uint256_t accum_inv = inv_all;
    uint256_t temp_v, next_accum;

    // Process indices 63 down to 1
    for (int i = 63; i >= 1; i--) {
        mul_mod(temp_v, accum_inv, c[i-1]);
        mul_mod(next_accum, accum_inv, values[i]);
        values[i] = temp_v;
        accum_inv = next_accum;
    }

    // Index 0: accum_inv is now values[0]^-1
    values[0] = accum_inv;
}

// ==========================================
// Montgomery's Trick (Batch Inversion) - Window 128
// ==========================================
// Inverts 128 numbers simultaneously.
// Cost: 1 inv_mod + 381 mul_mod (vs 4x batch_inverse_32 = ~4x speedup)

inline void batch_inverse_128(thread uint256_t* values) {
    uint256_t c[128]; // Prefix products

    // 1. Calculate Prefix Products (127 multiplications)
    c[0] = values[0];
    for (int i = 1; i < 128; i++) {
        mul_mod(c[i], c[i-1], values[i]);
    }

    // 2. Invert the Final Product (The ONLY expensive step)
    uint256_t inv_all;
    inv_mod(inv_all, c[127]);

    // 3. Unwind backwards to find individual inverses (254 multiplications)
    uint256_t accum_inv = inv_all;
    uint256_t temp_v, next_accum;

    // Process indices 127 down to 1
    for (int i = 127; i >= 1; i--) {
        mul_mod(temp_v, accum_inv, c[i-1]);
        mul_mod(next_accum, accum_inv, values[i]);
        values[i] = temp_v;
        accum_inv = next_accum;
    }

    // Index 0: accum_inv is now values[0]^-1
    values[0] = accum_inv;
}

// ==========================================
// Montgomery's Trick (Batch Inversion) - Window 256
// ==========================================
// Inverts 256 numbers simultaneously.
// Cost: 1 inv_mod + 765 mul_mod (vs 8x batch_inverse_32 = ~8x speedup)

inline void batch_inverse_256(thread uint256_t* values) {
    uint256_t c[256]; // Prefix products

    // 1. Calculate Prefix Products (255 multiplications)
    c[0] = values[0];
    for (int i = 1; i < 256; i++) {
        mul_mod(c[i], c[i-1], values[i]);
    }

    // 2. Invert the Final Product (The ONLY expensive step)
    uint256_t inv_all;
    inv_mod(inv_all, c[255]);

    // 3. Unwind backwards to find individual inverses (510 multiplications)
    uint256_t accum_inv = inv_all;
    uint256_t temp_v, next_accum;

    // Process indices 255 down to 1
    for (int i = 255; i >= 1; i--) {
        mul_mod(temp_v, accum_inv, c[i-1]);
        mul_mod(next_accum, accum_inv, values[i]);
        values[i] = temp_v;
        accum_inv = next_accum;
    }

    // Index 0: accum_inv is now values[0]^-1
    values[0] = accum_inv;
}

// ==========================================
// Montgomery's Trick (Batch Inversion) - Window 512
// ==========================================
// Inverts 512 numbers simultaneously.
// Cost: 1 inv_mod + 1533 mul_mod (vs 16x batch_inverse_32 = ~16x speedup)

inline void batch_inverse_512(thread uint256_t* values) {
    uint256_t c[512]; // Prefix products

    // 1. Calculate Prefix Products (511 multiplications)
    c[0] = values[0];
    for (int i = 1; i < 512; i++) {
        mul_mod(c[i], c[i-1], values[i]);
    }

    // 2. Invert the Final Product (The ONLY expensive step)
    uint256_t inv_all;
    inv_mod(inv_all, c[511]);

    // 3. Unwind backwards to find individual inverses (1022 multiplications)
    uint256_t accum_inv = inv_all;
    uint256_t temp_v, next_accum;

    // Process indices 511 down to 1
    for (int i = 511; i >= 1; i--) {
        mul_mod(temp_v, accum_inv, c[i-1]);
        mul_mod(next_accum, accum_inv, values[i]);
        values[i] = temp_v;
        accum_inv = next_accum;
    }

    // Index 0: accum_inv is now values[0]^-1
    values[0] = accum_inv;
}

// ==========================================
// GLV Endomorphism Helper
// ==========================================
// Apply GLV endomorphism to get a second point for free
// ψ(x, y) = (β·x, y) where β is cube root of unity mod p

inline void apply_glv_endomorphism(thread const uint256_t& x_in,
                                   thread const uint256_t& y_in,
                                   thread uint256_t& x_out,
                                   thread uint256_t& y_out) {
    // x_out = β * x_in (mod p)
    mul_mod_const2(x_out, x_in, BETA);
    // y_out = y_in (unchanged)
    y_out = y_in;
}

// ==========================================
// 6. Point Addition (Jacobian Coordinates)
// ==========================================

// Mixed point addition: P (Jacobian) + G (Affine)
void point_add_mixed(thread JacobianPoint& P) {
    // Check if P is point at infinity (z = 0)
    bool p_is_inf = true;
    for(int i=0; i<4; i++) {
        if(P.z.d[i] != 0) {
            p_is_inf = false;
            break;
        }
    }

    if (p_is_inf) {
        // P is infinity, result is G
        P.x = G_X;
        P.y = G_Y;
        for(int i=1; i<4; i++) P.z.d[i] = 0;
        P.z.d[0] = 1;
        return;
    }

    // Mixed addition formula
    uint256_t z1z1, u2, s2, h, hh, r, v, h_cubed, r_sq, two_v, v_minus_x3, term1, term2;

    // z1z1 = Z1^2
    sqr_mod(z1z1, P.z);

    // u2 = x2 * Z1^2
    mul_mod_const(u2, G_X, z1z1);

    // s2 = y2 * Z1^3 = y2 * Z1 * Z1^2
    mul_mod(s2, P.z, z1z1);
    mul_mod_const2(s2, s2, G_Y);

    // h = u2 - X1
    mod_sub(h, u2, P.x);

    // hh = h^2
    sqr_mod(hh, h);

    // r = s2 - Y1
    mod_sub(r, s2, P.y);

    // h_cubed = h^3 = h * h^2
    mul_mod(h_cubed, h, hh);

    // v = X1 * h^2
    mul_mod(v, P.x, hh);

    // r_sq = r^2
    sqr_mod(r_sq, r);

    // X3 = r^2 - h^3 - 2*v
    mod_sub(P.x, r_sq, h_cubed);
    mod_add(two_v, v, v);
    mod_sub(P.x, P.x, two_v);

    // Y3 = r * (v - X3) - Y1 * h^3
    mod_sub(v_minus_x3, v, P.x);
    mul_mod(term1, r, v_minus_x3);
    mul_mod(term2, P.y, h_cubed);
    mod_sub(P.y, term1, term2);

    // Z3 = Z1 * h
    mul_mod(P.z, P.z, h);
}

// ==========================================
// 7. Coordinate Conversion
// ==========================================

// Convert Jacobian point to Affine coordinates (standalone version)
void jacobian_to_affine(thread JacobianPoint& P, thread uint256_t& x, thread uint256_t& y) {
    uint256_t z_inv, z_inv2, z_inv3;

    // z_inv = Z^(-1)
    inv_mod(z_inv, P.z);

    // z_inv2 = Z^(-2)
    sqr_mod(z_inv2, z_inv);

    // z_inv3 = Z^(-3) = Z^(-2) * Z^(-1)
    mul_mod(z_inv3, z_inv2, z_inv);

    // x = X / Z^2
    mul_mod(x, P.x, z_inv2);

    // y = Y / Z^3
    mul_mod(y, P.y, z_inv3);
}

// Convert Jacobian to affine in-place (for affine batch addition optimization)
inline void jacobian_to_affine_inplace(thread uint256_t& ax, thread uint256_t& ay,
                                        thread const JacobianPoint& P) {
    uint256_t z_inv, z_inv2, z_inv3;
    inv_mod(z_inv, P.z);
    sqr_mod(z_inv2, z_inv);
    mul_mod(z_inv3, z_inv2, z_inv);
    mul_mod(ax, P.x, z_inv2);
    mul_mod(ay, P.y, z_inv3);
}

// ==========================================
// 7b. Precomputation Table Functions
// ==========================================

// Convert Affine point to Jacobian (Z = 1)
inline JacobianPoint affine_to_jacobian(thread const AffinePoint& p) {
    JacobianPoint result;
    result.x = p.x;
    result.y = p.y;

    // Z = 1
    for (int i = 0; i < 4; i++) result.z.d[i] = 0;
    result.z.d[0] = 1;

    return result;
}

// Point addition: Jacobian + Affine -> Jacobian (mixed addition)
// This is more efficient than Jacobian + Jacobian when one point is affine
inline void point_add_affine(thread JacobianPoint* P, constant AffinePoint* Q) {
    // Mixed addition formula for P (Jacobian) + Q (Affine)
    // Similar to point_add_mixed but works with generic affine points

    uint256_t z1z1, u2, s2, h, hh, r, v, h_cubed, r_sq, two_v, v_minus_x3, term1, term2;

    // z1z1 = Z1^2
    sqr_mod(z1z1, P->z);

    // u2 = x2 * Z1^2
    uint256_t q_x;
    for (int i = 0; i < 4; i++) q_x.d[i] = Q->x.d[i];
    mul_mod(u2, q_x, z1z1);

    // s2 = y2 * Z1^3 = y2 * Z1 * Z1^2
    uint256_t q_y;
    for (int i = 0; i < 4; i++) q_y.d[i] = Q->y.d[i];
    mul_mod(s2, P->z, z1z1);
    mul_mod(s2, s2, q_y);

    // h = u2 - X1
    mod_sub(h, u2, P->x);

    // hh = h^2
    sqr_mod(hh, h);

    // r = s2 - Y1
    mod_sub(r, s2, P->y);

    // h_cubed = h^3 = h * h^2
    mul_mod(h_cubed, h, hh);

    // v = X1 * h^2
    mul_mod(v, P->x, hh);

    // r_sq = r^2
    sqr_mod(r_sq, r);

    // X3 = r^2 - h^3 - 2*v
    mod_sub(P->x, r_sq, h_cubed);
    mod_add(two_v, v, v);
    mod_sub(P->x, P->x, two_v);

    // Y3 = r * (v - X3) - Y1 * h^3
    mod_sub(v_minus_x3, v, P->x);
    mul_mod(term1, r, v_minus_x3);
    mul_mod(term2, P->y, h_cubed);
    mod_sub(P->y, term1, term2);

    // Z3 = Z1 * h
    mul_mod(P->z, P->z, h);
}

// Fast scalar multiplication using precomputation table
// Decomposes scalar into bytes and uses table lookups + point additions
// Expected speedup: 5-10x over traditional scalar multiplication
inline void point_from_scalar_precomp(
    constant AffinePoint* precomp,      // Precomputation table (8160 points)
    thread const uchar* scalar_bytes,   // 32-byte scalar (big-endian)
    thread JacobianPoint* result        // Output point
) {
    bool is_first = true;

    // For each byte position (0 to 31)
    for (int i = 0; i < 32; i++) {
        uint8_t byte_val = scalar_bytes[i];

        if (byte_val != 0) {
            // Lookup precomputed point: precomp[i * 255 + (byte_val - 1)]
            // Note: We skip byte_val=0 since 0*P = infinity (not stored in table)
            constant AffinePoint* p = &precomp[i * 255 + (byte_val - 1)];

            if (is_first) {
                // First non-zero byte: convert affine to jacobian
                // Copy from constant to thread-local memory to fix address space mismatch
                AffinePoint local_p;
                for (int i = 0; i < 4; i++) {
                    local_p.x.d[i] = p->x.d[i];
                    local_p.y.d[i] = p->y.d[i];
                }
                *result = affine_to_jacobian(local_p);
                is_first = false;
            } else {
                // Subsequent bytes: add to accumulator
                point_add_affine(result, p);
            }
        }
    }

    // Note: If all bytes are zero (scalar = 0), result is undefined
    // Caller should ensure scalar != 0
}

// GLV-optimized scalar multiplication using two precomputation tables
// Uses GLV endomorphism to split 256-bit scalar into two 128-bit scalars
// Expected speedup: ~30-50% over standard precomputation
inline void point_from_scalar_glv(
    constant AffinePoint* precomp_g,        // G precomputation table (4080 points, 16 positions)
    constant AffinePoint* precomp_psi_g,    // ψ(G) precomputation table (4080 points, 16 positions)
    thread const uchar* scalar_bytes,       // 32-byte scalar (big-endian)
    thread JacobianPoint* result            // Output point
) {
    // GLV decomposition: split scalar into k1 (low 128 bits) and k2 (high 128 bits)
    // This is a simplified decomposition; full GLV would use lattice reduction
    // k·G ≈ k1·G + k2·ψ(G)

    // k1 = scalar[16..31] (low 128 bits)
    // k2 = scalar[0..15] (high 128 bits)

    bool is_first = true;

    // Process k1·G (low 128 bits, positions 0-15)
    for (int i = 0; i < 16; i++) {
        uint8_t byte_val = scalar_bytes[16 + i];  // Low 128 bits

        if (byte_val != 0) {
            constant AffinePoint* p = &precomp_g[i * 255 + (byte_val - 1)];

            if (is_first) {
                AffinePoint local_p;
                for (int j = 0; j < 4; j++) {
                    local_p.x.d[j] = p->x.d[j];
                    local_p.y.d[j] = p->y.d[j];
                }
                *result = affine_to_jacobian(local_p);
                is_first = false;
            } else {
                point_add_affine(result, p);
            }
        }
    }

    // Process k2·ψ(G) (high 128 bits, positions 0-15 of ψ(G) table)
    for (int i = 0; i < 16; i++) {
        uint8_t byte_val = scalar_bytes[i];  // High 128 bits

        if (byte_val != 0) {
            constant AffinePoint* p = &precomp_psi_g[i * 255 + (byte_val - 1)];

            if (is_first) {
                AffinePoint local_p;
                for (int j = 0; j < 4; j++) {
                    local_p.x.d[j] = p->x.d[j];
                    local_p.y.d[j] = p->y.d[j];
                }
                *result = affine_to_jacobian(local_p);
                is_first = false;
            } else {
                point_add_affine(result, p);
            }
        }
    }

    // Note: If all bytes are zero (scalar = 0), result is undefined
    // Caller should ensure scalar != 0
}

// ==========================================
// 8. Optimized Keccak-256 Implementation (Unrolled)
// ==========================================

inline ulong rotl64(ulong x, uint n) {
    return (x << n) | (x >> (64 - n));
}

// Byte-swap a 64-bit value (reverse byte order)
// Used to convert between big-endian and little-endian representations
inline ulong bswap64(ulong x) {
    x = ((x >> 8) & 0x00FF00FF00FF00FFULL) | ((x & 0x00FF00FF00FF00FFULL) << 8);
    x = ((x >> 16) & 0x0000FFFF0000FFFFULL) | ((x & 0x0000FFFF0000FFFFULL) << 16);
    return (x >> 32) | (x << 32);
}

constant ulong RC[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
    0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
    0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

void keccak_f1600_fast(thread ulong* st) {
    #pragma unroll
    for (int r = 0; r < 24; r++) {
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

        // Rho & Pi (hardcoded rotations)
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
        ulong v0, v1, v2, v3, v4;

        v0 = st[0]; v1 = st[1]; v2 = st[2]; v3 = st[3]; v4 = st[4];
        st[0] ^= (~v1) & v2; st[1] ^= (~v2) & v3; st[2] ^= (~v3) & v4; st[3] ^= (~v4) & v0; st[4] ^= (~v0) & v1;

        v0 = st[5]; v1 = st[6]; v2 = st[7]; v3 = st[8]; v4 = st[9];
        st[5] ^= (~v1) & v2; st[6] ^= (~v2) & v3; st[7] ^= (~v3) & v4; st[8] ^= (~v4) & v0; st[9] ^= (~v0) & v1;

        v0 = st[10]; v1 = st[11]; v2 = st[12]; v3 = st[13]; v4 = st[14];
        st[10] ^= (~v1) & v2; st[11] ^= (~v2) & v3; st[12] ^= (~v3) & v4; st[13] ^= (~v4) & v0; st[14] ^= (~v0) & v1;

        v0 = st[15]; v1 = st[16]; v2 = st[17]; v3 = st[18]; v4 = st[19];
        st[15] ^= (~v1) & v2; st[16] ^= (~v2) & v3; st[17] ^= (~v3) & v4; st[18] ^= (~v4) & v0; st[19] ^= (~v0) & v1;

        v0 = st[20]; v1 = st[21]; v2 = st[22]; v3 = st[23]; v4 = st[24];
        st[20] ^= (~v1) & v2; st[21] ^= (~v2) & v3; st[22] ^= (~v3) & v4; st[23] ^= (~v4) & v0; st[24] ^= (~v0) & v1;

        // Iota
        st[0] ^= RC[r];
    }
}

// Optimized for 64-byte input (public key X || Y)
inline void keccak_256_64_fast(thread const uchar* input, thread uchar* output) {
    ulong state[25] = {0};

    // Absorb 64 bytes as 8 ulongs (little-endian)
    thread const ulong* in_u64 = (thread const ulong*)input;
    state[0] ^= in_u64[0];
    state[1] ^= in_u64[1];
    state[2] ^= in_u64[2];
    state[3] ^= in_u64[3];
    state[4] ^= in_u64[4];
    state[5] ^= in_u64[5];
    state[6] ^= in_u64[6];
    state[7] ^= in_u64[7];

    // Padding: 0x01 at byte 64, 0x80 at byte 135
    state[8] ^= 0x0000000000000001UL;
    state[16] ^= 0x8000000000000000UL;

    // Permute
    keccak_f1600_fast(state);

    // Squeeze 32 bytes
    thread ulong* out_u64 = (thread ulong*)output;
    out_u64[0] = state[0];
    out_u64[1] = state[1];
    out_u64[2] = state[2];
    out_u64[3] = state[3];
}

// Optimized Keccak-256: absorb directly from uint256_t limbs
// Eliminates the intermediate byte serialization step entirely.
// uint256_t stores limbs in little-endian order (d[0]=LSB, d[3]=MSB).
// Ethereum hashes the public key in big-endian byte order.
// When big-endian bytes are cast to little-endian ulongs (as keccak does),
// the result is byte-swapped limbs in reverse order.
inline void keccak_256_from_uint256(thread const uint256_t& x, thread const uint256_t& y, thread uchar* output) {
    ulong state[25] = {0};

    // Absorb X coordinate (32 bytes big-endian → 4 ulongs)
    // Big-endian byte order: d[3](MSB) || d[2] || d[1] || d[0](LSB)
    // As little-endian ulongs: bswap(d[3]), bswap(d[2]), bswap(d[1]), bswap(d[0])
    state[0] = bswap64(x.d[3]);
    state[1] = bswap64(x.d[2]);
    state[2] = bswap64(x.d[1]);
    state[3] = bswap64(x.d[0]);

    // Absorb Y coordinate (32 bytes big-endian → 4 ulongs)
    state[4] = bswap64(y.d[3]);
    state[5] = bswap64(y.d[2]);
    state[6] = bswap64(y.d[1]);
    state[7] = bswap64(y.d[0]);

    // Keccak padding for 64-byte input with rate=136
    state[8] ^= 0x0000000000000001UL;
    state[16] ^= 0x8000000000000000UL;

    // Permute
    keccak_f1600_fast(state);

    // Squeeze 32 bytes
    thread ulong* out_u64 = (thread ulong*)output;
    out_u64[0] = state[0];
    out_u64[1] = state[1];
    out_u64[2] = state[2];
    out_u64[3] = state[3];
}

// ==========================================
// 9. Helper Functions
// ==========================================

// Convert uint256_t to bytes (Big Endian)
inline void uint256_to_bytes(thread const uint256_t& num, thread uchar* bytes) {
    for (int i = 0; i < 4; i++) {
        int byte_offset = (3 - i) * 8;  // 4 limbs × 8 bytes each
        ulong limb = num.d[i];
        // Extract 8 bytes from each 64-bit limb (big-endian within limb)
        bytes[byte_offset + 7] = (uchar)(limb & 0xFF);
        bytes[byte_offset + 6] = (uchar)((limb >> 8) & 0xFF);
        bytes[byte_offset + 5] = (uchar)((limb >> 16) & 0xFF);
        bytes[byte_offset + 4] = (uchar)((limb >> 24) & 0xFF);
        bytes[byte_offset + 3] = (uchar)((limb >> 32) & 0xFF);
        bytes[byte_offset + 2] = (uchar)((limb >> 40) & 0xFF);
        bytes[byte_offset + 1] = (uchar)((limb >> 48) & 0xFF);
        bytes[byte_offset + 0] = (uchar)((limb >> 56) & 0xFF);
    }
}

// ==========================================
// 10. ETH Pattern Matching (Hex)
// ==========================================

// Reusable switch-case checker at any offset
inline bool check_at_offset(thread const uchar* hash,
                             thread const uchar* pat,
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

// Dual-pattern check: prefix at hash[12], suffix at hash[32-suffix_len]
inline bool check_pattern_dual(thread const uchar* hash,
                                thread const uchar* pattern_cache,
                                uint prefix_len, uint suffix_len) {
    if (prefix_len > 0 && !check_at_offset(hash, pattern_cache, prefix_len, 12))
        return false;
    if (suffix_len > 0 && !check_at_offset(hash, pattern_cache + prefix_len,
                                             suffix_len, 32 - suffix_len))
        return false;
    return (prefix_len > 0 || suffix_len > 0);
}

// Check hex pattern match for ETH address (LEGACY - kept for reference)
// ETH address = hash[12..32] (last 20 bytes)
// NOTE: This function is no longer used - replaced by check_pattern_fast()
inline bool check_hex_pattern(thread const uchar* hash_bytes,
                              constant uchar* pattern,
                              uint pattern_len,
                              bool is_suffix) {
    if (is_suffix) {
        // Suffix: check last pattern_len bytes
        uint start_offset = 32 - pattern_len;
        for (uint i = 0; i < pattern_len; i++) {
            if (hash_bytes[start_offset + i] != pattern[i]) {
                return false;
            }
        }
    } else {
        // Prefix: check first pattern_len bytes of address (hash[12..])
        for (uint i = 0; i < pattern_len; i++) {
            if (hash_bytes[12 + i] != pattern[i]) {
                return false;
            }
        }
    }
    return true;
}

// ==========================================
// 10. Seed Generation Kernel (Precomp-based)
// ==========================================

// Generate starting points from private keys using precomputation table
// This parallelizes the expensive scalar multiplication step
kernel void generate_seeds(
    device const uint256_t* privkeys          [[ buffer(0) ]],
    device JacobianPoint* output_points       [[ buffer(1) ]],
    constant AffinePoint* precomp             [[ buffer(2) ]],
    uint gid [[ thread_position_in_grid ]])
{
    // Get private key for this thread
    uint256_t privkey = privkeys[gid];

    // Convert to big-endian bytes for precomp lookup
    uchar scalar_bytes[32];
    uint256_to_bytes(privkey, scalar_bytes);

    // Compute public key: P = privkey * G using standard precomputation
    // NOTE: GLV optimization disabled - the naive split was mathematically incorrect
    // Full GLV requires proper lattice-based scalar decomposition
    JacobianPoint result;
    point_from_scalar_precomp(precomp, scalar_bytes, &result);

    // Store result
    output_points[gid] = result;
}

// ==========================================
// 11. Main ETH Search Kernel (Batch Optimized)
// ==========================================

kernel void eth_vanity_search(
    device const JacobianPoint* start_points  [[ buffer(0) ]],
    device const uint256_t* start_privkeys    [[ buffer(1) ]],
    constant uchar* pattern                   [[ buffer(2) ]],  // [prefix|suffix] concatenated
    constant uint& prefix_len                 [[ buffer(3) ]],  // was pattern_len
    constant uint& suffix_len                 [[ buffer(4) ]],  // was is_suffix
    device atomic_uint* found_flag            [[ buffer(5) ]],
    device uint* result_thread_id             [[ buffer(6) ]],
    device uint* result_offset                [[ buffer(7) ]],
    constant uint& steps_per_thread           [[ buffer(8) ]],
    constant AffinePoint* stride_table        [[ buffer(9) ]],
    uint gid [[ thread_position_in_grid ]])
{
    if (atomic_load_explicit(found_flag, memory_order_relaxed) > 0) return;

    JacobianPoint P = start_points[gid];

    // Cache pattern in registers
    uchar pattern_cache[20];
    uint total_pattern_len = min(prefix_len + suffix_len, 20u);
    for (uint k = 0; k < total_pattern_len; k++) {
        pattern_cache[k] = pattern[k];
    }

    // Process in batches of 16
    uint num_batches = steps_per_thread / 16;

    // Initial: convert Jacobian starting point to affine (one-time cost)
    uint256_t aff_px, aff_py;
    jacobian_to_affine_inplace(aff_px, aff_py, P);

    // Thread-local copy of P for mod_sub (constant address space cannot be passed as thread ref)
    uint256_t p_local;
    for (int i = 0; i < 4; i++) p_local.d[i] = SECP256K1_P.d[i];

    for (uint batch = 0; batch < num_batches; batch++) {
        // Check found flag periodically
        if (batch % 16 == 0 && batch > 0) {
            if (atomic_load_explicit(found_flag, memory_order_relaxed) > 0) return;
        }

        // --- PHASE 1: COMPUTE X_DIFFS FOR BATCH INVERSE ---
        uint256_t diffs[16];
        for (int k = 0; k < 16; k++) {
            // Copy constant to thread-local (Metal address space requirement)
            uint256_t qx;
            for (int i = 0; i < 4; i++) qx.d[i] = stride_table[k].x.d[i];
            mod_sub(diffs[k], qx, aff_px);
        }

        // --- PHASE 2: BATCH INVERSE ALL 16 DENOMINATORS ---
        batch_inverse_16(diffs);

        // --- PHASE 3: COMPLETE AFFINE ADDITIONS + 6-WAY ADDRESS CHECKS ---
        uint256_t next_px, next_py;
        for (int k = 0; k < 16; k++) {
            // Read stride table entry to thread-local
            uint256_t qx, qy;
            for (int i = 0; i < 4; i++) {
                qx.d[i] = stride_table[k].x.d[i];
                qy.d[i] = stride_table[k].y.d[i];
            }

            // Affine addition: P + kG
            // s = (Q.y - P.y) * inv_diff
            uint256_t dy, s;
            mod_sub(dy, qy, aff_py);
            mul_mod(s, dy, diffs[k]);

            // x3 = s^2 - P.x - Q.x
            uint256_t s2, x3;
            sqr_mod(s2, s);
            mod_sub(x3, s2, aff_px);
            mod_sub(x3, x3, qx);

            // y3 = s * (P.x - x3) - P.y
            uint256_t dx, y3;
            mod_sub(dx, aff_px, x3);
            mul_mod(y3, s, dx);
            mod_sub(y3, y3, aff_py);

            // Save last point for next batch (P + 16G)
            if (k == 15) {
                next_px = x3;
                next_py = y3;
            }

            // Precompute derived coordinates for 6-way check
            uint256_t glv_x;      // beta * x3
            mul_mod_const2(glv_x, x3, BETA);

            uint256_t glv2_x;     // beta^2 * x3
            mul_mod_const2(glv2_x, x3, BETA_SQ);

            uint256_t neg_y;      // p - y3
            mod_sub(neg_y, p_local, y3);

            uint real_offset = (batch * 16) + k + 1;

            // --- CHECK 1: Original (x3, y3) --- variant 0
            {
                uchar hash[32];
                keccak_256_from_uint256(x3, y3, hash);
                if (check_pattern_dual(hash, pattern_cache, prefix_len, suffix_len)) {
                    uint expected = 0;
                    if (atomic_compare_exchange_weak_explicit(
                            found_flag, &expected, 1,
                            memory_order_relaxed, memory_order_relaxed)) {
                        *result_thread_id = gid;
                        *result_offset = real_offset;
                    }
                    return;
                }
            }

            // --- CHECK 2: GLV beta (beta*x3, y3) --- variant 1
            {
                uchar hash[32];
                keccak_256_from_uint256(glv_x, y3, hash);
                if (check_pattern_dual(hash, pattern_cache, prefix_len, suffix_len)) {
                    uint expected = 0;
                    if (atomic_compare_exchange_weak_explicit(
                            found_flag, &expected, 1,
                            memory_order_relaxed, memory_order_relaxed)) {
                        *result_thread_id = gid;
                        *result_offset = real_offset | (1u << 29);
                    }
                    return;
                }
            }

            // --- CHECK 3: GLV beta^2 (beta^2*x3, y3) --- variant 2
            {
                uchar hash[32];
                keccak_256_from_uint256(glv2_x, y3, hash);
                if (check_pattern_dual(hash, pattern_cache, prefix_len, suffix_len)) {
                    uint expected = 0;
                    if (atomic_compare_exchange_weak_explicit(
                            found_flag, &expected, 1,
                            memory_order_relaxed, memory_order_relaxed)) {
                        *result_thread_id = gid;
                        *result_offset = real_offset | (2u << 29);
                    }
                    return;
                }
            }

            // --- CHECK 4: Negation (x3, neg_y) --- variant 3
            {
                uchar hash[32];
                keccak_256_from_uint256(x3, neg_y, hash);
                if (check_pattern_dual(hash, pattern_cache, prefix_len, suffix_len)) {
                    uint expected = 0;
                    if (atomic_compare_exchange_weak_explicit(
                            found_flag, &expected, 1,
                            memory_order_relaxed, memory_order_relaxed)) {
                        *result_thread_id = gid;
                        *result_offset = real_offset | (3u << 29);
                    }
                    return;
                }
            }

            // --- CHECK 5: GLV beta + neg (beta*x3, neg_y) --- variant 4
            {
                uchar hash[32];
                keccak_256_from_uint256(glv_x, neg_y, hash);
                if (check_pattern_dual(hash, pattern_cache, prefix_len, suffix_len)) {
                    uint expected = 0;
                    if (atomic_compare_exchange_weak_explicit(
                            found_flag, &expected, 1,
                            memory_order_relaxed, memory_order_relaxed)) {
                        *result_thread_id = gid;
                        *result_offset = real_offset | (4u << 29);
                    }
                    return;
                }
            }

            // --- CHECK 6: GLV beta^2 + neg (beta^2*x3, neg_y) --- variant 5
            {
                uchar hash[32];
                keccak_256_from_uint256(glv2_x, neg_y, hash);
                if (check_pattern_dual(hash, pattern_cache, prefix_len, suffix_len)) {
                    uint expected = 0;
                    if (atomic_compare_exchange_weak_explicit(
                            found_flag, &expected, 1,
                            memory_order_relaxed, memory_order_relaxed)) {
                        *result_thread_id = gid;
                        *result_offset = real_offset | (5u << 29);
                    }
                    return;
                }
            }
        }

        // Update P for next batch
        aff_px = next_px;
        aff_py = next_py;
    }
}

