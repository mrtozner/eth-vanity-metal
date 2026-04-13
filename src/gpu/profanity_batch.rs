/// Profanity2-style batch inversion for Metal GPU
///
/// This implements the profanity2 algorithm:
/// - Store (deltaX, prevLambda) instead of (X, Y, Z)
/// - Batch inverse 255 values with 1 inverse
/// - Point iteration with only 2 field multiplications
use crate::gpu::{GpuError, MetalContext};
use metal::{Buffer, ComputePipelineState, Device, MTLResourceOptions, MTLSize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const PROFANITY_INVERSE_SIZE: usize = 255;
const NUM_WORK_ITEMS: usize = 1024; // Number of batch inversion work items (reduced for testing)
const TOTAL_POINTS: usize = NUM_WORK_ITEMS * PROFANITY_INVERSE_SIZE; // ~260K points

/// Profanity2-style GPU searcher
#[allow(dead_code)]
pub struct ProfanityBatchSearcher {
    device: Device,
    command_queue: metal::CommandQueue,

    // Pipelines
    inverse_pipeline: ComputePipelineState,
    iterate_pipeline: ComputePipelineState,
    score_pipeline: ComputePipelineState,

    // Buffers
    delta_x_buffer: Buffer,
    inverse_buffer: Buffer,
    prev_lambda_buffer: Buffer,
    address_hash_buffer: Buffer,
    found_flag_buffer: Buffer,
    found_id_buffer: Buffer,
    pattern_buffer: Buffer,
    pattern_len_buffer: Buffer,
    is_suffix_buffer: Buffer,

    // Private keys (stored on CPU for result retrieval)
    private_keys: Vec<[u8; 32]>,

    // Configuration
    pattern: Vec<u8>,
    is_suffix: bool,
}

impl ProfanityBatchSearcher {
    /// Create a new profanity-style batch searcher
    pub fn new(ctx: &MetalContext, pattern: &[u8], is_suffix: bool) -> Result<Self, GpuError> {
        let device = ctx.device.clone();
        let command_queue = ctx.command_queue.clone();

        // Load and compile shader
        let shader_source = include_str!("profanity_batch.metal");
        let options = metal::CompileOptions::new();
        let library = device
            .new_library_with_source(shader_source, &options)
            .map_err(|e| GpuError::ShaderCompilationFailed(e.to_string()))?;

        // Create pipelines
        let inverse_fn = library
            .get_function("profanity_inverse", None)
            .map_err(|e| GpuError::PipelineCreationFailed(e.to_string()))?;
        let inverse_pipeline = device
            .new_compute_pipeline_state_with_function(&inverse_fn)
            .map_err(|e| GpuError::PipelineCreationFailed(e.to_string()))?;

        let iterate_fn = library
            .get_function("profanity_iterate", None)
            .map_err(|e| GpuError::PipelineCreationFailed(e.to_string()))?;
        let iterate_pipeline = device
            .new_compute_pipeline_state_with_function(&iterate_fn)
            .map_err(|e| GpuError::PipelineCreationFailed(e.to_string()))?;

        let score_fn = library
            .get_function("profanity_score_matching", None)
            .map_err(|e| GpuError::PipelineCreationFailed(e.to_string()))?;
        let score_pipeline = device
            .new_compute_pipeline_state_with_function(&score_fn)
            .map_err(|e| GpuError::PipelineCreationFailed(e.to_string()))?;

        // Create buffers
        // mp_number = 8 x u32 = 32 bytes
        let mp_size = 32;
        let delta_x_buffer = device.new_buffer(
            (TOTAL_POINTS * mp_size) as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let inverse_buffer = device.new_buffer(
            (TOTAL_POINTS * mp_size) as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let prev_lambda_buffer = device.new_buffer(
            (TOTAL_POINTS * mp_size) as u64,
            MTLResourceOptions::StorageModeShared,
        );
        // Address hash: 5 x u32 = 20 bytes per point
        let address_hash_buffer = device.new_buffer(
            (TOTAL_POINTS * 20) as u64,
            MTLResourceOptions::StorageModeShared,
        );

        let found_flag_buffer = device.new_buffer(4, MTLResourceOptions::StorageModeShared);
        let found_id_buffer = device.new_buffer(4, MTLResourceOptions::StorageModeShared);

        let pattern_buffer = device.new_buffer(
            std::cmp::max(pattern.len(), 1) as u64,
            MTLResourceOptions::StorageModeShared,
        );
        let pattern_len_buffer = device.new_buffer(4, MTLResourceOptions::StorageModeShared);
        let is_suffix_buffer = device.new_buffer(4, MTLResourceOptions::StorageModeShared);

        // Initialize pattern buffers
        unsafe {
            let ptr = pattern_buffer.contents() as *mut u8;
            std::ptr::copy_nonoverlapping(pattern.as_ptr(), ptr, pattern.len());

            let len_ptr = pattern_len_buffer.contents() as *mut u32;
            *len_ptr = pattern.len() as u32;

            let suffix_ptr = is_suffix_buffer.contents() as *mut u32;
            *suffix_ptr = if is_suffix { 1 } else { 0 };
        }

        Ok(Self {
            device,
            command_queue,
            inverse_pipeline,
            iterate_pipeline,
            score_pipeline,
            delta_x_buffer,
            inverse_buffer,
            prev_lambda_buffer,
            address_hash_buffer,
            found_flag_buffer,
            found_id_buffer,
            pattern_buffer,
            pattern_len_buffer,
            is_suffix_buffer,
            private_keys: Vec::with_capacity(TOTAL_POINTS),
            pattern: pattern.to_vec(),
            is_suffix,
        })
    }

    /// Initialize points from random private keys
    /// This computes the initial deltaX and prevLambda values
    /// Optimized: Uses sequential keys with point addition for 10-100x speedup
    pub fn initialize_points(&mut self) -> Result<(), GpuError> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::{AffinePoint, ProjectivePoint, SecretKey as K256SecretKey};
        use rayon::prelude::*;

        let start_time = std::time::Instant::now();
        println!("  Initializing {} points (optimized)...", TOTAL_POINTS);

        // Step 1: Generate random base private key
        let mut rng = rand::thread_rng();
        let base_key_bytes: [u8; 32] = rand::Rng::gen(&mut rng);

        // Validate base key is valid secp256k1 scalar
        let base_key = K256SecretKey::from_bytes((&base_key_bytes).into())
            .map_err(|_| GpuError::InitializationFailed("Invalid base key".into()))?;
        let base_key_bytes = base_key.to_bytes();

        // Step 2: Compute base point = base_key * G
        print!("  Computing base point...");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        let base_point_projective = ProjectivePoint::from(*base_key.public_key().as_affine());
        println!(" done");

        // Step 3: Pre-compute lookup table for fast point addition
        // For each byte position and byte value, pre-compute the point
        // Table[byte_pos][byte_val] = (byte_val * 256^byte_pos) * G
        print!("  Pre-computing lookup table...");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        // We need 4 byte positions to cover 0..261120 (< 256^4)
        const NUM_BYTE_POSITIONS: usize = 4;

        // Pre-compute multiples for each byte position
        // Position 0: G, 2G, 3G, ..., 255G
        // Position 1: 256G, 2*256G, ..., 255*256G
        // Position 2: 256^2*G, 2*256^2*G, ..., 255*256^2*G
        // Position 3: 256^3*G, 2*256^3*G, ..., 255*256^3*G
        let lookup_table: Vec<Vec<AffinePoint>> = (0..NUM_BYTE_POSITIONS)
            .into_par_iter()
            .map(|pos| {
                // For each byte value 1..=255
                (1u8..=255)
                    .map(|val| {
                        // Compute scalar = val * 256^pos
                        let mut scalar_bytes = [0u8; 32];
                        scalar_bytes[31 - pos] = val; // Big-endian: byte_pos from right

                        let sk = K256SecretKey::from_bytes((&scalar_bytes).into())
                            .expect("Valid scalar");
                        *sk.public_key().as_affine()
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        println!(" done ({:.2}s)", start_time.elapsed().as_secs_f64());

        // Step 4: Compute all points using lookup table and point addition
        print!(
            "  Computing {} points using point addition...",
            TOTAL_POINTS
        );
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        // secp256k1 field prime p
        let p = num_bigint::BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            16,
        )
        .unwrap();

        // Generator point G coordinates
        let gx = num_bigint::BigUint::parse_bytes(
            b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            16,
        )
        .unwrap();
        let gy = num_bigint::BigUint::parse_bytes(
            b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            16,
        )
        .unwrap();

        // Process in chunks for better cache locality
        let chunk_size = 1024;
        let num_chunks = (TOTAL_POINTS + chunk_size - 1) / chunk_size;

        let points_data: Vec<([u8; 32], [u32; 8], [u32; 8])> = (0..num_chunks)
            .into_par_iter()
            .flat_map(|chunk_idx| {
                let start_idx = chunk_idx * chunk_size;
                let end_idx = ((chunk_idx + 1) * chunk_size).min(TOTAL_POINTS);

                (start_idx..end_idx)
                    .map(|i| {
                        // Compute private key: base_key + i
                        let privkey = add_to_private_key(base_key_bytes.as_ref(), i as u64);

                        // Compute public key using point addition with byte decomposition
                        // point[i] = base_point + i*G
                        // Decompose i into bytes: i = b0 + b1*256 + b2*256^2 + b3*256^3
                        // Then: point[i] = base_point + b0*G + b1*256G + b2*256^2*G + b3*256^3*G

                        let mut point_projective = base_point_projective;

                        // Extract bytes from index (little-endian)
                        let bytes = [
                            (i & 0xFF) as u8,
                            ((i >> 8) & 0xFF) as u8,
                            ((i >> 16) & 0xFF) as u8,
                            ((i >> 24) & 0xFF) as u8,
                        ];

                        // Add contribution from each non-zero byte
                        for (pos, &byte_val) in bytes.iter().enumerate() {
                            if byte_val > 0 && pos < NUM_BYTE_POSITIONS {
                                // lookup_table[pos][byte_val - 1] = byte_val * 256^pos * G
                                point_projective = point_projective
                                    + ProjectivePoint::from(
                                        lookup_table[pos][byte_val as usize - 1],
                                    );
                            }
                        }

                        let point_affine = point_projective.to_affine();
                        let point_encoded = point_affine.to_encoded_point(false);
                        let x_bytes = point_encoded.x().unwrap();
                        let y_bytes = point_encoded.y().unwrap();

                        // Convert to BigUint for profanity2 representation
                        let px = num_bigint::BigUint::from_bytes_be(x_bytes);
                        let py = num_bigint::BigUint::from_bytes_be(y_bytes);

                        // deltaX = px - gx (mod p)
                        let delta_x = if px >= gx {
                            &px - &gx
                        } else {
                            &p - (&gx - &px)
                        };

                        // prevLambda = (py - gy) / (px - gx) mod p
                        let num = if py >= gy {
                            &py - &gy
                        } else {
                            &p - (&gy - &py)
                        };

                        let delta_x_inv = mod_inverse(&delta_x, &p);
                        let prev_lambda = (&num * &delta_x_inv) % &p;

                        // Convert to 8 x u32 (little-endian words)
                        let delta_x_words = biguint_to_words(&delta_x);
                        let lambda_words = biguint_to_words(&prev_lambda);

                        (privkey, delta_x_words, lambda_words)
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        println!(" done ({:.2}s)", start_time.elapsed().as_secs_f64());

        // Step 5: Write to GPU buffers and private key storage
        print!("  Writing to GPU buffers...");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();

        self.private_keys.clear();
        self.private_keys.reserve(TOTAL_POINTS);

        let delta_x_ptr = self.delta_x_buffer.contents() as *mut [u32; 8];
        let prev_lambda_ptr = self.prev_lambda_buffer.contents() as *mut [u32; 8];

        for (i, (privkey, delta_x_words, lambda_words)) in points_data.into_iter().enumerate() {
            self.private_keys.push(privkey);
            unsafe {
                *delta_x_ptr.add(i) = delta_x_words;
                *prev_lambda_ptr.add(i) = lambda_words;
            }
        }

        // Reset found flag
        unsafe {
            let flag_ptr = self.found_flag_buffer.contents() as *mut u32;
            *flag_ptr = 0;
        }

        let total_time = start_time.elapsed().as_secs_f64();
        println!(" done");
        println!(
            "  Total initialization time: {:.2}s ({:.0} points/sec)",
            total_time,
            TOTAL_POINTS as f64 / total_time
        );

        Ok(())
    }

    /// Run one iteration cycle (inverse -> iterate -> score)
    pub fn run_iteration(&self) -> Result<Option<(usize, [u8; 32])>, GpuError> {
        let command_buffer = self.command_queue.new_command_buffer();

        // 1. Batch Inversion Kernel
        {
            let encoder = command_buffer.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&self.inverse_pipeline);
            encoder.set_buffer(0, Some(&self.delta_x_buffer), 0);
            encoder.set_buffer(1, Some(&self.inverse_buffer), 0);

            let thread_count = NUM_WORK_ITEMS as u64;
            let threads_per_group = std::cmp::min(
                self.inverse_pipeline.max_total_threads_per_threadgroup(),
                64,
            );
            let threadgroups = (thread_count + threads_per_group - 1) / threads_per_group;

            encoder.dispatch_thread_groups(
                MTLSize::new(threadgroups, 1, 1),
                MTLSize::new(threads_per_group, 1, 1),
            );
            encoder.end_encoding();
        }

        // 2. Point Iteration Kernel
        {
            let encoder = command_buffer.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&self.iterate_pipeline);
            encoder.set_buffer(0, Some(&self.delta_x_buffer), 0);
            encoder.set_buffer(1, Some(&self.inverse_buffer), 0);
            encoder.set_buffer(2, Some(&self.prev_lambda_buffer), 0);
            encoder.set_buffer(3, Some(&self.address_hash_buffer), 0);

            let thread_count = TOTAL_POINTS as u64;
            let threads_per_group = std::cmp::min(
                self.iterate_pipeline.max_total_threads_per_threadgroup(),
                256,
            );
            let threadgroups = (thread_count + threads_per_group - 1) / threads_per_group;

            encoder.dispatch_thread_groups(
                MTLSize::new(threadgroups, 1, 1),
                MTLSize::new(threads_per_group, 1, 1),
            );
            encoder.end_encoding();
        }

        // 3. Pattern Matching Kernel
        {
            let encoder = command_buffer.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&self.score_pipeline);
            encoder.set_buffer(0, Some(&self.address_hash_buffer), 0);
            encoder.set_buffer(1, Some(&self.found_flag_buffer), 0);
            encoder.set_buffer(2, Some(&self.found_id_buffer), 0);
            encoder.set_buffer(3, Some(&self.pattern_buffer), 0);
            encoder.set_buffer(4, Some(&self.pattern_len_buffer), 0);
            encoder.set_buffer(5, Some(&self.is_suffix_buffer), 0);

            let thread_count = TOTAL_POINTS as u64;
            let threads_per_group =
                std::cmp::min(self.score_pipeline.max_total_threads_per_threadgroup(), 256);
            let threadgroups = (thread_count + threads_per_group - 1) / threads_per_group;

            encoder.dispatch_thread_groups(
                MTLSize::new(threadgroups, 1, 1),
                MTLSize::new(threads_per_group, 1, 1),
            );
            encoder.end_encoding();
        }

        command_buffer.commit();
        command_buffer.wait_until_completed();

        // Check if found
        let found_flag = unsafe { *(self.found_flag_buffer.contents() as *const u32) };

        if found_flag > 0 {
            let found_id = unsafe { *(self.found_id_buffer.contents() as *const u32) } as usize;

            if found_id < self.private_keys.len() {
                return Ok(Some((found_id, self.private_keys[found_id])));
            }
        }

        Ok(None)
    }

    /// Get total points per iteration
    pub fn points_per_iteration(&self) -> usize {
        TOTAL_POINTS
    }

    /// Debug: dump first N addresses from GPU and compare with CPU computation
    pub fn debug_compare_addresses(&self, iteration: u64, count: usize) {
        // Read GPU address hashes
        let hash_ptr = self.address_hash_buffer.contents() as *const u32;

        println!(
            "\n=== DEBUG: Comparing first {} addresses (iteration {}) ===",
            count, iteration
        );

        for i in 0..count.min(self.private_keys.len()) {
            // Read GPU address (5 x u32 = 20 bytes)
            let base = i * 5;
            let mut gpu_addr = [0u8; 20];
            unsafe {
                let h0 = *hash_ptr.add(base);
                let h1 = *hash_ptr.add(base + 1);
                let h2 = *hash_ptr.add(base + 2);
                let h3 = *hash_ptr.add(base + 3);
                let h4 = *hash_ptr.add(base + 4);

                // Unpack from big-endian format (MSB first) - matches Metal kernel
                gpu_addr[0] = ((h0 >> 24) & 0xFF) as u8;
                gpu_addr[1] = ((h0 >> 16) & 0xFF) as u8;
                gpu_addr[2] = ((h0 >> 8) & 0xFF) as u8;
                gpu_addr[3] = (h0 & 0xFF) as u8;
                gpu_addr[4] = ((h1 >> 24) & 0xFF) as u8;
                gpu_addr[5] = ((h1 >> 16) & 0xFF) as u8;
                gpu_addr[6] = ((h1 >> 8) & 0xFF) as u8;
                gpu_addr[7] = (h1 & 0xFF) as u8;
                gpu_addr[8] = ((h2 >> 24) & 0xFF) as u8;
                gpu_addr[9] = ((h2 >> 16) & 0xFF) as u8;
                gpu_addr[10] = ((h2 >> 8) & 0xFF) as u8;
                gpu_addr[11] = (h2 & 0xFF) as u8;
                gpu_addr[12] = ((h3 >> 24) & 0xFF) as u8;
                gpu_addr[13] = ((h3 >> 16) & 0xFF) as u8;
                gpu_addr[14] = ((h3 >> 8) & 0xFF) as u8;
                gpu_addr[15] = (h3 & 0xFF) as u8;
                gpu_addr[16] = ((h4 >> 24) & 0xFF) as u8;
                gpu_addr[17] = ((h4 >> 16) & 0xFF) as u8;
                gpu_addr[18] = ((h4 >> 8) & 0xFF) as u8;
                gpu_addr[19] = (h4 & 0xFF) as u8;
            }

            // Compute CPU address for adjusted private key
            let actual_privkey = add_to_private_key(&self.private_keys[i], iteration);
            let cpu_address = compute_eth_address(&actual_privkey);

            let gpu_hex = format!("0x{}", hex::encode(&gpu_addr));
            let match_str = if gpu_hex.to_lowercase() == cpu_address.to_lowercase() {
                "✓ MATCH"
            } else {
                "✗ MISMATCH"
            };

            println!(
                "[{}] GPU: {} | CPU: {} {}",
                i, gpu_hex, cpu_address, match_str
            );
        }
        println!("=== END DEBUG ===\n");
    }
}

/// Modular inverse using extended Euclidean algorithm
fn mod_inverse(a: &num_bigint::BigUint, m: &num_bigint::BigUint) -> num_bigint::BigUint {
    use num_bigint::BigInt;
    use num_traits::{One, Zero};

    let a = BigInt::from(a.clone());
    let m = BigInt::from(m.clone());

    let mut old_r = m.clone();
    let mut r = a;
    let mut old_s = BigInt::zero();
    let mut s = BigInt::one();

    while !r.is_zero() {
        let quotient = &old_r / &r;
        let temp_r = r.clone();
        r = old_r - &quotient * &r;
        old_r = temp_r;

        let temp_s = s.clone();
        s = old_s - &quotient * &s;
        old_s = temp_s;
    }

    // Make sure result is positive
    if old_s < BigInt::zero() {
        old_s += &m;
    }

    old_s.to_biguint().unwrap()
}

/// Convert BigUint to 8 x u32 words (little-endian)
fn biguint_to_words(n: &num_bigint::BigUint) -> [u32; 8] {
    let bytes = n.to_bytes_le();
    let mut words = [0u32; 8];

    for (i, chunk) in bytes.chunks(4).enumerate() {
        if i >= 8 {
            break;
        }
        let mut word = 0u32;
        for (j, &byte) in chunk.iter().enumerate() {
            word |= (byte as u32) << (j * 8);
        }
        words[i] = word;
    }

    words
}

/// Convert big-endian bytes to little-endian mp_number words
fn bytes_to_mp_words(bytes: &[u8]) -> [u32; 8] {
    assert_eq!(bytes.len(), 32);
    let mut words = [0u32; 8];
    // bytes is big-endian (MSB first)
    // words[7] should be MSW
    for i in 0..8 {
        let offset = i * 4;
        words[7 - i] = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
    }
    words
}

/// Add a scalar offset to a private key (mod secp256k1 curve order n)
/// This is used to account for GPU iterations where each iteration adds G to the point
fn add_to_private_key(privkey: &[u8; 32], offset: u64) -> [u8; 32] {
    use num_bigint::BigUint;

    // secp256k1 curve order n
    let n = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();

    let key = BigUint::from_bytes_be(privkey);
    let result = (key + BigUint::from(offset)) % &n;

    // Convert back to 32 bytes, big-endian, zero-padded
    let bytes = result.to_bytes_be();
    let mut output = [0u8; 32];
    let offset_idx = 32 - bytes.len();
    output[offset_idx..].copy_from_slice(&bytes);
    output
}

/// Debug: Test GPU Keccak with known public key
pub fn debug_test_keccak(ctx: &MetalContext) -> Result<(), GpuError> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use tiny_keccak::{Hasher, Keccak};

    println!("\n=== DEBUG: Testing GPU Keccak ===");

    // Use a known test private key
    let privkey_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let privkey_bytes: [u8; 32] = hex::decode(privkey_hex).unwrap().try_into().unwrap();

    // Compute public key on CPU
    let secret_key = SecretKey::from_bytes((&privkey_bytes).into()).unwrap();
    let public_key = secret_key.public_key();
    let point = public_key.to_encoded_point(false);
    let x_bytes = point.x().unwrap();
    let y_bytes = point.y().unwrap();

    println!("Private key: {}", privkey_hex);
    println!("Public X: {}", hex::encode(x_bytes));
    println!("Public Y: {}", hex::encode(y_bytes));

    // Compute expected address on CPU
    let mut pubkey_bytes = [0u8; 64];
    pubkey_bytes[..32].copy_from_slice(x_bytes);
    pubkey_bytes[32..].copy_from_slice(y_bytes);

    let mut hasher = Keccak::v256();
    let mut hash = [0u8; 32];
    hasher.update(&pubkey_bytes);
    hasher.finalize(&mut hash);
    let cpu_address = format!("0x{}", hex::encode(&hash[12..]));
    println!("CPU address: {}", cpu_address);

    // Convert X, Y to mp_number format (little-endian words)
    let x_words = bytes_to_mp_words(x_bytes);
    let y_words = bytes_to_mp_words(y_bytes);

    println!("X words (LE): {:08x?}", x_words);
    println!("Y words (LE): {:08x?}", y_words);

    // Compile shader
    let shader_source = include_str!("profanity_batch.metal");
    let options = metal::CompileOptions::new();
    let library = ctx
        .device
        .new_library_with_source(shader_source, &options)
        .map_err(|e| GpuError::ShaderCompilationFailed(e.to_string()))?;

    // Create GPU buffers
    let x_buffer = ctx.device.new_buffer_with_data(
        x_words.as_ptr() as *const _,
        std::mem::size_of_val(&x_words) as u64,
        metal::MTLResourceOptions::StorageModeShared,
    );

    let y_buffer = ctx.device.new_buffer_with_data(
        y_words.as_ptr() as *const _,
        std::mem::size_of_val(&y_words) as u64,
        metal::MTLResourceOptions::StorageModeShared,
    );

    let output_buffer = ctx.device.new_buffer(
        (5 * std::mem::size_of::<u32>()) as u64,
        metal::MTLResourceOptions::StorageModeShared,
    );

    // Get kernel function
    let kernel = library
        .get_function("debug_keccak_test", None)
        .map_err(|e| {
            GpuError::PipelineCreationFailed(format!(
                "Failed to get debug_keccak_test kernel: {}",
                e
            ))
        })?;

    // Create pipeline
    let pipeline = ctx
        .device
        .new_compute_pipeline_state_with_function(&kernel)
        .map_err(|e| {
            GpuError::PipelineCreationFailed(format!("Failed to create pipeline: {}", e))
        })?;

    // Execute kernel
    let command_buffer = ctx.command_queue.new_command_buffer();
    let encoder = command_buffer.new_compute_command_encoder();
    encoder.set_compute_pipeline_state(&pipeline);
    encoder.set_buffer(0, Some(&x_buffer), 0);
    encoder.set_buffer(1, Some(&y_buffer), 0);
    encoder.set_buffer(2, Some(&output_buffer), 0);
    encoder.dispatch_thread_groups(metal::MTLSize::new(1, 1, 1), metal::MTLSize::new(1, 1, 1));
    encoder.end_encoding();
    command_buffer.commit();
    command_buffer.wait_until_completed();

    // Read result
    let result_ptr = output_buffer.contents() as *const u32;
    let gpu_hash: Vec<u32> = unsafe { std::slice::from_raw_parts(result_ptr, 5).to_vec() };

    // Convert GPU result to address string
    let mut gpu_address_bytes = [0u8; 20];
    for i in 0..5 {
        let bytes = gpu_hash[i].to_be_bytes();
        gpu_address_bytes[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    let gpu_address = format!("0x{}", hex::encode(&gpu_address_bytes));

    println!("GPU address: {}", gpu_address);
    println!("Match: {}", cpu_address == gpu_address);

    println!("=== END DEBUG ===\n");

    if cpu_address != gpu_address {
        return Err(GpuError::InitializationFailed(format!(
            "GPU Keccak mismatch! CPU: {}, GPU: {}",
            cpu_address, gpu_address
        )));
    }

    Ok(())
}

/// Main search function with progress reporting
pub fn search_profanity_batch(
    ctx: &MetalContext,
    pattern: &[u8],
    is_suffix: bool,
    prefix: Option<&str>,
    suffix: Option<&str>,
    stop_signal: Arc<AtomicBool>,
    progress_callback: impl Fn(u64, f64),
) -> Result<Option<([u8; 32], String)>, GpuError> {
    println!("Profanity2-style batch search");
    println!("  Total points per batch: {}", TOTAL_POINTS);
    println!("  Batch inverse groups: {}", NUM_WORK_ITEMS);
    println!("  Points per inverse: {}", PROFANITY_INVERSE_SIZE);

    // Debug: test Keccak implementation
    // debug_test_keccak(ctx)?;

    let mut searcher = ProfanityBatchSearcher::new(ctx, pattern, is_suffix)?;

    let start_time = std::time::Instant::now();
    let mut total_keys: u64 = 0;
    let mut iteration = 0u64;

    loop {
        // stop_signal is "running" - true means continue, false means stop
        if !stop_signal.load(Ordering::Relaxed) {
            return Ok(None);
        }

        // Initialize new batch of points
        searcher.initialize_points()?;

        // Run multiple iterations per batch (each iteration advances all points by 1)
        for iter in 0..255u64 {
            if !stop_signal.load(Ordering::Relaxed) {
                return Ok(None);
            }

            if let Some((_found_id, original_privkey)) = searcher.run_iteration()? {
                // Found a match! Compute actual private key accounting for iterations
                // Each iteration adds G, so actual_key = original_key + (iter + 1)
                // Note: iter + 1 because we check AFTER the first iteration runs

                // Debug: verify addresses before returning
                // searcher.debug_compare_addresses(iter + 1, 5);

                let actual_privkey = add_to_private_key(&original_privkey, iter + 1);
                let address = compute_eth_address(&actual_privkey);
                if crate::address::eth_address_matches_patterns(&address, prefix, suffix) {
                    return Ok(Some((actual_privkey, address)));
                }
            }

            total_keys += TOTAL_POINTS as u64;
            iteration += 1;

            // Debug: print first iteration's addresses for verification
            // if iter == 0 {
            //     searcher.debug_compare_addresses(iter + 1, 5);
            // }

            // Progress callback every 10 iterations
            if iteration % 10 == 0 {
                let elapsed = start_time.elapsed().as_secs_f64();
                let rate = total_keys as f64 / elapsed / 1_000_000.0;
                progress_callback(total_keys, rate);
            }
        }
    }
}

/// Compute ETH address from private key
fn compute_eth_address(privkey: &[u8; 32]) -> String {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use tiny_keccak::{Hasher, Keccak};

    let secret_key = SecretKey::from_bytes(privkey.into()).unwrap();
    let public_key = secret_key.public_key();
    let point = public_key.to_encoded_point(false);

    // Get uncompressed public key (without 0x04 prefix)
    let mut pubkey_bytes = [0u8; 64];
    pubkey_bytes[..32].copy_from_slice(point.x().unwrap());
    pubkey_bytes[32..].copy_from_slice(point.y().unwrap());

    // Keccak-256 hash
    let mut hasher = Keccak::v256();
    let mut hash = [0u8; 32];
    hasher.update(&pubkey_bytes);
    hasher.finalize(&mut hash);

    // Take last 20 bytes
    let address = &hash[12..];
    format!("0x{}", hex::encode(address))
}
