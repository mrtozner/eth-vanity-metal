//! GPU-Native Vanity Search for Ethereum
//! Runs the full EC math + Keccak on GPU for maximum speed

use crate::gpu::{GpuError, MetalContext};
use secp256k1::{SecretKey, Secp256k1, Scalar};
use std::sync::Arc;
use std::io::Write;

/// GLV endomorphism eigenvalue λ for secp256k1
/// λ·G has the same x-coordinate as β·G.x (mod p)
/// λ = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
const GLV_LAMBDA: [u8; 32] = [
    0x53, 0x63, 0xAD, 0x4C, 0xC0, 0x5C, 0x30, 0xE0,
    0xA5, 0x26, 0x1C, 0x02, 0x88, 0x12, 0x64, 0x5A,
    0x12, 0x2E, 0x22, 0xEA, 0x20, 0x81, 0x66, 0x78,
    0xDF, 0x02, 0x96, 0x7C, 0x1B, 0x23, 0xBD, 0x72,
];

/// GLV endomorphism eigenvalue λ² mod n for secp256k1
/// λ² = 0xAC9C52B33FA3CF1F5AD9E3FD77ED9BA4A880B9FC8EC739C2E0CFC810B51283CE
const GLV_LAMBDA_SQ: [u8; 32] = [
    0xAC, 0x9C, 0x52, 0xB3, 0x3F, 0xA3, 0xCF, 0x1F,
    0x5A, 0xD9, 0xE3, 0xFD, 0x77, 0xED, 0x9B, 0xA4,
    0xA8, 0x80, 0xB9, 0xFC, 0x8E, 0xC7, 0x39, 0xC2,
    0xE0, 0xCF, 0xC8, 0x10, 0xB5, 0x12, 0x83, 0xCE,
];

// ==========================================
// GPU-Compatible Structs
// ==========================================

/// Must match uint256_t in Metal (4 x u64, little-endian)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GpuUint256 {
    pub d: [u64; 4],  // Changed from [u32; 8] to match Metal's ulong d[4]
}

/// Must match JacobianPoint in Metal
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GpuJacobianPoint {
    pub x: GpuUint256,
    pub y: GpuUint256,
    pub z: GpuUint256,
}

impl From<[u8; 32]> for GpuUint256 {
    fn from(bytes: [u8; 32]) -> Self {
        let mut d = [0u64; 4];
        // Convert big-endian bytes to little-endian 64-bit limbs
        // d[0] is LSB limb (bytes[24..31]), d[3] is MSB limb (bytes[0..7])
        for i in 0..4 {
            let start = (3 - i) * 8;  // d[0] <- bytes[24..31], d[3] <- bytes[0..7]
            d[i] = u64::from_be_bytes([
                bytes[start], bytes[start+1], bytes[start+2], bytes[start+3],
                bytes[start+4], bytes[start+5], bytes[start+6], bytes[start+7]
            ]);
        }
        Self { d }
    }
}

impl GpuUint256 {
    pub fn one() -> Self {
        let mut d = [0u64; 4];
        d[0] = 1;  // LSB limb
        Self { d }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        // d[3] is MSB -> bytes[0..7]
        // d[0] is LSB -> bytes[24..31]
        for i in 0..4 {
            let limb = self.d[3 - i];  // Start from MSB
            let start = i * 8;
            bytes[start..start+8].copy_from_slice(&limb.to_be_bytes());
        }
        bytes
    }
}

// ==========================================
// Hex Pattern Parsing
// ==========================================

/// Parse hex pattern string to bytes
/// Example: "dead" → [0xDE, 0xAD]
pub fn parse_hex_pattern(pattern: &str) -> Result<Vec<u8>, String> {
    if pattern.len() % 2 != 0 {
        return Err(format!(
            "Hex pattern '{}' must have even length (full bytes). Use '{}0' or '0{}' to match '{}'",
            pattern, pattern, pattern, pattern
        ));
    }

    hex::decode(pattern).map_err(|e| format!("Invalid hex pattern: {}", e))
}

// ==========================================
// Seed Generation
// ==========================================

/// Generate GPU seeds - starting points spread across search space
/// Uses GPU precomputation table for parallel public key generation
pub fn generate_gpu_seeds(
    searcher: &GpuNativeSearcher,
    num_threads: usize,
    steps_per_thread: u64,
) -> Result<(Vec<GpuJacobianPoint>, Vec<GpuUint256>, SecretKey), GpuError> {
    // Generate random base private key
    let base_key = SecretKey::new(&mut rand::thread_rng());

    let mut privkeys = Vec::with_capacity(num_threads);

    // Offset between threads
    let offset_bytes = steps_per_thread.to_be_bytes();
    let mut offset_32 = [0u8; 32];
    offset_32[24..32].copy_from_slice(&offset_bytes);
    let offset_scalar = Scalar::from_be_bytes(offset_32)
        .map_err(|_| GpuError::InitializationFailed("Invalid scalar".to_string()))?;

    let mut current_key = base_key;

    // Generate private keys for each thread
    for _ in 0..num_threads {
        // Store private key for result recovery
        let priv_bytes: [u8; 32] = current_key.secret_bytes();
        privkeys.push(GpuUint256::from(priv_bytes));

        // Advance to next thread's starting position
        current_key = current_key.add_tweak(&offset_scalar)
            .map_err(|_| GpuError::InitializationFailed("Key overflow".to_string()))?;
    }

    // Compute public keys on GPU using precomputation table
    // This parallelizes the expensive scalar multiplication
    let points = searcher.generate_seeds_gpu(&privkeys)?;

    Ok((points, privkeys, base_key))
}

// ==========================================
// Stride Table Precomputation
// ==========================================

/// Compute stride table: kG for k=1..16
/// Each point is encoded as two uint256_t values (x, y), each with 4 little-endian 64-bit limbs
fn compute_stride_table() -> Vec<u8> {
    let secp = secp256k1::Secp256k1::new();
    let mut table = Vec::new();

    for k in 1u64..=16 {
        // Create scalar for k
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes[24..32].copy_from_slice(&k.to_be_bytes());
        let key = secp256k1::SecretKey::from_slice(&scalar_bytes).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &key);
        let serialized = pubkey.serialize_uncompressed(); // 04 || x(32) || y(32)

        // Convert x and y from big-endian bytes to little-endian 64-bit limbs
        for coord in [&serialized[1..33], &serialized[33..65]] {
            // coord is 32 bytes in big-endian
            // We need to convert to 4 limbs in little-endian order
            // Limb order: d[0] = LSB, d[1], d[2], d[3] = MSB
            // Byte layout in big-endian: [MSB...LSB]
            // So: d[3] <- bytes[0..7], d[2] <- bytes[8..15], d[1] <- bytes[16..23], d[0] <- bytes[24..31]
            for limb_idx in 0..4 {
                let offset = (3 - limb_idx) * 8; // d[0] <- bytes[24..31] (LSB), d[3] <- bytes[0..7] (MSB)
                let limb = u64::from_be_bytes(coord[offset..offset+8].try_into().unwrap());
                table.extend_from_slice(&limb.to_le_bytes());
            }
        }
    }

    table
}

// ==========================================
// GPU Search Execution
// ==========================================

pub struct GpuNativeSearcher {
    context: Arc<MetalContext>,
    pipeline: metal::ComputePipelineState,
    seed_pipeline: metal::ComputePipelineState,
    num_threads: usize,
    steps_per_thread: u32,
    precomp_buffer: metal::Buffer,
    stride_table_buffer: metal::Buffer,
}

impl GpuNativeSearcher {
    pub fn new(context: Arc<MetalContext>, num_threads: usize, steps_per_thread: u32) -> Result<Self, GpuError> {
        // Load and compile the search_native.metal shader
        let shader_source = include_str!("search_native.metal");

        println!("  → Loading shader source ({} bytes)", shader_source.len());
        std::io::stdout().flush().unwrap();

        println!("  → Compiling Metal shader (this may take 10-30 seconds)...");
        std::io::stdout().flush().unwrap();

        // Create compile options with fast-math disabled to speed up compilation
        let compile_options = metal::CompileOptions::new();
        // Note: We can't set many options through the Rust bindings, but compilation should still work

        let library = context.device()
            .new_library_with_source(shader_source, &compile_options)
            .map_err(|e| GpuError::ShaderCompilationFailed(e.to_string()))?;

        println!("  → Shader compiled successfully");
        std::io::stdout().flush().unwrap();

        println!("  → Getting kernel function...");
        std::io::stdout().flush().unwrap();

        let function = library.get_function("eth_vanity_search", None)
            .map_err(|e| GpuError::ShaderCompilationFailed(e.to_string()))?;

        println!("  → Creating compute pipeline...");
        std::io::stdout().flush().unwrap();

        let pipeline = context.device()
            .new_compute_pipeline_state_with_function(&function)
            .map_err(|e| GpuError::PipelineCreationFailed(e.to_string()))?;

        println!("  → Pipeline created successfully");
        std::io::stdout().flush().unwrap();

        println!("  → Getting seed generation kernel function...");
        std::io::stdout().flush().unwrap();

        let seed_function = library.get_function("generate_seeds", None)
            .map_err(|e| GpuError::ShaderCompilationFailed(e.to_string()))?;

        println!("  → Creating seed generation pipeline...");
        std::io::stdout().flush().unwrap();

        let seed_pipeline = context.device()
            .new_compute_pipeline_state_with_function(&seed_function)
            .map_err(|e| GpuError::PipelineCreationFailed(e.to_string()))?;

        println!("  → Seed generation pipeline created successfully");
        std::io::stdout().flush().unwrap();

        // Generate precomputation table for fast scalar multiplication
        println!("  → Generating precomputation table...");
        std::io::stdout().flush().unwrap();

        let precomp_table = crate::gpu::generate_precomp_table();

        // Create GPU buffer for precomputation table
        // Using StorageModeShared for compatibility, marked as constant in kernel
        let precomp_buffer_size = (precomp_table.len() * std::mem::size_of::<crate::gpu::GpuAffinePoint>()) as u64;
        let precomp_buffer = context.device().new_buffer_with_data(
            precomp_table.as_ptr() as *const _,
            precomp_buffer_size,
            metal::MTLResourceOptions::StorageModeShared,
        );

        println!("  → Precomputation table uploaded to GPU ({} KB)",
                 precomp_buffer_size / 1024);
        std::io::stdout().flush().unwrap();

        // Generate and upload stride table for affine batch addition
        println!("  → Generating stride table [G, 2G, ..., 16G]...");
        std::io::stdout().flush().unwrap();

        let stride_table = compute_stride_table();
        let stride_table_size = stride_table.len() as u64;
        let stride_table_buffer = context.device().new_buffer_with_data(
            stride_table.as_ptr() as *const _,
            stride_table_size,
            metal::MTLResourceOptions::StorageModeShared,
        );

        println!("  → Stride table uploaded to GPU ({} bytes)",
                 stride_table_size);
        std::io::stdout().flush().unwrap();

        Ok(Self {
            context,
            pipeline,
            seed_pipeline,
            num_threads,
            steps_per_thread,
            precomp_buffer,
            stride_table_buffer,
        })
    }

    /// Generate starting points from private keys using GPU precomputation table
    /// This parallelizes the expensive scalar multiplication
    pub fn generate_seeds_gpu(
        &self,
        privkeys: &[GpuUint256],
    ) -> Result<Vec<GpuJacobianPoint>, GpuError> {
        let device = self.context.device();

        // Create buffer for private keys
        let privkeys_buffer = device.new_buffer_with_data(
            privkeys.as_ptr() as *const _,
            (privkeys.len() * std::mem::size_of::<GpuUint256>()) as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );

        // Create buffer for output points
        let output_size = (privkeys.len() * std::mem::size_of::<GpuJacobianPoint>()) as u64;
        let output_buffer = device.new_buffer(
            output_size,
            metal::MTLResourceOptions::StorageModeShared,
        );

        // Create command buffer
        let command_buffer = self.context.command_queue().new_command_buffer();
        let encoder = command_buffer.new_compute_command_encoder();

        // Set pipeline and buffers
        encoder.set_compute_pipeline_state(&self.seed_pipeline);
        encoder.set_buffer(0, Some(&privkeys_buffer), 0);
        encoder.set_buffer(1, Some(&output_buffer), 0);
        encoder.set_buffer(2, Some(&self.precomp_buffer), 0);

        // Dispatch threads (one per private key)
        let threadgroup_size = 256.min(self.seed_pipeline.max_total_threads_per_threadgroup()) as u64;
        let threadgroups = (privkeys.len() as u64 + threadgroup_size - 1) / threadgroup_size;

        encoder.dispatch_thread_groups(
            metal::MTLSize { width: threadgroups, height: 1, depth: 1 },
            metal::MTLSize { width: threadgroup_size, height: 1, depth: 1 },
        );

        encoder.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();

        // Read results
        let output_ptr = output_buffer.contents() as *const GpuJacobianPoint;
        let output_slice = unsafe {
            std::slice::from_raw_parts(output_ptr, privkeys.len())
        };

        Ok(output_slice.to_vec())
    }

    /// Run a single search iteration
    /// Returns (found, thread_id, offset) if match found
    pub fn search_iteration(
        &self,
        points: &[GpuJacobianPoint],
        privkeys: &[GpuUint256],
        prefix_pattern: &[u8],
        suffix_pattern: &[u8],
    ) -> Result<Option<(u32, u32)>, GpuError> {
        let device = self.context.device();

        // Create buffers
        let points_buffer = device.new_buffer_with_data(
            points.as_ptr() as *const _,
            (points.len() * std::mem::size_of::<GpuJacobianPoint>()) as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let privkeys_buffer = device.new_buffer_with_data(
            privkeys.as_ptr() as *const _,
            (privkeys.len() * std::mem::size_of::<GpuUint256>()) as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );

        // Concatenate prefix + suffix patterns
        let mut combined = Vec::with_capacity(prefix_pattern.len() + suffix_pattern.len());
        combined.extend_from_slice(prefix_pattern);
        combined.extend_from_slice(suffix_pattern);

        let pattern_buffer = device.new_buffer_with_data(
            combined.as_ptr() as *const _,
            std::cmp::max(combined.len(), 1) as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let prefix_len: u32 = prefix_pattern.len() as u32;
        let prefix_len_buffer = device.new_buffer_with_data(
            &prefix_len as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let suffix_len: u32 = suffix_pattern.len() as u32;
        let suffix_len_buffer = device.new_buffer_with_data(
            &suffix_len as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        // Result buffers
        let found_flag: u32 = 0;
        let found_buffer = device.new_buffer_with_data(
            &found_flag as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let result_thread: u32 = 0;
        let result_thread_buffer = device.new_buffer_with_data(
            &result_thread as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let result_offset: u32 = 0;
        let result_offset_buffer = device.new_buffer_with_data(
            &result_offset as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        let steps_buffer = device.new_buffer_with_data(
            &self.steps_per_thread as *const _ as *const _,
            4,
            metal::MTLResourceOptions::StorageModeShared,
        );

        // Create command buffer
        let command_buffer = self.context.command_queue().new_command_buffer();
        let encoder = command_buffer.new_compute_command_encoder();

        // Set pipeline and buffers
        encoder.set_compute_pipeline_state(&self.pipeline);
        encoder.set_buffer(0, Some(&points_buffer), 0);
        encoder.set_buffer(1, Some(&privkeys_buffer), 0);
        encoder.set_buffer(2, Some(&pattern_buffer), 0);
        encoder.set_buffer(3, Some(&prefix_len_buffer), 0);
        encoder.set_buffer(4, Some(&suffix_len_buffer), 0);
        encoder.set_buffer(5, Some(&found_buffer), 0);
        encoder.set_buffer(6, Some(&result_thread_buffer), 0);
        encoder.set_buffer(7, Some(&result_offset_buffer), 0);
        encoder.set_buffer(8, Some(&steps_buffer), 0);
        encoder.set_buffer(9, Some(&self.stride_table_buffer), 0);

        // Dispatch threads
        let threadgroup_size = 256.min(self.pipeline.max_total_threads_per_threadgroup()) as u64;
        let threadgroups = (self.num_threads as u64 + threadgroup_size - 1) / threadgroup_size;

        encoder.dispatch_thread_groups(
            metal::MTLSize { width: threadgroups, height: 1, depth: 1 },
            metal::MTLSize { width: threadgroup_size, height: 1, depth: 1 },
        );

        encoder.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();

        // Read results
        let found_ptr = found_buffer.contents() as *const u32;
        let thread_ptr = result_thread_buffer.contents() as *const u32;
        let offset_ptr = result_offset_buffer.contents() as *const u32;

        let found = unsafe { *found_ptr };
        if found > 0 {
            let thread_id = unsafe { *thread_ptr };
            let offset = unsafe { *offset_ptr };
            Ok(Some((thread_id, offset)))
        } else {
            Ok(None)
        }
    }
}

/// Recover private key from GPU search result
/// The top 3 bits of offset encode the endomorphism variant (0-5):
///   0: original point (x, y)           -> key = k
///   1: GLV β point (β·x, y)            -> key = λ·k mod n
///   2: GLV β² point (β²·x, y)          -> key = λ²·k mod n
///   3: negated point (x, -y)            -> key = n - k
///   4: GLV β + negation (β·x, -y)       -> key = n - (λ·k mod n)
///   5: GLV β² + negation (β²·x, -y)     -> key = n - (λ²·k mod n)
/// The bottom 29 bits encode the step offset within the thread.
pub fn recover_private_key(
    base_key: &SecretKey,
    thread_id: u32,
    offset: u32,
    steps_per_thread: u64,
) -> Result<SecretKey, String> {
    // Decode variant from top 3 bits, real offset from bottom 29 bits
    let variant = (offset >> 29) as u8;
    let real_offset = offset & 0x1FFFFFFF;

    // Calculate total offset: thread_id * steps_per_thread + real_offset
    let thread_offset = (thread_id as u64)
        .checked_mul(steps_per_thread)
        .ok_or("Thread offset overflow")?;

    let total_offset = thread_offset
        .checked_add(real_offset as u64)
        .ok_or("Total offset overflow")?;

    // Convert to scalar
    let offset_bytes = total_offset.to_be_bytes();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[24..32].copy_from_slice(&offset_bytes);

    let offset_scalar = Scalar::from_be_bytes(scalar_bytes)
        .map_err(|_| "Invalid scalar")?;

    // Add offset to base key: k = base_key + offset
    let mut key = base_key.add_tweak(&offset_scalar)
        .map_err(|e| format!("Key addition failed: {}", e))?;

    // Apply variant transformation
    match variant {
        0 => {
            // Original point - key as-is
        }
        1 => {
            // GLV β: multiply by λ
            let lambda_scalar = Scalar::from_be_bytes(GLV_LAMBDA)
                .map_err(|_| "Invalid lambda scalar")?;
            key = key.mul_tweak(&lambda_scalar)
                .map_err(|e| format!("GLV lambda multiplication failed: {}", e))?;
        }
        2 => {
            // GLV β²: multiply by λ²
            let lambda_sq_scalar = Scalar::from_be_bytes(GLV_LAMBDA_SQ)
                .map_err(|_| "Invalid lambda_sq scalar")?;
            key = key.mul_tweak(&lambda_sq_scalar)
                .map_err(|e| format!("GLV lambda_sq multiplication failed: {}", e))?;
        }
        3 => {
            // Negation: n - k
            key = key.negate();
        }
        4 => {
            // GLV β + negation: negate(λ·k)
            let lambda_scalar = Scalar::from_be_bytes(GLV_LAMBDA)
                .map_err(|_| "Invalid lambda scalar")?;
            key = key.mul_tweak(&lambda_scalar)
                .map_err(|e| format!("GLV lambda multiplication failed: {}", e))?;
            key = key.negate();
        }
        5 => {
            // GLV β² + negation: negate(λ²·k)
            let lambda_sq_scalar = Scalar::from_be_bytes(GLV_LAMBDA_SQ)
                .map_err(|_| "Invalid lambda_sq scalar")?;
            key = key.mul_tweak(&lambda_sq_scalar)
                .map_err(|e| format!("GLV lambda_sq multiplication failed: {}", e))?;
            key = key.negate();
        }
        _ => return Err(format!("Invalid endomorphism variant: {}", variant)),
    }

    Ok(key)
}
