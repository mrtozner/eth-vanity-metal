/// High-performance Ethereum vanity address generator optimized for Apple Silicon
///
/// This library provides functionality to generate Ethereum addresses and search for
/// vanity addresses with specific patterns.

pub mod address;
pub mod search;
pub mod difficulty;
pub mod hardware;
pub mod stats;
pub mod display;
pub mod gpu;

pub use address::{
    eth_address_matches_patterns,
    generate_keypair,
    generate_keypair_direct,
    public_key_to_eth_address,
    public_key_to_raw_address,
    private_key_to_hex,
    SequentialGenerator,
};

pub use search::{
    VanitySearcher, VanityResult, VanityConfig, FoundAddress,
    search_parallel, search_with_config, search_continuous,
};

pub use difficulty::{
    calculate_difficulty, format_difficulty, format_duration, estimate_time,
};

pub use hardware::{
    get_cpu_info, get_core_count, is_apple_silicon, display_hardware_info,
};

pub use stats::{
    SearchStats, format_number, format_speed,
};

pub use display::{
    create_progress_bar, update_progress, display_success_enhanced,
};

pub use gpu::{
    MetalContext, GpuError, is_gpu_available, initialize,
};

pub use gpu::native_search::{
    GpuNativeSearcher, GpuUint256, GpuJacobianPoint,
    generate_gpu_seeds, parse_hex_pattern, recover_private_key,
};
