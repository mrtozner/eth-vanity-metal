use clap::Parser;
use std::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::io::Write;
use eth_vanity_metal::{
    VanityConfig, SequentialGenerator, public_key_to_eth_address, private_key_to_hex,
    display_hardware_info, calculate_difficulty, format_difficulty,
    is_gpu_available,
};
use eth_vanity_metal::gpu::{
    initialize as gpu_initialize,
};
use eth_vanity_metal::gpu::native_search::{
    GpuNativeSearcher, generate_gpu_seeds, recover_private_key, parse_hex_pattern,
};
use eth_vanity_metal::gpu::profanity_batch::search_profanity_batch;

#[derive(Parser)]
#[command(name = "eth-vanity-metal")]
#[command(about = "High-performance Ethereum vanity address generator for Apple Silicon", long_about = None)]
struct Cli {
    /// Prefix pattern (hex characters after 0x)
    /// Example: 'dead' finds '0xdead...', 'abc' finds '0xabc...'
    #[arg(short = 'p', long = "prefix", value_name = "PREFIX")]
    prefix: Option<String>,

    /// Suffix pattern (hex at end of address)
    /// Example: 'beef' finds '...beef', '9' finds '...9'
    #[arg(short = 'e', long = "end", value_name = "SUFFIX")]
    suffix: Option<String>,

    /// Number of threads to use (default: all CPU cores)
    #[arg(short = 't', long, value_name = "N")]
    threads: Option<usize>,

    /// Show hardware information
    #[arg(long = "info")]
    show_info: bool,

    /// Run benchmark mode (10 second test)
    #[arg(long = "benchmark")]
    benchmark: bool,

    /// Use GPU-native acceleration (full EC math on GPU)
    #[arg(long = "gpu-native")]
    use_gpu_native: bool,

    /// Use profanity2-style batch inversion (experimental)
    #[arg(long = "gpu-profanity")]
    use_gpu_profanity: bool,
}

fn main() {
    let cli = Cli::parse();

    // Handle benchmark mode
    if cli.benchmark {
        run_benchmark(cli.threads.unwrap_or_else(num_cpus::get));
        return;
    }

    // Handle hardware info display
    if cli.show_info {
        display_hardware_info();
        if cli.prefix.is_none() && cli.suffix.is_none() {
            return;
        }
        println!();
    }

    // Validate that we have at least one pattern
    if cli.prefix.is_none() && cli.suffix.is_none() {
        eprintln!("Error: Must specify -p (prefix) or -e (suffix) pattern");
        eprintln!("Example: {} -p dead", env!("CARGO_PKG_NAME"));
        std::process::exit(1);
    }

    // Validate hex patterns
    if let Some(ref p) = cli.prefix {
        if let Err(e) = validate_hex_pattern(p) {
            eprintln!("Error in prefix: {}", e);
            std::process::exit(1);
        }
    }
    if let Some(ref s) = cli.suffix {
        if let Err(e) = validate_hex_pattern(s) {
            eprintln!("Error in suffix: {}", e);
            std::process::exit(1);
        }
    }

    // Check GPU availability if requested
    if (cli.use_gpu_native || cli.use_gpu_profanity) && !is_gpu_available() {
        eprintln!("Error: GPU acceleration requested but Metal is not available on this system");
        std::process::exit(1);
    }

    let config = VanityConfig {
        prefix: cli.prefix.clone(),
        suffix: cli.suffix.clone(),
        threads: cli.threads.unwrap_or_else(num_cpus::get),
    };

    // Display configuration
    let pattern_desc = match (&config.prefix, &config.suffix) {
        (Some(p), Some(s)) => format!("0x{}...{}", p, s),
        (Some(p), None) => format!("0x{}...", p),
        (None, Some(s)) => format!("0x...{}", s),
        (None, None) => "unknown".to_string(),
    };

    println!("\nSearching for addresses like: {}", pattern_desc);

    // Show acceleration mode
    if cli.use_gpu_profanity {
        println!("Acceleration: Metal GPU (profanity2-style batch inversion)");
    } else if cli.use_gpu_native {
        println!("Acceleration: Metal GPU (native - full EC math on GPU)");
    } else {
        println!("Acceleration: CPU-only");
        println!("Threads: {}", config.threads);
    }

    let difficulty = calculate_difficulty(config.prefix.as_deref(), config.suffix.as_deref());
    println!("Difficulty: 1 in {}", format_difficulty(difficulty));
    println!("\nPress Ctrl+C to stop\n");

    // Setup Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");

    let attempts = Arc::new(AtomicU64::new(0));
    let start_time = std::time::Instant::now();

    // Handle GPU-profanity mode (experimental batch inversion)
    if cli.use_gpu_profanity {
        if config.prefix.is_none() && config.suffix.is_none() {
            eprintln!("Error: GPU-profanity mode requires -p (prefix) or -e (suffix)");
            std::process::exit(1);
        }
        if let Err(e) = run_gpu_profanity_search(&config, running.clone(), attempts.clone()) {
            eprintln!("\nGPU-profanity search failed: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // Handle GPU-native mode
    if cli.use_gpu_native {
        if config.prefix.is_none() && config.suffix.is_none() {
            eprintln!("Error: GPU-native mode requires -p (prefix) or -e (suffix)");
            std::process::exit(1);
        }
        if let Err(e) = run_gpu_native_search(&config, running.clone(), attempts.clone()) {
            eprintln!("\nGPU-native search failed: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // Spawn search threads
    let handles: Vec<_> = (0..config.threads)
        .map(|_| {
            let prefix = config.prefix.clone();
            let suffix = config.suffix.clone();
            let running = Arc::clone(&running);
            let attempts = Arc::clone(&attempts);

            std::thread::spawn(move || {
                let mut gen = SequentialGenerator::new();
                
                while running.load(Ordering::Relaxed) {
                    let (secret, public) = gen.next();
                    let address = public_key_to_eth_address(public);
                    
                    attempts.fetch_add(1, Ordering::Relaxed);
                    
                    // Check pattern match (skip "0x" prefix)
                    let addr_lower = address[2..].to_lowercase();
                    let matches = if let Some(ref p) = prefix {
                        addr_lower.starts_with(&p.to_lowercase())
                    } else if let Some(ref s) = suffix {
                        addr_lower.ends_with(&s.to_lowercase())
                    } else {
                        false
                    };
                    
                    if matches {
                        running.store(false, Ordering::Relaxed);
                        return Some((address.clone(), private_key_to_hex(secret)));
                    }
                }
                None
            })
        })
        .collect();

    // Monitor progress
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
        
        let current_attempts = attempts.load(Ordering::Relaxed);
        let elapsed = start_time.elapsed();
        let rate = if elapsed.as_secs() > 0 {
            (current_attempts as f64 / elapsed.as_secs_f64()) as u64
        } else {
            0
        };
        
        print!("\r[Searching] Scanned: {} | Speed: {:.2}M keys/s | Time: {}s",
            format_number(current_attempts),
            rate as f64 / 1_000_000.0,
            elapsed.as_secs()
        );
        std::io::stdout().flush().unwrap();
    }

    // Collect results
    for handle in handles {
        if let Ok(Some((address, private_key))) = handle.join() {
            println!("\n\n✓ Found vanity address!");
            println!("========================");
            println!("Address:      {}", address);
            println!("Private Key:  {}", private_key);
            println!("\nWARNING: Keep your private key secure! Anyone with this key can access your funds.");
            return;
        }
    }

    println!("\n\nSearch interrupted.");
}

fn validate_hex_pattern(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("Pattern cannot be empty".to_string());
    }
    
    for ch in pattern.chars() {
        if !ch.is_ascii_hexdigit() {
            return Err(format!("Invalid character '{}'. Use only hex characters (0-9, a-f, A-F)", ch));
        }
    }
    
    Ok(())
}

fn format_number(n: u64) -> String {
    n.to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap()
        .join(",")
}

fn run_benchmark(threads: usize) {
    println!("\nRunning 10-second benchmark...");
    println!("Threads: {}\n", threads);

    let running = Arc::new(AtomicBool::new(true));
    let attempts = Arc::new(AtomicU64::new(0));

    // Spawn threads
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let running = Arc::clone(&running);
            let attempts = Arc::clone(&attempts);

            std::thread::spawn(move || {
                let mut gen = SequentialGenerator::new();
                while running.load(Ordering::Relaxed) {
                    let (_secret, public) = gen.next();
                    let _address = public_key_to_eth_address(public);
                    attempts.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();

    // Run for 10 seconds
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(100));

        let current = attempts.load(Ordering::Relaxed);
        let elapsed = start.elapsed().as_secs_f64();
        let rate = current as f64 / elapsed;

        print!("\r[Benchmark] Speed: {:.2}M keys/s", rate / 1_000_000.0);
        std::io::stdout().flush().unwrap();
    }

    running.store(false, Ordering::Relaxed);

    // Wait for threads
    for handle in handles {
        let _ = handle.join();
    }

    let final_attempts = attempts.load(Ordering::Relaxed);
    let final_rate = final_attempts as f64 / 10.0;

    println!("\n\nBenchmark Results:");
    println!("  Total keys:  {}", format_number(final_attempts));
    println!("  Avg speed:   {:.2}M keys/s", final_rate / 1_000_000.0);
    println!("  Per thread:  {:.2}M keys/s", final_rate / threads as f64 / 1_000_000.0);
}

/// Run GPU-native search (full EC math + Keccak on GPU)
fn run_gpu_native_search(
    config: &VanityConfig,
    running: Arc<AtomicBool>,
    attempts: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize GPU context
    println!("Step 1: Initializing GPU context...");
    std::io::stdout().flush().unwrap();
    let context = gpu_initialize()?;
    println!("Step 1: GPU context initialized successfully");
    std::io::stdout().flush().unwrap();

    // GPU configuration - maximum performance (matches Tron version)
    let num_threads = 131072;   // Maximum threads
    let steps_per_thread = 2048;  // Maximum steps per thread

    // Parse both patterns independently
    let prefix_bytes = config.prefix.as_deref()
        .map(|p| parse_hex_pattern(p))
        .transpose()?
        .unwrap_or_default();
    let suffix_bytes = config.suffix.as_deref()
        .map(|s| parse_hex_pattern(s))
        .transpose()?
        .unwrap_or_default();

    // Validate combined length
    if prefix_bytes.len() + suffix_bytes.len() > 20 {
        return Err("Combined prefix + suffix cannot exceed 20 hex bytes (40 chars)".into());
    }

    // Warn about overlapping patterns
    if prefix_bytes.len() + suffix_bytes.len() > 20 {
        eprintln!("Warning: Prefix + suffix overlap in address space. Contradicting bytes will never match.");
    }

    println!("Step 2: Patterns parsed - prefix: {} bytes, suffix: {} bytes",
        prefix_bytes.len(), suffix_bytes.len());
    std::io::stdout().flush().unwrap();

    // Create GPU searcher
    println!("Step 3: Creating GPU searcher (compiling shader)...");
    std::io::stdout().flush().unwrap();
    let searcher = GpuNativeSearcher::new(context, num_threads, steps_per_thread as u32)?;
    println!("Step 3: GPU searcher created successfully");
    std::io::stdout().flush().unwrap();

    println!("GPU-Native Mode: {} threads × {} steps = {} keys/batch",
        num_threads, steps_per_thread, (num_threads as u64) * (steps_per_thread as u64));
    if !prefix_bytes.is_empty() {
        println!("Prefix: '{}' ({} bytes)", config.prefix.as_deref().unwrap_or(""), prefix_bytes.len());
    }
    if !suffix_bytes.is_empty() {
        println!("Suffix: '{}' ({} bytes)", config.suffix.as_deref().unwrap_or(""), suffix_bytes.len());
    }

    let start_time = std::time::Instant::now();
    let mut found_count = 0u64;
    let mut batch_count = 0u64;

    println!("Initializing GPU search...");
    std::io::stdout().flush().unwrap();

    while running.load(Ordering::SeqCst) {
        // Generate seeds for this batch (GPU-accelerated with precomp table)
        let (points, privkeys, base_key) = generate_gpu_seeds(&searcher, num_threads, steps_per_thread as u64)?;

        // Run GPU search iteration
        if let Some((thread_id, offset)) = searcher.search_iteration(
            &points,
            &privkeys,
            &prefix_bytes,
            &suffix_bytes,
        )? {
            // Recover the private key
            let found_key = recover_private_key(&base_key, thread_id, offset, steps_per_thread as u64)?;

            // Generate and verify address on CPU (security: never trust GPU-only results)
            let secp = secp256k1::Secp256k1::new();
            let pub_key = secp256k1::PublicKey::from_secret_key(&secp, &found_key);
            let address = public_key_to_eth_address(&pub_key);
            let private_hex = private_key_to_hex(&found_key);

            // Decode endomorphism variant from top 3 bits
            let variant = offset >> 29;
            let variant_label = match variant {
                0 => "",
                1 => " (via GLV λ)",
                2 => " (via GLV λ²)",
                3 => " (via negation)",
                4 => " (via GLV λ + neg)",
                5 => " (via GLV λ² + neg)",
                _ => " (unknown variant)",
            };

            // Verify the address actually matches both patterns on CPU
            let addr_hex = &address[2..].to_lowercase();
            let prefix_ok = config.prefix.as_ref()
                .map(|p| addr_hex.starts_with(&p.to_lowercase()))
                .unwrap_or(true);
            let suffix_ok = config.suffix.as_ref()
                .map(|s| addr_hex.ends_with(&s.to_lowercase()))
                .unwrap_or(true);

            if !prefix_ok || !suffix_ok {
                continue;
            }

            found_count += 1;
            println!("\n\n✓ Found vanity address!{}", variant_label);
            println!("========================");
            println!("Address:      {}", address);
            println!("Private Key:  {}", private_hex);
            println!("\nWARNING: Keep your private key secure! Anyone with this key can access your funds.");
        }

        batch_count += 1;
        // Each EC point yields 6 address checks (original + 2 GLV + 3 negations)
        let total_keys = batch_count * (num_threads as u64) * (steps_per_thread as u64) * 6;
        attempts.store(total_keys, Ordering::Relaxed);

        // Update progress
        let elapsed = start_time.elapsed();
        let rate = total_keys as f64 / elapsed.as_secs_f64();
        print!("\r[GPU-Native+6way] Found: {} | Scanned: {} | Speed: {:.2}M addr/s | Time: {}s   ",
            found_count,
            format_number(total_keys),
            rate / 1_000_000.0,
            elapsed.as_secs()
        );
        std::io::stdout().flush().unwrap();
    }

    println!("\n\nSearch interrupted.");
    Ok(())
}

/// Run GPU-profanity search (profanity2-style batch inversion)
fn run_gpu_profanity_search(
    config: &VanityConfig,
    running: Arc<AtomicBool>,
    _attempts: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize GPU context
    println!("Initializing GPU context...");
    std::io::stdout().flush().unwrap();
    let context = gpu_initialize()?;
    println!("GPU: {}", context.device_name());

    // Parse both patterns independently
    let prefix_bytes = config.prefix.as_deref()
        .map(|p| parse_hex_pattern(p))
        .transpose()?
        .unwrap_or_default();
    let suffix_bytes = config.suffix.as_deref()
        .map(|s| parse_hex_pattern(s))
        .transpose()?
        .unwrap_or_default();

    // Validate combined length
    if prefix_bytes.len() + suffix_bytes.len() > 20 {
        return Err("Combined prefix + suffix cannot exceed 20 hex bytes (40 chars)".into());
    }

    println!("Patterns: prefix={} bytes, suffix={} bytes",
        prefix_bytes.len(), suffix_bytes.len());

    // Run the profanity batch search
    let stop_signal = running.clone();

    // Progress callback
    let progress_callback = |total: u64, rate: f64| {
        print!("\r[GPU-Profanity] Scanned: {} | Speed: {:.2}M keys/s   ",
            format_number(total),
            rate
        );
        std::io::stdout().flush().unwrap();
    };

    match search_profanity_batch(&context, &prefix_bytes, &suffix_bytes, stop_signal, progress_callback) {
        Ok(Some((privkey, address))) => {
            println!("\n\n✓ Found vanity address!");
            println!("========================");
            println!("Address:      {}", address);
            println!("Private Key:  {}", hex::encode(privkey));
            println!("\nWARNING: Keep your private key secure! Anyone with this key can access your funds.");
        }
        Ok(None) => {
            println!("\n\nSearch interrupted.");
        }
        Err(e) => {
            return Err(format!("Search failed: {:?}", e).into());
        }
    }

    Ok(())
}
