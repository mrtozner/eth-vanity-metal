/// Benchmark for profanity batch initialization performance
///
/// This demonstrates the speedup from the optimized initialize_points() function
///
/// Run with:
/// cargo run --release --example benchmark_init

use eth_vanity_metal::gpu::{initialize, profanity_batch::ProfanityBatchSearcher};
use std::time::Instant;

fn main() {
    println!("=== Profanity Batch Initialization Benchmark ===\n");

    // Initialize GPU context
    println!("Initializing Metal GPU context...");
    let ctx = match initialize() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to initialize GPU: {:?}", e);
            eprintln!("This benchmark requires Apple Silicon with Metal support.");
            std::process::exit(1);
        }
    };

    println!("GPU Device: {}\n", ctx.device_name());

    // Run initialization benchmark
    println!("Benchmarking initialization (260,160 points)...");
    println!("This will take a few seconds...\n");

    // Create a simple pattern for testing (doesn't matter for init benchmark)
    let pattern = vec![0xDE, 0xAD]; // "dead" prefix

    let mut searcher = match ProfanityBatchSearcher::new(&ctx, &pattern, &[]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create searcher: {:?}", e);
            std::process::exit(1);
        }
    };

    // Benchmark initialization
    let start = Instant::now();
    match searcher.initialize_points() {
        Ok(_) => {
            let elapsed = start.elapsed();
            let total_points = 260_160;
            let points_per_sec = total_points as f64 / elapsed.as_secs_f64();

            println!("\n=== Results ===");
            println!("Total time: {:.3}s", elapsed.as_secs_f64());
            println!("Points generated: {}", total_points);
            println!("Throughput: {:.0} points/sec", points_per_sec);

            if elapsed.as_secs_f64() < 2.0 {
                println!("\n✓ EXCELLENT! Initialization is under 2 seconds.");
            } else if elapsed.as_secs_f64() < 5.0 {
                println!("\n✓ GOOD! Initialization is under 5 seconds.");
            } else {
                println!("\n⚠ Initialization took longer than expected.");
            }

            println!("\nOptimizations applied:");
            println!("  - Sequential keys instead of random");
            println!("  - secp256k1 crate (optimized for speed)");
            println!("  - Rayon parallel computation");
        }
        Err(e) => {
            eprintln!("\nInitialization failed: {:?}", e);
            std::process::exit(1);
        }
    }
}
