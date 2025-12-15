# eth-vanity-metal

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-macOS-blue.svg)](https://www.apple.com/macos/)
[![Apple Silicon](https://img.shields.io/badge/Apple%20Silicon-M1%2FM2%2FM3%2FM4-green.svg)](https://www.apple.com/mac/)
[![Status](https://img.shields.io/badge/status-Work%20In%20Progress-orange.svg)]()

**A Metal GPU-accelerated Ethereum vanity address generator for Apple Silicon.**

Generate custom Ethereum addresses with specific prefixes or suffixes using Apple Silicon's native Metal GPU acceleration.

> **Work In Progress**: Currently optimizing to match/exceed profanity2's OpenCL performance. See [Roadmap](#roadmap) below.

## Performance

| Mode | Speed | Hardware |
|------|-------|----------|
| **Metal GPU** | **~45 MH/s** | Apple M4 Pro |
| CPU multi-threaded | ~2 MH/s | 14-core M4 Pro |
| profanity2 (OpenCL) | ~100 MH/s | Apple M4 Pro |

Current Metal implementation uses Jacobian coordinates (~16 field multiplications per iteration). Working on implementing profanity2's optimized deltaX/lambda algorithm with batch inversion (~2 multiplications per iteration) to reach 100+ MH/s.

### Difficulty Estimates (at 45 MH/s)

| Pattern Length | Combinations | Approximate Time |
|----------------|--------------|------------------|
| 1 character | 16 | Instant |
| 2 characters | 256 | Instant |
| 3 characters | 4,096 | < 1 second |
| 4 characters | 65,536 | ~1 second |
| 5 characters | 1,048,576 | ~23 seconds |
| 6 characters | 16,777,216 | ~6 minutes |
| 7 characters | 268,435,456 | ~1.6 hours |
| 8 characters | 4,294,967,296 | ~26 hours |

## Features

- **Metal GPU Acceleration** - Native Apple Silicon GPU compute for maximum performance
- **Prefix Search** - Find addresses starting with custom hex patterns (e.g., `0xdead...`)
- **Suffix Search** - Find addresses ending with patterns (e.g., `...beef`)
- **Simpler than TRON** - No Base58, just hex! Pattern matching is straightforward
- **Real-time Progress** - Live speed, match counter, and time elapsed
- **Secure** - All keys generated locally, never transmitted
- **Validated** - Generated addresses verified against reference implementations

## Installation

### Prerequisites

- macOS 12.0+ (Monterey or later)
- Apple Silicon Mac (M1/M2/M3/M4) or Intel Mac with AMD GPU
- Rust 1.70+

### Build from Source

```bash
git clone https://github.com/mrtozner/eth-vanity-metal.git
cd eth-vanity-metal
cargo build --release
```

The binary will be at `./target/release/eth-vanity-metal`.

## Usage

### GPU-Accelerated Search (Recommended)

```bash
# Find address starting with "dead"
./target/release/eth-vanity-metal -p dead --gpu-native

# Find address ending with "beef"
./target/release/eth-vanity-metal -e beef --gpu-native

# Find address starting with "cafe" AND ending with "42"
./target/release/eth-vanity-metal -p cafe -e 42 --gpu-native
```

### CPU-Only Search (Slower, for compatibility testing)

```bash
./target/release/eth-vanity-metal -p dead
```

### Command Line Options

```
Options:
  -p, --prefix <PREFIX>    Hex prefix pattern (e.g., 'dead' for 0xdead...)
  -e, --end <SUFFIX>       Hex suffix pattern (e.g., 'beef' for ...beef)
      --gpu-native         Use Metal GPU acceleration (recommended)
      --benchmark          Run performance benchmark
      --info               Show hardware information
  -t, --threads <N>        Number of CPU threads (CPU mode only)
  -h, --help               Print help
```

### Output Format

```
Found vanity address!
========================
Address:      0xdead5d0d95924acc737fb0f7e5289a5a8d0bb6bd
Private Key:  58fd1dac4f979cb27d4acb35119e27a6a759a3c655636f3ad7995dab52d50a59

WARNING: Keep your private key secure! Anyone with this key can access your funds.
```

**IMPORTANT:** Save the private key immediately! It's only displayed once.

## Technical Details

### Algorithm

1. Generate random 256-bit private keys in batches (268M per GPU batch)
2. Compute public key points using precomputation table lookup
3. Apply Keccak-256 hash to uncompressed public key (64 bytes, excluding 0x04 prefix)
4. Take last 20 bytes as Ethereum address
5. Check if address matches hex pattern
6. Return matching private key

### GPU Optimizations (Current)

- **Precomputation Table** - 8,160 precomputed EC points for fast scalar multiplication
- **64-bit Limbs** - Optimized uint256 arithmetic using 4x64-bit limbs
- **Jacobian Coordinates** - Avoids per-operation inversions (~16 field muls per point addition)
- **Optimized Keccak-256** - Unrolled 24-round permutation for Metal shaders
- **131K GPU Threads** - Parallel processing with 2048 steps each
- **Fast Modular Reduction** - Exploits secp256k1 prime structure: 2^256 ≡ 2^32 + 977 (mod P)

### Planned Optimizations

- **Montgomery Batch Inversion** - Amortize 1 inverse across 255 keys (8x speedup potential)
- **deltaX/lambda representation** - Reduce to ~2 field muls per iteration (vs current ~16)

### Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│  Rust CLI   │────▶│   Metal Shader   │────▶│  GPU Cores  │
│  (main.rs)  │◀────│ (search_native)  │◀────│  (M4 Pro)   │
└─────────────┘     └──────────────────┘     └─────────────┘
      │                      │                      │
      │         ┌────────────┴────────────┐       │
      │         │                         │       │
      │    ┌────┴────┐             ┌─────┴─────┐  │
      │    │ Precomp │             │ EC Point  │  │
      │    │  Table  │             │ Addition  │  │
      │    │(8160 pt)│             │ (Jacobian)│  │
      │    └─────────┘             └───────────┘  │
      │                                           │
      │         ┌──────────────────┐             │
      └────────▶│    Keccak-256    │◀────────────┘
                │  (unrolled 24r)  │
                └──────────────────┘
```

### Precomputation Table

The GPU uses a precomputation table of 8,160 elliptic curve points:
- 32 byte positions × 255 non-zero values
- Allows computing k×G with only ~32 point additions instead of ~256
- Table size: ~510 KB (fits comfortably in GPU cache)

## Security

- Private keys are generated using cryptographically secure random number generator
- All computation happens locally on your machine
- No network connections or telemetry
- Keys are displayed once and not stored
- Addresses validated against reference implementation (eth_account Python library)

**WARNING:**
- Never share your private key
- Test the generated address with a small amount first
- Consider using a hardware wallet for large amounts
- Verify the address checksum before use

## Comparison

| Tool | GPU Support | Speed | Platform |
|------|-------------|-------|----------|
| **profanity2** | OpenCL | **~100 MH/s** | Linux/Windows/macOS |
| **eth-vanity-metal** | Metal (native) | ~45 MH/s | macOS (Apple Silicon) |
| vanity-eth (Node) | CPU only | ~50 KH/s | Cross-platform |
| ethvanity (Go) | CPU only | ~200 KH/s | Cross-platform |

*Note: This is the only Metal-native implementation for Apple Silicon. Performance optimization is ongoing.*

## Ethereum Address Format

Unlike TRON (which uses Base58Check), Ethereum addresses are simpler:
- 20 bytes (40 hex characters)
- Prefixed with `0x`
- No checksum in the address itself (EIP-55 provides optional mixed-case checksum)
- Example: `0xdead5d0d95924acc737fb0f7e5289a5a8d0bb6bd`

This means pattern matching is straightforward - what you search for is exactly what appears in the address!

## Roadmap

### Current Status: ~45 MH/s (Jacobian Coordinates)

### Target: 100+ MH/s (profanity2-style Batch Inversion)

- [ ] **Implement deltaX/lambda point representation** - Store `(deltaX, lambda)` instead of Jacobian `(X, Y, Z)`
- [ ] **Montgomery batch inversion** - Amortize 1 modular inverse across 255 keys (currently each key does inline inversion)
- [ ] **Optimize field multiplication** - Port profanity2's `mp_mod_mul` algorithm with fixed 8 iterations
- [ ] **GLV endomorphism** - Use secp256k1 endomorphism for ~2x speedup on scalar multiplication
- [ ] **Multi-GPU support** - Distribute work across multiple Metal devices

### Why Metal Should Win

Metal is Apple's native GPU API with lower overhead than OpenCL on Apple Silicon. With the same algorithm, Metal should achieve 100-150 MH/s. The current gap is due to algorithmic differences, not API limitations.

## Contributing

Contributions welcome! Areas of interest:

- Implementing profanity2-style batch inversion in Metal
- GLV endomorphism optimization
- Multi-GPU support
- Further Metal shader optimizations
- Support for EIP-55 checksum patterns

## License

MIT License - see [LICENSE](LICENSE)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Acknowledgments

- [profanity2](https://github.com/1inch/profanity2) for GPU optimization techniques
- secp256k1 curve implementation techniques from libsecp256k1
- Montgomery batch inversion algorithm
- Apple Metal Compute documentation

---

**Made with Metal for Apple Silicon**
