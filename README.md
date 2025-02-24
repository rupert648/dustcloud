# DustCloud

A Rust CLI tool for monitoring DNS requests on macOS, with a focus on traffic routed through Cloudflare (1.1.1.1).

## Requirements

- Rust and Cargo installed
- Administrative privileges (needed for packet capture)
- macOS (primarily designed for macOS, but may work on other platforms)

## Building



## Usage



Note: Administrative privileges are required for network packet capture.

### Options

- `--cloudflare-only`: Only capture DNS traffic to/from Cloudflare (1.1.1.1)
- `--output <FILE>`: Optional output file to save results
- `--verbose`: Enable verbose output

## License

MIT
