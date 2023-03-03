# Stream Extractor

The TCP Stream Extractor is a small utility that can read in a PCAP file, search through it for TCP streams, and write out each stream to a separate new PCAP file.

## Usage

```bash
Usage: stream-extractor [OPTIONS] --input <INPUT>

Options:
  -i, --input <INPUT>    Input pcap file to split
  -o, --output <OUTPUT>  Output name template [default: output_]
  -h, --help             Print help
```

## Build

To build `stream-extractor`, execute:
```bash
cargo build
```

An example PCAP is located in `sample/`.
