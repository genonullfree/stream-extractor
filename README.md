# Stream Extractor

The TCP Stream Extractor is a small utility that can read in a PCAP file, search through it for TCP streams, and write out each stream to a separate new PCAP file.

## Usage

```bash
Usage: stream-extractor [OPTIONS] --input <INPUT>

Options:
  -i, --input <INPUT>    Input pcap file to split
  -o, --output <OUTPUT>  Output name template [default: output_]
  -p, --port <PORT>      Filter output files to ones that contain the specified port number
      --ip <IP>          Filter output files to ones that contain the specified IP address
  -h, --help             Print help
```

## Filter Options

The filter options `--port` and `--ip` are available to allow you to only write out the detected TCP streams that match the filter values. This can help simplify
the research step of identifying exactly which streams you may be interested in.

Example:
```bash
stream-extractor --ip 192.168.110.10 -p 80 -i sample/test.pcap
Packets processed: 21933, Streams detected: 662
Filtering streams by communications including port: 80
 + Found 3 matching streams
Filtering streams by communications including IP address: 192.168.110.10
 + Found 1 matching streams
Number of streams that matched filters: 1
Writing output file: 1
```

## Build

To build `stream-extractor`, execute:
```bash
cargo build
```

An example PCAP is located in `sample/`.
