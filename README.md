# Stream Extractor

The Stream Extractor is a small utility that can read in a PCAP file, search through it for TCP and UDP streams, and write out each stream to a separate new PCAP file.

## Usage

```bash
Usage: stream-extractor <COMMAND>

Commands:
  extract  Extract TCP and UDP streams from a PCAP
  scan     Scan the PCAP and search for an IP or Port
  list     List all of the PCAP communication info
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Extract

```bash
Usage: stream-extractor extract [OPTIONS] --input <INPUT>

Options:
  -i, --input <INPUT>    Input pcap file to extract TCP and UDP streams from
  -o, --output <OUTPUT>  Output name template [default: output_]
  -p, --port <PORT>      Filter output files to ones that contain the specified port number
      --ip <IP>          Filter output files to ones that contain the specified IP address
  -v, --verbose          Enable verbose mode to print stream info for each output PCAP file
  -h, --help             Print help
```

### Scan

```bash
Usage: stream-extractor scan [OPTIONS] --input <INPUT>

Options:
  -i, --input <INPUT>  Input pcap file to scan
  -p, --port <PORT>    Search PCAP to see if this port number is present
      --ip <IP>        Search PCAP to see if this IP address is present
  -m, --mac <MAC>      Search PCAP to see if this MAC address is present
  -c, --count          Count how many times the search terms are present
  -v, --verbose        Enable to print verbose connection info
  -h, --help           Print help
```

### List

```bash
Usage: stream-extractor list [OPTIONS] --input <INPUT>

Options:
  -i, --input <INPUT>  Input pcap file to list
  -c, --count          Count how many communications are present
  -p, --ports          List the port numbers present
      --ip             List the IP addresses present
  -m, --mac            List the MAC addresses present
  -v, --verbose        Print all connection statistics
  -h, --help           Print help
```

## Filter Options

The filter options `--port`, `--ip`, and `--mac` are available to allow you to only write out the detected streams that match the filter values. This can help simplify
the research step of identifying exactly which streams you may be interested in.

Example:
```bash
stream-extractor extract --ip 192.168.110.10 -p 80 -i sample/test.pcap
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

## Install from cargo

To build and install from `cargo`, execute:
```bash
cargo install stream-extractor
```

An example PCAP is located in `sample/`.
