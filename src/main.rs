use clap::Parser;
use pcap_file::pcap::PcapHeader;
use pcap_file::pcap::PcapPacket;
use pcap_file::pcap::{PcapReader, PcapWriter};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Write;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Data that represents a TCP stream
#[derive(Debug, Copy, Clone, PartialEq)]
struct StreamInfo {
    a_port: u16,
    b_port: u16,
    a_ip: Ipv4Addr,
    b_ip: Ipv4Addr,
    a_mac: MacAddr,
    b_mac: MacAddr,
    packet_type: PacketType,
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum PacketType {
    Tcp,
    Udp,
    Ipv4,
}

#[derive(Debug, Default, Clone, PartialEq)]
struct StreamCounts {
    tcp: usize,
    udp: usize,
    ipv4: usize,
    ports: Vec<u16>,
    ipaddrs: Vec<Ipv4Addr>,
    macs: Vec<MacAddr>,
}

impl StreamCounts {
    pub fn tally(input: &Vec<Stream>) -> Self {
        let mut counts = Self::default();
        for stream in input {
            match stream.info.packet_type {
                PacketType::Tcp => counts.tcp += 1,
                PacketType::Udp => counts.udp += 1,
                PacketType::Ipv4 => counts.ipv4 += 1,
            };

            if !counts.ports.contains(&stream.info.a_port) {
                counts.ports.push(stream.info.a_port);
            }

            if !counts.ports.contains(&stream.info.b_port) {
                counts.ports.push(stream.info.b_port);
            }

            if !counts.ipaddrs.contains(&stream.info.a_ip) {
                counts.ipaddrs.push(stream.info.a_ip);
            }

            if !counts.ipaddrs.contains(&stream.info.b_ip) {
                counts.ipaddrs.push(stream.info.b_ip);
            }
            if !counts.macs.contains(&stream.info.a_mac) {
                counts.macs.push(stream.info.a_mac);
            }
            if !counts.macs.contains(&stream.info.b_mac) {
                counts.macs.push(stream.info.b_mac);
            }
        }

        counts.ports.sort();
        counts.ipaddrs.sort();
        counts.macs.sort();

        counts
    }

    pub fn print_comms(&self) {
        println!(
            "TCP stream count: {}\nUDP communications count: {}\nIPv4 pair count: {}\nUnique ports: {}\nUnique IP addresses: {}\nUnique MAC addresses: {}",
            self.tcp, self.udp, self.ipv4, self.ports.len(), self.ipaddrs.len(), self.macs.len(),
        );
    }

    pub fn print_ports(&self) {
        println!("Ports present: {:?}", self.ports);
    }

    pub fn print_ipaddrs(&self) {
        println!("IP Addresses present: {:?}", self.ipaddrs);
    }

    pub fn print_macs(&self) {
        println!("MAC Addresses present: {:?}", self.macs);
    }
}

/// The TCP Stream Extractor will extract all TCP streams from a pcap and rewrite them into separate pcap files
#[derive(Debug, Clone, Parser)]
#[command(version)]
struct Opt {
    /// Command
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Clone, Parser)]
enum Cmd {
    /// Extract TCP streams from a PCAP
    Extract(ExtractOpt),

    /// Scan the PCAP and search for an IP or Port
    Scan(ScanOpt),

    /// List all of the PCAP communication info
    List(ListOpt),
}

#[derive(Debug, Clone, Parser)]
struct ExtractOpt {
    /// Input pcap file to extract TCP streams from
    #[arg(short, long, required = true)]
    input: String,

    /// Output name template
    #[arg(short, long, default_value = "output_")]
    output: String,

    /// Filter output files to ones that contain the specified port number
    #[arg(short, long)]
    port: Option<u16>,

    /// Filter output files to ones that contain the specified IP address
    #[arg(long)]
    ip: Option<Ipv4Addr>,

    /// Deduplicate adjacent packets
    #[arg(short, long)]
    deduplicate: bool,

    /// Enable verbose mode to print TCP stream info for each output PCAP file
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone, Parser)]
struct ListOpt {
    /// Input pcap file to list
    #[arg(short, long, required = true)]
    input: String,

    /// Count how many communications are present
    #[arg(short, long)]
    count: bool,

    /// List the port numbers present
    #[arg(short, long)]
    ports: bool,

    /// List the IP addresses present
    #[arg(long)]
    ip: bool,

    /// List the MAC addresses present
    #[arg(short, long)]
    mac: bool,

    /// Print all connection statistics
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone, Parser)]
struct ScanOpt {
    /// Input pcap file to scan
    #[arg(short, long, required = true)]
    input: String,

    /// Search PCAP to see if this port number is present
    #[arg(short, long)]
    port: Option<u16>,

    /// Search PCAP to see if this IP address is present
    #[arg(long)]
    ip: Option<Ipv4Addr>,

    /// Search PCAP to see if this MAC address is present
    #[arg(short, long)]
    mac: Option<MacAddr>,

    /// Count how many times the search terms are present
    #[arg(short, long)]
    count: bool,

    /// Enable to print verbose connection info
    #[arg(short, long)]
    verbose: bool,
}

impl StreamInfo {
    /// Attempt to generate a new StreamInfo from an Ethernet packet payload
    pub fn new(input: &EthernetPacket) -> Option<Self> {
        let ipv4 = Ipv4Packet::new(input.payload())?;
        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
            return Some(Self {
                a_port: tcp.get_source(),
                b_port: tcp.get_destination(),
                a_ip: ipv4.get_source(),
                b_ip: ipv4.get_destination(),
                a_mac: input.get_source(),
                b_mac: input.get_destination(),
                packet_type: PacketType::Tcp,
            });
        } else if let Some(udp) = UdpPacket::new(ipv4.payload()) {
            return Some(Self {
                a_port: udp.get_source(),
                b_port: udp.get_destination(),
                a_ip: ipv4.get_source(),
                b_ip: ipv4.get_destination(),
                a_mac: input.get_source(),
                b_mac: input.get_destination(),
                packet_type: PacketType::Udp,
            });
        }

        Some(Self {
            a_port: 0,
            b_port: 0,
            a_ip: ipv4.get_source(),
            b_ip: ipv4.get_destination(),
            a_mac: input.get_source(),
            b_mac: input.get_destination(),
            packet_type: PacketType::Ipv4,
        })
    }

    /// Validate if the current stream is the same as the other stream
    pub fn is_stream(&self, other: &StreamInfo) -> bool {
        self.same_ports(other) && self.same_ips(other) && self.same_packet_type(other)
    }

    fn same_ports(&self, other: &StreamInfo) -> bool {
        (self.a_port == other.a_port && self.b_port == other.b_port)
            || (self.a_port == other.b_port && self.b_port == other.a_port)
    }

    fn same_ips(&self, other: &StreamInfo) -> bool {
        (self.a_ip == other.a_ip && self.b_ip == other.b_ip)
            || (self.a_ip == other.b_ip && self.b_ip == other.a_ip)
    }

    fn same_packet_type(&self, other: &StreamInfo) -> bool {
        self.packet_type == other.packet_type
    }

    fn contains_port(&self, port: u16) -> bool {
        self.a_port == port || self.b_port == port
    }
    fn contains_ipaddr(&self, ip: Ipv4Addr) -> bool {
        self.a_ip == ip || self.b_ip == ip
    }

    fn contains_mac(&self, mac: MacAddr) -> bool {
        self.a_mac == mac || self.b_mac == mac
    }
}

impl fmt::Display for StreamInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MAC Addresses: [{}, {}] IP Addresses: [{}, {}] Ports: [{}, {}] {:?}",
            self.a_mac,
            self.b_mac,
            self.a_ip,
            self.b_ip,
            self.a_port,
            self.b_port,
            self.packet_type,
        )
    }
}

/// Temporary data structure that contains the minumum amount of data to reconstruct the pcap
#[derive(Debug, Clone)]
struct PPacket {
    ts: Duration,
    data: Vec<u8>,
}

impl PPacket {
    /// Generate a new PPacket from a pcap_file::PcapPacket
    pub fn new(packet: &PcapPacket) -> Self {
        Self {
            ts: packet.timestamp,
            data: packet.data.to_vec(),
        }
    }

    /// Get the length of the captured packet data
    pub fn len(&self) -> u32 {
        self.data.len().try_into().unwrap()
    }

    /// Export a PPacket as a pcap_file::PcapPacket
    pub fn to_pcap_packet(&self) -> PcapPacket {
        PcapPacket::new(self.ts, self.len(), &self.data)
    }
}

#[derive(Debug, Clone)]
struct Stream {
    info: StreamInfo,
    packets: Vec<PPacket>,
}

impl Stream {
    /// Generate a new Stream struct
    pub fn new(info: StreamInfo, packet: PPacket) -> Stream {
        let packets = vec![packet];

        Self { info, packets }
    }

    /// Add a captured packet to the Stream and also update the StreamInfo
    pub fn add_and_update(&mut self, si: StreamInfo, packet: PPacket) {
        self.info = si;
        self.add(packet);
    }

    /// Add a captured packet to the Stream
    pub fn add(&mut self, packet: PPacket) {
        self.packets.push(packet);
    }

    /// Check if the StreamInfo matches the current stream
    pub fn is_stream(&self, other: &StreamInfo) -> bool {
        self.info.is_stream(other)
    }
}

fn main() {
    let opt = Opt::parse();

    match opt.cmd {
        Cmd::Extract(ext) => exec_extract(ext),
        Cmd::List(list) => exec_list(list),
        Cmd::Scan(scan) => exec_scan(scan),
    };
}

fn exec_list(opt: ListOpt) {
    if let Some((_, output)) = read_pcap(&opt.input) {
        if output.is_empty() {
            println!("No streams present.");
            return;
        }
        if opt.verbose {
            for (n, stream) in output.iter().enumerate() {
                println!("{n}: {} Packets: {}", stream.info, stream.packets.len());
            }
        }
        if opt.count || opt.ports || opt.ip || opt.mac {
            let counts = StreamCounts::tally(&output);
            if opt.count {
                counts.print_comms();
            }
            if opt.ports {
                counts.print_ports();
            }
            if opt.ip {
                counts.print_ipaddrs();
            }
            if opt.mac {
                counts.print_macs();
            }
        }
    }
}

fn exec_scan(opt: ScanOpt) {
    if let Some((_, mut output)) = read_pcap(&opt.input) {
        output = filter_port(output, opt.port);
        output = filter_ip(output, opt.ip);
        output = filter_mac(output, opt.mac);
        if output.is_empty() {
            println!("No streams matched filter.");
            return;
        }
        if opt.verbose {
            for (n, stream) in output.iter().enumerate() {
                println!("{n}: {} Packets: {}", stream.info, stream.packets.len());
            }
        }
        if opt.count {
            let counts = StreamCounts::tally(&output);
            counts.print_comms();
        }
    }
}

fn exec_extract(opt: ExtractOpt) {
    if let Some((header, mut output)) = read_pcap(&opt.input) {
        let orig_len = output.len();
        output = filter_port(output, opt.port);
        output = filter_ip(output, opt.ip);
        output = filter_dedupe(output, opt.deduplicate);
        if output.is_empty() {
            println!("No streams matched filter.");
            return;
        }
        if orig_len != output.len() {
            println!("Number of streams that matched filters: {}", output.len());
        }
        // Write out all extracted TCP streams
        write_pcap(header, output, &opt.output, opt.verbose, PacketType::Tcp);
    }
}

fn read_pcap(input: &str) -> Option<(PcapHeader, Vec<Stream>)> {
    let file_in = File::open(input).expect("Error opening file");
    let mut pcap_reader = PcapReader::new(file_in).unwrap();

    // Save pcap header for later
    let header = pcap_reader.header();

    let mut output = Vec::<Stream>::new();

    // Iterate over each packet in the original pcap file
    let mut count = 0;
    'nextpkt: while let Some(pkt) = pcap_reader.next_packet() {
        count += 1;
        print!(
            "\rPackets processed: {count}, Connections detected: {}",
            output.len()
        );
        io::stdout().flush().expect("Fatal IO error");

        // Extract each packet
        let pkt = pkt.unwrap();
        let packet = PPacket::new(&pkt);

        // Validate it is an Ethernet packet
        if let Some(eth) = EthernetPacket::new(&pkt.data) {
            // Validate it is an IPv4 packet
            if eth.get_ethertype() == EtherTypes::Ipv4 {
                // Validate it is a TCP packet and we have extracted it
                if let Some(si) = StreamInfo::new(&eth) {
                    // If our list is empty, add it
                    if output.is_empty() {
                        output.push(Stream::new(si, packet));
                        continue 'nextpkt;
                    } else {
                        // Iterate through our list of Streams
                        // Add packet to Stream if we found a match
                        for s in output.iter_mut() {
                            if s.is_stream(&si) {
                                s.add_and_update(si, packet);
                                continue 'nextpkt;
                            }
                        }

                        // If no stream matched, add a new Stream to our list
                        output.push(Stream::new(si, packet));
                    }
                }
            }
        }
    }
    println!();

    if output.is_empty() {
        None
    } else {
        Some((header, output))
    }
}

fn filter_port(streams: Vec<Stream>, port: Option<u16>) -> Vec<Stream> {
    if let Some(port) = port {
        println!("Filtering streams by communications including port: {port}");
        let filtered: Vec<_> = streams
            .into_iter()
            .filter(|s| s.info.contains_port(port))
            .collect();
        println!(" + Found {} matching streams", filtered.len());
        filtered
    } else {
        streams
    }
}

fn filter_ip(streams: Vec<Stream>, ip: Option<Ipv4Addr>) -> Vec<Stream> {
    if let Some(ip) = ip {
        println!("Filtering streams by communications including IP address: {ip}");
        let filtered: Vec<_> = streams
            .into_iter()
            .filter(|s| s.info.contains_ipaddr(ip))
            .collect();
        println!(" + Found {} matching streams", filtered.len());
        filtered
    } else {
        streams
    }
}

fn filter_mac(streams: Vec<Stream>, mac: Option<MacAddr>) -> Vec<Stream> {
    if let Some(mac) = mac {
        println!("Filtering streams by communications including MAC address: {mac}");
        let filtered: Vec<_> = streams
            .into_iter()
            .filter(|s| s.info.contains_mac(mac))
            .collect();
        println!(" + Found {} matching streams", filtered.len());
        filtered
    } else {
        streams
    }
}

fn filter_dedupe(streams: Vec<Stream>, dedupe: bool) -> Vec<Stream> {
    if dedupe {
        let mut filtered = Vec::<Stream>::new();
        for stream in streams {
            if stream.packets.len() <= 1 {
                filtered.push(stream);
                continue;
            }
            let mut prev_data = stream.packets[0].clone();
            let mut new_stream = Stream::new(stream.info, prev_data.clone());
            for p in stream.packets.iter().skip(1) {
                if p.data == prev_data.data {
                    continue;
                }

                new_stream.add(p.clone());
                prev_data = p.clone();
            }
            filtered.push(new_stream);
        }

        filtered
    } else {
        streams
    }
}

fn write_pcap(
    header: PcapHeader,
    streams: Vec<Stream>,
    out: &str,
    verbose: bool,
    packet_type: PacketType,
) {
    if verbose {
        println!("Writing files...");
    }

    // Iterate through every stream
    for (n, stream) in streams.iter().enumerate() {
        if stream.info.packet_type != packet_type {
            continue;
        }
        // Open new file with the original pcap header
        let filename = format!("{out}{n:04}.pcap");
        let file = File::create(&filename).expect("Error opening output file");
        let mut pcap_writer = PcapWriter::with_header(file, header).expect("Error writing file");

        if verbose {
            println!(
                "{filename}: {} Packets: {}",
                stream.info,
                stream.packets.len()
            );
        } else {
            print!("\rWriting output file: {}", n + 1,);
            io::stdout().flush().expect("Fatal IO error");
        }

        // Write every packet in the Stream to the new pcap file
        for p in &stream.packets {
            let packet = p.to_pcap_packet();
            pcap_writer.write_packet(&packet).unwrap();
        }
    }
    println!();
}
