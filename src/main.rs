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
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Write;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Data that represents a packet stream
#[derive(Debug, Copy, Clone)]
struct StreamInfo {
    a_port: u16,
    b_port: u16,
    a_ip: Ipv4Addr,
    b_ip: Ipv4Addr,
    a_mac: MacAddr,
    b_mac: MacAddr,
    packet_type: PacketType,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
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
    /// Unique stream id. We embed this here
    /// to avoid an implicit dependency between the order we saw this Stream
    /// and the order in which it is stored in a datastructure.
    id: usize,
    info: StreamInfo,
    packets: Vec<PPacket>,
}

impl Stream {
    /// Generate a new Stream struct
    pub fn new(id: usize, info: StreamInfo, packet: PPacket) -> Stream {
        let packets = vec![packet];

        Self { id, info, packets }
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
}

fn main() {
    let opt = Opt::parse();

    match opt.cmd {
        Cmd::Extract(ext) => exec_extract_tcpstreams(ext),
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
            for stream in output.iter() {
                println!(
                    "{}: {} Packets: {}",
                    stream.id,
                    stream.info,
                    stream.packets.len()
                );
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
            for stream in output.iter() {
                println!(
                    "{}: {} Packets: {}",
                    stream.id,
                    stream.info,
                    stream.packets.len()
                );
            }
        }
        if opt.count {
            let counts = StreamCounts::tally(&output);
            counts.print_comms();
        }
    }
}

fn exec_extract_tcpstreams(opt: ExtractOpt) {
    if let Some((header, mut output)) = read_pcap(&opt.input) {
        let orig_len = output.len();
        output = filter_port(output, opt.port);
        output = filter_ip(output, opt.ip);
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

/// Used internally in read_pcap to identify a stream for quick lookups
#[derive(Ord, PartialOrd, PartialEq, Eq)]
struct StreamKey {
    ips: [Ipv4Addr; 2],
    ports: [u16; 2],
    macs: [MacAddr; 2],
    packet_type: PacketType,
}
impl StreamKey {
    fn new(
        ip_a: Ipv4Addr,
        port_a: u16,
        mac_a: MacAddr,
        ip_b: Ipv4Addr,
        port_b: u16,
        mac_b: MacAddr,
        packet_type: PacketType,
    ) -> Self {
        let mut ips = [ip_a, ip_b];
        ips.sort();
        let mut ports = [port_a, port_b];
        ports.sort();
        let mut macs = [mac_a, mac_b];
        macs.sort();
        Self {
            ips,
            ports,
            macs,
            packet_type,
        }
    }
}
fn read_pcap(input: &str) -> Option<(PcapHeader, Vec<Stream>)> {
    let file_in = File::open(input).expect("Error opening file");
    let mut pcap_reader = PcapReader::new(file_in).unwrap();

    // Save pcap header for later
    let header = pcap_reader.header();

    // We want to retain the order we saw each stream without having to sort the output vector.
    // This isn't as good as a HashMap, but it's a stdlib structure with support for this
    let mut output: BTreeMap<StreamKey, Stream> = BTreeMap::new();

    // Iterate over each packet in the original pcap file
    let mut count = 0;
    while let Some(pkt) = pcap_reader.next_packet() {
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
                    let key = StreamKey::new(
                        si.a_ip,
                        si.a_port,
                        si.a_mac,
                        si.b_ip,
                        si.b_port,
                        si.b_mac,
                        si.packet_type,
                    );

                    if let Some(s) = output.get_mut(&key) {
                        // Stream already exists. Extend it
                        s.add_and_update(si, packet);
                    } else {
                        // No matching stream, create set it's id and store it
                        if output.insert(key, Stream::new(count, si, packet)).is_some() {
                            panic!("This should never happen");
                        }
                    }
                }
            }
        }
    }
    println!();

    if output.is_empty() {
        None
    } else {
        Some((header, output.into_values().collect()))
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
    for stream in streams.iter() {
        let streamid = stream.id;

        if stream.info.packet_type != packet_type {
            continue;
        }
        // Open new file with the original pcap header
        let filename = format!("{out}{streamid:04}.pcap");
        let file = File::create(&filename).expect("Error opening output file");
        let mut pcap_writer = PcapWriter::with_header(file, header).expect("Error writing file");

        if verbose {
            println!(
                "{filename}: {} Packets: {}",
                stream.info,
                stream.packets.len()
            );
        } else {
            print!("\rWriting output file: {}", streamid,);
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
