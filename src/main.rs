use clap::Parser;
use parallel::read_pcaps;
use parallel::write_pcaps;
use parallel::StreamKey;
use pcap_file::pcap::PcapHeader;
use pcap_file::pcap::PcapPacket;
use pcap_file::pcap::PcapReader;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::net::Ipv4Addr;
use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::thread;
use std::time::Duration;

mod parallel;

/// Data that represents a packet stream
#[derive(Debug, Copy, Clone)]
struct StreamInfo {
    /// Unique stream id. We embed this here
    /// to avoid an implicit dependency between the order we saw this Stream
    /// and the order in which it is stored in a datastructure.
    id: usize,
    a_port: u16,
    b_port: u16,
    a_ip: Ipv4Addr,
    b_ip: Ipv4Addr,
    a_mac: MacAddr,
    b_mac: MacAddr,
    packet_type: PacketType,
    size: usize,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
enum PacketType {
    Tcp,
    Udp,
    Ipv4,
}

#[derive(Default, Clone)]
struct StreamCounts {
    seen: HashSet<StreamKey>,
    tcp: usize,
    udp: usize,
    ipv4: usize,
    ports: Vec<u16>,
    ipaddrs: Vec<Ipv4Addr>,
    macs: Vec<MacAddr>,
}

impl StreamCounts {
    /// Use StreamInfo to calculate statistics and give it back
    /// Allowing data to be streamed through
    pub fn tally(&mut self, info: StreamInfo) -> StreamInfo {
        let key = StreamKey::new(
            info.a_ip,
            info.a_port,
            info.a_mac,
            info.b_ip,
            info.b_port,
            info.b_mac,
            info.packet_type,
        );
        if !self.seen.contains(&key) {
            self.seen.insert(key);
            match info.packet_type {
                PacketType::Tcp => self.tcp += 1,
                PacketType::Udp => self.udp += 1,
                PacketType::Ipv4 => self.ipv4 += 1,
            };

            if !self.ports.contains(&info.a_port) {
                self.ports.push(info.a_port);
            }

            if !self.ports.contains(&info.b_port) {
                self.ports.push(info.b_port);
            }

            if !self.ipaddrs.contains(&info.a_ip) {
                self.ipaddrs.push(info.a_ip);
            }

            if !self.ipaddrs.contains(&info.b_ip) {
                self.ipaddrs.push(info.b_ip);
            }
            if !self.macs.contains(&info.a_mac) {
                self.macs.push(info.a_mac);
            }
            if !self.macs.contains(&info.b_mac) {
                self.macs.push(info.b_mac);
            }
        }
        info
    }

    pub fn sort(&mut self) {
        self.ports.sort();
        self.ipaddrs.sort();
        self.macs.sort();
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
    /// Input pcap file
    #[arg(short, long, required = true)]
    input: String,

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
    /// Output name template
    #[arg(short, long, default_value = "output_")]
    output: String,

    /// Filter output files to ones that contain the specified port numbers
    #[arg(short, long)]
    port: Option<Vec<u16>>,

    /// Filter output files to ones that contain the specified IP addresses
    #[arg(long)]
    ip: Option<Vec<Ipv4Addr>>,

    /// Filter output files to ones that contain the specified MAC addresses
    #[arg(short, long)]
    mac: Option<Vec<MacAddr>>,

    /// Enable verbose mode to print TCP stream info for each output PCAP file
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone, Parser)]
struct ListOpt {
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
    /// Search PCAP to see if any of provided ports is present
    #[arg(short, long)]
    port: Option<Vec<u16>>,

    /// Search PCAP to see if any of provided addresss is present
    #[arg(long)]
    ip: Option<Vec<Ipv4Addr>>,

    /// Search PCAP to see if any of provided MAC address is present
    #[arg(short, long)]
    mac: Option<Vec<MacAddr>>,

    /// Count how many times the search terms are present
    #[arg(short, long)]
    count: bool,

    /// Enable to print verbose connection info
    #[arg(short, long)]
    verbose: bool,
}

impl StreamInfo {
    /// Attempt to generate a new StreamInfo from an Ethernet packet payload
    pub fn new(input: &EthernetPacket, id: usize, size: usize) -> Option<Self> {
        let ipv4 = Ipv4Packet::new(input.payload())?;
        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
            return Some(Self {
                id,
                a_port: tcp.get_source(),
                b_port: tcp.get_destination(),
                a_ip: ipv4.get_source(),
                b_ip: ipv4.get_destination(),
                a_mac: input.get_source(),
                b_mac: input.get_destination(),
                packet_type: PacketType::Tcp,
                size,
            });
        } else if let Some(udp) = UdpPacket::new(ipv4.payload()) {
            return Some(Self {
                id,

                a_port: udp.get_source(),
                b_port: udp.get_destination(),
                a_ip: ipv4.get_source(),
                b_ip: ipv4.get_destination(),
                a_mac: input.get_source(),
                b_mac: input.get_destination(),
                packet_type: PacketType::Udp,
                size,
            });
        }

        Some(Self {
            id,
            a_port: 0,
            b_port: 0,
            a_ip: ipv4.get_source(),
            b_ip: ipv4.get_destination(),
            a_mac: input.get_source(),
            b_mac: input.get_destination(),
            packet_type: PacketType::Ipv4,
            size,
        })
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

fn main() {
    let opt = Opt::parse();

    let file_in = File::open(opt.input).expect("Error opening file");
    let pcap_reader = PcapReader::new(file_in).unwrap();
    let header = pcap_reader.header();
    let (sender, receiver) = channel();

    // Start the reading thread
    let _handle = thread::spawn(move || {
        read_pcaps(pcap_reader, sender);
    });

    match opt.cmd {
        Cmd::Extract(ext) => exec_extract_tcpstreams(receiver, header, ext),
        Cmd::List(list) => exec_list(receiver, list),
        Cmd::Scan(scan) => exec_scan(receiver, scan),
    };
}
fn exec_list(input: Receiver<(StreamKey, (StreamInfo, PPacket))>, opt: ListOpt) {
    let mut counts = StreamCounts::default();

    input
        .into_iter()
        .map(|x| {
            let (_, (info, _)) = x;
            info
        })
        .map(|info| counts.tally(info))
        .map(|info| {
            // Kinda dumb having to do this if check each time, but the performance is negligible
            // compared to println
            if opt.verbose {
                println!("{}: {} Packets: {}", info.id, info, info.size);
            }
            info
        })
        .count();

    if opt.count || opt.ports || opt.ip || opt.mac {
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

fn exec_scan(input: Receiver<(StreamKey, (StreamInfo, PPacket))>, opt: ScanOpt) {
    let mut counts = StreamCounts::default();
    let mut filter = Filter::new(opt.port, opt.ip, opt.mac);

    input
        .into_iter()
        .map(|x| {
            let (_, (info, _)) = x;
            info
        })
        .filter(|info| {
            let res = filter.filter_ip(&[info.a_ip, info.b_ip])
                && filter.filter_port(&[info.a_port, info.b_port])
                && filter.filter_mac(&[info.a_mac, info.b_mac]);
            if res {
                filter.bump();
            }
            res
        })
        .map(|info| counts.tally(info))
        .map(|info| {
            // Kinda dumb having to do this if check each time, but the performance is negligible
            // compared to println
            if opt.verbose {
                println!("{}: {} Packets: {}", info.id, info, info.size);
            }
            info
        })
        .count();
    println!("Number of streams that matched filters: {}", filter.matches);

    if opt.count {
        counts.print_comms();
    }
}

fn exec_extract_tcpstreams(
    input: Receiver<(StreamKey, (StreamInfo, PPacket))>,
    header: PcapHeader,
    opt: ExtractOpt,
) {
    let mut filter = Filter::new(opt.port, opt.ip, opt.mac);
    let iter = input.into_iter().filter(|x| {
        let (_, (info, _)) = x;
        let res = filter.filter_ip(&[info.a_ip, info.b_ip])
            && filter.filter_port(&[info.a_port, info.b_port])
            && filter.filter_mac(&[info.a_mac, info.b_mac]);
        if res {
            filter.bump();
        }
        res
    });

    write_pcaps(header, &opt.output, iter);
    println!("Number of streams that matched filters: {}", filter.matches);
}

struct Filter {
    matches: usize,
    ports: Option<Vec<u16>>,
    ips: Option<Vec<Ipv4Addr>>,
    macs: Option<Vec<MacAddr>>,
}
impl Filter {
    pub fn new(
        ports: Option<Vec<u16>>,
        ips: Option<Vec<Ipv4Addr>>,
        macs: Option<Vec<MacAddr>>,
    ) -> Self {
        Self {
            matches: 0,
            ports,
            ips,
            macs,
        }
    }
    pub fn bump(&mut self) {
        self.matches += 1;
    }
    fn filter_port(&mut self, port: &[u16]) -> bool {
        if let Some(ref ports) = self.ports {
            port.iter().any(|x| ports.contains(x))
        } else {
            // Default to allowed if no filter is set
            true
        }
    }

    fn filter_ip(&mut self, ip: &[Ipv4Addr]) -> bool {
        if let Some(ref ips) = self.ips {
            ip.iter().any(|x| ips.contains(x))
        } else {
            // Default to allowed if no filter is set
            true
        }
    }

    fn filter_mac(&mut self, mac: &[MacAddr]) -> bool {
        if let Some(ref macs) = self.macs {
            mac.iter().any(|x| macs.contains(&x))
        } else {
            // Default to allowed if no filter is set
            true
        }
    }
}
