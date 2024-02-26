use clap::Parser;
use streaming::read_pcaps;
use streaming::write_pcaps;
use parsing::PPacket;
use parsing::StreamInfo;
use parsing::StreamKey;
use pcap_file::pcap::PcapHeader;
use pcap_file::pcap::PcapReader;
use pnet::util::MacAddr;
use std::fs::File;
use std::net::IpAddr;
use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::thread;

use crate::parsing::PacketType;
use crate::parsing::StreamCounts;

mod streaming;
mod parsing;

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
    ip: Option<Vec<IpAddr>>,

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
    ip: Option<Vec<IpAddr>>,

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
        // We want things sorted
        counts.sort();
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
    let mut filter = Filter::new(opt.port, opt.ip, opt.mac, None);

    input
        .into_iter()
        .map(|x| {
            let (_, (info, _)) = x;
            info
        })
        .filter(|info| {
            let res = filter.filter(&info);
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
    let mut filter = Filter::new(opt.port, opt.ip, opt.mac, Some([PacketType::Tcp].to_vec()));
    let iter = input
        .into_iter()
        .filter(|x| {
            let (_, (info, _)) = x;
            let res = filter.filter(&info);
            if res {
                filter.bump();
            }
            res
        })
        .filter(|x| {
            let (_, (info, _)) = x;
            matches!(info.packet_type, PacketType::Tcp)
        });

    write_pcaps(header, &opt.output, iter);
    println!("Number of streams that matched filters: {}", filter.matches);
}

struct Filter {
    matches: usize,
    ports: Option<Vec<u16>>,
    ips: Option<Vec<IpAddr>>,
    macs: Option<Vec<MacAddr>>,
    protos: Option<Vec<PacketType>>,
}
impl Filter {
    pub fn new(
        ports: Option<Vec<u16>>,
        ips: Option<Vec<IpAddr>>,
        macs: Option<Vec<MacAddr>>,
        protos: Option<Vec<PacketType>>,
    ) -> Self {
        Self {
            matches: 0,
            ports,
            ips,
            macs,
            protos,
        }
    }
    pub fn filter(&self, info: &StreamInfo) -> bool {
        self.filter_ip(&[info.a_ip, info.b_ip])
            && self.filter_port(&[info.a_port, info.b_port])
            && self.filter_mac(&[info.a_mac, info.b_mac])
            && self.filter_proto(&[info.packet_type])
    }
    pub fn bump(&mut self) {
        self.matches += 1;
    }
    fn filter_proto(&self, proto: &[PacketType]) -> bool {
        if let Some(ref protos) = self.protos {
            proto.iter().any(|x| protos.contains(x))
        } else {
            // Default to allowed if no filter is set
            true
        }
    }
    fn filter_port(&self, port: &[u16]) -> bool {
        if let Some(ref ports) = self.ports {
            port.iter().any(|x| ports.contains(x))
        } else {
            // Default to allowed if no filter is set
            true
        }
    }

    fn filter_ip(&self, ip: &[IpAddr]) -> bool {
        if let Some(ref ips) = self.ips {
            ip.iter().any(|x| ips.contains(x))
        } else {
            // Default to allowed if no filter is set
            true
        }
    }

    fn filter_mac(&self, mac: &[MacAddr]) -> bool {
        if let Some(ref macs) = self.macs {
            mac.iter().any(|x| macs.contains(&x))
        } else {
            // Default to allowed if no filter is set
            true
        }
    }
}
