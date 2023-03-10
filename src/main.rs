use clap::Parser;
use pcap_file::pcap::PcapHeader;
use pcap_file::pcap::PcapPacket;
use pcap_file::pcap::{PcapReader, PcapWriter};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
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
    seq: u32,
    ack: u32,
}

/// The TCP Stream Extractor will extract all TCP streams from a pcap and rewrite them into separate pcap files
#[derive(Debug, Clone, Parser)]
struct Opt {
    /// Input pcap file to split
    #[arg(short, long, required = true)]
    input: String,

    /// Output name template
    #[arg(short, long, default_value = "output_")]
    output: String,
}

impl StreamInfo {
    /// Attempt to generate a new StreamInfo from an Ethernet packet payload
    pub fn new(input: &[u8]) -> Option<Self> {
        let ipv4 = Ipv4Packet::new(input)?;
        let tcp = TcpPacket::new(ipv4.payload())?;

        Some(Self {
            a_port: tcp.get_source(),
            b_port: tcp.get_destination(),
            a_ip: ipv4.get_source(),
            b_ip: ipv4.get_destination(),
            seq: tcp.get_sequence(),
            ack: tcp.get_acknowledgement(),
        })
    }

    /// Validate if the current stream is the same as the other stream
    pub fn is_stream(&self, other: &StreamInfo) -> bool {
        self.same_ports(other) && self.same_ips(other) //&& self.sequence(other)
    }

    fn same_ports(&self, other: &StreamInfo) -> bool {
        (self.a_port == other.a_port && self.b_port == other.b_port)
            || (self.a_port == other.b_port && self.b_port == other.a_port)
    }

    fn same_ips(&self, other: &StreamInfo) -> bool {
        (self.a_ip == other.a_ip && self.b_ip == other.b_ip)
            || (self.a_ip == other.b_ip && self.b_ip == other.a_ip)
    }

    fn sequence(&self, other: &StreamInfo) -> bool {
        (self.ack == other.seq) || (self.ack == other.ack && self.seq == other.seq)
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

    if let Some((header, output)) = read_pcap(&opt.input) {
        // Write out all extracted TCP streams
        write_pcap(header, output, &opt.output);
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
            "\rPackets processed: {count}, Streams detected: {}",
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
                if let Some(si) = StreamInfo::new(eth.payload()) {
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

fn write_pcap(header: PcapHeader, streams: Vec<Stream>, out: &str) {
    // Iterate through every stream
    for (n, stream) in streams.iter().enumerate() {
        // Open new file with the original pcap header
        let file = File::create(format!("{out}{n:04}.pcap")).expect("Error opening output file");
        let mut pcap_writer = PcapWriter::with_header(file, header).expect("Error writing file");

        print!("\rWriting output file: {}", n + 1,);
        io::stdout().flush().expect("Fatal IO error");

        // Write every packet in the Stream to the new pcap file
        for p in &stream.packets {
            let packet = p.to_pcap_packet();
            pcap_writer.write_packet(&packet).unwrap();
        }
    }
    println!();
}
