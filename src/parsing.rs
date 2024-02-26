use std::{collections::HashSet, fmt, net::IpAddr, time::Duration};

use pcap_file::pcap::PcapPacket;
use pnet::{
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        tcp::TcpPacket,
        udp::UdpPacket,
        Packet,
    },
    util::MacAddr,
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum PacketType {
    Tcp,
    Udp,
    Other,
}

/// Temporary data structure that contains the minumum amount of data to reconstruct the pcap
#[derive(Debug, Clone)]
pub struct PPacket {
    ts: Duration,
    pub data: Vec<u8>,
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

/// Used internally in read_pcap to identify a stream for quick lookups
#[derive(Ord, PartialOrd, PartialEq, Eq, Hash, Clone)]
pub struct StreamKey {
    ips: [IpAddr; 2],
    ports: [u16; 2],
    macs: [MacAddr; 2],
    packet_type: PacketType,
}
impl StreamKey {
    pub fn new(
        ip_a: IpAddr,
        port_a: u16,
        mac_a: MacAddr,
        ip_b: IpAddr,
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

/// Data that represents a packet stream
#[derive(Debug, Copy, Clone)]
pub struct StreamInfo {
    /// Unique stream id. We embed this here
    /// to avoid an implicit dependency between the order we saw this Stream
    /// and the order in which it is stored in a datastructure.
    pub id: usize,
    pub a_port: u16,
    pub b_port: u16,
    pub a_ip: IpAddr,
    pub b_ip: IpAddr,
    pub a_mac: MacAddr,
    pub b_mac: MacAddr,
    pub packet_type: PacketType,
    pub size: usize,
}
impl StreamInfo {
    /// Attempt to generate a new StreamInfo from an Ethernet packet payload
    pub fn new(input: &EthernetPacket, id: usize, size: usize) -> Option<Self> {
        let ethertype = input.get_ethertype();

        let next_proto = if ethertype == EtherTypes::Ipv4 {
            let packet = Ipv4Packet::new(input.payload())?;
            let source: IpAddr = packet.get_source().into();
            let dest: IpAddr = packet.get_destination().into();

            Some((packet.get_next_level_protocol(), source, dest))
        } else if ethertype == EtherTypes::Ipv6 {
            let packet = Ipv6Packet::new(input.payload())?;
            let source: IpAddr = packet.get_source().into();
            let dest: IpAddr = packet.get_destination().into();
            Some((packet.get_next_header(), source, dest))
        } else {
            None
        };
        let (proto, source, destination) = next_proto?;

        if proto == IpNextHeaderProtocols::Tcp {
            let tcp = TcpPacket::new(input.payload())?;
            Some(Self {
                id,
                a_port: tcp.get_source(),
                b_port: tcp.get_destination(),
                a_ip: source,
                b_ip: destination,
                a_mac: input.get_source(),
                b_mac: input.get_destination(),
                packet_type: PacketType::Tcp,
                size,
            })
        } else if proto == IpNextHeaderProtocols::Udp {
            let udp = UdpPacket::new(input.payload())?;
            Some(Self {
                id,
                a_port: udp.get_source(),
                b_port: udp.get_destination(),
                a_ip: source,
                b_ip: destination,
                a_mac: input.get_source(),
                b_mac: input.get_destination(),
                packet_type: PacketType::Udp,
                size,
            })
        } else {
            Some(Self {
                id,
                a_port: 0,
                b_port: 0,
                a_ip: source,
                b_ip: destination,
                a_mac: input.get_source(),
                b_mac: input.get_destination(),
                packet_type: PacketType::Other,
                size,
            })
        }
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

#[derive(Default, Clone)]
pub struct StreamCounts {
    seen: HashSet<StreamKey>,
    tcp: usize,
    udp: usize,
    other: usize,
    ports: Vec<u16>,
    ipaddrs: Vec<IpAddr>,
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
                PacketType::Other => self.other += 1,
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
            "TCP stream count: {}\nUDP communications count: {}\nOther protos count: {}\nUnique ports: {}\nUnique IP addresses: {}\nUnique MAC addresses: {}",
            self.tcp, self.udp, self.other, self.ports.len(), self.ipaddrs.len(), self.macs.len(),
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
