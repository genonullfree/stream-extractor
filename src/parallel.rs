use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read, Write},
    net::IpAddr,
    sync::mpsc::Sender,
};

use pcap_file::pcap::{PcapHeader, PcapReader, PcapWriter};
use pnet::{packet::ethernet::EthernetPacket, util::MacAddr};

use crate::{PPacket, PacketType, StreamInfo};

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

pub fn read_pcaps<R: Read>(
    mut input: PcapReader<R>,
    destination: Sender<(StreamKey, (StreamInfo, PPacket))>,
) {
    let mut seen_streams: HashMap<StreamKey, usize> = HashMap::new();

    // For statistics
    let mut count = 0;
    while let Some(pkt) = input.next_packet() {
        count += 1;
        print!(
            "\rPackets processed: {count}, Connections detected: {}",
            seen_streams.len()
        );
        io::stdout().flush().expect("Fatal IO error");

        // Extract each packet
        let pkt = pkt.unwrap();
        let packet = PPacket::new(&pkt);

        // Validate it is an Ethernet packet
        if let Some(eth) = EthernetPacket::new(&pkt.data) {
            // Validate it is a TCP packet and we have extracted it
            if let Some(mut si) = StreamInfo::new(&eth, count, packet.data.len()) {
                let key = StreamKey::new(
                    si.a_ip,
                    si.a_port,
                    si.a_mac,
                    si.b_ip,
                    si.b_port,
                    si.b_mac,
                    si.packet_type,
                );

                match seen_streams.get_mut(&key) {
                    Some(id) => {
                        // Stream is already seen. Grab info from map and send it on Sender
                        si.id = *id;
                        destination.send((key, (si, packet))).unwrap();
                    }
                    None => {
                        // We have never seen this stream before. Create an entry for it and pass it on
                        let id = seen_streams.len();
                        si.id = id;

                        seen_streams.insert(key.clone(), id);
                        destination.send((key, (si, packet))).unwrap();
                    }
                }
            }
        }
    }
    println!();
}

pub fn write_pcaps(
    header: PcapHeader,
    filename_prefix: &str,
    source: impl Iterator<Item = (StreamKey, (StreamInfo, PPacket))>,
) {
    let mut destinations: HashMap<StreamKey, PcapWriter<File>> = HashMap::new();

    for (key, (si, p)) in source {
        let packet = p.to_pcap_packet();

        match destinations.get_mut(&key) {
            Some(writer) => {
                writer.write_packet(&packet).unwrap();
            }
            None => {
                let streamid = si.id;

                let filename = format!("{filename_prefix}{streamid:04}.pcap");
                // TODO: We cant have all these handles open all the time. Get around this somehow.
                let file = File::create(&filename).expect("Error opening output file");
                let mut pcap_writer =
                    PcapWriter::with_header(file, header).expect("Error writing file");
                pcap_writer.write_packet(&packet).unwrap();

                destinations.insert(key, pcap_writer);
            }
        }
    }
}
