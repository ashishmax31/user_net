use crate::ethernet;
use crate::ipv4::icmp;
use crate::ipv4::udp;
use crate::net_util;
use crate::tap::tap_device::MTU;
use std::convert::TryInto;
use std::sync::mpsc::channel;
use std::thread;

#[derive(Debug, Clone)]
pub struct IPstackWriter(std::sync::mpsc::Sender<Layer4Response>);

#[derive(Debug, Clone)]
pub struct Layer4Response {
    pub data: Vec<u8>,
    pub protocol: u8,
    pub src_ip_header: IpHeader,
}

// No bit fields :(
// MSB 0 bit numbering
#[derive(Debug, Clone)]
pub struct IPv4 {
    version: u8,
    ihl: u8,
    ecn: u8,
    t_len: u16,
    id: u16,
    flags: u8,
    frag_offset: u16,
    ttl: u8,
    proto: Protocol,
    chksm: u16,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct IpHeader {
    version: u8,
    ihl: u8,
    ecn: u8,
    t_len: u16,
    id: u16,
    flags: u8,
    frag_offset: u16,
    ttl: u8,
    pub proto: Protocol,
    chksm: u16,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

const ICMP: u8 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    ICMP,
    TCP,
    UDP,
    Unsupported,
}

impl ethernet::LinkLayerWritable for IPv4 {
    fn data(&self) -> Vec<u8> {
        self.packet_to_bytes()
    }

    fn spa(&self) -> ethernet::ProtocolAddr {
        self.src
    }

    fn tpa(&self) -> ethernet::ProtocolAddr {
        self.dst
    }

    fn ether_type(&self) -> [u8; 2] {
        (ethernet::ETH_IPV4 as u16).to_be_bytes()
    }
}

impl IPstackWriter {
    pub fn write(&self, packet_to_write: Layer4Response) {
        self.0.send(packet_to_write).unwrap();
    }
}

impl IpHeader {
    pub fn make_unfragmented_ip_header(
        src_ip: ethernet::ProtocolAddr,
        dst_ip: ethernet::ProtocolAddr,
        proto: u8,
        payload_len: u16,
    ) -> Self {
        let ihl = 5u8;
        IpHeader {
            version: 4,
            ihl: ihl,
            ecn: 0,
            t_len: (payload_len + (ihl * 4) as u16),
            id: 0,
            flags: 0,
            frag_offset: 0,
            ttl: 50,
            proto: set_proto(proto),
            chksm: 0,
            src: src_ip,
            dst: dst_ip,
        }
    }
}

impl IPv4 {
    pub fn process_packet(
        eth: &ethernet::Ethernet,
        frame: ethernet::EthernetFrame,
        ipv4_stack_writer: &IPstackWriter,
    ) {
        IPv4::handle_frame(frame, ipv4_stack_writer);
    }

    pub fn payload_bytes(&self) -> &[u8] {
        &self.data
    }
    // MSB 0 bit numbering
    // First n bytes means the the first n bytes from the left to right.
    pub fn packet_from_net_bytes(data: &[u8]) -> IPv4 {
        let parsed_packet = IPv4 {
            version: net_util::get_bits(data[0], 4..8),
            ihl: net_util::get_bits(data[0], 0..4),
            ecn: data[1],
            t_len: net_util::ntohs(&data[2..4]),
            id: net_util::ntohs(&data[4..6]),
            flags: net_util::get_bits(data[6], 5..8),
            frag_offset: (net_util::get_bits(data[6], 0..5) as u16) << 8 | data[7] as u16,
            ttl: data[8],
            proto: set_proto(data[9]),
            chksm: net_util::ntohs(&data[10..12]),
            src: data[12..16].try_into().unwrap(),
            dst: data[16..20].try_into().unwrap(),
            data: data[20..].to_owned(),
        };
        parsed_packet
    }

    fn packet_to_bytes(&self) -> Vec<u8> {
        let mut packet_buffer = Vec::new();
        let flag_frag_offset = self.frag_offset | (self.flags as u16);

        let version_header_byte = self.version << 4 | self.ihl;
        packet_buffer.push(version_header_byte);
        packet_buffer.push(self.ecn);
        packet_buffer.extend_from_slice(&self.t_len.to_be_bytes());
        packet_buffer.extend_from_slice(&self.id.to_be_bytes()); //
        packet_buffer.extend_from_slice(&flag_frag_offset.to_be_bytes());
        packet_buffer.push(self.ttl);
        packet_buffer.push(IPv4::get_proto_val(&self));
        packet_buffer.extend_from_slice(&self.chksm.to_be_bytes()); // Set header checksum as zero before computing the checksum
        packet_buffer.extend_from_slice(&self.src);
        packet_buffer.extend_from_slice(&self.dst);
        let (checksum, _) = net_util::compute_ip_checksum(&packet_buffer, 10..12);
        let chksum_bytes = checksum.to_be_bytes();
        packet_buffer[10] = chksum_bytes[0];
        packet_buffer[11] = chksum_bytes[1];
        packet_buffer.append(&mut self.data.clone());
        packet_buffer
    }

    pub fn ip_header(&self) -> IpHeader {
        IpHeader {
            version: self.version,
            ihl: self.ihl,
            ecn: self.ecn,
            t_len: self.t_len,
            id: self.id,
            flags: self.flags,
            frag_offset: self.frag_offset,
            ttl: self.ttl,
            proto: self.proto,
            chksm: self.chksm,
            src: self.src,
            dst: self.dst,
        }
    }

    pub fn src_str(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.src[0], self.src[1], self.src[2], self.src[3]
        )
    }

    fn get_proto_val(&self) -> u8 {
        match self.proto {
            Protocol::TCP => TCP,
            Protocol::ICMP => ICMP,
            Protocol::UDP => UDP,
            Protocol::Unsupported => unimplemented!(),
        }
    }

    fn build_unfragmented_packet(src_header: IpHeader, payload: Vec<u8>, proto: u8) -> IPv4 {
        let total_packet_len = (20 as usize + payload.len()) as u16;
        IPv4 {
            version: 04u8,
            ihl: 5u8, //No options field, so the header is always 20bytes.
            ecn: src_header.ecn,
            t_len: total_packet_len,
            id: 0u16,
            flags: 0u8,
            frag_offset: 0u16,
            ttl: 50u8,
            proto: set_proto(proto),
            chksm: 0u16,
            src: src_header.dst,
            dst: src_header.src,
            data: payload,
        }
    }

    fn build_ipv4_response(src_ip_header: IpHeader, payload: Vec<u8>, protocol: u8) -> IPv4 {
        if (payload.len() as u32) > MTU {
            // Need to implement ip packet fragmenting
            unimplemented!()
        } else {
            IPv4::build_unfragmented_packet(src_ip_header, payload, protocol)
        }
    }

    fn handle_frame(frame: ethernet::EthernetFrame, ipv4_stack: &IPstackWriter) {
        let protocol = IPv4::protocol_from_ip_bytes(frame.payload());

        match protocol {
            Protocol::ICMP => {
                icmp::ICMP::process_packet(frame, ipv4_stack);
            }
            Protocol::UDP => udp::UDP::process_packet(frame, ipv4_stack),
            Protocol::TCP => {
                // TODO: TCP
            }
            Protocol::Unsupported => {
                // Send ICMP error
            }
        }
    }

    fn protocol_from_ip_bytes(ipv4_bytes: &[u8]) -> Protocol {
        set_proto(ipv4_bytes[9])
    }

    pub fn src_from_bytes(ip_bytes: &[u8]) -> &[u8] {
        &ip_bytes[12..16]
    }

    pub fn dst_from_bytes(ip_bytes: &[u8]) -> &[u8] {
        &ip_bytes[16..20]
    }

    pub fn payload_from_bytes(ip_bytes: &[u8]) -> &[u8] {
        &ip_bytes[20..]
    }
}

pub fn initialize_ipv4_stack(eth_writer: ethernet::ChannelWriter) -> IPstackWriter {
    let (tx, rx) = channel::<Layer4Response>();
    intialize_writer_loop(eth_writer, rx);
    udp::udp_socket::intialize_stack(IPstackWriter(tx.clone()));
    IPstackWriter(tx)
}


// TODO: Implement graceful thread shutdown by implementing Drop for IPV4.
fn intialize_writer_loop(
    eth_writer: ethernet::ChannelWriter,
    rx: std::sync::mpsc::Receiver<Layer4Response>,
) {
    thread::spawn(move || loop {
        let packet_to_write = rx.recv().unwrap();
        let src_ip_header = packet_to_write.src_ip_header;
        let ip_resp_packet = IPv4::build_ipv4_response(
            src_ip_header,
            packet_to_write.data,
            packet_to_write.protocol,
        );
        eth_writer.send(Box::new(ip_resp_packet)).unwrap();
    });
}

fn set_proto(byte: u8) -> Protocol {
    if byte == ICMP {
        Protocol::ICMP
    } else if byte == TCP {
        Protocol::TCP
    } else if byte == UDP {
        Protocol::UDP
    } else {
        Protocol::Unsupported
    }
}
