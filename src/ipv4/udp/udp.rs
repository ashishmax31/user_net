use super::udp_socket;
use crate::ethernet;
use crate::ipv4::*;
use crate::net_util;

#[derive(Clone, Debug)]
pub struct UDP {
    header: UdpHeader,
    pub payload: Vec<u8>,
}

#[derive(Copy, Clone, Debug)]
pub struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    length: u16,
    chksm: u16,
}

pub const UDP_PROTO: u8 = 17;

impl UdpHeader {
    pub fn src_port(&self) -> u16 {
        self.src_port
    }

    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }

    pub fn length(&self) -> u16 {
        self.length
    }

    pub fn chksm(&self) -> u16 {
        self.chksm
    }

    pub fn set_chksm(&mut self, value: u16) {
        self.chksm = value;
    }
}

impl UDP {
    pub fn process_packet(frame: ethernet::EthernetFrame, layer_3_writer: &IPstackWriter) {
        let ipv4_packet = ipv4::IPv4::packet_from_net_bytes(frame.payload());
        let ip_header = ipv4_packet.ip_header();
        match Self::packet_from_bytes(ipv4_packet) {
            Some(mut datagram) => {
                let identifier = net_util::addr_identifier(ethernet::IP_ADDR, datagram.dst_port());
                match udp_socket::get_sock(&identifier) {
                    Some(mut_wrapped_sock) => {
                        let mut sock = mut_wrapped_sock.lock().unwrap();
                        sock.write_to_sockbuff(datagram, ip_header);
                    }
                    None => {
                        // println!("UDP Port not open");
                        // Port not open, send icmp error
                    }
                }
            }
            None => {
                // Send icmp error
                // Checksum mismatch
            }
        }
    }

    pub fn header(&self) -> UdpHeader {
        self.header
    }

    pub fn src_port(&self) -> u16 {
        self.header.src_port
    }

    pub fn dst_port(&self) -> u16 {
        self.header.dst_port
    }

    pub fn length(&self) -> u16 {
        self.header.length
    }

    pub fn chksm(&self) -> u16 {
        self.header.chksm
    }

    pub fn set_chksm(&mut self, value: u16) {
        self.header.chksm = value;
    }

    pub fn create_packet(
        payload: &[u8],
        src_port: u16,
        dst_port: u16,
        src_ip: ethernet::ProtocolAddr,
        dst_ip: ethernet::ProtocolAddr,
    ) -> (UDP, Vec<u8>) {
        let mut packet = UDP {
            header: UdpHeader {
                src_port: src_port,
                dst_port: dst_port,
                // Header length(8 bytes) + the payload length
                length: (8 + payload.len()) as u16,
                chksm: 0u16,
            },
            payload: payload.to_owned(),
        };
        let packet_bytes = packet.packet_to_bytes();
        let pseudo_header = Self::create_pseudo_header(&packet_bytes, &src_ip, &dst_ip);
        let (cmpted_chksum, _) = net_util::compute_ip_checksum(&pseudo_header, 18..20);
        packet.set_chksm(cmpted_chksum);
        (packet, packet_bytes)
    }

    pub fn packet_from_bytes(ipv4_packet: ipv4::IPv4) -> Option<UDP> {
        let pseudo_header = Self::create_pseudo_header(
            ipv4_packet.payload_bytes(),
            &ipv4_packet.src,
            &ipv4_packet.dst,
        );
        let (cmpted_chksum, received_chksm) = net_util::compute_ip_checksum(&pseudo_header, 18..20);
        // If checksum is zero, skip checksum validation
        if (cmpted_chksum != received_chksm) && (received_chksm != 0) {
            None
        } else {
            let udp_bytes = ipv4_packet.payload_bytes();
            let udp_datagram = UDP {
                header: UdpHeader {
                    src_port: net_util::ntohs(&udp_bytes[0..2]),
                    dst_port: net_util::ntohs(&udp_bytes[2..4]),
                    length: net_util::ntohs(&udp_bytes[4..6]),
                    chksm: net_util::ntohs(&udp_bytes[6..8]),
                },
                payload: udp_bytes[8..].to_owned(),
            };
            Some(udp_datagram)
        }
    }

    // https://en.wikipedia.org/wiki/User_Datagram_Protocol#IPv4_pseudo_header
    fn create_pseudo_header(udp_packet_bytes: &[u8], src_ip: &[u8], dst_ip: &[u8]) -> Vec<u8> {
        let mut pseudo_header = Vec::new();
        pseudo_header.extend_from_slice(src_ip);
        pseudo_header.extend_from_slice(dst_ip);
        pseudo_header.push(0u8);
        pseudo_header.push(UDP_PROTO);
        pseudo_header.extend_from_slice((udp_packet_bytes.len() as u16).to_be_bytes().as_ref());
        pseudo_header.extend_from_slice(udp_packet_bytes);
        pseudo_header
    }

    pub fn packet_to_bytes(&self) -> Vec<u8> {
        let mut packet_bytes = Vec::new();
        packet_bytes.extend_from_slice(self.src_port().to_be_bytes().as_ref());
        packet_bytes.extend_from_slice(self.dst_port().to_be_bytes().as_ref());
        packet_bytes.extend_from_slice(self.length().to_be_bytes().as_ref());
        packet_bytes.extend_from_slice(self.chksm().to_be_bytes().as_ref());
        packet_bytes.extend_from_slice(&self.payload);
        packet_bytes
    }
}
