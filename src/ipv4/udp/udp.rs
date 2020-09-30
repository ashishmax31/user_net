use super::udp_socket;
use crate::ethernet;
use crate::ipv4::IPv4;
use crate::ipv4::*;
use crate::net_util;
use std::convert::TryInto;

pub struct UDP {
    src_port: u16,
    dst_port: u16,
    length: u16,
    chksm: u16,
    payload: Vec<u8>,
}

const UDP: u8 = 17;

impl UDP {
    pub fn process_packet(frame: ethernet::EthernetFrame, layer_3_writer: &IPstackWriter) {
        let ipv4_packet = ipv4::IPv4::packet_from_net_bytes(frame.payload());
        match Self::packet_from_bytes(frame.payload()) {
            Some(mut datagram) => {
                let identifier = format!("10.0.0.2:{}", datagram.dst_port);
                match udp_socket::get_sock(&identifier) {
                    Some(mut_wrapped_sock) => {
                        let mut sock = mut_wrapped_sock.lock().unwrap();
                        sock.write_to_sockbuff(
                            datagram.payload,
                            format!("{}:{}", ipv4_packet.src_str(), datagram.src_port),
                        );
                    }
                    None => {
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

    fn packet_from_bytes(ip_bytes: &[u8]) -> Option<UDP> {
        let pseudo_header = Self::create_pseudo_header(ip_bytes);
        let (cmpted_chksum, received_chksm) = net_util::compute_ip_checksum(&pseudo_header, 18..20);
        // If checksum is zero, skip checksum validation
        if (cmpted_chksum != received_chksm) && (received_chksm != 0) {
            None
        } else {
            let udp_bytes = ipv4::IPv4::payload_from_bytes(ip_bytes);
            let udp_datagram = UDP {
                src_port: net_util::ntohs(&udp_bytes[0..2]),
                dst_port: net_util::ntohs(&udp_bytes[2..4]),
                length: net_util::ntohs(&udp_bytes[4..6]),
                chksm: net_util::ntohs(&udp_bytes[6..8]),
                payload: udp_bytes[8..].to_owned(),
            };
            Some(udp_datagram)
        }
    }

    // https://en.wikipedia.org/wiki/User_Datagram_Protocol#IPv4_pseudo_header
    fn create_pseudo_header(ip_bytes: &[u8]) -> Vec<u8> {
        let mut pseudo_header = Vec::new();
        let udp_bytes = ipv4::IPv4::payload_from_bytes(ip_bytes);
        pseudo_header.extend_from_slice(ipv4::IPv4::src_from_bytes(ip_bytes));
        pseudo_header.extend_from_slice(ipv4::IPv4::dst_from_bytes(ip_bytes));
        pseudo_header.push(0u8);
        pseudo_header.push(UDP);
        pseudo_header.push(udp_bytes.len().try_into().unwrap());
        pseudo_header.extend_from_slice(udp_bytes);
        pseudo_header
    }
}
