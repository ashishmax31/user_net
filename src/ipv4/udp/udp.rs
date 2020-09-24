use super::udp_socket;
use crate::ipv4::IPv4;
use crate::net_util;

pub struct UDP {
    src_port: u16,
    dst_port: u16,
    length: u16,
    chksm: u16,
    payload: Vec<u8>,
}

impl UDP {
    pub fn process_packet(bytes: &[u8], ip_header: &IPv4) {
        match Self::packet_from_bytes(bytes) {
            Some(mut datagram) => {
                let identifier = format!("10.0.0.2:{}", datagram.dst_port);
                match udp_socket::get_sock(&identifier) {
                    Some(mut_wrapped_sock) => {
                        let mut sock = mut_wrapped_sock.lock().unwrap();
                        sock.write_to_sockbuff(
                            datagram.payload,
                            format!("{}:{}", ip_header.src_str(), datagram.src_port),
                        );
                    }
                    None => {
                        // Send icmp error, port not open
                    }
                }
            }
            None => {
                // Send icmp error
                // Checksum mismatch
            }
        }
    }

    fn packet_from_bytes(bytes: &[u8]) -> Option<UDP> {
        let (cmpted_chksum, received_chksm) = net_util::compute_ip_checksum(bytes, 6..8);
        if cmpted_chksum != received_chksm {
            None
        } else {
            let udp_datagram = UDP {
                src_port: net_util::ntohs(&bytes[0..2]),
                dst_port: net_util::ntohs(&bytes[2..4]),
                length: net_util::ntohs(&bytes[4..6]),
                chksm: net_util::ntohs(&bytes[6..8]),
                payload: bytes[8..].to_owned(),
            };
            Some(udp_datagram)
        }
    }
}
