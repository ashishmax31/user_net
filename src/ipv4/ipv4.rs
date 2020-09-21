use crate::ethernet;
use crate::ipv4::icmp;
use crate::net_util;
use crate::tap::tap_device::MTU;
use std::convert::TryInto;

// No bit fields :(
// MSB 0 bit numbering
#[derive(Debug)]
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
    src: [u8; 4],
    dst: [u8; 4],
    data: Vec<u8>,
}

const ICMP: u8 = 1;
const TCP: u8 = 6;
const UDP: u8 = 17;

#[derive(Debug)]
pub enum Protocol {
    ICMP,
    TCP,
    UDP,
    Unsupported,
}

impl ethernet::LinkLayerWritable for IPv4 {
    fn data(self) -> Vec<u8> {
        self.packet_to_bytes()
    }
}

impl IPv4 {
    pub fn process_packet(
        payload: &[u8],
        eth: &ethernet::Ethernet,
        frame: &ethernet::EthernetFrame,
    ) {
        if let Some(layer_3_response) = IPv4::handle_packet(payload) {
            let eth_response_frame = frame.build_response_frame(layer_3_response);
            eth.write_frame(eth_response_frame).unwrap();
        }
    }
    // MSB 0 bit numbering
    // First n bytes means the the first n bytes from the left to right.
    fn packet_from_net_bytes(data: &[u8]) -> IPv4 {
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

    fn packet_to_bytes(mut self) -> Vec<u8> {
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
        packet_buffer.append(&mut self.data);
        packet_buffer
    }

    fn get_proto_val(&self) -> u8 {
        match self.proto {
            Protocol::TCP => TCP,
            Protocol::ICMP => ICMP,
            Protocol::UDP => UDP,
            Protocol::Unsupported => unimplemented!(),
        }
    }

    fn build_unfragmented_packet(src_packet: IPv4, payload: Vec<u8>, proto: u8) -> IPv4 {
        let total_packet_len = (20 as usize + payload.len()) as u16;
        IPv4 {
            version: 04u8,
            ihl: 5u8, //No options field, so the header is always 20bytes.
            ecn: src_packet.ecn,
            t_len: total_packet_len,
            id: 0u16,
            flags: 0u8,
            frag_offset: 0u16,
            ttl: 50u8,
            proto: set_proto(proto),
            chksm: 0u16,
            src: src_packet.dst,
            dst: src_packet.src,
            data: payload,
        }
    }

    fn handle_packet(data: &[u8]) -> Option<IPv4> {
        let received_packet = IPv4::packet_from_net_bytes(data);

        match received_packet.proto {
            Protocol::ICMP => {
                match icmp::ICMP::process_packet(&received_packet.data) {
                    Some(icmp_resp) => {
                        if (icmp_resp.len() as u32) > MTU {
                            // Need to implement ip packet fragmenting
                            unimplemented!()
                        } else {
                            Some(IPv4::build_unfragmented_packet(
                                received_packet,
                                icmp_resp,
                                ICMP,
                            ))
                        }
                    }
                    None => {
                        // Send ICMP error back?
                        // Write to some logs
                        None
                    }
                }
            }
            Protocol::UDP => {
                //  TODO: UDP
                None
            }
            Protocol::TCP => {
                // TODO: TCP
                None
            }
            Protocol::Unsupported => {
                // Send ICMP error
                None
            }
        }
    }
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
