use crate::ethernet;
use crate::ipv4::*;
use crate::net_util;

pub struct ICMP {
    msg_type: u8,
    code: u8,
    checksum: u16,
    header_dat: u32,
    payload: Vec<u8>,
}

const ECHO_REPLY: u8 = 0u8;
const ECHO_REQ: u8 = 8u8;

const ICMP: u8 = 1;

pub enum IcmpType {
    EchoReply,
    DestinationUnreachable,
    EchoRequest,
    Unsupported,
}

impl ICMP {
    pub fn icmp_type(&self) -> IcmpType {
        match self.msg_type {
            x if x == 0 => IcmpType::EchoReply,
            x if x == 3 => IcmpType::DestinationUnreachable,
            x if x == 8 => IcmpType::EchoRequest,
            _ => IcmpType::Unsupported,
        }
    }

    fn packet_to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.push(self.msg_type);
        buffer.push(self.code);
        buffer.extend_from_slice(&self.checksum.to_be_bytes());
        buffer.extend_from_slice(&self.header_dat.to_be_bytes());
        buffer.append(&mut self.payload.clone());
        buffer
    }

    fn packet_from_bytes(data: &[u8]) -> Option<Self> {
        let icmp_packet = ICMP {
            msg_type: data[0],
            code: data[1],
            checksum: net_util::ntohs(&data[2..4]),
            header_dat: net_util::ntohl(&data[4..8]),
            payload: data[8..].to_owned(),
        };
        let (computed_chksum, received_chksum) = net_util::compute_ip_checksum(&data, 2..4);
        if computed_chksum == received_chksum {
            Some(icmp_packet)
        } else {
            // Return none if the checksum doesnt match
            None
        }
    }

    fn build_icmp_echo_reply(packet: ICMP) -> ICMP {
        let mut reply = ICMP {
            msg_type: ECHO_REPLY,
            code: 0u8,      // Code is always zero for echo req and resp
            checksum: 0u16, // Initialize the packet with checksum zero
            header_dat: packet.header_dat,
            payload: packet.payload,
        };

        let (check_sum, _) = net_util::compute_ip_checksum(&reply.packet_to_bytes(), 2..4);
        reply.checksum = check_sum;
        reply
    }

    pub fn process_packet(frame: ethernet::EthernetFrame, layer_3_writer: &IPstackWriter) {
        let ipv4_packet = IPv4::packet_from_net_bytes(frame.payload());
        let icmp_reply = match ICMP::packet_from_bytes(ipv4_packet.payload_bytes()) {
            Some(icmp_packet) => match icmp_packet.icmp_type() {
                IcmpType::EchoRequest => {
                    let reply = ICMP::build_icmp_echo_reply(icmp_packet);
                    reply.packet_to_bytes()
                }
                _ => unimplemented!(),
            },
            None => return, // Checksum mismatch, dont do anything
        };

        let layer4_resp = ipv4::Layer4Response {
            data: icmp_reply,
            protocol: ICMP,
            src_ethernet_frame: frame,
        };
        layer_3_writer.write(layer4_resp);
    }
}
