use crate::ethernet;
use std::convert::TryInto;

const ARP_REPLY_OPCODE: u16 = 2u16;
const ARP_REQ_OPCODE: u16 = 1u16;

const BROADCAST_ADDR: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

pub struct ARP {
    data: Vec<u8>,
    kind: ARPKind,
}

enum ARPKind {
    Req,
    Reply,
}

impl ethernet::LinkLayerWritable for ARP {
    fn data(&self) -> Vec<u8> {
        self.data.to_owned()
    }

    fn spa(&self) -> ethernet::ProtocolAddr {
        self.spa().try_into().unwrap()
    }

    fn tpa(&self) -> ethernet::ProtocolAddr {
        self.tpa().try_into().unwrap()
    }

    fn ether_type(&self) -> [u8; 2] {
        (ethernet::ETH_ARP as u16).to_be_bytes()
    }
}

// Reference: https://en.wikipedia.org/wiki/Address_Resolution_Protocol
impl ARP {
    pub fn process_packet(eth: &ethernet::Ethernet, frame: ethernet::EthernetFrame) {
        let received_arp_packet = ARP::build_packet(frame.payload().to_owned());
        match received_arp_packet.kind {
            ARPKind::Reply => {
                let (protocol_addr, hw_addr) = received_arp_packet.parse_for_addr();
                eth.update_arp_cache(protocol_addr, hw_addr);
            }
            ARPKind::Req => {
                let resp = received_arp_packet.build_response(eth.address());
                eth.eth_layer_write(Box::new(resp)).unwrap();
            }
        }
    }

    fn build_packet(data: Vec<u8>) -> ARP {
        let arp_kind = Self::arp_kind_from_bytes(&data);
        ARP {
            data: data,
            kind: arp_kind,
        }
    }

    fn parse_for_addr(&self) -> (ethernet::ProtocolAddr, ethernet::HwAddr) {
        (
            self.spa().try_into().unwrap(),
            self.sha().try_into().unwrap(),
        )
    }

    fn arp_kind_from_bytes(bytes: &[u8]) -> ARPKind {
        let op_code: [u8; 2] = bytes[6..8].try_into().unwrap();
        if op_code == ARP_REPLY_OPCODE.to_be_bytes() {
            ARPKind::Reply
        } else if op_code == ARP_REQ_OPCODE.to_be_bytes() {
            ARPKind::Req
        } else {
            unimplemented!()
        }
    }

    fn operation(&self) -> ARPKind {
        let op = self.op();
        if op == (ARP_REPLY_OPCODE.to_be_bytes()) {
            ARPKind::Reply
        } else if op == (ARP_REQ_OPCODE.to_be_bytes()) {
            ARPKind::Req
        } else {
            unimplemented!()
        }
    }

    pub fn make_req_for_addr(
        target_addr: ethernet::ProtocolAddr,
        sender_hw_addr: &[u8],
    ) -> Box<ARP> {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice((1u16).to_be_bytes().as_ref());
        payload.extend_from_slice((ethernet::ETH_IPV4 as u16).to_be_bytes().as_ref());
        payload.push(6u8);
        payload.push(4u8);
        payload.extend_from_slice(ARP_REQ_OPCODE.to_be_bytes().as_ref());
        payload.extend_from_slice(sender_hw_addr);
        payload.extend_from_slice(&ethernet::IP_ADDR);
        payload.extend_from_slice(&BROADCAST_ADDR);
        payload.extend_from_slice(&target_addr);
        Box::new(ARP {
            data: payload,
            kind: ARPKind::Req,
        })
    }

    fn handle_packet(data: Vec<u8>, eth_addr: [u8; 6]) -> ARP {
        let req = ARP::build_request(data);
        req.build_response(eth_addr)
    }

    fn build_request(data: Vec<u8>) -> ARP {
        ARP {
            data: data,
            kind: ARPKind::Req,
        }
    }

    fn build_response(&self, eth_addr: [u8; 6]) -> ARP {
        let mut resp = ARP {
            data: self.data.clone(),
            kind: ARPKind::Reply,
        };
        resp.fill_values(eth_addr);
        resp
    }

    fn fill_values(&mut self, eth_addr: [u8; 6]) {
        self.set_op_code();
        self.set_hw_addrs(eth_addr);
        self.set_protocol_addrs();
    }

    fn set_protocol_addrs(&mut self) {
        // TODO: Maybe explicitly set an IP address for the user space eth device?
        // For now, the program assumes that its IP is whatever is seen in the ARP request's target ip(TPA attribute)
        // Swap the target and sender ip address for the response
        unsafe {
            let sender_ip_start = self.data.as_mut_ptr().add(self.sha_boundary());
            let target_ip_start = self.data.as_mut_ptr().add(self.tha_boundary());
            let addr_length = self.pln();

            std::ptr::swap_nonoverlapping(sender_ip_start, target_ip_start, addr_length as usize);
        }
    }
    fn set_hw_addrs(&mut self, eth_addr: [u8; 6]) {
        // Set the request's sender address as the target address for the reply.
        let sender_hw = self.sha().to_owned();
        self.data.splice(
            self.spa_boundary()..self.tha_boundary(),
            sender_hw.iter().cloned(),
        );

        // Set the virtual ethernet device's hw address as the sender addr for the reply.
        self.data.splice(
            self.op_boundary()..self.sha_boundary(),
            eth_addr.iter().cloned(),
        );
    }

    fn set_op_code(&mut self) {
        // Set reply as the op code.
        self.data.splice(
            self.pln_boundary()..self.op_boundary(),
            ARP_REPLY_OPCODE.to_be_bytes().iter().cloned(),
        );
    }
}

// Packet accessors and boundaries
impl ARP {
    pub fn hrd(&self) -> [u8; 2] {
        let mut hrd = [0; 2];
        hrd.copy_from_slice(&self.data[0..2]);
        hrd
    }

    pub fn pro(&self) -> [u8; 2] {
        let mut pro = [0; 2];
        pro.copy_from_slice(&self.data[2..4]);
        pro
    }

    pub fn hln(&self) -> u8 {
        let mut hln = [0; 1];
        hln.copy_from_slice(&self.data[4..5]);
        hln[0]
    }

    pub fn pln(&self) -> u8 {
        let mut pln = [0; 1];
        pln.copy_from_slice(&self.data[5..6]);
        pln[0]
    }

    pub fn op(&self) -> [u8; 2] {
        let mut op = [0; 2];
        op.copy_from_slice(&self.data[6..8]);
        op
    }

    pub fn sha(&self) -> &[u8] {
        &self.data[8..14]
    }

    pub fn spa(&self) -> &[u8] {
        &self.data[14..18]
    }

    pub fn tha(&self) -> &[u8] {
        &self.data[self.spa_boundary()..self.tha_boundary()]
    }

    pub fn tpa(&self) -> &[u8] {
        &self.data[self.tha_boundary()..self.tpa_boundary()]
    }

    fn pln_boundary(&self) -> usize {
        6
    }

    fn op_boundary(&self) -> usize {
        8
    }

    fn sha_boundary(&self) -> usize {
        self.hln() as usize + self.op_boundary()
    }

    fn spa_boundary(&self) -> usize {
        self.sha_boundary() as usize + self.pln() as usize
    }

    fn tha_boundary(&self) -> usize {
        self.spa_boundary() as usize + self.hln() as usize
    }

    fn tpa_boundary(&self) -> usize {
        self.tha_boundary() + self.pln() as usize
    }
}
