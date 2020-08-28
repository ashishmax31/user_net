use crate::ethernet::{Ethernet, LinkLayerWritable};
use crate::net_util;

const ARP_REPLY_OPCODE: [u8; 2] = [0, 2];
const ARP_REQ_OPCODE: [u8; 2] = [0, 1];

pub struct ARP {
    data: Vec<u8>,
    kind: ARPKind,
}

enum ARPKind {
    Req,
    Reply,
}

impl LinkLayerWritable for ARP {
    fn data(&self) -> &Vec<u8> {
        &self.data
    }
}

// Reference: http://www.tcpipguide.com/free/t_ARPMessageFormat.htm
impl ARP {
    pub fn build_request(data: Vec<u8>) -> ARP {
        ARP {
            data: data,
            kind: ARPKind::Req,
        }
    }

    pub fn build_response(&self, eth_addr: [u8; 6]) -> ARP {
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
            net_util::htons(ARP_REPLY_OPCODE).iter().cloned(),
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
        &self.data[8..self.sha_boundary()]
    }

    pub fn spa(&self) -> &[u8] {
        &self.data[self.sha_boundary()..self.spa_boundary()]
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
