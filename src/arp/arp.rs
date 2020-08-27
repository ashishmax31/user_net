pub use crate::ethernet::Ethernet;
use crate::net_util;

pub struct ARP {
    data: Vec<u8>,
}

impl ARP {
    pub fn new_request(data: Vec<u8>) -> Self {
        ARP { data: data }
    }

    // TODO: Clean up this shit!!
    pub fn build_response(&self, eth_frame: &Ethernet) -> Self {
        // An arp packet's max size is 28 byte, so initialize a vector with that size to avoid further allocations.
        let mut response = self.data.clone();
        let sender_hw = self.sha();
        let _: Vec<_> = response
            .splice(6..8, net_util::htons([0, 2]).iter().cloned())
            .collect();
        // Swap src and target mac
        let _: Vec<_> = response
            .splice(
                self.spa_boundary()..self.tha_boundary(),
                sender_hw.iter().cloned(),
            )
            .collect();
        let _: Vec<_> = response
            .splice(
                8..self.sha_boundary(),
                eth_frame.hw_address().iter().cloned(),
            )
            .collect();
        let sender_ip = self.spa();
        let target_ip = self.tpa();
        // swap src and target ip
        let _: Vec<_> = response
            .splice(
                self.sha_boundary()..self.spa_boundary(),
                target_ip.iter().cloned(),
            )
            .collect();
        let _: Vec<_> = response
            .splice(
                self.tha_boundary()..self.tpa_boundary(),
                sender_ip.iter().cloned(),
            )
            .collect();

        ARP { data: response }
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

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
        let boundary = self.sha_boundary();
        &self.data[8..boundary]
    }

    pub fn spa(&self) -> &[u8] {
        let boundary = self.spa_boundary();
        &self.data[self.sha_boundary()..boundary]
    }

    pub fn tha(&self) -> &[u8] {
        &self.data[self.spa_boundary()..self.tha_boundary()]
    }

    pub fn tpa(&self) -> &[u8] {
        &self.data[self.tha_boundary()..self.tpa_boundary()]
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

    fn sha_boundary(&self) -> usize {
        self.hln() as usize + 8 as usize
    }
}
