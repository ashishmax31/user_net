use crate::net_util;
use crate::tap::tap_device::MTU;
use crate::{
    ipv4::{initialize_ipv4_stack, IPstackWriter, IPv4},
    ARP,
};
use lazy_static::lazy_static;
use libc::{c_void, size_t};
use nix::errno;
use nix::sys::stat::fstat;
use nix::sys::stat::SFlag;
use rand::Rng;
use std::collections::HashMap;
use std::sync::mpsc::channel;
use std::sync::RwLock;
use std::{thread, time};

lazy_static! {
    static ref ARP_CACHE: RwLock<HashMap<ProtocolAddr, HwAddr>> = RwLock::new(HashMap::new());
}

pub type HwAddr = [u8; 6];

pub type ChannelWriter = std::sync::mpsc::Sender<Box<dyn LinkLayerWritable + Send>>;

pub type ProtocolAddr = [u8; 4];

pub trait LinkLayerWritable {
    fn spa(&self) -> ProtocolAddr;
    fn tpa(&self) -> ProtocolAddr;
    fn ether_type(&self) -> [u8; 2];
    fn data(&self) -> Vec<u8>;
}

#[derive(Debug, PartialEq)]
pub enum EtherType {
    IPv4,
    ARP,
    IPv6,
    Unsupported,
}

type ChannelReceiver = std::sync::mpsc::Receiver<Box<dyn LinkLayerWritable + Send>>;

impl EtherType {
    pub fn from_bytes(input: u16) -> Self {
        let input = input as i32;
        match input {
            ETH_IPV4 => Self::IPv4,
            ETH_ARP => Self::ARP,
            ETH_IPV6 => Self::IPv6,
            _ => Self::Unsupported,
        }
    }
    pub fn value(&self) -> u16 {
        match self {
            Self::IPv4 => ETH_IPV4 as u16,
            Self::IPv6 => ETH_IPV6 as u16,
            Self::ARP => ETH_ARP as u16,
            Self::Unsupported => panic!("Unknown ether_type"),
        }
    }
}

// This doesnt do anything useful now. Maybe later?
#[derive(Clone, Copy)]
enum State {
    Ready,
    Reading,
}

pub struct Ethernet {
    socket: i32,
    status: State,
    address: HwAddr,
    l3_resp_writer_chan: ChannelWriter,
    l3_resp_recv_chan: Option<ChannelReceiver>,
    l4_packet_write_chan: Option<IPstackWriter>,
}

#[derive(Debug, Clone)]
pub struct EthernetFrame {
    data: Vec<u8>,
}

const BROADCAST_ADDR: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
pub const ETH_IPV4: i32 = 0x800;
pub const ETH_ARP: i32 = 0x806;
pub const ETH_IPV6: i32 = 0x86DD;
pub const IP_ADDR: ProtocolAddr = [10, 0, 0, 2];

impl EthernetFrame {
    // Builds a response eth frame from for a given eth frame. The src address of the given frame would be set as
    // dst address of the returned response.
    pub fn build_response_frame<T>(&self, payload: T) -> Self
    where
        T: LinkLayerWritable,
    {
        let mut response = self.data.clone();
        // Set resp frame's dst as the req frame's src.
        response.splice(0..6, self.src().iter().cloned());
        // Write payload
        response.splice(14.., payload.data().iter().cloned());
        Self { data: response }
    }

    pub fn dst(&self) -> HwAddr {
        let mut dst = [0; 6];
        dst.copy_from_slice(&self.data[0..6]);
        dst
    }
    pub fn src(&self) -> HwAddr {
        let mut src = [0; 6];
        src.copy_from_slice(&self.data[6..12]);
        src
    }
    pub fn ether_type(&self) -> u16 {
        let mut ether_type = [0; 2];
        ether_type.copy_from_slice(&self.data[12..14]);
        net_util::ntohs(&ether_type)
    }

    pub fn payload(&self) -> &[u8] {
        &self.data[14..]
    }
}

impl Ethernet {
    pub fn address(&self) -> HwAddr {
        self.address
    }

    fn set_socket_state(&mut self, to_state: State) {
        self.status = to_state
    }

    pub fn bind(fd: i32) -> Result<Self, &'static str> {
        match Ethernet::socket_valid(fd) {
            Ok(_) => {
                let (tx, rx) = channel::<Box<dyn LinkLayerWritable + Send>>();
                let eth = Ethernet {
                    socket: fd,
                    status: State::Ready,
                    address: rand::thread_rng().gen::<HwAddr>(),
                    l3_resp_writer_chan: tx,
                    l3_resp_recv_chan: Some(rx),
                    l4_packet_write_chan: None,
                };
                Ok(eth)
            }
            Err(err) => Err(err),
        }
    }

    pub fn update_arp_cache(&self, protocol_addr: ProtocolAddr, hw_addr: HwAddr) {
        let mut arp_cache_obj = ARP_CACHE.write().unwrap();
        arp_cache_obj.insert(protocol_addr, hw_addr);
    }

    pub fn arp_cache_exists(&self, protocol_addr: &ProtocolAddr) -> bool {
        if *protocol_addr == IP_ADDR {
            true
        } else {
            let arp_cache_obj = ARP_CACHE.read().unwrap();
            arp_cache_obj.contains_key(protocol_addr)
        }
    }

    pub fn get_hw_addr_from_cache(&self, protocol_addr: &ProtocolAddr) -> HwAddr {
        if *protocol_addr == IP_ADDR {
            self.hw_address()
        } else {
            let arp_cache_obj = ARP_CACHE.read().unwrap();
            *arp_cache_obj.get(protocol_addr).unwrap()
        }
    }

    pub fn eth_layer_write(
        &self,
        payload: std::boxed::Box<dyn LinkLayerWritable + std::marker::Send>,
    ) -> Result<(), &'static str> {
        match self.l3_resp_writer_chan.send(payload) {
            Ok(_) => Ok(()),
            Err(_) => Err("Failed to write to the eth chan"),
        }
    }

    // TODO: Implement graceful thread shutdown by implementing Drop for ethernet.
    fn intialize_writer_loop(eth: Ethernet, rx: ChannelReceiver) {
        thread::spawn(move || loop {
            let layer3_resp = rx.recv().unwrap();
            eth.write_response(layer3_resp);
        });
    }

    fn write_response(&self, layer_3_resp: std::boxed::Box<dyn LinkLayerWritable + Send>) {
        let target_protocol_addr = layer_3_resp.tpa();
        if self.arp_cache_exists(&target_protocol_addr) {
            let dst_hw_addr = self.get_hw_addr_from_cache(&target_protocol_addr);
            let resp_eth_frame = self.make_response_frame(layer_3_resp, dst_hw_addr);
            self.write_frame(resp_eth_frame).unwrap();
        } else {
            // Make an ARP request, then re-insert the layer3 response to the eth layer writer chan
            self.make_arp_req_for_addr(target_protocol_addr);
            self.eth_layer_write(layer_3_resp).unwrap();
        }
    }

    fn make_arp_req_for_addr(&self, target_protocol_addr: ProtocolAddr) {
        let arp_req = ARP::make_req_for_addr(target_protocol_addr, &self.address);
        let eth_frame = self.make_response_frame(arp_req, BROADCAST_ADDR);
        self.write_frame(eth_frame).unwrap();
    }

    fn make_response_frame(
        &self,
        layer_3_resp: std::boxed::Box<dyn LinkLayerWritable>,
        dst_hw_addr: HwAddr,
    ) -> EthernetFrame {
        let mut resp_frame = Vec::new();
        resp_frame.extend_from_slice(&dst_hw_addr);
        resp_frame.extend_from_slice(&self.address);
        resp_frame.extend_from_slice(&layer_3_resp.ether_type());
        resp_frame.extend_from_slice(&layer_3_resp.data());
        EthernetFrame { data: resp_frame }
    }

    pub fn write_frame(&self, eth_frame: EthernetFrame) -> Result<(), &'static str> {
        // Loopback behaviour
        if eth_frame.dst() == self.hw_address() {
            let l4_stack_writer =  self.l4_packet_write_chan.as_ref().unwrap();
            self.process_frame(eth_frame, l4_stack_writer);
            Ok(())
        }else{
            let response_frame_data = eth_frame.data;
            match self.write_to_socket(response_frame_data) {
                Ok(_) => Ok(()),
                Err(err) => Err(err),
            }
        }
    }

    pub fn hw_address(&self) -> HwAddr {
        self.address
    }

    fn socket_valid(fd: i32) -> Result<(), &'static str> {
        // Validate that the given file descriptor is indeed a socket.
        // https://linux.die.net/man/2/fstat
        match fstat(fd) {
            Ok(file_stat_struct) => match SFlag::from_bits(file_stat_struct.st_mode) {
                Some(item) => {
                    if item.intersects(SFlag::S_IFSOCK) {
                        Ok(())
                    } else {
                        return Err("Given file descriptor is not a socket!");
                    }
                }
                _ => Ok(()),
            },
            Err(err) => return Err(err.as_errno().unwrap().desc()),
        }
    }

    pub fn start_stack(&mut self) {
        let mut buffer: Vec<u8> = vec![0; MTU as usize];
        let fd = self.socket;

        let l3_resp_recv_chan = self.l3_resp_recv_chan.take().unwrap();
        let ipstack_writer = initialize_ipv4_stack(self.l3_resp_writer_chan.clone());

        let eth_for_writer_loop = Ethernet {
            socket: self.socket,
            status: self.status,
            address: self.address,
            l3_resp_writer_chan: self.l3_resp_writer_chan.clone(),
            l3_resp_recv_chan: None,
            l4_packet_write_chan: Some(ipstack_writer.clone())
        };
        Self::intialize_writer_loop(eth_for_writer_loop, l3_resp_recv_chan);
        let buffer_ptr = buffer.as_mut_ptr() as *mut c_void;
        loop {
            unsafe {
                let res = libc::read(fd, buffer_ptr, buffer.capacity() as size_t);
                if res < 0 {
                    let err = errno::Errno::last();
                    eprintln!("{}", err.desc());
                    panic!(err.desc());
                } else {
                    let raw_payload = buffer[0..res as usize].to_vec();
                    let eth_frame = EthernetFrame { data: raw_payload };
                    self.process_frame(eth_frame, &ipstack_writer);
                }
            }
        }
    }

    //TODO: Buffered write to socket, potential bottleneck
    fn write_to_socket(&self, mut payload: Vec<u8>) -> Result<usize, &'static str> {
        let payload_buffer_ptr = payload.as_mut_ptr() as *mut c_void;
        unsafe {
            let res = libc::write(self.socket, payload_buffer_ptr, payload.len() as size_t);
            if res < 0 {
                let err = errno::Errno::last();
                eprintln!("{}", err.desc());
                Err(err.desc())
            } else {
                Ok(res as usize)
            }
        }
    }

    pub fn process_frame(&self, frame: EthernetFrame, ipstack_writer: &IPstackWriter) {
        let eth_type = frame.ether_type();

        match EtherType::from_bytes(eth_type) {
            EtherType::ARP => {
                ARP::process_packet(self, frame);
            }
            EtherType::IPv4 => {
                IPv4::process_packet(self, frame, ipstack_writer);
            }
            _ => {}
        };
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_ether_type() {
        // Ipv4
        let input = EtherType::from_bytes(0x800);
        assert_eq!(input, EtherType::IPv4);

        // ARP
        let input = EtherType::from_bytes(0x806);
        assert_eq!(input, EtherType::ARP);

        // Ipv6
        let input = EtherType::from_bytes(0x86DD);
        assert_eq!(input, EtherType::IPv6);

        // EtherCAT Protocol, Unsupported - What the hell is that ?? :D
        let input = EtherType::from_bytes(0xA488);
        assert_eq!(input, EtherType::Unsupported);
    }
}
