use crate::net_util;
use crate::tap::tap_device::MTU;
use crate::{
    ipv4::{initialize_ipv4_stack, IPstackWriter, IPv4},
    ARP,
};
use libc::{c_void, size_t};
use nix::errno;
use nix::sys::stat::fstat;
use nix::sys::stat::SFlag;
use rand::Rng;
use std::sync::mpsc::channel;
use std::thread;

pub trait LinkLayerWritable {
    fn data(self) -> Vec<u8>;
}

#[derive(Debug, PartialEq)]
pub enum EtherType {
    IPv4,
    ARP,
    IPv6,
    Unsupported,
}

impl EtherType {
    pub fn from_bytes(input: u16) -> Self {
        let input = input as i32;
        match input {
            0x800 => Self::IPv4,
            0x806 => Self::ARP,
            0x86DD => Self::IPv6,
            _ => Self::Unsupported,
        }
    }
}

pub type HwAddr = [u8; 6];
type ChannelReceiver = std::sync::mpsc::Receiver<EthernetFrame>;
pub type ChannelWriter = std::sync::mpsc::Sender<EthernetFrame>;

// This doesnt do anything useful now. Maybe later?
#[derive(Clone)]
enum State {
    Ready,
    Reading,
}
#[derive(Clone)]
pub struct Ethernet {
    socket: i32,
    status: State,
    address: HwAddr,
    write_chan: ChannelWriter,
}

#[derive(Debug, Clone)]
pub struct EthernetFrame {
    data: Vec<u8>,
}

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

    pub fn bind(fd: i32) -> Result<Ethernet, &'static str> {
        match Ethernet::socket_valid(fd) {
            Ok(_) => {
                let (tx, rx) = channel::<EthernetFrame>();
                let eth = Ethernet {
                    socket: fd,
                    status: State::Ready,
                    address: rand::thread_rng().gen::<HwAddr>(),
                    write_chan: tx,
                };

                Self::intialize_writer_loop(eth.clone(), rx);
                Ok(eth)
            }
            Err(err) => Err(err),
        }
    }

    fn intialize_writer_loop(eth: Ethernet, rx: ChannelReceiver) {
        thread::spawn(move || loop {
            let packet_to_write = rx.recv().unwrap();
            eth.write_frame(packet_to_write).unwrap();
        });
    }

    pub fn write_frame(&self, eth_frame: EthernetFrame) -> Result<(), &'static str> {
        let mut response_frame_data = eth_frame.data;
        // Set src as of the frame as this device's hw address before sending.
        response_frame_data.splice(6..12, self.address.iter().cloned());
        match self.write_to_socket(response_frame_data) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
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

    pub fn read_from_socket(&self) -> (std::sync::mpsc::Receiver<EthernetFrame>, IPstackWriter) {
        let mut buffer: Vec<u8> = vec![0; MTU as usize];
        let fd = self.socket;
        // self.set_socket_state(State::Reading);
        let ipstack_writer = initialize_ipv4_stack(self.write_chan.clone());
        let (tx, rx) = channel();
        std::thread::spawn(move || loop {
            let buffer_ptr = buffer.as_mut_ptr() as *mut c_void;
            unsafe {
                let res = libc::read(fd, buffer_ptr, buffer.capacity() as size_t);
                if res < 0 {
                    let err = errno::Errno::last();
                    eprintln!("{}", err.desc());
                    panic!(err.desc());
                } else {
                    let raw_payload = buffer[0..res as usize].to_vec();
                    let eth_frame = EthernetFrame { data: raw_payload };
                    tx.send(eth_frame).unwrap();
                }
            }
        });
        (rx, ipstack_writer)
    }

    pub fn start_stack(&self) {
        let mut buffer: Vec<u8> = vec![0; MTU as usize];
        let fd = self.socket;
        // self.set_socket_state(State::Reading);
        let ipstack_writer = initialize_ipv4_stack(self.write_chan.clone());
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
