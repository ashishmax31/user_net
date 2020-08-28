use crate::net_util;
use crate::tap::tap_device::MTU;
use byteorder::{ByteOrder, LittleEndian};
use libc::{c_void, size_t};
use nix::errno;
use nix::sys::stat::fstat;
use nix::sys::stat::SFlag;
use rand::Rng;
use std::sync::mpsc::channel;
use std::thread;

pub trait LinkLayerWritable {
    fn data(&self) -> &Vec<u8>;
}

#[derive(Debug, PartialEq)]
pub enum EtherType {
    IPv4,
    ARP,
    IPv6,
    Unsupported,
}

impl EtherType {
    pub fn from_bytes(input: [u8; 2]) -> Self {
        let inp_repr = LittleEndian::read_u16(&input) as i32;
        match inp_repr {
            0x800 => Self::IPv4,
            0x806 => Self::ARP,
            0x86DD => Self::IPv6,
            _ => Self::Unsupported,
        }
    }
}

pub type HwAddr = [u8; 6];

// This doesnt do anything useful now. Maybe later?
enum State {
    Ready,
    Reading,
}

pub struct Ethernet {
    socket: i32,
    status: State,
    address: HwAddr,
}

pub struct EthernetFrame {
    data: Vec<u8>,
}

impl EthernetFrame {
    // Builds a response eth frame from for a given eth frame. The src address of the given frame would be set as
    // dst address of the returned response.
    pub fn build_response_frame<T>(&self, payload: &T) -> Self
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
    pub fn ether_type(&self) -> [u8; 2] {
        let mut ether_type = [0; 2];
        ether_type.copy_from_slice(&self.data[12..14]);
        net_util::ntohs(ether_type)
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
            Ok(_) => Ok(Ethernet {
                socket: fd,
                status: State::Ready,
                address: rand::thread_rng().gen::<HwAddr>(),
            }),
            Err(err) => Err(err),
        }
    }

    // TODO: trait bounds based generics for payload.
    pub fn write_frame(&self, eth_frame: EthernetFrame) -> Result<(), &'static str> {
        let mut response_frame_data = eth_frame.data;
        // Set src as of the frame as this device's hw address before sending.
        response_frame_data.splice(6..12, self.address.iter().cloned());
        match self.write_to_socket(response_frame_data) {
            Ok(bytes_written) => {
                println!("Successfully written {} bytes", bytes_written);
                Ok(())
            }
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

    pub fn read_from_socket(&mut self) -> std::sync::mpsc::Receiver<EthernetFrame> {
        let mut buffer: Vec<u8> = vec![0; MTU as usize];
        let (tx, rx) = channel();
        let fd = self.socket;
        self.set_socket_state(State::Reading);

        thread::spawn(move || {
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
                        tx.send(eth_frame).unwrap();
                    }
                }
            }
        });
        return rx;
    }

    pub fn write_to_socket(&self, mut payload: Vec<u8>) -> Result<usize, &'static str> {
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
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_ether_type() {
        // Ipv4
        let input = EtherType::from_bytes([0x0, 0x8]);
        assert_eq!(input, EtherType::IPv4);

        // ARP
        let input = EtherType::from_bytes([0x6, 0x8]);
        assert_eq!(input, EtherType::ARP);

        // Ipv6
        let input = EtherType::from_bytes([0xDD, 0x86]);
        assert_eq!(input, EtherType::IPv6);

        // EtherCAT Protocol, Unsupported - What the hell is that ?? :D
        let input = EtherType::from_bytes([0xA4, 0x88]);
        assert_eq!(input, EtherType::Unsupported);
    }
}
