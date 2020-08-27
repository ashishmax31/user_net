use crate::tap::tap_device::MTU;
use libc::{c_void, size_t};
use nix::errno;
use nix::sys::stat::fstat;
use nix::sys::stat::SFlag;
use std::sync::mpsc::channel;
use std::thread;

enum State {
    Ready,
    Reading,
}

pub struct Ethernet {
    socket: i32,
    status: State,
}

pub struct EthernetFrame {
    data: Vec<u8>,
}

impl EthernetFrame {
    pub fn dst(&self) -> [u8; 6] {
        let mut dst = [0; 6];
        dst.copy_from_slice(&self.data[0..6]);
        dst
    }
    pub fn src(&self) -> [u8; 6] {
        let mut src = [0; 6];
        src.copy_from_slice(&self.data[6..12]);
        src
    }
    pub fn ether_type(&self) -> u16 {
        let mut ether_type = [0; 2];
        ether_type.copy_from_slice(&self.data[12..14]);
        (ether_type[0] as u16) << 8 | (ether_type[1] as u16)
    }
    pub fn payload(&self) -> &[u8] {
        &self.data[14..]
    }
}

impl Ethernet {
    fn set_socket_state(&mut self, to_state: State) {
        self.status = to_state
    }

    pub fn bind(fd: i32) -> Result<Ethernet, &'static str> {
        match Ethernet::socket_valid(fd) {
            Ok(_) => Ok(Ethernet {
                socket: fd,
                status: State::Ready,
            }),
            Err(err) => Err(err),
        }
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
}
