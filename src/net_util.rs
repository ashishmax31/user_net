use byteorder::{BigEndian, ByteOrder, LittleEndian};
use libc::{c_int, c_void, setsockopt, size_t, socket, socklen_t};
use nix::errno;
use std::ffi::CString;
use std::sync::mpsc::channel;
use std::thread;

// Swap bytes from big endian to little endian
#[inline]
pub fn ntohs(input: [u8; 2]) -> [u8; 2] {
    let mut result = [0; 2];
    LittleEndian::write_u16(&mut result, (input[0] as u16) << 8 | (input[1] as u16));
    result
}

#[inline]
pub fn htons(input: [u8; 2]) -> [u8; 2] {
    let mut result = [0; 2];
    BigEndian::write_u16(&mut result, (input[0] as u16) << 8 | (input[1] as u16));
    result
}

pub fn create_link_layer_socket() -> Result<c_int, &'static str> {
    let fd;
    unsafe {
        fd = socket(
            libc::AF_PACKET as c_int,
            libc::SOCK_RAW as c_int,
            (libc::ETH_P_ALL as u16).to_be() as c_int,
        );
    }
    if fd < 0 {
        let err = errno::Errno::last();
        Err(err.desc())
    } else {
        Ok(fd)
    }
}

pub fn bind_to_device(fd: c_int, interface: &'static str) -> Result<(), &'static str> {
    let device_name = match CString::new(interface) {
        Ok(c_string) => c_string,
        Err(_) => return Err("Null byte found in the device name string!"),
    };
    let device_name_ptr = device_name.as_ptr() as *const c_void;

    let res;
    //    TODO: trait based errors;
    unsafe {
        res = setsockopt(
            fd,
            libc::SOL_SOCKET as c_int,
            libc::SO_BINDTODEVICE as c_int,
            device_name_ptr,
            interface.len() as socklen_t,
        );
    }

    if res == 0 {
        Ok(())
    } else {
        let err = errno::Errno::last();
        Err(err.desc())
    }
}

// TODO: Possible memory leaks, need to implement drop trait (Wait for threads to join before exiting)
pub fn read_from_socket(fd: c_int, mtu: usize) -> std::sync::mpsc::Receiver<std::vec::Vec<u8>> {
    let (tx, rx) = channel();
    let mut buffer: Vec<u8> = vec![0; mtu];

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
                    println!("bytes read: {}", res as i32);
                    tx.send(buffer.clone()).unwrap();
                    // TODO:
                    // Parse the raw ethernet packets -> IPv4 packet -> layer 3 packet
                    //
                }
            }
        }
    });
    return rx;
}
