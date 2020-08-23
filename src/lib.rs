use libc::{c_int, c_void, setsockopt, size_t, socket, socklen_t};
use nix::errno;
use socket::htons;
use std::ffi::CString;

pub fn create_link_layer_socket() -> Result<c_int, &'static str> {
    let fd;
    unsafe {
        fd = socket(
            libc::AF_PACKET as c_int,
            libc::SOCK_RAW as c_int,
            htons(libc::ETH_P_ALL as u16) as c_int,
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

pub fn read_from_socket(fd: c_int, mtu: usize) {
    let mut buffer: Vec<u8> = vec![0; mtu];
    let buffer_ptr = buffer.as_mut_ptr() as *mut c_void;

    unsafe {
        loop {
            let res = libc::recv(fd, buffer_ptr, buffer.capacity() as size_t, 0 as c_int);
            if res < 0 {
                let err = errno::Errno::last();
                eprintln!("{}", err.desc());
                panic!(err.desc());
            } else {
                println!("bytes read: {}", res as i32);
                // TODO:
                // Parse the raw ethernet packets -> IPv4 packet -> layer 3 packet
                //
            }
        }
    }
}
