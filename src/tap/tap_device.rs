// Reference:
// https://www.kernel.org/doc/Documentation/networking/tuntap.txt

use ifstructs::ifreq;
use nix::errno;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use std::mem;

// Need to refactor error handling :/

pub fn create_tap_device(device_name: &'static str) -> Result<i32, &'static str> {
    let fd = match open("/dev/net/tap", OFlag::O_RDWR, Mode::empty()).unwrap() {
        fd if fd > 0 => fd,
        _ => {
            let err = errno::Errno::last();
            return Err(err.desc());
        }
    };

    let mut ifr: ifreq = unsafe { mem::zeroed() };

    // From /usr/include/linux/if_tun.h
    // Set mode as TAP and dont send any additional headers, we want 'pure' ethernet frames.
    ifr.set_flags(libc::IFF_TAP as libc::c_short | libc::IFF_NO_PI as libc::c_short);

    match ifr.set_name(device_name) {
        Ok(_) => {}
        Err(_) => return Err("Failed to set ifreq struct"),
    }

    // From /usr/include/linux/if_tun.h
    let tun_set_iff = iow!('T', 202, i32);

    match unsafe { libc::ioctl(fd, tun_set_iff as u64, &mut ifr) } {
        res if res < 0 => {
            let err = errno::Errno::last();
            return Err(err.desc());
        }
        _ => Ok(fd),
    }
}
