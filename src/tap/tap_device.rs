// Reference:
// https://www.kernel.org/doc/Documentation/networking/tuntap.txt

use ifstructs::ifreq;
use nix::errno;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use std::mem;
use std::process::Command;

pub const MTU: u32 = 1600;
// Need to refactor error handling :/

pub fn create_tap_device(device_name: &str) -> Result<(i32, String), &'static str> {
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
        _ => {
            // IOCTL can modify the device name if it already exists, hence we need to return it back.
            // Ex: If we pass 'TAP1' as the device name and if another device exists with the same name,
            // the kernel might modify the name to 'TAP2'.
            let interface_name = ifr.get_name().unwrap();
            Ok((fd, interface_name))
        }
    }
}

pub fn set_device_link_up(device_name: &str) -> Result<(), String> {
    let mut executor = Command::new("/sbin/ip");
    executor.arg("link").arg("set").arg(device_name).arg("up");

    execute_command(&mut executor)
}

pub fn add_ip_route(device_name: &str, cidr_range: &str) -> Result<(), String> {
    let mut executor = Command::new("/sbin/ip");
    executor
        .arg("addr")
        .arg("add")
        .arg(cidr_range)
        .arg("dev")
        .arg(device_name);

    execute_command(&mut executor)
}

fn execute_command(cmd: &mut Command) -> Result<(), String> {
    let output = match cmd.output() {
        Ok(res) => res,
        Err(_) => return Err("Failed to invoke /sbin/ip! Is it installed?".to_string()),
    };

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}
