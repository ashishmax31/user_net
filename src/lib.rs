#[macro_use]
extern crate ioctl_macros;
use std::{process, thread, time};
mod arp;
mod ethernet;
mod ipv4;
mod net_util;
mod tap;
pub mod udp_socket;
use arp::ARP;
use ethernet::Ethernet;

fn show_error<T>(err: T) -> !
where
    T: std::fmt::Display,
{
    eprintln!("ERROR: {}", err);
    process::exit(-1)
}

pub fn start_stack() {
    let (fd, device) = tap::create_tap_device("tap1").unwrap();

    // Allow some time for the kernel to allocate the tun/tap device
    thread::sleep(time::Duration::from_secs(1));

    match tap::set_device_link_up(&device) {
        Ok(_) => (),
        Err(err) => show_error(err),
    }

    match tap::add_ip_route(&device, "10.0.0.1/24") {
        Ok(_) => (),
        Err(err) => show_error(err),
    }

    let mut eth = match Ethernet::bind(fd) {
        Ok(eth) => eth,
        Err(err) => show_error(err),
    };
    std::thread::spawn(move || {
        eth.start_stack();
    });
    // Allow some time for the stack to get started before returning
    thread::sleep(time::Duration::from_secs(5));
}
