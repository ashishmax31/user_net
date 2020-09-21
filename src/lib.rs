#[macro_use]
extern crate ioctl_macros;
use std::{process, thread, time};
mod arp;
mod ethernet;
mod ipv4;
mod net_util;
mod tap;
use arp::ARP;
use ethernet::{EtherType, Ethernet};

pub fn show_error<T>(err: T) -> !
where
    T: std::fmt::Display,
{
    eprintln!("ERROR: {}", err);
    process::exit(-1)
}

pub fn start_stack() {
    let (fd, device) = tap::create_tap_device("tap1").unwrap();

    // Allow some time for the kernel to allocate the tun/tap device
    thread::sleep(time::Duration::from_secs(2));

    match tap::set_device_link_up(&device) {
        Ok(_) => (),
        Err(err) => show_error(err),
    }

    match tap::add_ip_route(&device, "10.0.0.1/24") {
        Ok(_) => (),
        Err(err) => show_error(err),
    }

    let mut eth = match Ethernet::bind(fd) {
        Ok(fd) => fd,
        Err(err) => show_error(err),
    };

    let rx = eth.read_from_socket();
    loop {
        let current_frame = rx.recv().unwrap();
        eth.process_frame(current_frame);
    }
}
