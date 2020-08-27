#[macro_use]
extern crate ioctl_macros;
use std::{process, thread, time};
mod ethernet;
mod net_util;
mod tap;
pub use ethernet::*;

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
        let src = current_frame.src();
        let dst = current_frame.dst();
        let eth_type = current_frame.ether_type();
        let payload = current_frame.payload();

        // let s = String::from_utf8_lossy(payload);
        if eth_type == 0x806 {
            println!("Arp req!");
        }
        println!("src: {:x?}", src);
        println!("dst: {:x?}", dst);
        println!("type: {:x?}", eth_type);
        println!("payload: {:x?}", payload);
    }
}
