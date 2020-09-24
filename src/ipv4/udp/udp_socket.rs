// UDP Sockets API

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

// For lack of better options, using a global mutable state here.
lazy_static! {
    static ref SOCKETS: Mutex<HashMap<String, Arc<Mutex<UdpSocket>>>> = Mutex::new(HashMap::new());
}

#[derive(Clone)]
pub struct UdpSocket {
    addr: std::net::SocketAddr,
    addr_identifier: String,
    buffer: Vec<payload_buff>,
    max_buff_size: u16,
}

#[derive(Clone)]
struct payload_buff {
    payload: Vec<u8>,
    from: UdpSocketIdentifier,
}

#[derive(Clone)]
pub struct UdpSocketIdentifier(String);

pub fn get_sock(identifier: &str) -> Option<std::sync::Arc<std::sync::Mutex<UdpSocket>>> {
    let created_sockets = SOCKETS.lock().unwrap();
    if created_sockets.contains_key(identifier) {
        let mutex_wrapped_socket = Arc::clone(created_sockets.get(identifier).unwrap());
        Some(mutex_wrapped_socket)
    } else {
        None
    }
}

impl UdpSocket {
    pub fn write_to_sockbuff(&mut self, payload: Vec<u8>, from: String) {
        if (self.buffer.len() as u16) < self.max_buff_size {
            self.buffer.push(payload_buff {
                payload: payload,
                from: UdpSocketIdentifier(from),
            });
        };
        // Buffer full
        // Drop packet
    }

    pub fn bind<A: std::net::ToSocketAddrs>(
        addr_str: A,
    ) -> Result<UdpSocketIdentifier, std::io::Error> {
        let mut addrs_iter = addr_str.to_socket_addrs()?;
        let sock_addr = addrs_iter.next().unwrap();
        let (ip_addr, port) = Self::sock_addr_parse(&sock_addr)?;
        let identifier = format!("{}:{}", ip_addr, port);
        Self::add_to_created_sockets(sock_addr, identifier.clone())?;
        Ok(UdpSocketIdentifier(identifier))
    }

    fn sock_addr_parse(sock_addr: &std::net::SocketAddr) -> Result<(String, u16), std::io::Error> {
        let ip_address = match sock_addr.ip() {
            IpAddr::V4(ipv4_addr) => ipv4_addr.octets(),
            IpAddr::V6(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "IPv6 address is not supported",
                ))
            }
        };
        let ip_address: String = ip_address.iter().map(|octet| *octet as char).collect();
        Ok((ip_address, sock_addr.port()))
    }

    fn add_to_created_sockets(
        addr: std::net::SocketAddr,
        identifier: String,
    ) -> Result<(), std::io::Error> {
        let mut created_sockets = SOCKETS.lock().unwrap();
        if created_sockets.contains_key(&identifier) {
            return Err(Error::new(
                ErrorKind::AddrInUse,
                "Address or Port already in use!",
            ));
        } else {
            let socket = UdpSocket {
                addr: addr,
                addr_identifier: identifier.clone(),
                buffer: Vec::new(),
                max_buff_size: 10000,
            };
            created_sockets.insert(identifier, Arc::new(Mutex::new(socket)));
        }
        Ok(())
    }
}
