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

#[derive(Debug, Clone)]
struct UdpSocket {
    addr: std::net::SocketAddr,
    addr_identifier: String,
    buffer: Vec<u8>,
    max_buffer_size: u16,
}

struct UdpSocketIdentifier {
    identifier: String,
}

impl UdpSocket {
    pub fn bind<A: std::net::ToSocketAddrs>(
        addr_str: A,
    ) -> Result<UdpSocketIdentifier, std::io::Error> {
        let mut addrs_iter = addr_str.to_socket_addrs()?;
        let sock_addr = addrs_iter.next().unwrap();
        let (ip_addr, port) = Self::sock_addr_parse(&sock_addr)?;
        let identifier = format!("{}:{}", ip_addr, port);
        Self::add_to_created_sockets(sock_addr, identifier.clone())?;
        Ok(UdpSocketIdentifier {
            identifier: identifier,
        })
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
                buffer: Vec::with_capacity(1000),
                max_buffer_size: 1000,
            };
            created_sockets.insert(identifier, Arc::new(Mutex::new(socket)));
        }
        Ok(())
    }

    fn get_sock(identifier: &str) -> Option<std::sync::Arc<std::sync::Mutex<UdpSocket>>> {
        let created_sockets = SOCKETS.lock().unwrap();
        if created_sockets.contains_key(identifier) {
            let mutex_wrapped_socket = Arc::clone(created_sockets.get(identifier).unwrap());
            Some(mutex_wrapped_socket)
        } else {
            None
        }
    }
}