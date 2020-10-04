// UDP Sockets API

use super::udp::{UdpHeader, UDP, UDP_PROTO};
use crate::ethernet;
use crate::ipv4::{IPstackWriter, IpHeader, Layer4Response};
use crate::net_util;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock, Condvar};

// For lack of better options, using a global mutable states here.
lazy_static! {
    static ref SOCKETS: RwLock<HashMap<String, Arc<(Mutex<UdpSockObj>, Condvar)>>> =
        RwLock::new(HashMap::new());
}

static mut LAYER3_WRITER: Option<IPstackWriter> = None;


pub struct UdpSockObj {
    pub sock: UdpSocket,
    pub buff_empty: bool
}

pub struct UdpSocket {
    addr: std::net::SocketAddr,
    addr_identifier: String,
    buffer: Vec<PayloadBuff>,
    max_buff_size: u16,
    layer_3_writer: Mutex<IPstackWriter>,
    connected_sock: Option<UdpSocketIdentifier>,
}

#[derive(Clone, Debug)]
struct PayloadBuff {
    udp_packet: UDP,
    src_ip_header: IpHeader,
}

#[derive(Clone)]
pub struct UdpSocketIdentifier {
    socket_identifier: String,
    bind_ip: ethernet::ProtocolAddr,
    port: u16,
}

pub struct SocketOutPut {
    src_ip_header: IpHeader,
    src_udp_header: UdpHeader,
}

pub fn get_sock(identifier: &str) -> Option<std::sync::Arc<(Mutex<UdpSockObj>, Condvar)>> {
    let created_sockets = SOCKETS.read().unwrap();
    if created_sockets.contains_key(identifier) {
        let mutex_wrapped_socket = Arc::clone(created_sockets.get(identifier).unwrap());
        Some(mutex_wrapped_socket)
    } else {
        None
    }
}

pub fn intialize_stack(ip_stack_writer: IPstackWriter) {
    unsafe {
        LAYER3_WRITER = Some(ip_stack_writer);
    }
}

impl UdpSocketIdentifier {
    pub fn new(identifier: String, bind_ip: ethernet::ProtocolAddr, port: u16) -> Self {
        Self {
            socket_identifier: identifier,
            bind_ip: bind_ip,
            port: port,
        }
    }

    pub fn identifier(&self) -> &String {
        &self.socket_identifier
    }

    pub fn ip(&self) -> ethernet::ProtocolAddr {
        self.bind_ip
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn recv_from(&self, buf: &mut Vec<u8>) -> Result<(usize, SocketOutPut), &'static str> {
        let mut_sock = match get_sock(self.identifier()) {
            Some(sock) => sock,
            None => return Err("Socket has become stale"),
        };
        let (lock, cond_var) = &*mut_sock;
        let mut sock = cond_var.wait_while(lock.lock().unwrap(), |sock_obj| {
            sock_obj.buff_empty
        }).unwrap();

        let recent_buff = sock.sock.buffer.pop().unwrap();
        if sock.sock.buffer.len() == 0 {
            sock.buff_empty = true;
        }
        let buf_len = buf.capacity();
        let received_ip_header = recent_buff.src_ip_header;
        let last_udp_packet = recent_buff.udp_packet;
        let received_len = last_udp_packet.payload.len();

        let copy_till = if buf_len > received_len {
            received_len
        } else {
            buf_len
        };
        for i in 0..copy_till {
            buf.push(last_udp_packet.payload[i]);
        }
        Ok((
            received_len,
            SocketOutPut {
                src_ip_header: received_ip_header,
                src_udp_header: last_udp_packet.header(),
            },
        ))
    }

    pub fn connect<A: std::net::ToSocketAddrs>(&self, addr_str: A) -> Result<(), std::io::Error> {
        let mut addrs_iter = addr_str.to_socket_addrs()?;
        let remote_sock_addr = addrs_iter.next().unwrap();
        let (remote_ip_addr, remote_port) = UdpSocket::sock_addr_parse(&remote_sock_addr)?;
        let identifier = Self::new(
            net_util::addr_identifier(remote_ip_addr, remote_port),
            remote_ip_addr,
            remote_port,
        );

        let mut_sock = match get_sock(self.identifier()) {
            Some(sk) => sk,
            None => panic!("Errored while trying to retreive the socket!"),
        };
        let (mut_sock, _) = &*mut_sock;
        let mut sock = mut_sock.lock().unwrap();
        sock.sock.connected_sock = Some(identifier);
        Ok(())
    }

    pub fn send(&self, buf: &[u8]) -> Result<usize, &'static str> {
        let mut_sock = match get_sock(self.identifier()) {
            Some(sk) => sk,
            None => panic!("Errored while trying to retreive the socket!"),
        };

        let (mut_sock, _) = &*mut_sock;

        let sock = mut_sock.lock().unwrap();

        if let Some(remote_sock) = &sock.sock.connected_sock {
            let (dst_ip, dst_port, src_ip, src_port) = (
                remote_sock.ip(),
                remote_sock.port(),
                sock.sock.sock_addr(),
                sock.sock.sock_port(),
            );
            let (_, udp_resp_bytes) = UDP::create_packet(buf, src_port, dst_port, src_ip, dst_ip);
            let udp_len = udp_resp_bytes.len();

            let ip_header = IpHeader::make_unfragmented_ip_header(
                        dst_ip,
                        src_ip,
                        UDP_PROTO,
                        udp_len as u16,
                    );
            let l4_resp = Layer4Response {
                data: udp_resp_bytes,
                protocol: UDP_PROTO,
                src_ip_header: ip_header
            };
            sock.sock.write(l4_resp);
            Ok(udp_len)
        } else {
            Err("Socket not connected to any remote socket!")
        }
    }

    pub fn send_to(&self, buf: &[u8], src: &SocketOutPut) {
        let mut_sock = match get_sock(self.identifier()) {
            Some(sk) => sk,
            None => panic!("Errored while trying to retreive the socket!"),
        };
        let (mut_sock, _) = &*mut_sock;

        let sock = mut_sock.lock().unwrap();
        // we need to send the response back to where we received it from.
        let (dst_ip, dst_port, src_ip, src_port) = (
            src.src_ip_header.src,
            src.src_udp_header.src_port(),
            sock.sock.sock_addr(),
            sock.sock.sock_port(),
        );

        let (_, udp_resp_bytes) = UDP::create_packet(buf, src_port, dst_port, src_ip, dst_ip);
        sock.sock.write(Layer4Response {
            data: udp_resp_bytes,
            protocol: UDP_PROTO,
            src_ip_header: src.src_ip_header,
        });
    }
}
impl UdpSocket {
    pub fn write_to_sockbuff(&mut self, udp_packet: UDP, src_ip_header: IpHeader) {
        if (self.buffer.len() as u16) < self.max_buff_size {
            self.buffer.push(PayloadBuff {
                src_ip_header: src_ip_header,
                udp_packet: udp_packet,
            });
        };
        // Buffer full, drop the packet.
    }

    pub fn bind<A: std::net::ToSocketAddrs>(
        addr_str: A,
    ) -> Result<UdpSocketIdentifier, std::io::Error> {
        let mut addrs_iter = addr_str.to_socket_addrs()?;
        let sock_addr = addrs_iter.next().unwrap();
        let (ip_addr, port) = Self::sock_addr_parse(&sock_addr)?;
        let identifier = net_util::addr_identifier(ip_addr, port);
        Self::add_to_created_sockets(sock_addr, identifier.clone())?;
        Ok(UdpSocketIdentifier::new(identifier, ip_addr, port))
    }

    fn sock_addr_parse(
        sock_addr: &std::net::SocketAddr,
    ) -> Result<(ethernet::ProtocolAddr, u16), std::io::Error> {
        let ip_address = match sock_addr.ip() {
            IpAddr::V4(ipv4_addr) => ipv4_addr.octets(),
            IpAddr::V6(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "IPv6 address is not supported",
                ))
            }
        };
        Ok((ip_address, sock_addr.port()))
    }

    fn write(&self, resp: Layer4Response) {
        let writer = loop {
            if let Ok(writer) = self.layer_3_writer.try_lock() {
                break writer;
            } else {
                continue;
            }
        };
        writer.write(resp);
    }

    fn sock_addr(&self) -> ethernet::ProtocolAddr {
        if let IpAddr::V4(ipv4_addr) = self.addr.ip() {
            ipv4_addr.octets()
        } else {
            panic!("IPv6 address is not supported")
        }
    }

    fn sock_port(&self) -> u16 {
        self.addr.port()
    }

    fn add_to_created_sockets(
        addr: std::net::SocketAddr,
        identifier: String,
    ) -> Result<(), std::io::Error> {
        let mut created_sockets = SOCKETS.write().unwrap();
        if created_sockets.contains_key(&identifier) {
            return Err(Error::new(
                ErrorKind::AddrInUse,
                "Address or Port already in use!",
            ));
        } else {
            let ip_stack_writer = unsafe { LAYER3_WRITER.clone().unwrap() };
            let socket = UdpSocket {
                addr: addr,
                addr_identifier: identifier.clone(),
                buffer: Vec::new(),
                max_buff_size: 10000,
                layer_3_writer: Mutex::new(ip_stack_writer),
                connected_sock: None,
            };
            let sock_obj = UdpSockObj{
                sock: socket,
                buff_empty: true
            };
            created_sockets.insert(identifier, Arc::new((Mutex::new(sock_obj), Condvar::new())));
        }
        Ok(())
    }
}
