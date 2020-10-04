pub use crate::ipv4::udp_socket::UdpSocketIdentifier;

use crate::ipv4::udp_socket::UdpSocket;

pub fn bind<A: std::net::ToSocketAddrs>(
    addr_str: A,
) -> Result<UdpSocketIdentifier, std::io::Error> {
    UdpSocket::bind(addr_str)
}
