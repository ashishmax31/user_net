pub mod ethernet;

pub use ethernet::EtherType;
pub use ethernet::LinkLayerWritable;
pub use ethernet::{
    ChannelWriter, Ethernet, EthernetFrame, HwAddr, ProtocolAddr, ETH_ARP, ETH_IPV4, IP_ADDR,
};
