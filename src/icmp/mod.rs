mod reader;
mod writer;

use self::reader::IcmpReader;
use self::writer::IcmpWriter;

use std::net::Ipv4Addr;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer3;

pub struct IcmpHandler {
    pub reader: IcmpReader,
    pub writer: IcmpWriter,
}

impl IcmpHandler {
    /// Construct a new IcmpHandler.
    ///
    /// This will write and read the received ICMP packets asynchronously.
    pub fn new(localip: &str) -> IcmpHandler {
        let local: Ipv4Addr = localip.parse().unwrap();
        let (reader, writer) = Self::generate_transport(local);
        return IcmpHandler {
            reader: reader,
            writer: writer,
        };
    }

    /// Construct the IcmpReader and IcmpWriter using the given local IPv4 Address.
    fn generate_transport(local: Ipv4Addr) -> (IcmpReader, IcmpWriter) {
        let protocol = Layer3(IpNextHeaderProtocols::Icmp);
        let (tx, rx) = match transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => panic!(
                "An error occurred when creating the transport channel:
                            {}",
                e
            ),
        };

        return (IcmpReader::new(rx, local), IcmpWriter::new(tx, local));
    }
}
