mod reader;
mod writer;

use self::reader::IcmpReader;
pub use self::reader::Responce;
use self::writer::IcmpWriter;

use std::net::Ipv4Addr;

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportChannelType::Layer3;
use pnet::transport::transport_channel;

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

    /// Check the packet payload and get the timestamp
    pub fn get_packet_timestamp_ms(payload: &[u8]) -> Result<u64, &str> {
        // The packet should be 10 bytes long
        if payload.len() < 10 {
            return Err("Payload is not of length 10");
        }

        // Check the payload key
        if payload[0..2] != *IcmpWriter::get_payload_key() {
            return Err("Payload key invalid");
        }

        // Get the timestamp from the payload and convert it from Big Endian
        return Ok(u64::from_be(Self::array_to_u64(&payload[2..10])));
    }

    fn array_to_u64(data: &[u8]) -> u64 {
        return data[7] as u64 | (data[6] as u64) << 8 | (data[5] as u64) << 16
            | (data[4] as u64) << 24 | (data[3] as u64) << 32
            | (data[2] as u64) << 40 | (data[1] as u64) << 48
            | (data[0] as u64) << 56;
    }
}
